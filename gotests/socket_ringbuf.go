package main

/*
#cgo CFLAGS: -I../.local_libbpf -I../libbpf/include -I../libbpf/include/uapi -I../libbpf/src
#cgo LDFLAGS: -L../.local_libbpf -lbpf -lz -lelf

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <bpf/libbpf.h>

struct ring_buffer;
struct netdata_ringbuf_stats;
struct netdata_socket_ringbuf_ctx;

int netdata_libbpf_get_error(const void *ptr);
struct netdata_socket_ringbuf_ctx *netdata_socket_ringbuf_ctx_new(struct netdata_ringbuf_stats *stats, uint64_t handle);
void netdata_socket_ringbuf_ctx_free(struct netdata_socket_ringbuf_ctx *ctx);
struct ring_buffer *netdata_socket_ring_buffer_new(int map_fd, struct netdata_socket_ringbuf_ctx *ctx);
int netdata_ring_buffer_poll(struct ring_buffer *rb, int timeout_ms);
uint64_t netdata_ringbuf_stats_samples(const struct netdata_ringbuf_stats *stats);
uint64_t netdata_ringbuf_stats_bytes(const struct netdata_ringbuf_stats *stats);
uint64_t netdata_ring_buffer_avail_data(const struct ring_buffer *rb);
uint64_t netdata_ring_buffer_size(const struct ring_buffer *rb);
void netdata_ring_buffer_free(struct ring_buffer *rb);
struct netdata_ringbuf_stats *netdata_ringbuf_stats_new(void);
void netdata_ringbuf_stats_free(struct netdata_ringbuf_stats *stats);
*/
import "C"

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	socketEventKeySize     = socketIdxPidOffset + 4
	socketEventValueSize   = socketValUDPBytesRecv + 8
	socketEventDataOffset   = socketEventKeySize
	socketArenaMapPages     = 256
	socketArenaSlotCount    = 1024
	socketArenaSlotSize     = socketEventKeySize + socketEventValueSize
	socketArenaStateHeader  = 8   // 4-byte head + 4-byte pad before 8-byte-aligned events[]
)

type socketRingbufCollector struct {
	mu      sync.Mutex
	entries map[string]*socketEntry
	order   []string
}

var (
	socketRingbufCollectorsMu sync.Mutex
	socketRingbufNextHandle    uint64 = 1
	socketRingbufCollectors           = map[uint64]*socketRingbufCollector{}
)

type socketRingBuffer struct {
	ptr    *C.struct_ring_buffer
	stats  *C.struct_netdata_ringbuf_stats
	ctx    *C.struct_netdata_socket_ringbuf_ctx
	handle uint64
}

func registerSocketRingbufCollector(c *socketRingbufCollector) uint64 {
	handle := atomic.AddUint64(&socketRingbufNextHandle, 1)

	socketRingbufCollectorsMu.Lock()
	socketRingbufCollectors[handle] = c
	socketRingbufCollectorsMu.Unlock()

	return handle
}

func unregisterSocketRingbufCollector(handle uint64) {
	socketRingbufCollectorsMu.Lock()
	delete(socketRingbufCollectors, handle)
	socketRingbufCollectorsMu.Unlock()
}

func getSocketRingbufCollector(handle uint64) *socketRingbufCollector {
	socketRingbufCollectorsMu.Lock()
	defer socketRingbufCollectorsMu.Unlock()
	return socketRingbufCollectors[handle]
}

func (c *socketRingbufCollector) add(raw []byte) {
	if len(raw) < socketEventValueSize {
		return
	}

	sample := socketDecodeKey(raw[:socketEventKeySize])
	socketAggregatePerCPU(&sample, raw[socketEventDataOffset:], socketEventValueSize, 1)

	key := string(raw[:socketEventKeySize])

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil {
		c.entries = make(map[string]*socketEntry)
	}

	if existing, ok := c.entries[key]; ok {
		socketMergeEntry(existing, &sample)
		return
	}

	entry := sample
	c.entries[key] = &entry
	c.order = append(c.order, key)
}

func socketArenaSlotEmpty(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}

// collectSocketArenaEntries reads socket events from a BPF arena using the
// libbpf-managed pointer returned by bpf_map__initial_value.
func collectSocketArenaEntries(arenaPtr unsafe.Pointer, collector *socketRingbufCollector) int {
	if arenaPtr == nil {
		return -1
	}

	pageSize := syscall.Getpagesize()
	arenaSize := socketArenaMapPages * pageSize
	mapped := unsafe.Slice((*byte)(arenaPtr), arenaSize)

	if len(mapped) < socketArenaStateHeader {
		return -1
	}

	head := binary.LittleEndian.Uint32(mapped[:4])
	if head == 0 {
		return 0
	}

	start := uint32(0)
	if head > socketArenaSlotCount {
		start = head - socketArenaSlotCount
	}

	for i := start; i < head; i++ {
		slot := int(i % socketArenaSlotCount)
		base := socketArenaStateHeader + slot*socketArenaSlotSize
		end := base + socketArenaSlotSize
		if end > len(mapped) {
			break
		}

		raw := mapped[base:end]
		if socketArenaSlotEmpty(raw) {
			continue
		}

		collector.add(raw)
	}

	return 0
}

func socketMergeEntry(dst, src *socketEntry) {
	if dst.name == "" && src.name != "" {
		dst.name = src.name
		dst.protocol = src.protocol
		dst.family = src.family
	}

	dst.tcpSentCalls += src.tcpSentCalls
	dst.tcpRecvCalls += src.tcpRecvCalls
	dst.tcpBytesSent += src.tcpBytesSent
	dst.tcpBytesRecv += src.tcpBytesRecv
	dst.tcpClose += src.tcpClose
	dst.tcpRetransmit += src.tcpRetransmit
	dst.tcpIPv4Connect += src.tcpIPv4Connect
	dst.tcpIPv6Connect += src.tcpIPv6Connect
	dst.udpSentCalls += src.udpSentCalls
	dst.udpRecvCalls += src.udpRecvCalls
	dst.udpBytesSent += src.udpBytesSent
	dst.udpBytesRecv += src.udpBytesRecv

	if src.tcpState != 0 {
		dst.tcpState = src.tcpState
	}
}

//export socketRingbufSample
func socketRingbufSample(handle C.uint64_t, data unsafe.Pointer, size C.size_t) {
	collector := getSocketRingbufCollector(uint64(handle))
	if collector == nil || data == nil {
		return
	}

	raw := C.GoBytes(data, C.int(size))
	collector.add(raw)
}

func newSocketRingBuffer(mapFD int) (*socketRingBuffer, int) {
	stats := C.netdata_ringbuf_stats_new()
	if stats == nil {
		return nil, -int(C.ENOMEM)
	}

	collector := &socketRingbufCollector{entries: make(map[string]*socketEntry)}
	handle := registerSocketRingbufCollector(collector)
	ctx := C.netdata_socket_ringbuf_ctx_new(stats, C.uint64_t(handle))
	if ctx == nil {
		C.netdata_ringbuf_stats_free(stats)
		unregisterSocketRingbufCollector(handle)
		return nil, -int(C.ENOMEM)
	}

	rb := C.netdata_socket_ring_buffer_new(C.int(mapFD), ctx)
	if err := int(C.libbpf_get_error(unsafe.Pointer(rb))); err != 0 {
		C.netdata_socket_ringbuf_ctx_free(ctx)
		C.netdata_ringbuf_stats_free(stats)
		unregisterSocketRingbufCollector(handle)
		return nil, err
	}

	return &socketRingBuffer{ptr: rb, stats: stats, ctx: ctx, handle: handle}, 0
}

func (rb *socketRingBuffer) free() {
	if rb == nil {
		return
	}

	unregisterSocketRingbufCollector(rb.handle)
	if rb.ptr != nil {
		C.netdata_ring_buffer_free(rb.ptr)
	}
	if rb.ctx != nil {
		C.netdata_socket_ringbuf_ctx_free(rb.ctx)
	}
	if rb.stats != nil {
		C.netdata_ringbuf_stats_free(rb.stats)
	}
}

func (rb *socketRingBuffer) poll(timeoutMS int) int {
	return int(C.netdata_ring_buffer_poll(rb.ptr, C.int(timeoutMS)))
}

func (rb *socketRingBuffer) samples() uint64 {
	return uint64(C.netdata_ringbuf_stats_samples(rb.stats))
}

func (rb *socketRingBuffer) bytes() uint64 {
	return uint64(C.netdata_ringbuf_stats_bytes(rb.stats))
}

func (rb *socketRingBuffer) availData() uint64 {
	return uint64(C.netdata_ring_buffer_avail_data(rb.ptr))
}

func (rb *socketRingBuffer) size() uint64 {
	return uint64(C.netdata_ring_buffer_size(rb.ptr))
}
