package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	socketSleepSec = 5
	socketNameLen  = 16

	// Binary offsets within netdata_socket_idx_t (40 bytes).
	socketIdxSaddrOffset = 0
	socketIdxDaddrOffset = 16
	socketIdxDportOffset = 32
	socketIdxPidOffset   = 36

	// Binary offsets within netdata_socket_t (112 bytes).
	socketValNameOffset        = 0
	socketValProtocolOffset    = 32
	socketValFamilyOffset      = 34
	socketValTCPSentCalls      = 40
	socketValTCPRecvCalls      = 44
	socketValTCPBytesSent      = 48
	socketValTCPBytesRecv      = 56
	socketValTCPClose          = 64
	socketValTCPRetransmit     = 68
	socketValTCPIPv4Connect    = 72
	socketValTCPIPv6Connect    = 76
	socketValTCPState          = 80
	socketValUDPSentCalls      = 88
	socketValUDPRecvCalls      = 92
	socketValUDPBytesSent      = 96
	socketValUDPBytesRecv      = 104
)

type socketEntry struct {
	saddr          [16]byte
	daddr          [16]byte
	dport          uint16
	pid            uint32
	name           string
	protocol       uint16
	family         uint16
	tcpSentCalls   uint32
	tcpRecvCalls   uint32
	tcpBytesSent   uint64
	tcpBytesRecv   uint64
	tcpClose       uint32
	tcpRetransmit  uint32
	tcpIPv4Connect uint32
	tcpIPv6Connect uint32
	tcpState       uint32
	udpSentCalls   uint32
	udpRecvCalls   uint32
	udpBytesSent   uint64
	udpBytesRecv   uint64
}

func socketDecodeKey(key []byte) (e socketEntry) {
	copy(e.saddr[:], key[socketIdxSaddrOffset:socketIdxSaddrOffset+16])
	copy(e.daddr[:], key[socketIdxDaddrOffset:socketIdxDaddrOffset+16])
	e.dport = binary.LittleEndian.Uint16(key[socketIdxDportOffset:])
	e.pid   = binary.LittleEndian.Uint32(key[socketIdxPidOffset:])
	return e
}

func socketRoundUp8(n int) int {
	return (n + 7) & ^7
}

/*
 * socketAggregatePerCPU sums all numeric fields across ncpus CPU slots.
 * Name, protocol, and family come from the first non-empty slot.
 */
func socketAggregatePerCPU(e *socketEntry, buf []byte, stride, ncpus int) {
	metaFound := false

	for cpu := 0; cpu < ncpus; cpu++ {
		slot := buf[cpu*stride:]

		if !metaFound && slot[socketValNameOffset] != 0 {
			raw := slot[socketValNameOffset : socketValNameOffset+socketNameLen]
			end := 0
			for end < len(raw) && raw[end] != 0 {
				end++
			}
			e.name     = string(raw[:end])
			e.protocol = binary.LittleEndian.Uint16(slot[socketValProtocolOffset:])
			e.family   = binary.LittleEndian.Uint16(slot[socketValFamilyOffset:])
			metaFound  = true
		}

		e.tcpSentCalls   += binary.LittleEndian.Uint32(slot[socketValTCPSentCalls:])
		e.tcpRecvCalls   += binary.LittleEndian.Uint32(slot[socketValTCPRecvCalls:])
		e.tcpBytesSent   += binary.LittleEndian.Uint64(slot[socketValTCPBytesSent:])
		e.tcpBytesRecv   += binary.LittleEndian.Uint64(slot[socketValTCPBytesRecv:])
		e.tcpClose       += binary.LittleEndian.Uint32(slot[socketValTCPClose:])
		e.tcpRetransmit  += binary.LittleEndian.Uint32(slot[socketValTCPRetransmit:])
		e.tcpIPv4Connect += binary.LittleEndian.Uint32(slot[socketValTCPIPv4Connect:])
		e.tcpIPv6Connect += binary.LittleEndian.Uint32(slot[socketValTCPIPv6Connect:])
		e.udpSentCalls   += binary.LittleEndian.Uint32(slot[socketValUDPSentCalls:])
		e.udpRecvCalls   += binary.LittleEndian.Uint32(slot[socketValUDPRecvCalls:])
		e.udpBytesSent   += binary.LittleEndian.Uint64(slot[socketValUDPBytesSent:])
		e.udpBytesRecv   += binary.LittleEndian.Uint64(slot[socketValUDPBytesRecv:])

		if st := binary.LittleEndian.Uint32(slot[socketValTCPState:]); st != 0 {
			e.tcpState = st
		}
	}
}

func socketFormatIP(family uint16, raw [16]byte) string {
	if family == syscall.AF_INET6 {
		return net.IP(raw[:16]).String()
	}
	return net.IP(raw[:4]).String()
}

func socketJSONEscapeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "\\\\")
	name = strings.ReplaceAll(name, "\"", "\\\"")
	return name
}

func socketWriteEntryJSON(w io.Writer, e *socketEntry) {
	srcIP := socketFormatIP(e.family, e.saddr)
	dstIP := socketFormatIP(e.family, e.daddr)

	fmt.Fprintf(w,
		"                                    "+
			"{ \"src_ip\" : \"%s\", \"dst_ip\" : \"%s\", "+
			"\"dst_port\" : %d, \"pid\" : %d, \"name\" : \"%s\", "+
			"\"protocol\" : %d, \"family\" : %d, "+
			"\"tcp\" : { \"sent_calls\" : %d, \"recv_calls\" : %d, "+
			"\"bytes_sent\" : %d, \"bytes_recv\" : %d, "+
			"\"close\" : %d, \"retransmit\" : %d, "+
			"\"ipv4_connect\" : %d, \"ipv6_connect\" : %d, "+
			"\"state\" : %d }, "+
			"\"udp\" : { \"sent_calls\" : %d, \"recv_calls\" : %d, "+
			"\"bytes_sent\" : %d, \"bytes_recv\" : %d } }",
		srcIP, dstIP,
		e.dport, e.pid, socketJSONEscapeName(e.name),
		e.protocol, e.family,
		e.tcpSentCalls, e.tcpRecvCalls,
		e.tcpBytesSent, e.tcpBytesRecv,
		e.tcpClose, e.tcpRetransmit,
		e.tcpIPv4Connect, e.tcpIPv6Connect,
		e.tcpState,
		e.udpSentCalls, e.udpRecvCalls,
		e.udpBytesSent, e.udpBytesRecv)
}

func hasSocketTable(obj *bpfObject) bool {
	return obj.findMapByName("tbl_nd_socket") != nil
}

func runSocketTableTester(w io.Writer, obj *bpfObject, iterations int) {
	m := obj.findMapByName("tbl_nd_socket")
	if m == nil {
		fmt.Fprint(w, "        \"Total tables\" : 0\n")
		return
	}

	meta := m.meta()
	ncpus := libbpfNumPossibleCPUs()
	if ncpus <= 0 {
		ncpus = 1
	}

	stride            := socketRoundUp8(int(meta.ValueSize))
	collectionSeconds := iterations * socketSleepSec

	fmt.Fprintf(w,
		"        \"socket_connections\" : {\n"+
			"            \"Info\" : { \"Length\" : { \"Key\" : %d, \"Value\" : %d},\n"+
			"                       \"Type\" : %d,\n"+
			"                       \"FD\" : %d,\n"+
			"                       \"ncpus\" : %d,\n"+
			"                       \"Collection Seconds\" : %d,\n"+
			"                       \"Data\" : [\n",
		meta.KeySize, meta.ValueSize, meta.Type, meta.FD, ncpus, collectionSeconds)

	time.Sleep(time.Duration(collectionSeconds) * time.Second)

	socketReadEntries(w, meta.FD, int(meta.KeySize), stride, ncpus)

	fmt.Fprint(w,
		"                                ]\n"+
			"                      }\n"+
			"        },\n"+
			"        \"Total tables\" : 1\n")
}

func socketReadEntries(w io.Writer, fd, keySize, stride, ncpus int) {
	keyBuf    := make([]byte, keySize)
	nextKey   := make([]byte, keySize)
	percpuBuf := make([]byte, stride*ncpus)
	first     := true

	if bpfMapGetNextKey(fd, nil, nextKey) != 0 {
		return
	}

	for {
		if bpfMapLookupElem(fd, nextKey, percpuBuf) == 0 {
			e := socketDecodeKey(nextKey)
			socketAggregatePerCPU(&e, percpuBuf, stride, ncpus)

			if !first {
				fmt.Fprint(w, ",\n")
			}
			socketWriteEntryJSON(w, &e)
			first = false
		}

		copy(keyBuf, nextKey)
		if bpfMapGetNextKey(fd, keyBuf, nextKey) != 0 {
			break
		}
	}

	if !first {
		fmt.Fprint(w, "\n")
	}
}

func socketKeyString(key []byte) string {
	return string(key[:socketEventKeySize])
}

func hasSocketEvents(obj *bpfObject) bool {
	return obj.findMapByName("socket_events") != nil
}

func socketWriteCollectedEntries(w io.Writer, coll *socketRingbufCollector) {
	if coll == nil {
		return
	}

	coll.mu.Lock()
	defer coll.mu.Unlock()

	first := true
	for _, key := range coll.order {
		entry := coll.entries[key]
		if entry == nil {
			continue
		}
		if !first {
			fmt.Fprint(w, ",\n")
		}
		socketWriteEntryJSON(w, entry)
		first = false
	}

	if !first {
		fmt.Fprint(w, "\n")
	}
}

func runSocketRingBufferTester(w io.Writer, obj *bpfObject, iterations int) {
	m := obj.findMapByName("socket_events")
	if m == nil {
		return
	}

	meta := m.meta()
	collectionSeconds := iterations * socketSleepSec
	collector := &socketRingbufCollector{entries: make(map[string]*socketEntry)}
	var rb *socketRingBuffer
	errCode := 0

	if meta.Type == bpfMapTypeRingBuf {
		rb, errCode = newSocketRingBuffer(meta.FD)
		if rb != nil {
			defer rb.free()
		}
	}

	fmt.Fprintf(w,
		"        \"socket_connections\" : {\n"+
			"            \"Info\" : { \"Length\" : { \"Key\" : %d, \"Value\" : %d},\n"+
			"                       \"Type\" : %d,\n"+
			"                       \"FD\" : %d,\n"+
			"                       \"Collection Seconds\" : %d,\n"+
			"                       \"Data\" : [\n",
		socketEventKeySize, socketEventValueSize, meta.Type, meta.FD, collectionSeconds)

	if errCode == 0 && rb != nil {
		for sec := 0; sec < collectionSeconds; sec++ {
			time.Sleep(time.Second)
			rb.poll(0)
		}
		rb.poll(0)
		socketWriteCollectedEntries(w, getSocketRingbufCollector(rb.handle))
	} else {
		arenaPtr, ainfo := m.initialValueInfo()
		fmt.Fprintf(os.Stderr,
			"[socket_arena_go] iptr=%p isize=%d page_size=%d arena_size=%d\n",
			ainfo.RawBase, ainfo.DataSize, ainfo.PageSize, ainfo.TotalSize)
		if ainfo.DataSize > 0 && arenaPtr != nil {
			initHead := binary.LittleEndian.Uint32(unsafe.Slice((*byte)(arenaPtr), 4))
			fmt.Fprintf(os.Stderr,
				"[socket_arena_go] isize>0 data_off=%d arena_state=%p head=%d\n",
				ainfo.DataOffset, arenaPtr, initHead)
		}
		fmt.Fprintf(os.Stderr,
			"[socket_arena_go] collecting for %ds — open external connections now\n",
			collectionSeconds)
		for sec := 0; sec < collectionSeconds; sec++ {
			time.Sleep(time.Second)
		}
		headBefore := uint32(0)
		if arenaPtr != nil {
			headBefore = binary.LittleEndian.Uint32(unsafe.Slice((*byte)(arenaPtr), 4))
		}
		fmt.Fprintf(os.Stderr, "[socket_arena_go] head=%d before collect\n", headBefore)
		if collectSocketArenaEntries(arenaPtr, collector) == 0 {
			socketWriteCollectedEntries(w, collector)
		}
		fmt.Fprintf(os.Stderr, "[socket_arena_go] coll.size=%d after collect\n", len(collector.entries))
	}

	if rb != nil {
		return
	}
}
