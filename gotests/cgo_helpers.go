package main

/*
#cgo CFLAGS: -I../.local_libbpf -I../libbpf/include -I../libbpf/include/uapi -I../libbpf/src
#cgo LDFLAGS: -L../.local_libbpf -lbpf -lz -lelf

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifdef LIBBPF_MAJOR_VERSION
static int netdata_libbpf_probe_bpf_map_type(unsigned int map_type)
{
	return libbpf_probe_bpf_map_type((enum bpf_map_type)map_type, NULL);
}
#else
static int netdata_libbpf_probe_bpf_map_type(unsigned int map_type)
{
	(void)map_type;
	return -EOPNOTSUPP;
}
#endif

static int netdata_libbpf_get_error(const void *ptr)
{
	return (int)libbpf_get_error(ptr);
}

static int netdata_open_capture_socket(int program_fd)
{
	struct sockaddr_ll bind_addr = { 0 };
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sockfd < 0)
		return errno ? -errno : -1;

	bind_addr.sll_family = AF_PACKET;
	bind_addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr))) {
		int err = errno ? -errno : -1;
		close(sockfd);
		return err;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_BPF, &program_fd, sizeof(program_fd))) {
		int err = errno ? -errno : -1;
		close(sockfd);
		return err;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
		int err = errno ? -errno : -1;
		close(sockfd);
		return err;
	}

	return sockfd;
}

static int netdata_set_memlock_rlimit(void)
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &r))
		return errno ? -errno : -1;

	return 0;
}

static int netdata_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	if (bpf_map_lookup_elem(fd, key, value))
		return errno ? -errno : -1;

	return 0;
}

static int netdata_bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	if (bpf_map_get_next_key(fd, key, next_key))
		return errno ? -errno : -1;

	return 0;
}

static int netdata_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
	if (bpf_map_update_elem(fd, key, value, flags))
		return errno ? -errno : -1;

	return 0;
}

static int netdata_close_fd(int fd)
{
	return close(fd);
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

const (
	bpfProgTypeKprobe = uint32(C.BPF_PROG_TYPE_KPROBE)

	// Map types probed to filter incompatible eBPF objects before load.
	bpfMapTypeHash        = uint32(C.BPF_MAP_TYPE_HASH)
	bpfMapTypeArray       = uint32(C.BPF_MAP_TYPE_ARRAY)
	bpfMapTypePerCPUHash  = uint32(C.BPF_MAP_TYPE_PERCPU_HASH)
	bpfMapTypePerCPUArray = uint32(C.BPF_MAP_TYPE_PERCPU_ARRAY)
)

type bpfObject struct {
	ptr *C.struct_bpf_object
}

type bpfProgram struct {
	ptr *C.struct_bpf_program
}

type bpfMap struct {
	ptr *C.struct_bpf_map
}

type bpfLink struct {
	ptr *C.struct_bpf_link
}

type mapMeta struct {
	Name       string
	FD         int
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
}

func openBPFObject(filename string) (*bpfObject, int) {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	obj := C.bpf_object__open_file(cFilename, nil)
	if err := int(C.netdata_libbpf_get_error(unsafe.Pointer(obj))); err != 0 {
		return nil, err
	}

	return &bpfObject{ptr: obj}, 0
}

func (o *bpfObject) close() {
	if o != nil && o.ptr != nil {
		C.bpf_object__close(o.ptr)
	}
}

func (o *bpfObject) load() int {
	return int(C.bpf_object__load(o.ptr))
}

func (o *bpfObject) firstProgram() *bpfProgram {
	prog := C.bpf_object__next_program(o.ptr, nil)
	if prog == nil {
		return nil
	}

	return &bpfProgram{ptr: prog}
}

func (o *bpfObject) nextProgram(prev *bpfProgram) *bpfProgram {
	var previous *C.struct_bpf_program
	if prev != nil {
		previous = prev.ptr
	}

	prog := C.bpf_object__next_program(o.ptr, previous)
	if prog == nil {
		return nil
	}

	return &bpfProgram{ptr: prog}
}

func (o *bpfObject) firstMap() *bpfMap {
	m := C.bpf_object__next_map(o.ptr, nil)
	if m == nil {
		return nil
	}

	return &bpfMap{ptr: m}
}

func (o *bpfObject) nextMap(prev *bpfMap) *bpfMap {
	var previous *C.struct_bpf_map
	if prev != nil {
		previous = prev.ptr
	}

	m := C.bpf_object__next_map(o.ptr, previous)
	if m == nil {
		return nil
	}

	return &bpfMap{ptr: m}
}

func (o *bpfObject) countPrograms() int {
	total := 0
	for prog := o.firstProgram(); prog != nil; prog = o.nextProgram(prog) {
		total++
	}

	return total
}

func (o *bpfObject) hasSocketFilter() bool {
	for prog := o.firstProgram(); prog != nil; prog = o.nextProgram(prog) {
		if prog.progType() == uint32(C.BPF_PROG_TYPE_SOCKET_FILTER) {
			return true
		}
	}

	return false
}

func (o *bpfObject) findSocketFilterProgram() *bpfProgram {
	for prog := o.firstProgram(); prog != nil; prog = o.nextProgram(prog) {
		if prog.progType() == uint32(C.BPF_PROG_TYPE_SOCKET_FILTER) {
			return prog
		}
	}

	return nil
}

func (o *bpfObject) findMapByName(name string) *bpfMap {
	for m := o.firstMap(); m != nil; m = o.nextMap(m) {
		if m.name() == name {
			return m
		}
	}

	return nil
}

func (p *bpfProgram) name() string {
	return C.GoString(C.bpf_program__name(p.ptr))
}

func (p *bpfProgram) progType() uint32 {
	return uint32(C.bpf_program__type(p.ptr))
}

func (p *bpfProgram) fd() int {
	return int(C.bpf_program__fd(p.ptr))
}

func (p *bpfProgram) attach() (*bpfLink, int) {
	link := C.bpf_program__attach(p.ptr)
	if err := int(C.netdata_libbpf_get_error(unsafe.Pointer(link))); err != 0 {
		return nil, err
	}

	return &bpfLink{ptr: link}, 0
}

func (p *bpfProgram) attachKprobe(retprobe bool, target string) (*bpfLink, int) {
	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))

	link := C.bpf_program__attach_kprobe(p.ptr, C.bool(retprobe), cTarget)
	if err := int(C.netdata_libbpf_get_error(unsafe.Pointer(link))); err != 0 {
		return nil, err
	}

	return &bpfLink{ptr: link}, 0
}

func (l *bpfLink) destroy() {
	if l != nil && l.ptr != nil {
		C.bpf_link__destroy(l.ptr)
	}
}

func (m *bpfMap) meta() mapMeta {
	return mapMeta{
		Name:       m.name(),
		FD:         int(C.bpf_map__fd(m.ptr)),
		Type:       uint32(C.bpf_map__type(m.ptr)),
		KeySize:    uint32(C.bpf_map__key_size(m.ptr)),
		ValueSize:  uint32(C.bpf_map__value_size(m.ptr)),
		MaxEntries: uint32(C.bpf_map__max_entries(m.ptr)),
	}
}

func (m *bpfMap) name() string {
	return C.GoString(C.bpf_map__name(m.ptr))
}

func probeMapTypeSupport(mapType uint32) int {
	return int(C.netdata_libbpf_probe_bpf_map_type(C.uint(mapType)))
}

func slicePointer(buf []byte) unsafe.Pointer {
	if len(buf) == 0 {
		return nil
	}

	return unsafe.Pointer(&buf[0])
}

func bpfMapLookupElem(fd int, key []byte, value []byte) int {
	return int(C.netdata_bpf_map_lookup_elem(C.int(fd), slicePointer(key), slicePointer(value)))
}

func bpfMapGetNextKey(fd int, key []byte, nextKey []byte) int {
	return int(C.netdata_bpf_map_get_next_key(C.int(fd), slicePointer(key), slicePointer(nextKey)))
}

func bpfMapUpdateElem(fd int, key []byte, value []byte, flags uint64) int {
	return int(C.netdata_bpf_map_update_elem(C.int(fd), slicePointer(key), slicePointer(value), C.__u64(flags)))
}

func openCaptureSocket(programFD int) (int, int) {
	fd := int(C.netdata_open_capture_socket(C.int(programFD)))
	if fd < 0 {
		return -1, fd
	}

	return fd, 0
}

func setMemlockLimit() int {
	return int(C.netdata_set_memlock_rlimit())
}

func closeFD(fd int) error {
	if ret := int(C.netdata_close_fd(C.int(fd))); ret != 0 {
		return errors.New("close failed")
	}

	return nil
}
