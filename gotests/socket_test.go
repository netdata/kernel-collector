package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"testing"
)

// buildSocketKey constructs a raw 40-byte netdata_socket_idx_t buffer.
func buildSocketKey(saddr, daddr [16]byte, dport uint16, pid uint32) []byte {
	key := make([]byte, socketIdxPidOffset+4) // 40 bytes
	copy(key[socketIdxSaddrOffset:], saddr[:])
	copy(key[socketIdxDaddrOffset:], daddr[:])
	binary.LittleEndian.PutUint16(key[socketIdxDportOffset:], dport)
	binary.LittleEndian.PutUint32(key[socketIdxPidOffset:], pid)
	return key
}

// buildSocketValue constructs a raw netdata_socket_t buffer for one CPU slot.
func buildSocketValue(name string, protocol, family uint16,
	tcpSent, tcpRecv uint32, tcpBytesSent, tcpBytesRecv uint64,
	tcpClose, tcpRetransmit, tcpIPv4, tcpIPv6, tcpState uint32,
	udpSent, udpRecv uint32, udpBytesSent, udpBytesRecv uint64) []byte {

	slot := make([]byte, socketValUDPBytesRecv+8) // 112 bytes
	n := copy(slot[socketValNameOffset:], name)
	if n < socketNameLen {
		slot[socketValNameOffset+n] = 0
	}
	binary.LittleEndian.PutUint16(slot[socketValProtocolOffset:], protocol)
	binary.LittleEndian.PutUint16(slot[socketValFamilyOffset:], family)
	binary.LittleEndian.PutUint32(slot[socketValTCPSentCalls:], tcpSent)
	binary.LittleEndian.PutUint32(slot[socketValTCPRecvCalls:], tcpRecv)
	binary.LittleEndian.PutUint64(slot[socketValTCPBytesSent:], tcpBytesSent)
	binary.LittleEndian.PutUint64(slot[socketValTCPBytesRecv:], tcpBytesRecv)
	binary.LittleEndian.PutUint32(slot[socketValTCPClose:], tcpClose)
	binary.LittleEndian.PutUint32(slot[socketValTCPRetransmit:], tcpRetransmit)
	binary.LittleEndian.PutUint32(slot[socketValTCPIPv4Connect:], tcpIPv4)
	binary.LittleEndian.PutUint32(slot[socketValTCPIPv6Connect:], tcpIPv6)
	binary.LittleEndian.PutUint32(slot[socketValTCPState:], tcpState)
	binary.LittleEndian.PutUint32(slot[socketValUDPSentCalls:], udpSent)
	binary.LittleEndian.PutUint32(slot[socketValUDPRecvCalls:], udpRecv)
	binary.LittleEndian.PutUint64(slot[socketValUDPBytesSent:], udpBytesSent)
	binary.LittleEndian.PutUint64(slot[socketValUDPBytesRecv:], udpBytesRecv)
	return slot
}

func TestSocketDecodeKey(t *testing.T) {
	var saddr, daddr [16]byte
	copy(saddr[:], net.ParseIP("192.168.1.1").To4())
	copy(daddr[:], net.ParseIP("8.8.8.8").To4())

	raw := buildSocketKey(saddr, daddr, 53, 1234)
	e := socketDecodeKey(raw)

	if e.saddr != saddr {
		t.Errorf("saddr mismatch: got %v want %v", e.saddr, saddr)
	}
	if e.daddr != daddr {
		t.Errorf("daddr mismatch: got %v want %v", e.daddr, daddr)
	}
	if e.dport != 53 {
		t.Errorf("dport: got %d want 53", e.dport)
	}
	if e.pid != 1234 {
		t.Errorf("pid: got %d want 1234", e.pid)
	}
}

func TestSocketDecodeKeyIPv6(t *testing.T) {
	var saddr, daddr [16]byte
	copy(saddr[:], net.ParseIP("2001:db8::1"))
	copy(daddr[:], net.ParseIP("2001:4860:4860::8888"))

	raw := buildSocketKey(saddr, daddr, 443, 9999)
	e := socketDecodeKey(raw)

	if e.saddr != saddr {
		t.Errorf("IPv6 saddr mismatch")
	}
	if e.dport != 443 {
		t.Errorf("dport: got %d want 443", e.dport)
	}
	if e.pid != 9999 {
		t.Errorf("pid: got %d want 9999", e.pid)
	}
}

func TestSocketAggregatePerCPUSingleSlot(t *testing.T) {
	slot := buildSocketValue("nginx", syscall.IPPROTO_TCP, syscall.AF_INET,
		10, 5, 1024, 2048, 1, 0, 3, 0, 1,
		0, 0, 0, 0)

	e := socketEntry{}
	socketAggregatePerCPU(&e, slot, len(slot), 1)

	if e.name != "nginx" {
		t.Errorf("name: got %q want %q", e.name, "nginx")
	}
	if e.protocol != syscall.IPPROTO_TCP {
		t.Errorf("protocol: got %d want %d", e.protocol, syscall.IPPROTO_TCP)
	}
	if e.family != syscall.AF_INET {
		t.Errorf("family: got %d want %d", e.family, syscall.AF_INET)
	}
	if e.tcpSentCalls != 10 {
		t.Errorf("tcpSentCalls: got %d want 10", e.tcpSentCalls)
	}
	if e.tcpBytesRecv != 2048 {
		t.Errorf("tcpBytesRecv: got %d want 2048", e.tcpBytesRecv)
	}
	if e.tcpIPv4Connect != 3 {
		t.Errorf("tcpIPv4Connect: got %d want 3", e.tcpIPv4Connect)
	}
	if e.tcpState != 1 {
		t.Errorf("tcpState: got %d want 1", e.tcpState)
	}
}

func TestSocketAggregatePerCPUMultipleSlots(t *testing.T) {
	stride := socketRoundUp8(112)

	// CPU 0: has name and some stats
	slot0 := buildSocketValue("sshd", syscall.IPPROTO_TCP, syscall.AF_INET,
		5, 3, 500, 600, 0, 1, 1, 0, 4,
		0, 0, 0, 0)

	// CPU 1: no name (zeroed), but has additional stats
	slot1 := buildSocketValue("", syscall.IPPROTO_TCP, syscall.AF_INET,
		3, 2, 200, 400, 0, 0, 0, 0, 0,
		0, 0, 0, 0)

	buf := make([]byte, 2*stride)
	copy(buf[0*stride:], slot0)
	copy(buf[1*stride:], slot1)

	e := socketEntry{}
	socketAggregatePerCPU(&e, buf, stride, 2)

	if e.name != "sshd" {
		t.Errorf("name: got %q want %q", e.name, "sshd")
	}
	if e.tcpSentCalls != 8 { // 5 + 3
		t.Errorf("tcpSentCalls: got %d want 8", e.tcpSentCalls)
	}
	if e.tcpBytesSent != 700 { // 500 + 200
		t.Errorf("tcpBytesSent: got %d want 700", e.tcpBytesSent)
	}
	if e.tcpBytesRecv != 1000 { // 600 + 400
		t.Errorf("tcpBytesRecv: got %d want 1000", e.tcpBytesRecv)
	}
	if e.tcpRetransmit != 1 {
		t.Errorf("tcpRetransmit: got %d want 1", e.tcpRetransmit)
	}
	if e.tcpState != 4 {
		t.Errorf("tcpState: got %d want 4", e.tcpState)
	}
}

func TestSocketAggregatePerCPUNameFromSecondSlot(t *testing.T) {
	stride := socketRoundUp8(112)

	// CPU 0: no name
	slot0 := buildSocketValue("", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	// CPU 1: has name
	slot1 := buildSocketValue("curl", syscall.IPPROTO_TCP, syscall.AF_INET6,
		1, 1, 100, 100, 0, 0, 0, 1, 6,
		0, 0, 0, 0)

	buf := make([]byte, 2*stride)
	copy(buf[0*stride:], slot0)
	copy(buf[1*stride:], slot1)

	e := socketEntry{}
	socketAggregatePerCPU(&e, buf, stride, 2)

	if e.name != "curl" {
		t.Errorf("name from second slot: got %q want %q", e.name, "curl")
	}
	if e.family != syscall.AF_INET6 {
		t.Errorf("family: got %d want AF_INET6=%d", e.family, syscall.AF_INET6)
	}
}

func TestSocketRoundUp8(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 0}, {1, 8}, {8, 8}, {9, 16}, {112, 112}, {113, 120},
	}
	for _, c := range cases {
		if got := socketRoundUp8(c.in); got != c.want {
			t.Errorf("socketRoundUp8(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSocketFormatIPv4(t *testing.T) {
	var raw [16]byte
	copy(raw[:], net.ParseIP("10.0.0.1").To4())

	got := socketFormatIP(syscall.AF_INET, raw)
	if got != "10.0.0.1" {
		t.Errorf("IPv4 format: got %q want %q", got, "10.0.0.1")
	}
}

func TestSocketFormatIPv6(t *testing.T) {
	var raw [16]byte
	copy(raw[:], net.ParseIP("2001:db8::1"))

	got := socketFormatIP(syscall.AF_INET6, raw)
	if got != "2001:db8::1" {
		t.Errorf("IPv6 format: got %q want %q", got, "2001:db8::1")
	}
}

func TestSocketJSONEscapeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"nginx", "nginx"},
		{"my\"app", `my\"app`},
		{"back\\slash", `back\\slash`},
		{"", ""},
	}
	for _, c := range cases {
		got := socketJSONEscapeName(c.in)
		if got != c.want {
			t.Errorf("escape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSocketWriteEntryJSON(t *testing.T) {
	var saddr, daddr [16]byte
	copy(saddr[:], net.ParseIP("192.168.0.1").To4())
	copy(daddr[:], net.ParseIP("93.184.216.34").To4())

	e := socketEntry{
		saddr:          saddr,
		daddr:          daddr,
		dport:          80,
		pid:            1001,
		name:           "wget",
		protocol:       uint16(syscall.IPPROTO_TCP),
		family:         uint16(syscall.AF_INET),
		tcpSentCalls:   7,
		tcpRecvCalls:   3,
		tcpBytesSent:   4096,
		tcpBytesRecv:   8192,
		tcpClose:       1,
		tcpRetransmit:  0,
		tcpIPv4Connect: 1,
		tcpIPv6Connect: 0,
		tcpState:       5,
		udpSentCalls:   0,
		udpRecvCalls:   0,
		udpBytesSent:   0,
		udpBytesRecv:   0,
	}

	var buf bytes.Buffer
	socketWriteEntryJSON(&buf, &e)
	out := buf.String()

	checks := []string{
		`"src_ip" : "192.168.0.1"`,
		`"dst_ip" : "93.184.216.34"`,
		`"dst_port" : 80`,
		`"pid" : 1001`,
		`"name" : "wget"`,
		`"sent_calls" : 7`,
		`"recv_calls" : 3`,
		`"bytes_sent" : 4096`,
		`"bytes_recv" : 8192`,
		`"close" : 1`,
		`"ipv4_connect" : 1`,
		`"state" : 5`,
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("JSON missing %q\ngot: %s", want, out)
		}
	}
}

func TestSocketWriteEntryJSONIPv6(t *testing.T) {
	var saddr, daddr [16]byte
	copy(saddr[:], net.ParseIP("::1"))
	copy(daddr[:], net.ParseIP("2001:db8::2"))

	e := socketEntry{
		saddr:    saddr,
		daddr:    daddr,
		dport:    443,
		pid:      2002,
		name:     "curl",
		protocol: uint16(syscall.IPPROTO_TCP),
		family:   uint16(syscall.AF_INET6),
	}

	var buf bytes.Buffer
	socketWriteEntryJSON(&buf, &e)
	out := buf.String()

	if !strings.Contains(out, `"src_ip" : "::1"`) {
		t.Errorf("expected IPv6 src_ip, got: %s", out)
	}
	if !strings.Contains(out, `"dst_port" : 443`) {
		t.Errorf("expected dst_port 443, got: %s", out)
	}
}

func TestSocketWriteEntryJSONEscapedName(t *testing.T) {
	e := socketEntry{
		name:   `proc"name`,
		family: uint16(syscall.AF_INET),
	}

	var buf bytes.Buffer
	socketWriteEntryJSON(&buf, &e)
	out := buf.String()

	if !strings.Contains(out, `"name" : "proc\"name"`) {
		t.Errorf("expected escaped name, got: %s", out)
	}
}

func TestSocketReadEntriesEmpty(t *testing.T) {
	// socketReadEntries with no map data: verifies it produces no output.
	// We pass fd=-1 which bpfMapGetNextKey will reject immediately (returns non-zero).
	var buf bytes.Buffer
	socketReadEntries(&buf, -1, socketIdxPidOffset+4, socketRoundUp8(112), 1)
	if buf.Len() != 0 {
		t.Errorf("expected empty output for invalid fd, got: %q", buf.String())
	}
}
