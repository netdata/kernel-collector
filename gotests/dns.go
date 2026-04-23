package main

import (
	"bytes"
	"fmt"
	"io"
	"syscall"
	"time"
)

const (
	dnsCaptureInterval = 5
	dnsTimeoutUsec     = 5 * 1000000
	dnsMaxDomainLength = 256
	dnsPacketBuffer    = 65536
	dnsIPv4MinHeader   = 20
	dnsIPv6Header      = 40
	dnsUDPHeader       = 8
	dnsTCPMinHeader    = 20
	ethHeaderLength    = 14
	ethProto8021Q      = 0x8100
	ethProto8021AD     = 0x88A8
	ethProtoIPv4       = 0x0800
	ethProtoIPv6       = 0x86DD
)

type dnsFlowKey struct {
	family     uint8
	protocol   uint8
	clientPort uint16
	serverIP   [16]byte
	clientIP   [16]byte
}

type dnsRcodeCounter struct {
	code  uint32
	count uint32
}

type dnsStats struct {
	key               dnsFlowKey
	queryType         uint16
	domain            string
	timeouts          uint32
	successLatencySum uint64
	failureLatencySum uint64
	rcodes            []dnsRcodeCounter
}

type dnsState struct {
	key           dnsFlowKey
	transactionID uint16
	queryType     uint16
	timestampUsec uint64
	domain        string
}

type dnsCollector struct {
	stats          []*dnsStats
	state          []*dnsState
	pendingQueries int
	totalResults   int
}

type dnsPacket struct {
	key           dnsFlowKey
	transactionID uint16
	queryType     uint16
	response      bool
	rcode         uint8
	domain        string
}

type dnsDebug struct {
	stage              string
	operation          string
	errorCode          int
	mapsRequested      bool
	iterations         int
	captureSeconds     int
	programFD          int
	sockFD             int
	dnsPortsFound      bool
	dnsPortsFD         int
	dnsPortsKeySize    uint32
	dnsPortsValueSize  uint32
	dnsPortsMaxEntries uint32
	dnsPortsType       uint32
}

func dnsReadU16(src []byte) uint16 {
	return (uint16(src[0]) << 8) | uint16(src[1])
}

func dnsNowUsec() uint64 {
	return uint64(time.Now().UnixNano() / 1000)
}

func dnsIPSize(family uint8) int {
	if family == syscall.AF_INET6 {
		return 16
	}

	return 4
}

func dnsFlowKeyEqual(a, b dnsFlowKey) bool {
	if a.family != b.family || a.protocol != b.protocol || a.clientPort != b.clientPort {
		return false
	}

	size := dnsIPSize(a.family)
	return bytes.Equal(a.serverIP[:size], b.serverIP[:size]) && bytes.Equal(a.clientIP[:size], b.clientIP[:size])
}

func dnsReadName(data []byte, offset int) (string, int, bool) {
	current := offset
	out := make([]byte, 0, dnsMaxDomainLength)
	jumps := 0
	jumped := false
	next := 0

	for current < len(data) && jumps < 32 {
		label := data[current]
		if label&0xC0 == 0xC0 {
			if current+1 >= len(data) {
				return "", 0, false
			}

			pointer := int(label&0x3F)<<8 | int(data[current+1])
			if !jumped {
				next = current + 2
				jumped = true
			}

			current = pointer
			jumps++
			continue
		}

		current++
		if label == 0 {
			if !jumped {
				next = current
			}

			if len(out) == 0 {
				return ".", next, true
			}

			return string(out), next, true
		}

		if label > 63 || current+int(label) > len(data) {
			return "", 0, false
		}

		if len(out) > 0 {
			if len(out)+1 >= dnsMaxDomainLength {
				return "", 0, false
			}
			out = append(out, '.')
		}

		if len(out)+int(label) >= dnsMaxDomainLength {
			return "", 0, false
		}

		for i := 0; i < int(label); i++ {
			ch := data[current]
			current++
			if ch >= 'A' && ch <= 'Z' {
				ch = ch - 'A' + 'a'
			}
			out = append(out, ch)
		}

		jumps++
	}

	return "", 0, false
}

func dnsParsePayload(payload []byte, protocol uint8) (dnsPacket, bool) {
	message := payload
	messageLen := len(payload)
	offset := 12
	var packet dnsPacket

	if protocol == syscall.IPPROTO_TCP {
		if len(payload) < 2 {
			return dnsPacket{}, false
		}

		dnsLength := int(dnsReadU16(payload))
		if dnsLength == 0 || dnsLength+2 > len(payload) {
			return dnsPacket{}, false
		}

		message = payload[2:]
		messageLen = dnsLength
	}

	if messageLen < 12 {
		return dnsPacket{}, false
	}

	packet.transactionID = dnsReadU16(message)
	flags := dnsReadU16(message[2:])
	qdcount := dnsReadU16(message[4:])
	if qdcount != 1 {
		return dnsPacket{}, false
	}

	domain, next, ok := dnsReadName(message[:messageLen], offset)
	if !ok {
		return dnsPacket{}, false
	}

	offset = next
	if offset+4 > messageLen {
		return dnsPacket{}, false
	}

	packet.queryType = dnsReadU16(message[offset:])
	qclass := dnsReadU16(message[offset+2:])
	if qclass != 1 {
		return dnsPacket{}, false
	}

	packet.response = flags&0x8000 != 0
	packet.rcode = uint8(flags & 0x000F)
	packet.domain = domain

	return packet, true
}

func dnsParseIPv4(packet []byte, offset int) (dnsPacket, bool) {
	if offset+dnsIPv4MinHeader > len(packet) || packet[offset]>>4 != 4 {
		return dnsPacket{}, false
	}

	ihl := int(packet[offset]&0x0F) * 4
	if ihl < dnsIPv4MinHeader || offset+ihl > len(packet) {
		return dnsPacket{}, false
	}

	totalLength := int(dnsReadU16(packet[offset+2:]))
	if totalLength < ihl {
		return dnsPacket{}, false
	}

	fragOff := dnsReadU16(packet[offset+6:])
	if fragOff&0x1FFF != 0 {
		return dnsPacket{}, false
	}

	protocol := packet[offset+9]
	if protocol != syscall.IPPROTO_UDP && protocol != syscall.IPPROTO_TCP {
		return dnsPacket{}, false
	}

	l4Offset := offset + ihl
	if offset+totalLength < l4Offset {
		return dnsPacket{}, false
	}

	l4Length := len(packet) - l4Offset
	if offset+totalLength <= len(packet) {
		l4Length = offset + totalLength - l4Offset
	}

	if l4Length == 0 {
		return dnsPacket{}, false
	}

	var srcPort, dstPort uint16
	var payload []byte
	if protocol == syscall.IPPROTO_UDP {
		if l4Length < dnsUDPHeader {
			return dnsPacket{}, false
		}
		srcPort = dnsReadU16(packet[l4Offset:])
		dstPort = dnsReadU16(packet[l4Offset+2:])
		payload = packet[l4Offset+dnsUDPHeader : l4Offset+l4Length]
	} else {
		if l4Length < dnsTCPMinHeader {
			return dnsPacket{}, false
		}
		srcPort = dnsReadU16(packet[l4Offset:])
		dstPort = dnsReadU16(packet[l4Offset+2:])
		tcpHeaderLength := int((packet[l4Offset+12]>>4)&0x0F) * 4
		if tcpHeaderLength < dnsTCPMinHeader || tcpHeaderLength > l4Length {
			return dnsPacket{}, false
		}
		payload = packet[l4Offset+tcpHeaderLength : l4Offset+l4Length]
	}

	dnsPkt, ok := dnsParsePayload(payload, protocol)
	if !ok {
		return dnsPacket{}, false
	}

	dnsPkt.key.family = syscall.AF_INET
	dnsPkt.key.protocol = protocol
	if !dnsPkt.response {
		copy(dnsPkt.key.clientIP[:4], packet[offset+12:offset+16])
		copy(dnsPkt.key.serverIP[:4], packet[offset+16:offset+20])
		dnsPkt.key.clientPort = srcPort
	} else {
		copy(dnsPkt.key.serverIP[:4], packet[offset+12:offset+16])
		copy(dnsPkt.key.clientIP[:4], packet[offset+16:offset+20])
		dnsPkt.key.clientPort = dstPort
	}

	return dnsPkt, true
}

func dnsParseIPv6(packet []byte, offset int) (dnsPacket, bool) {
	if offset+dnsIPv6Header > len(packet) || packet[offset]>>4 != 6 {
		return dnsPacket{}, false
	}

	payloadSize := int(dnsReadU16(packet[offset+4:]))
	protocol := packet[offset+6]
	if protocol != syscall.IPPROTO_UDP && protocol != syscall.IPPROTO_TCP {
		return dnsPacket{}, false
	}

	l4Offset := offset + dnsIPv6Header
	if l4Offset > len(packet) {
		return dnsPacket{}, false
	}

	l4Length := len(packet) - l4Offset
	if l4Offset+payloadSize <= len(packet) {
		l4Length = payloadSize
	}

	if l4Length == 0 {
		return dnsPacket{}, false
	}

	var srcPort, dstPort uint16
	var payload []byte
	if protocol == syscall.IPPROTO_UDP {
		if l4Length < dnsUDPHeader {
			return dnsPacket{}, false
		}
		srcPort = dnsReadU16(packet[l4Offset:])
		dstPort = dnsReadU16(packet[l4Offset+2:])
		payload = packet[l4Offset+dnsUDPHeader : l4Offset+l4Length]
	} else {
		if l4Length < dnsTCPMinHeader {
			return dnsPacket{}, false
		}
		srcPort = dnsReadU16(packet[l4Offset:])
		dstPort = dnsReadU16(packet[l4Offset+2:])
		tcpHeaderLength := int((packet[l4Offset+12]>>4)&0x0F) * 4
		if tcpHeaderLength < dnsTCPMinHeader || tcpHeaderLength > l4Length {
			return dnsPacket{}, false
		}
		payload = packet[l4Offset+tcpHeaderLength : l4Offset+l4Length]
	}

	dnsPkt, ok := dnsParsePayload(payload, protocol)
	if !ok {
		return dnsPacket{}, false
	}

	dnsPkt.key.family = syscall.AF_INET6
	dnsPkt.key.protocol = protocol
	if !dnsPkt.response {
		copy(dnsPkt.key.clientIP[:], packet[offset+8:offset+24])
		copy(dnsPkt.key.serverIP[:], packet[offset+24:offset+40])
		dnsPkt.key.clientPort = srcPort
	} else {
		copy(dnsPkt.key.serverIP[:], packet[offset+8:offset+24])
		copy(dnsPkt.key.clientIP[:], packet[offset+24:offset+40])
		dnsPkt.key.clientPort = dstPort
	}

	return dnsPkt, true
}

func dnsParsePacket(packet []byte) (dnsPacket, bool) {
	if len(packet) < ethHeaderLength {
		return dnsPacket{}, false
	}

	offset := ethHeaderLength
	protocol := dnsReadU16(packet[12:])
	for protocol == ethProto8021Q || protocol == ethProto8021AD {
		if offset+4 > len(packet) {
			return dnsPacket{}, false
		}
		protocol = dnsReadU16(packet[offset+2:])
		offset += 4
	}

	switch protocol {
	case ethProtoIPv4:
		return dnsParseIPv4(packet, offset)
	case ethProtoIPv6:
		return dnsParseIPv6(packet, offset)
	default:
		return dnsPacket{}, false
	}
}

func (c *dnsCollector) findStats(key dnsFlowKey, domain string, queryType uint16) *dnsStats {
	for _, stats := range c.stats {
		if stats.queryType == queryType && stats.domain == domain && dnsFlowKeyEqual(stats.key, key) {
			return stats
		}
	}

	return nil
}

func (c *dnsCollector) getStats(key dnsFlowKey, domain string, queryType uint16) *dnsStats {
	if stats := c.findStats(key, domain, queryType); stats != nil {
		return stats
	}

	stats := &dnsStats{
		key:       key,
		queryType: queryType,
		domain:    domain,
	}

	c.stats = append([]*dnsStats{stats}, c.stats...)
	c.totalResults++
	return stats
}

func (s *dnsStats) incrementRcode(rcode uint8) {
	for i := range s.rcodes {
		if s.rcodes[i].code == uint32(rcode) {
			s.rcodes[i].count++
			return
		}
	}

	s.rcodes = append([]dnsRcodeCounter{{code: uint32(rcode), count: 1}}, s.rcodes...)
}

func (c *dnsCollector) timeoutState(state *dnsState) {
	stats := c.getStats(state.key, state.domain, state.queryType)
	stats.timeouts++
}

func (c *dnsCollector) expireStates(nowUsec uint64) {
	remaining := c.state[:0]
	for _, state := range c.state {
		if nowUsec-state.timestampUsec > dnsTimeoutUsec {
			c.timeoutState(state)
			c.pendingQueries--
			continue
		}
		remaining = append(remaining, state)
	}
	c.state = remaining
}

func (c *dnsCollector) processQuery(packet dnsPacket, nowUsec uint64) {
	for _, state := range c.state {
		if state.transactionID == packet.transactionID && dnsFlowKeyEqual(state.key, packet.key) {
			return
		}
	}

	state := &dnsState{
		key:           packet.key,
		transactionID: packet.transactionID,
		queryType:     packet.queryType,
		timestampUsec: nowUsec,
		domain:        packet.domain,
	}

	c.state = append([]*dnsState{state}, c.state...)
	c.pendingQueries++
}

func (c *dnsCollector) processResponse(packet dnsPacket, nowUsec uint64) {
	for idx, state := range c.state {
		if state.transactionID == packet.transactionID && dnsFlowKeyEqual(state.key, packet.key) {
			latency := nowUsec - state.timestampUsec
			stats := c.getStats(state.key, state.domain, state.queryType)
			if latency > dnsTimeoutUsec {
				stats.timeouts++
			} else {
				stats.incrementRcode(packet.rcode)
				if packet.rcode == 0 {
					stats.successLatencySum += latency
				} else {
					stats.failureLatencySum += latency
				}
			}

			c.state = append(c.state[:idx], c.state[idx+1:]...)
			c.pendingQueries--
			return
		}
	}
}

func dnsWritePortsJSON(w io.Writer, meta mapMeta, ports []uint16) {
	fmt.Fprintf(w,
		"        \"dns_ports\" : {\n"+
			"            \"Info\" : { \"Length\" : { \"Key\" : %d, \"Value\" : %d},\n"+
			"                       \"Type\" : %d,\n"+
			"                       \"FD\" : %d,\n"+
			"                       \"Configured Ports\" : [",
		meta.KeySize, meta.ValueSize, meta.Type, meta.FD)

	for i, port := range ports {
		if i > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprint(w, port)
	}

	fmt.Fprintf(w,
		"],\n"+
			"                       \"Data\" : [\n"+
			"                                    { \"Iteration\" : 1, \"Total\" : %d, \"Filled\" : %d, \"Zero\" : %d }\n"+
			"                                ]\n"+
			"                      }\n"+
			"        }",
		meta.MaxEntries, len(ports), int(meta.MaxEntries)-len(ports))
}

func dnsWriteRcodesJSON(w io.Writer, rcodes []dnsRcodeCounter) {
	fmt.Fprint(w, "{ ")
	for i, rcode := range rcodes {
		if i > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprintf(w, "\"%d\" : %d", rcode.code, rcode.count)
	}
	fmt.Fprint(w, " }")
}

func dnsWriteResultsJSON(w io.Writer, collector *dnsCollector, captureSeconds int) {
	fmt.Fprintf(w,
		"        \"dns_results\" : {\n"+
			"            \"Info\" : { \"Collection Seconds\" : %d,\n"+
			"                       \"Timeout Window Usec\" : %d,\n"+
			"                       \"Pending Queries\" : %d,\n"+
			"                       \"Total Results\" : %d,\n"+
			"                       \"Data\" : [\n",
		captureSeconds, dnsTimeoutUsec, collector.pendingQueries, collector.totalResults)

	for i, stats := range collector.stats {
		if i > 0 {
			fmt.Fprint(w, ",\n")
		}

		serverIP := dnsFormatIP(stats.key.family, stats.key.serverIP)
		clientIP := dnsFormatIP(stats.key.family, stats.key.clientIP)
		fmt.Fprintf(w,
			"                                    { \"server_ip\" : \"%s\", \"client_ip\" : \"%s\", "+
				"\"client_port\" : %d, \"protocol\" : %d, \"query_type\" : %d, \"domain\" : \"%s\", "+
				"\"stats\" : { \"Timeouts\" : %d, \"SuccessLatencySum\" : %d, "+
				"\"FailureLatencySum\" : %d, \"CountByRcode\" : ",
			serverIP, clientIP, stats.key.clientPort, stats.key.protocol, stats.queryType, stats.domain,
			stats.timeouts, stats.successLatencySum, stats.failureLatencySum)
		dnsWriteRcodesJSON(w, stats.rcodes)
		fmt.Fprint(w, " } }")
	}

	if len(collector.stats) > 0 {
		fmt.Fprint(w, "\n")
	}

	fmt.Fprint(w,
		"                                ]\n"+
			"                      }\n"+
			"        }")
}

func dnsWriteFailureDebug(w io.Writer, ports []uint16, debug dnsDebug) {
	fmt.Fprintf(w,
		"        \"Debug\" : {\n"+
			"            \"Info\" : { \"Stage\" : \"%s\",\n"+
			"                       \"Operation\" : \"%s\",\n"+
			"                       \"Error Code\" : %d,\n"+
			"                       \"Error Message\" : \"%s\",\n"+
			"                       \"Maps Requested\" : %d,\n"+
			"                       \"Iterations\" : %d,\n"+
			"                       \"Capture Seconds\" : %d,\n"+
			"                       \"Program FD\" : %d,\n"+
			"                       \"Socket FD\" : %d,\n"+
			"                       \"dns_ports Found\" : %d,\n"+
			"                       \"dns_ports FD\" : %d,\n"+
			"                       \"dns_ports Type\" : %d,\n"+
			"                       \"dns_ports Key Size\" : %d,\n"+
			"                       \"dns_ports Value Size\" : %d,\n"+
			"                       \"dns_ports Max Entries\" : %d,\n"+
			"                       \"Configured Ports\" : [",
		debug.stage, debug.operation, debug.errorCode, describeError(debug.errorCode),
		boolToInt(debug.mapsRequested), debug.iterations, debug.captureSeconds,
		debug.programFD, debug.sockFD, boolToInt(debug.dnsPortsFound), debug.dnsPortsFD,
		debug.dnsPortsType, debug.dnsPortsKeySize, debug.dnsPortsValueSize, debug.dnsPortsMaxEntries)

	for i, port := range ports {
		if i > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprint(w, port)
	}

	fmt.Fprint(w, "]\n                      }\n        }\n")
}

func runDNSSocketFilterTester(obj *bpfObject, maps bool, w io.Writer, iterations int, ports []uint16) string {
	const (
		success = "Success"
		failure = "Fail"
	)

	debug := dnsDebug{
		stage:          "initializing",
		operation:      "initialize",
		mapsRequested:  maps,
		iterations:     iterations,
		captureSeconds: iterations * dnsCaptureInterval,
		programFD:      -1,
		sockFD:         -1,
		dnsPortsFD:     -1,
	}

	if loadErr := obj.load(); loadErr != 0 {
		debug.stage = "load_object"
		debug.operation = "bpf_object__load"
		debug.errorCode = loadErr
		dnsWriteFailureDebug(w, ports, debug)
		return failure
	}

	prog := obj.findSocketFilterProgram()
	if prog == nil {
		debug.stage = "find_socket_filter_program"
		debug.operation = "bpf_object__next_program"
		debug.errorCode = -int(syscall.ENOENT)
		dnsWriteFailureDebug(w, ports, debug)
		return failure
	}

	debug.programFD = prog.fd()

	dnsPortsMap := obj.findMapByName("dns_ports")
	if dnsPortsMap == nil {
		debug.stage = "configure_ports"
		debug.operation = "find_dns_ports_map"
		debug.errorCode = -int(syscall.ENOENT)
		dnsWriteFailureDebug(w, ports, debug)
		return failure
	}

	meta := dnsPortsMap.meta()
	debug.dnsPortsFound = true
	debug.dnsPortsFD = meta.FD
	debug.dnsPortsType = meta.Type
	debug.dnsPortsKeySize = meta.KeySize
	debug.dnsPortsValueSize = meta.ValueSize
	debug.dnsPortsMaxEntries = meta.MaxEntries

	for _, port := range ports {
		key := make([]byte, meta.KeySize)
		value := make([]byte, meta.ValueSize)
		putUint16(key, port)
		if len(value) > 0 {
			value[0] = 1
		}
		if err := bpfMapUpdateElem(meta.FD, key, value, 0); err != 0 {
			debug.stage = "configure_ports"
			debug.operation = "bpf_map_update_elem"
			debug.errorCode = err
			dnsWriteFailureDebug(w, ports, debug)
			return failure
		}
	}

	sockFD, sockErr := openCaptureSocket(debug.programFD)
	if sockErr != 0 {
		debug.stage = "open_capture_socket"
		debug.operation = "netdata_open_capture_socket"
		debug.errorCode = sockErr
		dnsWriteFailureDebug(w, ports, debug)
		return failure
	}
	defer closeFD(sockFD)

	debug.sockFD = sockFD

	if maps {
		collector := &dnsCollector{}
		dnsCollectPackets(sockFD, collector, debug.captureSeconds)
		dnsWritePortsJSON(w, meta, ports)
		fmt.Fprint(w, ",\n")
		dnsWriteResultsJSON(w, collector, debug.captureSeconds)
		fmt.Fprint(w, ",\n        \"Total tables\" : 2\n")
	}

	return success
}

func dnsCollectPackets(sockFD int, collector *dnsCollector, captureSeconds int) {
	packet := make([]byte, dnsPacketBuffer)
	deadline := time.Now().Add(time.Duration(captureSeconds) * time.Second)

	for time.Now().Before(deadline) {
		n, err := syscall.Read(sockFD, packet)
		nowUsec := dnsNowUsec()
		collector.expireStates(nowUsec)

		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			break
		}

		if n <= 0 {
			continue
		}

		dnsPacket, ok := dnsParsePacket(packet[:n])
		if !ok {
			continue
		}

		if !dnsPacket.response {
			collector.processQuery(dnsPacket, nowUsec)
		} else {
			collector.processResponse(dnsPacket, nowUsec)
		}
	}

	collector.expireStates(dnsNowUsec())
}
