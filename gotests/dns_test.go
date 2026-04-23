package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"testing"
)

func encodeDNSName(domain string) []byte {
	if domain == "." {
		return []byte{0}
	}

	var out []byte
	for _, label := range strings.Split(domain, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}

	return append(out, 0)
}

func buildDNSMessage(id uint16, flags uint16, domain string, qtype uint16) []byte {
	question := encodeDNSName(domain)
	msg := make([]byte, 12, 12+len(question)+4)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], flags)
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, question...)

	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:], qtype)
	binary.BigEndian.PutUint16(qtail[2:], 1)
	msg = append(msg, qtail...)

	return msg
}

func buildUDPDatagram(srcPort, dstPort uint16, payload []byte) []byte {
	out := make([]byte, dnsUDPHeader+len(payload))
	binary.BigEndian.PutUint16(out[0:], srcPort)
	binary.BigEndian.PutUint16(out[2:], dstPort)
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)))
	copy(out[dnsUDPHeader:], payload)
	return out
}

func buildTCPSegment(srcPort, dstPort uint16, payload []byte) []byte {
	out := make([]byte, dnsTCPMinHeader+len(payload))
	binary.BigEndian.PutUint16(out[0:], srcPort)
	binary.BigEndian.PutUint16(out[2:], dstPort)
	out[12] = 5 << 4
	copy(out[dnsTCPMinHeader:], payload)
	return out
}

func buildIPv4Packet(srcIP, dstIP [4]byte, protocol uint8, l4 []byte) []byte {
	out := make([]byte, dnsIPv4MinHeader+len(l4))
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	out[8] = 64
	out[9] = protocol
	copy(out[12:16], srcIP[:])
	copy(out[16:20], dstIP[:])
	copy(out[dnsIPv4MinHeader:], l4)
	return out
}

func buildIPv6Packet(srcIP, dstIP [16]byte, protocol uint8, l4 []byte) []byte {
	out := make([]byte, dnsIPv6Header+len(l4))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:], uint16(len(l4)))
	out[6] = protocol
	out[7] = 64
	copy(out[8:24], srcIP[:])
	copy(out[24:40], dstIP[:])
	copy(out[dnsIPv6Header:], l4)
	return out
}

func buildEthernetFrame(etherType uint16, payload []byte) []byte {
	out := make([]byte, ethHeaderLength+len(payload))
	binary.BigEndian.PutUint16(out[12:], etherType)
	copy(out[ethHeaderLength:], payload)
	return out
}

func buildVLANFrame(innerType uint16, payload []byte) []byte {
	out := make([]byte, ethHeaderLength+4+len(payload))
	binary.BigEndian.PutUint16(out[12:], ethProto8021Q)
	binary.BigEndian.PutUint16(out[16:], innerType)
	copy(out[18:], payload)
	return out
}

func mustIPv6(t *testing.T, value string) [16]byte {
	t.Helper()

	ip := net.ParseIP(value)
	if ip == nil {
		t.Fatalf("invalid IPv6 literal %q", value)
	}

	var out [16]byte
	copy(out[:], ip.To16())
	return out
}

func TestDNSReadName(t *testing.T) {
	t.Run("simple name is lowercased", func(t *testing.T) {
		data := encodeDNSName("WWW.Example.COM")

		got, next, ok := dnsReadName(data, 0)
		if !ok {
			t.Fatal("dnsReadName returned ok=false")
		}
		if got != "www.example.com" {
			t.Fatalf("unexpected domain: %q", got)
		}
		if next != len(data) {
			t.Fatalf("unexpected next offset: got %d want %d", next, len(data))
		}
	})

	t.Run("compressed name follows pointer", func(t *testing.T) {
		base := encodeDNSName("example.com")
		data := append(append([]byte{}, base...), 3, 'w', 'w', 'w', 0xC0, 0x00)

		got, next, ok := dnsReadName(data, len(base))
		if !ok {
			t.Fatal("dnsReadName returned ok=false")
		}
		if got != "www.example.com" {
			t.Fatalf("unexpected domain: %q", got)
		}
		if next != len(base)+6 {
			t.Fatalf("unexpected next offset: got %d want %d", next, len(base)+6)
		}
	})

	t.Run("truncated label is rejected", func(t *testing.T) {
		if _, _, ok := dnsReadName([]byte{3, 'w', 'w'}, 0); ok {
			t.Fatal("expected truncated label to fail")
		}
	})
}

func TestDNSParsePayload(t *testing.T) {
	t.Run("udp query", func(t *testing.T) {
		payload := buildDNSMessage(0x1234, 0x0100, "WWW.Example.COM", 1)

		packet, ok := dnsParsePayload(payload, syscall.IPPROTO_UDP)
		if !ok {
			t.Fatal("dnsParsePayload returned ok=false")
		}
		if packet.transactionID != 0x1234 {
			t.Fatalf("unexpected transaction ID: %#x", packet.transactionID)
		}
		if packet.queryType != 1 {
			t.Fatalf("unexpected query type: %d", packet.queryType)
		}
		if packet.response {
			t.Fatal("expected query packet")
		}
		if packet.domain != "www.example.com" {
			t.Fatalf("unexpected domain: %q", packet.domain)
		}
	})

	t.Run("tcp response", func(t *testing.T) {
		msg := buildDNSMessage(0x4321, 0x8003, "example.com", 28)
		payload := make([]byte, 2, 2+len(msg))
		binary.BigEndian.PutUint16(payload, uint16(len(msg)))
		payload = append(payload, msg...)

		packet, ok := dnsParsePayload(payload, syscall.IPPROTO_TCP)
		if !ok {
			t.Fatal("dnsParsePayload returned ok=false")
		}
		if !packet.response {
			t.Fatal("expected response packet")
		}
		if packet.rcode != 3 {
			t.Fatalf("unexpected rcode: %d", packet.rcode)
		}
		if packet.queryType != 28 {
			t.Fatalf("unexpected query type: %d", packet.queryType)
		}
	})

	t.Run("invalid question count is rejected", func(t *testing.T) {
		payload := buildDNSMessage(0x9999, 0x0100, "example.com", 1)
		binary.BigEndian.PutUint16(payload[4:], 2)

		if _, ok := dnsParsePayload(payload, syscall.IPPROTO_UDP); ok {
			t.Fatal("expected invalid question count to fail")
		}
	})
}

func TestDNSParsePacket(t *testing.T) {
	t.Run("ipv4 udp query over vlan", func(t *testing.T) {
		payload := buildDNSMessage(0x1111, 0x0100, "example.com", 1)
		ip := buildIPv4Packet(
			[4]byte{192, 0, 2, 10},
			[4]byte{198, 51, 100, 53},
			syscall.IPPROTO_UDP,
			buildUDPDatagram(12345, 53, payload),
		)
		frame := buildVLANFrame(ethProtoIPv4, ip)

		packet, ok := dnsParsePacket(frame)
		if !ok {
			t.Fatal("dnsParsePacket returned ok=false")
		}
		if packet.key.family != syscall.AF_INET {
			t.Fatalf("unexpected family: %d", packet.key.family)
		}
		if packet.key.protocol != syscall.IPPROTO_UDP {
			t.Fatalf("unexpected protocol: %d", packet.key.protocol)
		}
		if packet.key.clientPort != 12345 {
			t.Fatalf("unexpected client port: %d", packet.key.clientPort)
		}
		if !bytes.Equal(packet.key.clientIP[:4], []byte{192, 0, 2, 10}) {
			t.Fatalf("unexpected client ip: %v", packet.key.clientIP[:4])
		}
		if !bytes.Equal(packet.key.serverIP[:4], []byte{198, 51, 100, 53}) {
			t.Fatalf("unexpected server ip: %v", packet.key.serverIP[:4])
		}
	})

	t.Run("ipv6 tcp response", func(t *testing.T) {
		msg := buildDNSMessage(0x2222, 0x8000, "ipv6.example.com", 28)
		tcpPayload := make([]byte, 2, 2+len(msg))
		binary.BigEndian.PutUint16(tcpPayload, uint16(len(msg)))
		tcpPayload = append(tcpPayload, msg...)

		src := mustIPv6(t, "2001:db8::53")
		dst := mustIPv6(t, "2001:db8::1234")
		ip := buildIPv6Packet(src, dst, syscall.IPPROTO_TCP, buildTCPSegment(53, 40000, tcpPayload))
		frame := buildEthernetFrame(ethProtoIPv6, ip)

		packet, ok := dnsParsePacket(frame)
		if !ok {
			t.Fatal("dnsParsePacket returned ok=false")
		}
		if packet.key.family != syscall.AF_INET6 {
			t.Fatalf("unexpected family: %d", packet.key.family)
		}
		if packet.key.protocol != syscall.IPPROTO_TCP {
			t.Fatalf("unexpected protocol: %d", packet.key.protocol)
		}
		if packet.key.clientPort != 40000 {
			t.Fatalf("unexpected client port: %d", packet.key.clientPort)
		}
		if packet.domain != "ipv6.example.com" {
			t.Fatalf("unexpected domain: %q", packet.domain)
		}
		if !bytes.Equal(packet.key.serverIP[:], src[:]) {
			t.Fatalf("unexpected server ip: %v", packet.key.serverIP)
		}
		if !bytes.Equal(packet.key.clientIP[:], dst[:]) {
			t.Fatalf("unexpected client ip: %v", packet.key.clientIP)
		}
	})
}

func TestDNSParseIPv4RejectsFragments(t *testing.T) {
	payload := buildDNSMessage(0x3333, 0x0100, "fragment.example.com", 1)
	packet := buildIPv4Packet(
		[4]byte{192, 0, 2, 1},
		[4]byte{198, 51, 100, 1},
		syscall.IPPROTO_UDP,
		buildUDPDatagram(53000, 53, payload),
	)
	binary.BigEndian.PutUint16(packet[6:], 1)

	if _, ok := dnsParseIPv4(packet, 0); ok {
		t.Fatal("expected fragmented packet to fail")
	}
}

func TestDNSCollectorStateManagement(t *testing.T) {
	key := dnsFlowKey{
		family:     syscall.AF_INET,
		protocol:   syscall.IPPROTO_UDP,
		clientPort: 53000,
		serverIP:   [16]byte{198, 51, 100, 10},
		clientIP:   [16]byte{192, 0, 2, 20},
	}

	t.Run("query deduplication and successful response", func(t *testing.T) {
		collector := &dnsCollector{}
		query := dnsPacket{key: key, transactionID: 7, queryType: 1, domain: "example.com"}

		collector.processQuery(query, 100)
		collector.processQuery(query, 120)

		if collector.pendingQueries != 1 || len(collector.state) != 1 {
			t.Fatalf("unexpected collector state after dedupe: pending=%d states=%d", collector.pendingQueries, len(collector.state))
		}

		response := query
		response.response = true
		collector.processResponse(response, 600)

		if collector.pendingQueries != 0 || len(collector.state) != 0 {
			t.Fatalf("unexpected collector state after response: pending=%d states=%d", collector.pendingQueries, len(collector.state))
		}
		if collector.totalResults != 1 || len(collector.stats) != 1 {
			t.Fatalf("unexpected stats count: totalResults=%d stats=%d", collector.totalResults, len(collector.stats))
		}

		stats := collector.stats[0]
		if stats.successLatencySum != 500 {
			t.Fatalf("unexpected success latency: %d", stats.successLatencySum)
		}
		if stats.failureLatencySum != 0 || stats.timeouts != 0 {
			t.Fatalf("unexpected failure stats: failure=%d timeouts=%d", stats.failureLatencySum, stats.timeouts)
		}
		if len(stats.rcodes) != 1 || stats.rcodes[0].code != 0 || stats.rcodes[0].count != 1 {
			t.Fatalf("unexpected rcodes: %+v", stats.rcodes)
		}
	})

	t.Run("failure response tracks rcode", func(t *testing.T) {
		collector := &dnsCollector{}
		query := dnsPacket{key: key, transactionID: 8, queryType: 28, domain: "failure.example.com"}

		collector.processQuery(query, 1_000)
		response := query
		response.response = true
		response.rcode = 3
		collector.processResponse(response, 1_900)

		stats := collector.stats[0]
		if stats.failureLatencySum != 900 {
			t.Fatalf("unexpected failure latency: %d", stats.failureLatencySum)
		}
		if len(stats.rcodes) != 1 || stats.rcodes[0].code != 3 || stats.rcodes[0].count != 1 {
			t.Fatalf("unexpected rcodes: %+v", stats.rcodes)
		}
	})

	t.Run("expired states become timeouts", func(t *testing.T) {
		collector := &dnsCollector{}
		query := dnsPacket{key: key, transactionID: 9, queryType: 15, domain: "timeout.example.com"}

		collector.processQuery(query, 10)
		collector.expireStates(10 + dnsTimeoutUsec + 1)

		if collector.pendingQueries != 0 || len(collector.state) != 0 {
			t.Fatalf("unexpected collector state after expire: pending=%d states=%d", collector.pendingQueries, len(collector.state))
		}
		if collector.totalResults != 1 || len(collector.stats) != 1 {
			t.Fatalf("unexpected stats count: totalResults=%d stats=%d", collector.totalResults, len(collector.stats))
		}
		if collector.stats[0].timeouts != 1 {
			t.Fatalf("unexpected timeout count: %d", collector.stats[0].timeouts)
		}
		if len(collector.stats[0].rcodes) != 0 {
			t.Fatalf("unexpected rcodes for timeout-only entry: %+v", collector.stats[0].rcodes)
		}
	})
}

func TestDNSJSONWriters(t *testing.T) {
	t.Run("ports writer includes metadata and ports", func(t *testing.T) {
		var out bytes.Buffer
		dnsWritePortsJSON(&out, mapMeta{KeySize: 2, ValueSize: 4, Type: 1, FD: 9, MaxEntries: 8}, []uint16{53, 5353})

		got := out.String()
		for _, want := range []string{
			`"dns_ports"`,
			`"FD" : 9`,
			`"Configured Ports" : [53, 5353]`,
			`"Filled" : 2`,
			`"Zero" : 6`,
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q in output: %s", want, got)
			}
		}
	})

	t.Run("results writer renders IPs and rcodes", func(t *testing.T) {
		var out bytes.Buffer
		collector := &dnsCollector{
			pendingQueries: 1,
			totalResults:   1,
			stats: []*dnsStats{{
				key: dnsFlowKey{
					family:     syscall.AF_INET,
					protocol:   syscall.IPPROTO_UDP,
					clientPort: 53123,
					serverIP:   [16]byte{8, 8, 8, 8},
					clientIP:   [16]byte{192, 0, 2, 44},
				},
				queryType:         1,
				domain:            "example.com",
				timeouts:          2,
				successLatencySum: 17,
				failureLatencySum: 5,
				rcodes: []dnsRcodeCounter{
					{code: 0, count: 3},
					{code: 3, count: 1},
				},
			}},
		}

		dnsWriteResultsJSON(&out, collector, 5)
		got := out.String()
		for _, want := range []string{
			`"Collection Seconds" : 5`,
			`"Pending Queries" : 1`,
			`"server_ip" : "8.8.8.8"`,
			`"client_ip" : "192.0.2.44"`,
			`"domain" : "example.com"`,
			`"CountByRcode" : { "0" : 3, "3" : 1 }`,
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q in output: %s", want, got)
			}
		}
	})
}
