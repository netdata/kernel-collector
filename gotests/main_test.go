package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestParseDNSPortList(t *testing.T) {
	t.Run("returns default when no valid ports exist", func(t *testing.T) {
		var out bytes.Buffer

		ports := parseDNSPortList(&out, "0, abc, ,", nil)
		if len(ports) != 1 || ports[0] != netdataDNSDefaultPort {
			t.Fatalf("unexpected ports: %v", ports)
		}

		log := out.String()
		for _, want := range []string{
			`DNS port value (0) is not valid`,
			`DNS port value (abc) is not valid`,
		} {
			if !strings.Contains(log, want) {
				t.Fatalf("missing %q in output: %s", want, log)
			}
		}
	})

	t.Run("deduplicates entries and enforces maximum", func(t *testing.T) {
		var out bytes.Buffer
		var items []string
		for i := 1; i <= netdataDNSMaxPorts+2; i++ {
			items = append(items, strconv.Itoa(i))
		}
		items = append(items, "2")

		ports := parseDNSPortList(&out, strings.Join(items, ","), nil)
		if len(ports) != netdataDNSMaxPorts {
			t.Fatalf("unexpected number of ports: got %d want %d", len(ports), netdataDNSMaxPorts)
		}
		if ports[0] != 1 || ports[len(ports)-1] != netdataDNSMaxPorts {
			t.Fatalf("unexpected port ordering: %v", ports)
		}
		if !strings.Contains(out.String(), `Maximum number of DNS ports`) {
			t.Fatalf("missing max-ports warning: %s", out.String())
		}
	})
}

func TestKernelSelectionHelpers(t *testing.T) {
	parseCases := []struct {
		name    string
		release string
		want    int
	}{
		{name: "plain release", release: "6.8.12", want: 6*65536 + 8*256 + 12},
		{name: "debian release", release: "6.12.74+deb13-amd64", want: 6*65536 + 12*256 + 74},
		{name: "debian plus suffix chain", release: "6.12.74+deb13+1-amd64", want: 6*65536 + 12*256 + 74},
		{name: "dash suffix", release: "5.15.0-101-generic", want: 5*65536 + 15*256},
		{name: "clamps patch", release: "6.12.999-custom", want: 6*65536 + 12*256 + 255},
		{name: "invalid release", release: "not-a-kernel", want: -1},
	}

	for _, tc := range parseCases {
		t.Run("parse "+tc.name, func(t *testing.T) {
			if got := parseKernelRelease(tc.release); got != tc.want {
				t.Fatalf("unexpected parsed kernel release for %q: got %d want %d", tc.release, got, tc.want)
			}
		})
	}

	rhCases := []struct {
		name    string
		release string
		want    int
	}{
		{name: "rh release", release: "Red Hat Enterprise Linux release 9.4 (Plow)\n", want: 9*256 + 4},
		{name: "centos release", release: "CentOS Linux release 7.9.2009 (Core)\n", want: 7*256 + 9},
		{name: "alma release", release: "AlmaLinux release 9.5 (Teal Serval)\n", want: 9*256 + 5},
		{name: "invalid release", release: "Debian GNU/Linux\n", want: -1},
	}

	for _, tc := range rhCases {
		t.Run("rh "+tc.name, func(t *testing.T) {
			if got := parseRedHatRelease(tc.release); got != tc.want {
				t.Fatalf("unexpected parsed redhat release for %q: got %d want %d", tc.release, got, tc.want)
			}
		})
	}

	osReleaseCases := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "alma 9 without redhat-release",
			content: `NAME="AlmaLinux"
VERSION="9.4 (Seafoam Ocelot)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
`,
			want: 9*256 + 4,
		},
		{
			name: "rhel 8 via ID_LIKE",
			content: `NAME="Red Hat Enterprise Linux"
VERSION="8.9 (Ootpa)"
ID="rhel"
VERSION_ID="8.9"
`,
			want: 8*256 + 9,
		},
		{
			name: "rocky linux",
			content: `NAME="Rocky Linux"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.3"
`,
			want: 9*256 + 3,
		},
		{
			name: "debian ignored",
			content: `NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="12"
`,
			want: -1,
		},
		{
			name: "empty content",
			content: ``,
			want:    -1,
		},
	}

	for _, tc := range osReleaseCases {
		t.Run("os-release "+tc.name, func(t *testing.T) {
			if got := parseOSRelease(tc.content); got != tc.want {
				t.Fatalf("unexpected parsed os-release for %q: got %d want %d", tc.name, got, tc.want)
			}
		})
	}

	leadingCases := []struct {
		input string
		want  int
	}{
		{input: "74+deb13+1", want: 74},
		{input: "9 ", want: 9},
		{input: "+12beta", want: 12},
		{input: "-5rc1", want: -5},
	}

	for _, tc := range leadingCases {
		t.Run("leading "+tc.input, func(t *testing.T) {
			if got := parseLeadingLong(tc.input); got != tc.want {
				t.Fatalf("unexpected parsed leading integer for %q: got %d want %d", tc.input, got, tc.want)
			}
		})
	}

	maxCases := []struct {
		name          string
		rhfVersion    int
		kernelVersion int
		want          uint32
	}{
		{name: "rhf 5.14", rhfVersion: 1, kernelVersion: netdataEBPFKernel514, want: 7},
		{name: "rhf 5.4", rhfVersion: 1, kernelVersion: netdataEBPFKernel54, want: 4},
		{name: "generic 6.8", rhfVersion: 0, kernelVersion: netdataEBPFKernel68, want: 10},
		{name: "generic 4.15", rhfVersion: 0, kernelVersion: netdataEBPFKernel415, want: 2},
		{name: "too old", rhfVersion: 0, kernelVersion: netdataMinimumEBPFKernel - 1, want: 0},
	}

	for _, tc := range maxCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectMaxIndex(tc.rhfVersion, tc.kernelVersion); got != tc.want {
				t.Fatalf("unexpected max index: got %d want %d", got, tc.want)
			}
		})
	}

	if got := selectKernelName(10); got != "6.8" {
		t.Fatalf("unexpected kernel name: %q", got)
	}

	if got := selectIndex(netdataV514, -1, netdataEBPFKernel514); got != 0 {
		t.Fatalf("expected 5.14-only selector to be masked for non-RHF, got %d", got)
	}

	if got := selectIndex(netdataV514|netdataV510, -1, netdataEBPFKernel514); got != 5 {
		t.Fatalf("expected fallback to 5.10 selector, got %d", got)
	}
}

func TestCandidateSelectionHelpers(t *testing.T) {
	t.Run("matches expected module, version, family, and probe type", func(t *testing.T) {
		cases := []struct {
			name      string
			filename  string
			module    string
			isReturn  bool
			version   string
			rhf       int
			wantMatch bool
		}{
			{name: "exact rhf entry", filename: "pnetdata_ebpf_swap.3.10.rhf.o", module: "swap", version: "3.10", rhf: 1, wantMatch: true},
			{name: "rhf variant", filename: "pnetdata_ebpf_swap.3.10.variant.rhf.o", module: "swap", version: "3.10", rhf: 1, wantMatch: true},
			{name: "wrong probe type", filename: "rnetdata_ebpf_swap.3.10.rhf.o", module: "swap", version: "3.10", rhf: 1, wantMatch: false},
			{name: "wrong version", filename: "pnetdata_ebpf_swap.4.14.rhf.o", module: "swap", version: "3.10", rhf: 1, wantMatch: false},
			{name: "wrong family", filename: "pnetdata_ebpf_swap.3.10.o", module: "swap", version: "3.10", rhf: 1, wantMatch: false},
			{name: "non-rhf exact", filename: "pnetdata_ebpf_swap.5.14.o", module: "swap", version: "5.14", rhf: -1, wantMatch: true},
			{name: "non-rhf rejects rhf", filename: "pnetdata_ebpf_swap.5.14.rhf.o", module: "swap", version: "5.14", rhf: -1, wantMatch: false},
			{name: "arena suffix exact", filename: "pnetdata_ebpf_swap_arena.6.12.o", module: "swap", version: "6.12", rhf: -1, wantMatch: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				arenaMode := tc.name == "arena suffix exact"
				if got := candidateMatches(tc.filename, tc.module, tc.isReturn, tc.version, tc.rhf, false, arenaMode); got != tc.wantMatch {
					t.Fatalf("unexpected match result for %q: got %v want %v", tc.filename, got, tc.wantMatch)
				}
			})
		}
	})

	t.Run("discovers and sorts matching candidates", func(t *testing.T) {
		dir := t.TempDir()
		files := []string{
			"pnetdata_ebpf_swap.3.10.variant.rhf.o",
			"pnetdata_ebpf_swap.3.10.rhf.o",
			"pnetdata_ebpf_swap.3.10.o",
			"rnetdata_ebpf_swap.3.10.rhf.o",
			"pnetdata_ebpf_process.3.10.rhf.o",
		}
		for _, name := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatalf("cannot create %s: %v", name, err)
			}
		}

		got := discoverCandidates("swap", false, 1, netdataV310, 0, dir, false, false)
		want := []string{
			filepath.Join(dir, "pnetdata_ebpf_swap.3.10.rhf.o"),
			filepath.Join(dir, "pnetdata_ebpf_swap.3.10.variant.rhf.o"),
		}

		if len(got) != len(want) {
			t.Fatalf("unexpected candidate count: got %v want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("unexpected candidate ordering: got %v want %v", got, want)
			}
		}
	})

	t.Run("discovers best compatible version in netdata path", func(t *testing.T) {
		dir := t.TempDir()
		files := []string{
			"pnetdata_ebpf_swap.5.4.o",
			"pnetdata_ebpf_swap.6.8.o",
			"pnetdata_ebpf_swap.6.12.o",
			"rnetdata_ebpf_swap.6.12.o",
			"pnetdata_ebpf_swap.5.14.rhf.o",
		}
		for _, name := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatalf("cannot create %s: %v", name, err)
			}
		}

		got := discoverCandidates("swap", false, -1, netdataV54|netdataV68|netdataV612, 11, dir, false, false)
		want := []string{filepath.Join(dir, "pnetdata_ebpf_swap.6.12.o")}
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatalf("unexpected candidates: got %v want %v", got, want)
		}
	})

	t.Run("discovers arena candidates when arena mode is enabled", func(t *testing.T) {
		dir := t.TempDir()
		files := []string{
			"pnetdata_ebpf_swap_arena.5.4.o",
			"pnetdata_ebpf_swap_buffer.5.4.o",
			"pnetdata_ebpf_swap_arena.6.12.o",
			"pnetdata_ebpf_swap_buffer.6.12.o",
		}
		for _, name := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatalf("cannot create %s: %v", name, err)
			}
		}

		got := discoverCandidates("swap", false, -1, netdataV54|netdataV68|netdataV612, 11, dir, false, true)
		want := []string{filepath.Join(dir, "pnetdata_ebpf_swap_arena.6.12.o")}
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatalf("unexpected arena candidates: got %v want %v", got, want)
		}
	})

	t.Run("returns first unsupported map type", func(t *testing.T) {
		supported := map[uint32]bool{
			bpfMapTypeHash:        true,
			bpfMapTypeArray:       true,
			bpfMapTypePerCPUHash:  true,
			bpfMapTypePerCPUArray: false,
			bpfMapTypeRingBuf:     false,
			bpfMapTypeUserRingBuf: true,
		}

		mapType, ok := firstUnsupportedMapType([]uint32{bpfMapTypeHash, bpfMapTypeRingBuf, bpfMapTypePerCPUArray}, supported)
		if !ok {
			t.Fatal("expected unsupported map type")
		}
		if mapType != bpfMapTypeRingBuf {
			t.Fatalf("unexpected unsupported map type: got %d want %d", mapType, bpfMapTypeRingBuf)
		}
	})

	t.Run("names ring buffer map types", func(t *testing.T) {
		if got := mapTypeName(bpfMapTypeRingBuf); got != "ringbuf" {
			t.Fatalf("unexpected ringbuf name: %q", got)
		}
		if got := mapTypeName(bpfMapTypeUserRingBuf); got != "user_ringbuf" {
			t.Fatalf("unexpected user ringbuf name: %q", got)
		}
	})

	t.Run("disables key value io for ring buffers", func(t *testing.T) {
		if supportsMapKeyValueIO(bpfMapTypeRingBuf) {
			t.Fatal("ringbuf should not use generic key/value io")
		}
		if supportsMapKeyValueIO(bpfMapTypeUserRingBuf) {
			t.Fatal("user ringbuf should not use generic key/value io")
		}
		if !supportsMapKeyValueIO(bpfMapTypeHash) {
			t.Fatal("hash maps should keep generic key/value io")
		}
	})

	t.Run("falls back to non-percpu support on rhf 3.10", func(t *testing.T) {
		if fallbackPerCPUMapSupport(1, netdataMinimumEBPFKernel-1) {
			t.Fatal("expected percpu fallback support to be disabled for old RH kernels")
		}
		if !fallbackPerCPUMapSupport(-1, netdataMinimumEBPFKernel) {
			t.Fatal("expected percpu fallback support for supported generic kernels")
		}
	})
}

func TestBinaryAndIPHelpers(t *testing.T) {
	buf16 := []byte{0, 0}
	putUint16(buf16, 0x1234)
	if buf16[0] != 0x34 || buf16[1] != 0x12 {
		t.Fatalf("unexpected uint16 encoding: %v", buf16)
	}

	buf32 := []byte{0, 0, 0, 0}
	putUint32(buf32, 0x12345678)
	if want := []byte{0x78, 0x56, 0x34, 0x12}; !bytes.Equal(buf32, want) {
		t.Fatalf("unexpected uint32 encoding: %v", buf32)
	}

	short := []byte{0}
	putUint16(short, 0xFFFF)
	if short[0] != 0 {
		t.Fatalf("short buffer should remain unchanged: %v", short)
	}

	if got := boolToInt(true); got != 1 {
		t.Fatalf("unexpected boolToInt(true): %d", got)
	}
	if got := boolToInt(false); got != 0 {
		t.Fatalf("unexpected boolToInt(false): %d", got)
	}

	if got := dnsFormatIP(syscall.AF_INET, [16]byte{192, 0, 2, 10}); got != "192.0.2.10" {
		t.Fatalf("unexpected IPv4 format: %q", got)
	}

	ipv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if got := dnsFormatIP(syscall.AF_INET6, ipv6); got != "2001:db8::1" {
		t.Fatalf("unexpected IPv6 format: %q", got)
	}
}

func TestParseArgumentsUnitTest(t *testing.T) {
	var log bytes.Buffer
	opts, code := parseArguments([]string{"--unit-test"}, netdataEBPFKernel68, -1, &logState{writer: &log})
	if code != 0 {
		t.Fatalf("unexpected parse code: %d", code)
	}
	if !opts.unitTest {
		t.Fatal("expected unitTest flag to be enabled")
	}
	if opts.flags != 0 {
		t.Fatalf("expected no runtime flags when unit-test is selected, got %#x", opts.flags)
	}
	if log.Len() != 0 {
		t.Fatalf("expected no parse output, got %q", log.String())
	}
}

func TestParseArgumentsAll(t *testing.T) {
	t.Run("--all enables content flag for PID collection", func(t *testing.T) {
		var log bytes.Buffer
		opts, code := parseArguments([]string{"--all"}, netdataEBPFKernel68, -1, &logState{writer: &log})
		if code != 0 {
			t.Fatalf("unexpected parse code: %d", code)
		}
		if opts.flags&flagContent == 0 {
			t.Fatal("--all must enable flagContent so PID collection runs via fillCtrl/testMaps")
		}
		if opts.flags&flagCollectors == 0 {
			t.Fatal("--all must enable flagCollectors")
		}
	})

	t.Run("--pid 3 is accepted", func(t *testing.T) {
		var log bytes.Buffer
		opts, code := parseArguments([]string{"--all", "--pid", "3"}, netdataEBPFKernel68, -1, &logState{writer: &log})
		if code != 0 {
			t.Fatalf("unexpected parse code: %d", code)
		}
		if opts.mapLevel != 3 {
			t.Fatalf("expected mapLevel 3 (ring buffer mode), got %d", opts.mapLevel)
		}
		if log.Len() != 0 {
			t.Fatalf("expected no parse error for pid=3, got %q", log.String())
		}
	})
}

func TestParseArgumentsBuffer(t *testing.T) {
	t.Run("--buffer enables content flag for ring buffer data", func(t *testing.T) {
		var log bytes.Buffer
		opts, code := parseArguments([]string{"--buffer"}, netdataEBPFKernel612, -1, &logState{writer: &log})
		if code != 0 {
			t.Fatalf("unexpected parse code: %d", code)
		}
		if !opts.bufferMode {
			t.Fatal("--buffer must set bufferMode")
		}
		if opts.flags&flagContent == 0 {
			t.Fatal("--buffer must enable flagContent so ring buffer data is collected and ring size is shown")
		}
	})

	t.Run("--arena enables content flag for arena data", func(t *testing.T) {
		var log bytes.Buffer
		opts, code := parseArguments([]string{"--arena"}, netdataEBPFKernel69, -1, &logState{writer: &log})
		if code != 0 {
			t.Fatalf("unexpected parse code: %d", code)
		}
		if !opts.arenaMode {
			t.Fatal("--arena must set arenaMode")
		}
		if opts.flags&flagContent == 0 {
			t.Fatal("--arena must enable flagContent so arena data is collected and ring size is shown")
		}
	})

	t.Run("--buffer on RH kernel below 5.8 skips version abort", func(t *testing.T) {
		var log bytes.Buffer
		// netdataMinimumEBPFKernel (4.11) is below the 5.8 ring-buffer threshold.
		// On a non-RH kernel this must be rejected; on RH it must proceed.
		_, nonRHCode := parseArguments([]string{"--buffer"}, netdataMinimumEBPFKernel, -1, &logState{writer: &log})
		if nonRHCode == 0 {
			t.Fatal("non-RH kernel below 5.8 must be rejected for --buffer")
		}
		log.Reset()
		_, rhCode := parseArguments([]string{"--buffer"}, netdataMinimumEBPFKernel, 1, &logState{writer: &log})
		if rhCode != 0 {
			t.Fatalf("RH kernel must bypass version check for --buffer, got code %d", rhCode)
		}
	})

	t.Run("--arena on RH kernel below 6.9 skips version abort", func(t *testing.T) {
		var log bytes.Buffer
		_, nonRHCode := parseArguments([]string{"--arena"}, netdataEBPFKernel514, -1, &logState{writer: &log})
		if nonRHCode == 0 {
			t.Fatal("non-RH kernel below 6.9 must be rejected for --arena")
		}
		log.Reset()
		_, rhCode := parseArguments([]string{"--arena"}, netdataEBPFKernel514, 1, &logState{writer: &log})
		if rhCode != 0 {
			t.Fatalf("RH kernel must bypass version check for --arena, got code %d", rhCode)
		}
	})

	t.Run("mountName uses arena suffix", func(t *testing.T) {
		got := mountName(11, "swap", false, -1, "/tmp", false, true)
		want := "/tmp/pnetdata_ebpf_swap_arena.6.12.o"
		if got != want {
			t.Fatalf("unexpected arena mount name: got %q want %q", got, want)
		}
	})
}

func TestResolveUnitTestDir(t *testing.T) {
	t.Run("finds gotests module from repo root cwd", func(t *testing.T) {
		root := t.TempDir()
		gotestsDir := filepath.Join(root, "gotests")
		if err := os.MkdirAll(gotestsDir, 0o755); err != nil {
			t.Fatalf("cannot create gotests dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gotestsDir, "go.mod"), []byte("module "+gotestsModuleName+"\n"), 0o644); err != nil {
			t.Fatalf("cannot write go.mod: %v", err)
		}

		dir, err := resolveUnitTestDir(root, filepath.Join(t.TempDir(), "go_tester"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dir != gotestsDir {
			t.Fatalf("unexpected dir: got %q want %q", dir, gotestsDir)
		}
	})

	t.Run("finds gotests module from executable directory", func(t *testing.T) {
		root := t.TempDir()
		gotestsDir := filepath.Join(root, "bin", "gotests")
		if err := os.MkdirAll(gotestsDir, 0o755); err != nil {
			t.Fatalf("cannot create gotests dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(gotestsDir, "go.mod"), []byte("module "+gotestsModuleName+"\n"), 0o644); err != nil {
			t.Fatalf("cannot write go.mod: %v", err)
		}

		dir, err := resolveUnitTestDir("", filepath.Join(gotestsDir, "go_tester"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dir != gotestsDir {
			t.Fatalf("unexpected dir: got %q want %q", dir, gotestsDir)
		}
	})

	t.Run("returns error when module cannot be found", func(t *testing.T) {
		if _, err := resolveUnitTestDir(t.TempDir(), filepath.Join(t.TempDir(), "go_tester")); err == nil {
			t.Fatal("expected resolveUnitTestDir to fail")
		}
	})
}

func TestUnitTestEnv(t *testing.T) {
	t.Run("preserves explicit gocache", func(t *testing.T) {
		env := unitTestEnv([]string{"PATH=/bin", "GOCACHE=/custom/cache"})
		if len(env) != 2 || env[1] != "GOCACHE=/custom/cache" {
			t.Fatalf("unexpected env: %v", env)
		}
	})

	t.Run("adds temp gocache when missing", func(t *testing.T) {
		env := unitTestEnv([]string{"PATH=/bin"})
		if len(env) != 2 {
			t.Fatalf("unexpected env length: %d", len(env))
		}
		if env[1] != "GOCACHE="+filepath.Join(os.TempDir(), "kernel-collector-gocache") {
			t.Fatalf("unexpected gocache entry: %q", env[1])
		}
	})
}

func TestMapDataHelpers(t *testing.T) {
	t.Run("roundUpSize aligns to boundary", func(t *testing.T) {
		cases := []struct{ value, align, want int }{
			{0, 8, 0},
			{1, 8, 8},
			{7, 8, 8},
			{8, 8, 8},
			{9, 8, 16},
			{3, 4, 4},
			{4, 4, 4},
			{5, 4, 8},
		}
		for _, tc := range cases {
			if got := roundUpSize(tc.value, tc.align); got != tc.want {
				t.Fatalf("roundUpSize(%d, %d) = %d, want %d", tc.value, tc.align, got, tc.want)
			}
		}
	})

	t.Run("mapValueStride returns raw size for non-percpu", func(t *testing.T) {
		meta := mapMeta{Type: bpfMapTypeHash, ValueSize: 10}
		if got := mapValueStride(meta); got != 10 {
			t.Fatalf("unexpected stride for hash map: %d", got)
		}
	})

	t.Run("mapValueStride rounds up for percpu", func(t *testing.T) {
		cases := []struct {
			mapType   uint32
			valueSize uint32
			want      int
		}{
			{bpfMapTypePerCPUHash, 10, 16},
			{bpfMapTypePerCPUArray, 8, 8},
			{bpfMapTypePerCPUHash, 1, 8},
			{bpfMapTypePerCPUArray, 17, 24},
		}
		for _, tc := range cases {
			meta := mapMeta{Type: tc.mapType, ValueSize: tc.valueSize}
			if got := mapValueStride(meta); got != tc.want {
				t.Fatalf("mapValueStride(type=%d, size=%d) = %d, want %d", tc.mapType, tc.valueSize, got, tc.want)
			}
		}
	})

	t.Run("mapValueLength ignores nprocesses for non-percpu", func(t *testing.T) {
		meta := mapMeta{Type: bpfMapTypeHash, ValueSize: 10}
		if got := mapValueLength(meta, 4); got != 10 {
			t.Fatalf("unexpected length: %d", got)
		}
	})

	t.Run("mapValueLength multiplies stride by nprocesses for percpu", func(t *testing.T) {
		meta := mapMeta{Type: bpfMapTypePerCPUHash, ValueSize: 10}
		// stride=16, nprocesses=4 → 64
		if got := mapValueLength(meta, 4); got != 64 {
			t.Fatalf("unexpected percpu length: %d", got)
		}
	})

	t.Run("mapValueLength clamps nprocesses below 1 to 1", func(t *testing.T) {
		meta := mapMeta{Type: bpfMapTypePerCPUHash, ValueSize: 10}
		// stride=16, nprocesses clamped to 1 → 16
		if got := mapValueLength(meta, 0); got != 16 {
			t.Fatalf("unexpected clamped length: %d", got)
		}
	})

	t.Run("controllerEntryLimit returns constant when MaxEntries exceeds it", func(t *testing.T) {
		meta := mapMeta{MaxEntries: 100}
		if got := controllerEntryLimit(meta); got != netdataControllerEnd {
			t.Fatalf("unexpected limit: got %d want %d", got, netdataControllerEnd)
		}
	})

	t.Run("controllerEntryLimit returns MaxEntries when smaller than constant", func(t *testing.T) {
		meta := mapMeta{MaxEntries: 3}
		if got := controllerEntryLimit(meta); got != 3 {
			t.Fatalf("unexpected limit: got %d want 3", got)
		}
	})

	t.Run("controllerEntryLimit treats zero MaxEntries as no constraint", func(t *testing.T) {
		meta := mapMeta{MaxEntries: 0}
		if got := controllerEntryLimit(meta); got != netdataControllerEnd {
			t.Fatalf("unexpected limit for zero MaxEntries: got %d want %d", got, netdataControllerEnd)
		}
	})

	t.Run("fillScalarValue writes 8-byte little-endian", func(t *testing.T) {
		dst := make([]byte, 8)
		fillScalarValue(dst, 8, 0x0102030405060708)
		want := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
		if !bytes.Equal(dst, want) {
			t.Fatalf("unexpected 8-byte encoding: got %v want %v", dst, want)
		}
	})

	t.Run("fillScalarValue writes 4-byte little-endian when valueSize < 8", func(t *testing.T) {
		dst := make([]byte, 4)
		fillScalarValue(dst, 4, 0x12345678)
		want := []byte{0x78, 0x56, 0x34, 0x12}
		if !bytes.Equal(dst, want) {
			t.Fatalf("unexpected 4-byte encoding: got %v want %v", dst, want)
		}
	})

	t.Run("fillScalarValue falls through to 4-byte when buffer too short for 8", func(t *testing.T) {
		dst := make([]byte, 4)
		fillScalarValue(dst, 8, 0x12345678)
		want := []byte{0x78, 0x56, 0x34, 0x12}
		if !bytes.Equal(dst, want) {
			t.Fatalf("unexpected fallback 4-byte encoding: got %v want %v", dst, want)
		}
	})

	t.Run("fillScalarValue does not write when valueSize too small", func(t *testing.T) {
		dst := make([]byte, 8)
		fillScalarValue(dst, 2, 0xFFFF)
		if !bytes.Equal(dst, make([]byte, 8)) {
			t.Fatalf("expected no write for valueSize=2: %v", dst)
		}
	})

	t.Run("allocateTableData sizes slices from mapValueLength", func(t *testing.T) {
		meta := mapMeta{Type: bpfMapTypePerCPUHash, KeySize: 4, ValueSize: 10, MaxEntries: 8}
		td := allocateTableData(meta, 2)
		// stride=16, nprocesses=2 → valueLength=32
		if len(td.key) != 4 || len(td.nextKey) != 4 {
			t.Fatalf("unexpected key lengths: key=%d nextKey=%d", len(td.key), len(td.nextKey))
		}
		if len(td.value) != 32 || len(td.defValue) != 32 {
			t.Fatalf("unexpected value lengths: value=%d defValue=%d", len(td.value), len(td.defValue))
		}
		if td.keyLength != 4 || td.valueLength != 32 {
			t.Fatalf("unexpected stored lengths: keyLength=%d valueLength=%d", td.keyLength, td.valueLength)
		}
	})
}

func TestMapTypePredicates(t *testing.T) {
	percpuTypes := []uint32{bpfMapTypePerCPUHash, bpfMapTypePerCPUArray}
	nonPercpuTypes := []uint32{bpfMapTypeHash, bpfMapTypeArray, bpfMapTypeRingBuf, bpfMapTypeUserRingBuf}

	for _, mt := range percpuTypes {
		if !isPerCPUMapType(mt) {
			t.Fatalf("expected map type %d to be percpu", mt)
		}
	}
	for _, mt := range nonPercpuTypes {
		if isPerCPUMapType(mt) {
			t.Fatalf("expected map type %d to not be percpu", mt)
		}
	}

	ringbufTypes := []uint32{bpfMapTypeRingBuf, bpfMapTypeUserRingBuf}
	nonRingbufTypes := []uint32{bpfMapTypeHash, bpfMapTypeArray, bpfMapTypePerCPUHash, bpfMapTypePerCPUArray}

	for _, mt := range ringbufTypes {
		if !isRingBufferMapType(mt) {
			t.Fatalf("expected map type %d to be ringbuf", mt)
		}
	}
	for _, mt := range nonRingbufTypes {
		if isRingBufferMapType(mt) {
			t.Fatalf("expected map type %d to not be ringbuf", mt)
		}
	}

	if !isUserRingBufferMapType(bpfMapTypeUserRingBuf) {
		t.Fatal("expected user_ringbuf to be user ringbuf type")
	}
	if isUserRingBufferMapType(bpfMapTypeRingBuf) {
		t.Fatal("expected ringbuf to not be user ringbuf type")
	}
}

func TestModeSuffix(t *testing.T) {
	if got := modeSuffix(false, false); got != "" {
		t.Fatalf("unexpected plain mode suffix: %q", got)
	}
	if got := modeSuffix(true, false); got != "_buffer" {
		t.Fatalf("unexpected buffer mode suffix: %q", got)
	}
	if got := modeSuffix(false, true); got != "_arena" {
		t.Fatalf("unexpected arena mode suffix: %q", got)
	}
	// arena takes precedence over buffer
	if got := modeSuffix(true, true); got != "_arena" {
		t.Fatalf("arena must take precedence over buffer, got %q", got)
	}
}

func TestModuleModeLookup(t *testing.T) {
	bufferArenaModules := []string{"cachestat", "dc", "fd", "oomkill", "process", "shm", "swap", "vfs", "dns"}
	for _, name := range bufferArenaModules {
		if !moduleHasBuffer(name) {
			t.Fatalf("expected %q to have buffer support", name)
		}
		if !moduleHasArena(name) {
			t.Fatalf("expected %q to have arena support", name)
		}
	}

	plainOnlyModules := []string{"btrfs", "disk", "ext4", "hardirq", "mdflush", "mount", "nfs", "network_viewer", "softirq", "socket", "xfs", "zfs"}
	for _, name := range plainOnlyModules {
		if moduleHasBuffer(name) {
			t.Fatalf("expected %q to not have buffer support", name)
		}
		if moduleHasArena(name) {
			t.Fatalf("expected %q to not have arena support", name)
		}
	}
}

func TestFindOptionalName(t *testing.T) {
	names := []specifyName{
		{programName: "netdata_foo", functionToAttach: "foo_fn"},
		{programName: "netdata_bar", functionToAttach: "bar_fn"},
	}

	got := findOptionalName(&names, "netdata_foo")
	if got == nil || got.programName != "netdata_foo" {
		t.Fatal("expected to find netdata_foo")
	}

	if got := findOptionalName(&names, "netdata_baz"); got != nil {
		t.Fatal("expected nil for absent name")
	}

	if got := findOptionalName(nil, "netdata_foo"); got != nil {
		t.Fatal("expected nil for nil slice")
	}
}

func TestSetCommonFlag(t *testing.T) {
	got := setCommonFlag()

	included := []uint64{flagCachestat, flagDC, flagDisk, flagFD, flagSync, flagHardIRQ,
		flagMount, flagNetworkViewer, flagOOMKill, flagProcess, flagSHM, flagSocket,
		flagSoftIRQ, flagSwap, flagDNS}
	for _, f := range included {
		if got&f == 0 {
			t.Fatalf("expected flag %#x to be included in setCommonFlag", f)
		}
	}

	excluded := []uint64{flagBtrfs, flagExt4, flagVFS, flagNFS, flagXFS, flagZFS,
		flagMDFlush, flagContent, flagLoadBinary}
	for _, f := range excluded {
		if got&f != 0 {
			t.Fatalf("expected flag %#x to be excluded from setCommonFlag", f)
		}
	}
}

func TestDescribeError(t *testing.T) {
	if got := describeError(0); got != "No error information" {
		t.Fatalf("unexpected zero error description: %q", got)
	}

	posDesc := describeError(int(syscall.ENOENT))
	negDesc := describeError(-int(syscall.ENOENT))
	if posDesc != negDesc {
		t.Fatalf("positive and negative errno must yield the same description: %q vs %q", posDesc, negDesc)
	}
	if !strings.Contains(strings.ToLower(posDesc), "no such") {
		t.Fatalf("unexpected ENOENT description: %q", posDesc)
	}
}

func TestResolveBinaryDir(t *testing.T) {
	dir := t.TempDir()
	if got := resolveBinaryDir(dir); got != dir {
		t.Fatalf("unexpected resolved path: got %q want %q", got, dir)
	}

	// empty input falls back to cwd — just verify it returns something non-empty
	if got := resolveBinaryDir(""); got == "" {
		t.Fatal("expected non-empty path for empty input")
	}
}

func TestWriteSupportedMapTypes(t *testing.T) {
	supported := map[uint32]bool{
		bpfMapTypeHash:        true,
		bpfMapTypeArray:       false,
		bpfMapTypePerCPUHash:  true,
		bpfMapTypePerCPUArray: false,
		bpfMapTypeRingBuf:     false,
		bpfMapTypeUserRingBuf: false,
	}

	var out bytes.Buffer
	writeSupportedMapTypes(&out, supported)
	got := out.String()

	if !strings.HasPrefix(got, "[") || !strings.HasSuffix(got, "]") {
		t.Fatalf("expected JSON array format, got %q", got)
	}
	if !strings.Contains(got, `"hash"`) {
		t.Fatalf("expected hash in output: %s", got)
	}
	if !strings.Contains(got, `"percpu_hash"`) {
		t.Fatalf("expected percpu_hash in output: %s", got)
	}
	if strings.Contains(got, `"array"`) {
		t.Fatalf("array must not appear (disabled): %s", got)
	}
	if strings.Contains(got, `"ringbuf"`) {
		t.Fatalf("ringbuf must not appear (disabled): %s", got)
	}
}

func TestCandidateVersionIndex(t *testing.T) {
	cases := []struct {
		name      string
		filename  string
		module    string
		rhf       int
		kernels   uint32
		maxIndex  uint32
		arenaMode bool
		wantIndex int
	}{
		{
			name: "rhf 5.14 matches at index 7",
			filename: "pnetdata_ebpf_swap.5.14.rhf.o",
			module: "swap", rhf: 1, kernels: netdataV514, maxIndex: 7,
			wantIndex: 7,
		},
		{
			name: "non-rhf masks out V514",
			filename: "pnetdata_ebpf_swap.5.14.rhf.o",
			module: "swap", rhf: -1, kernels: netdataV514, maxIndex: 10,
			wantIndex: -1,
		},
		{
			name: "non-rhf 6.8 matches at index 10",
			filename: "pnetdata_ebpf_swap.6.8.o",
			module: "swap", rhf: -1, kernels: netdataV68, maxIndex: 10,
			wantIndex: 10,
		},
		{
			name: "picks file version from multi-version kernel set",
			filename: "pnetdata_ebpf_swap.5.4.o",
			module: "swap", rhf: -1, kernels: netdataV54 | netdataV68, maxIndex: 10,
			wantIndex: 4,
		},
		{
			name: "wrong module name returns -1",
			filename: "pnetdata_ebpf_process.6.8.o",
			module: "swap", rhf: -1, kernels: netdataV68, maxIndex: 10,
			wantIndex: -1,
		},
		{
			name: "arena file matches with arenaMode enabled",
			filename: "pnetdata_ebpf_swap_arena.6.12.o",
			module: "swap", rhf: -1, kernels: netdataV612, maxIndex: 11, arenaMode: true,
			wantIndex: 11,
		},
		{
			name: "arena file rejected without arenaMode",
			filename: "pnetdata_ebpf_swap_arena.6.12.o",
			module: "swap", rhf: -1, kernels: netdataV612, maxIndex: 11, arenaMode: false,
			wantIndex: -1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := candidateVersionIndex(tc.filename, tc.module, false, tc.rhf, tc.kernels, tc.maxIndex, false, tc.arenaMode)
			if got != tc.wantIndex {
				t.Fatalf("unexpected index: got %d want %d", got, tc.wantIndex)
			}
		})
	}
}
