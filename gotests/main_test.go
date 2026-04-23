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
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := candidateMatches(tc.filename, tc.module, tc.isReturn, tc.version, tc.rhf); got != tc.wantMatch {
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

		got := discoverCandidates("swap", false, "3.10", 1, dir)
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

	t.Run("returns first unsupported map type", func(t *testing.T) {
		supported := map[uint32]bool{
			bpfMapTypeHash:        true,
			bpfMapTypeArray:       true,
			bpfMapTypePerCPUHash:  true,
			bpfMapTypePerCPUArray: false,
		}

		mapType, ok := firstUnsupportedMapType([]uint32{bpfMapTypeHash, bpfMapTypePerCPUArray}, supported)
		if !ok {
			t.Fatal("expected unsupported map type")
		}
		if mapType != bpfMapTypePerCPUArray {
			t.Fatalf("unexpected unsupported map type: got %d want %d", mapType, bpfMapTypePerCPUArray)
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
	opts, code := parseArguments([]string{"--unit-test"}, netdataEBPFKernel68, &logState{writer: &log})
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
