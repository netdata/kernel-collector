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
