package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	versionStringLen            = 256
	netdataDefaultProcessNumber = 4096
	netdataDNSMaxPorts          = 32
	netdataDNSDefaultPort       = 53
	netdataControllerEnd        = 6
	diskHistogramBins           = 24
	netdataMinimumEBPFKernel    = 264960
	netdataEBPFKernel414        = 265728
	netdataEBPFKernel415        = 265984
	netdataEBPFKernel417        = 266496
	netdataEBPFKernel418        = 266752
	netdataEBPFKernel54         = 328704
	netdataEBPFKernel58         = 329728
	netdataEBPFKernel60         = 393216
	netdataEBPFKernel510        = 330240
	netdataEBPFKernel511        = 330496
	netdataEBPFKernel514        = 331264
	netdataEBPFKernel515        = 331520
	netdataEBPFKernel516        = 331776
	netdataEBPFKernel517        = 332032
	netdataEBPFKernel68         = 395264
	netdataEBPFKernel69         = 395520
	netdataEBPFKernel612        = 396288
	netdataEBPFKernel616        = 397312
	netdataEBPFKernel70         = 458752

	netdataV310 = 1 << 0
	netdataV414 = 1 << 1
	netdataV416 = 1 << 2
	netdataV418 = 1 << 3
	netdataV54  = 1 << 4
	netdataV510 = 1 << 5
	netdataV511 = 1 << 6
	netdataV514 = 1 << 7
	netdataV515 = 1 << 8
	netdataV516 = 1 << 9
	netdataV68  = 1 << 10
	netdataV612 = 1 << 11
	netdataV70  = 1 << 12
	netdataV517 = 1 << 13

	flagBtrfs         uint64 = 1 << 0
	flagCachestat     uint64 = 1 << 1
	flagDC            uint64 = 1 << 2
	flagDisk          uint64 = 1 << 3
	flagExt4          uint64 = 1 << 4
	flagFD            uint64 = 1 << 5
	flagSync          uint64 = 1 << 6
	flagHardIRQ       uint64 = 1 << 7
	flagMDFlush       uint64 = 1 << 8
	flagMount         uint64 = 1 << 9
	flagNetworkViewer uint64 = 1 << 10
	flagOOMKill       uint64 = 1 << 11
	flagProcess       uint64 = 1 << 12
	flagSHM           uint64 = 1 << 13
	flagSocket        uint64 = 1 << 14
	flagSoftIRQ       uint64 = 1 << 15
	flagSwap          uint64 = 1 << 16
	flagVFS           uint64 = 1 << 17
	flagNFS           uint64 = 1 << 18
	flagXFS           uint64 = 1 << 19
	flagZFS           uint64 = 1 << 20
	flagLoadBinary    uint64 = 1 << 21
	flagContent       uint64 = 1 << 22
	flagDNS           uint64 = 1 << 23

	flagFS         uint64 = flagBtrfs | flagExt4 | flagVFS | flagNFS | flagXFS | flagZFS
	flagCollectors uint64 = flagBtrfs | flagCachestat | flagDC | flagDisk |
		flagExt4 | flagFD | flagSync | flagHardIRQ |
		flagMDFlush | flagMount | flagNetworkViewer |
		flagOOMKill | flagProcess | flagSHM | flagSocket |
		flagSoftIRQ | flagSwap | flagVFS | flagNFS |
		flagXFS | flagZFS | flagDNS
	flagAll uint64 = flagCollectors
)

type specifyName struct {
	programName      string
	functionToAttach string
	fallbackFunction string
	optional         string
	retprobe         bool
	required         bool
}

type module struct {
	kernels       uint32
	bufferKernels uint32
	arenaKernels  uint32
	flags         uint64
	name          string
	updateNames   *[]specifyName
	ctrlTable     string
}

type options struct {
	flags        uint64
	specificEBPF string
	netdataPath  string
	logPath      string
	iterations   int
	mapLevel     int
	dnsPorts     []uint16
	unitTest     bool
	showHelp     bool
	bufferMode   bool
	arenaMode    bool
}

type logState struct {
	writer io.Writer
	file   *os.File
}

type attachSummary struct {
	links             []*bpfLink
	success           int
	fail              int
	skipped           int
	lastError         int
	failedProgramName string
	failedProgramType uint32
}

type tableData struct {
	key         []byte
	nextKey     []byte
	value       []byte
	defValue    []byte
	keyLength   int
	valueLength int
	filled      uint64
	zero        uint64
}

type jsonMemberState struct {
	first bool
}

type skippedModule struct {
	Module string `json:"Module"`
	Reason string `json:"Reason"`
}

func (state *jsonMemberState) prefix(w io.Writer) {
	if !state.first {
		fmt.Fprint(w, ",\n")
	}
	state.first = false
}

var (
	testsStarted   = 0
	skippedModules []skippedModule

	netdataSyscalls = map[string]struct{}{
		"fdatasync":       {},
		"fsync":           {},
		"mount":           {},
		"msync":           {},
		"shmat":           {},
		"shmctl":          {},
		"shmdt":           {},
		"shmget":          {},
		"sync":            {},
		"sync_file_range": {},
		"syncfs":          {},
		"umount":          {},
	}

	dcOptionalNames = []specifyName{
		{
			programName:      "netdata_lookup_fast",
			functionToAttach: "lookup_fast",
			retprobe:         false,
		},
	}

	swapOptionalNames = []specifyName{
		{
			programName:      "netdata_swap_readpage",
			functionToAttach: "swap_read_folio",
			fallbackFunction: "swap_readpage",
			retprobe:         false,
			required:         true,
		},
		{
			programName:      "netdata_swap_writepage",
			functionToAttach: "__swap_writepage",
			fallbackFunction: "swap_writepage",
			retprobe:         false,
			required:         true,
		},
		{
			programName:      "netdata_swap_readpage_buffer",
			functionToAttach: "swap_read_folio",
			fallbackFunction: "swap_readpage",
			retprobe:         false,
			required:         true,
		},
		{
			programName:      "netdata_swap_writepage_buffer",
			functionToAttach: "__swap_writepage",
			fallbackFunction: "swap_writepage",
			retprobe:         false,
			required:         true,
		},
	}

	// close_fd replaced __close_fd in kernel 5.11; RH backported this rename to their 5.10 kernels.
	fdOptionalNames = []specifyName{
		{
			programName:      "netdata_close_buffer",
			functionToAttach: "close_fd",
			fallbackFunction: "__close_fd",
			retprobe:         false,
			required:         true,
		},
	}

	zfsOptionalNames = []specifyName{
		{
			programName:      "netdata_zpl_iter_read",
			functionToAttach: "zpl_iter_read",
			retprobe:         false,
		},
		{
			programName:      "netdata_zpl_iter_write",
			functionToAttach: "zpl_iter_write",
			retprobe:         false,
		},
		{
			programName:      "netdata_zpl_open",
			functionToAttach: "zpl_open",
			retprobe:         false,
		},
		{
			programName:      "netdata_zpl_fsync",
			functionToAttach: "zpl_fsync",
			retprobe:         false,
		},
		{
			programName:      "netdata_ret_zpl_iter_read",
			functionToAttach: "zpl_iter_read",
			retprobe:         true,
		},
		{
			programName:      "netdata_ret_zpl_iter_write",
			functionToAttach: "zpl_iter_write",
			retprobe:         true,
		},
		{
			programName:      "netdata_ret_zpl_open",
			functionToAttach: "zpl_open",
			retprobe:         true,
		},
		{
			programName:      "netdata_ret_zpl_fsync",
			functionToAttach: "zpl_fsync",
			retprobe:         true,
		},
	}

	ebpfModules = []module{
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV510 | netdataV514, flags: flagBtrfs, name: "btrfs", ctrlTable: "btrfs_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV515 | netdataV514 | netdataV516, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagCachestat, name: "cachestat", ctrlTable: "cstat_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagDC, name: "dc", updateNames: &dcOptionalNames, ctrlTable: "dcstat_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV511 | netdataV514 | netdataV516 | netdataV517 | netdataV68, flags: flagDisk, name: "disk", ctrlTable: "disk_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagExt4, name: "ext4", ctrlTable: "ext4_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV511 | netdataV514, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagFD, name: "fd", updateNames: &fdOptionalNames, ctrlTable: "fd_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "fdatasync"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "fsync"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagHardIRQ, name: "hardirq"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagMDFlush, name: "mdflush"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagMount, name: "mount"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "msync"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagSocket, name: "socket", ctrlTable: "socket_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagDNS, name: "dns"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagNFS, name: "nfs", ctrlTable: "nfs_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagNetworkViewer, name: "network_viewer", ctrlTable: "nv_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagOOMKill, name: "oomkill"},
		{kernels: netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514 | netdataV510 | netdataV612 | netdataV70, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagProcess, name: "process", ctrlTable: "process_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagSHM, name: "shm", ctrlTable: "shm_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSoftIRQ, name: "softirq"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "sync"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "syncfs"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "sync_file_range"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514 | netdataV68 | netdataV612 | netdataV70, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagSwap, name: "swap", updateNames: &swapOptionalNames, ctrlTable: "swap_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, bufferKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, arenaKernels: netdataV510 | netdataV511 | netdataV514 | netdataV515 | netdataV516 | netdataV68 | netdataV612 | netdataV70, flags: flagVFS, name: "vfs", ctrlTable: "vfs_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagXFS, name: "xfs", ctrlTable: "xfs_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagZFS, name: "zfs", updateNames: &zfsOptionalNames, ctrlTable: "zfs_ctrl"},
	}
)

func main() {
	os.Exit(run())
}

func run() int {
	kernelVersion := getKernelVersion()
	rhfVersion := getRedHatRelease()
	testsStarted = 0
	skippedModules = nil
	nprocesses := libbpfNumPossibleCPUs()
	if nprocesses < 1 {
		nprocesses = runtime.NumCPU()
	}
	if nprocesses < 1 {
		fmt.Fprintf(os.Stderr, "Cannot find number of process, using the default %d\n", netdataDefaultProcessNumber)
		nprocesses = netdataDefaultProcessNumber
	}

	logger := &logState{writer: os.Stderr}
	opts, parseCode := parseArguments(os.Args[1:], kernelVersion, rhfVersion, logger)
	if logger.file != nil {
		defer logger.file.Close()
	}
	if parseCode != 0 || opts.showHelp {
		return parseCode
	}
	if opts.unitTest {
		return runUnitTests()
	}
	if opts.iterations > 1 {
		fmt.Fprintln(os.Stderr, "Warning: --iteration is deprecated and ignored; the tester uses one capture window per object.")
		opts.iterations = 1
	}
	if logger.file == nil {
		logger.writer = os.Stdout
	}

	writer := bufio.NewWriter(logger.writer)
	defer writer.Flush()

	fmt.Fprint(writer, "{\n  \"Run Info\" : {\n")
	kernelRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	fmt.Fprintf(writer, "    \"Kernel Version\" : %q,\n    \"Kernel Code\" : %d,\n    \"Red Hat Version\" : %d,\n    \"Flags\" : %d,\n    \"Buffer Mode\" : %t,\n    \"Arena Mode\" : %t\n  }", strings.TrimSpace(string(kernelRelease)), kernelVersion, rhfVersion, opts.flags, opts.bufferMode, opts.arenaMode)
	if err := memlockLimit(); err != nil {
		writeErrorExit(writer, "Cannot adjust memory limit.")
		return 2
	}

	if opts.flags&flagLoadBinary == 0 {
		fillNames()
		runNetdataTests(writer, rhfVersion, kernelVersion, true, opts, nprocesses)
		runNetdataTests(writer, rhfVersion, kernelVersion, false, opts, nprocesses)
	} else if opts.specificEBPF != "" {
		members := startExternalJSON(writer, opts.specificEBPF)
		result := ebpfTester(writer, opts.specificEBPF, nil, opts.flags&flagContent != 0, "", opts, nprocesses, kernelVersion, members)
		fmt.Fprintf(writer, "    },\n    \"Status\" : \"%s\"\n}", result)
	}

	if len(skippedModules) > 0 {
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		_ = encoder.Encode(skippedModules)
		fmt.Fprintf(writer, ",\n  \"Skipped\" : %s", strings.TrimSpace(encoded.String()))
	} else {
		fmt.Fprint(writer, ",\n  \"Skipped\" : []")
	}
	if testsStarted == 0 {
		fmt.Fprint(writer, ",\n  \"Error\" : \"No eBPF tests were started. Check selected options, binary name, and --netdata-path.\"")
		fmt.Fprint(writer, ",\n  \"End\" : \"Good bye!!!\" }\n")
		return 1
	}

	fmt.Fprint(writer, ",\n  \"End\" : \"Good bye!!!\" }\n")
	return 0
}

func getKernelVersion() int {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return -1
	}

	return parseKernelRelease(strings.TrimSpace(string(data)))
}

func parseLeadingLong(s string) int {
	s = strings.TrimSpace(s)
	sign := 1
	if strings.HasPrefix(s, "-") {
		sign = -1
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}

	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}

	return sign * n
}

func parseKernelRelease(version string) int {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 3 {
		return -1
	}

	patch := parts[2]
	if idx := strings.IndexAny(patch, "-\n"); idx >= 0 {
		patch = patch[:idx]
	}

	major := parseLeadingLong(parts[0])
	minor := parseLeadingLong(parts[1])
	sublevel := parseLeadingLong(patch)
	if major < 0 || minor < 0 || sublevel < 0 {
		return -1
	}

	if sublevel > 255 {
		sublevel = 255
	}

	return major*65536 + minor*256 + sublevel
}

func getRedHatRelease() int {
	data, err := os.ReadFile("/etc/redhat-release")
	if err == nil {
		if result := parseRedHatRelease(string(data)); result != -1 {
			return result
		}
	}

	data, err = os.ReadFile("/etc/os-release")
	if err != nil {
		return -1
	}
	return parseOSRelease(string(data))
}

// parseOSRelease detects the explicitly supported RH-family IDs, then
// parses VERSION_ID to return major*256+minor. Returns -1 on no match.
func parseOSRelease(content string) int {
	major := 0
	minor := 0
	isRHEL := false

	for _, line := range strings.Split(content, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "ID":
			for _, id := range strings.Fields(strings.Trim(val, "\"'")) {
				if isRHELFamilyID(id) {
					isRHEL = true
					break
				}
			}
		case "VERSION_ID":
			val = strings.Trim(val, "\"'")
			parts := strings.SplitN(val, ".", 2)
			major = parseLeadingLong(parts[0])
			if len(parts) == 2 {
				minor = parseLeadingLong(parts[1])
			}
		}
	}

	if isRHEL && major > 0 {
		return major*256 + minor
	}
	return -1
}

func isRHELFamilyID(id string) bool {
	switch strings.ToLower(id) {
	case "rhel", "centos", "almalinux", "rocky":
		return true
	default:
		return false
	}
}

func IsDebianFlavor() bool {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "ID=") {
			continue
		}

		value := strings.TrimSpace(strings.TrimPrefix(line, "ID="))
		value = strings.Trim(value, "\"'")
		return value == "debian"
	}

	return false
}

func parseRedHatRelease(release string) int {
	version := strings.Index(release, "release")
	if version < 0 {
		return -1
	}
	vendor := strings.ToLower(strings.TrimSpace(release[:version]))
	if !strings.HasPrefix(vendor, "red hat") && !strings.HasPrefix(vendor, "centos") &&
		!strings.HasPrefix(vendor, "almalinux") && !strings.HasPrefix(vendor, "rocky linux") {
		return -1
	}

	fields := strings.Fields(release[version+len("release"):])
	if len(fields) == 0 {
		return -1
	}

	parts := strings.SplitN(fields[0], ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil || major <= 0 || major > (int(^uint(0)>>1)-255)/256 {
		return -1
	}

	minor := 0
	if len(parts) == 2 {
		minorPart := parts[1]
		if suffix := strings.IndexByte(minorPart, '.'); suffix >= 0 {
			minorPart = minorPart[:suffix]
		}
		minor, err = strconv.Atoi(minorPart)
		if err != nil || minor < 0 || minor > 255 {
			return -1
		}
	}

	return major*256 + minor
}

func memlockLimit() error {
	if ret := setMemlockLimit(); ret != 0 {
		return fmt.Errorf("setrlimit failed: %d", ret)
	}

	return nil
}

func helpText(exe string) string {
	return fmt.Sprintf("Usage: ./%s [OPTION]....\n"+
		"Load eBPF binaries printing final status of the test.\n\n"+
		"The following global options are available:\n"+
		"--help             Prints this help.\n"+
		"--unit-test        Run Go unit tests for gotests and exit.\n"+
		"--all              Test all netdata eBPF programs.\n"+
		"--common           Test eBPF programs that does not need specific module to be loaded.\n"+
		"                   This option does not test mdflush, ext4, nfs, zfs, xfs and btrfs.\n"+
		"--load-binary      Load a given eBPF program into  kernel.\n"+
		"--dns-port         Comma separated list of DNS ports to monitor. Default value is 53.\n"+
		"--netdata-path     Directory where eBPF programs are present.\n"+
		"--log-path         Filename for JSON output. Without this option, JSON goes to stdout.\n\n"+
		"--content          Inspect maps even when one or more programs fail to attach.\n"+
		"--iteration        Deprecated and ignored; retained for CLI compatibility.\n"+
		"--pid              Specify the number that identifies PID  that will be monitored: 0 - Real Parent PID (Default), 1 - Parent PID, 2 - All PID, and 3 - Ignore PID (ring buffer mode).\n"+
		"--buffer           Test ring buffer versions of collectors (cachestat, dc, fd, oomkill, process, shm, swap, vfs, dns, socket).\n"+
		"--arena            Test arena versions of collectors (cachestat, dc, fd, oomkill, process, shm, swap, vfs, dns, socket).\n\n"+
		"You can also specify an unique eBPF program developed by Netdata with the following\n"+
		"options:\n"+
		"--btrfs            Latency for btrfs.\n"+
		"--cachestat        Linux page cache.\n"+
		"--dc               Linux directory cache.\n"+
		"--disk             Disk latency using tracepoints.\n"+
		"--ext4             Latency for ext4.\n"+
		"--filedescriptor   File descriptor actions(open and close).\n"+
		"--sync             Calls for sync (2) syscall.\n"+
		"--hardirq          Latency for hard IRQ.\n"+
		"--mdflush          Calls for md_flush_request.\n"+
		"--mount            Calls for mount (2) and umount (2) syscalls.\n"+
		"--networkviewer    Network Viewer.\n"+
		"--oomkill          Monitoring oomkill events.\n"+
		"--process          Monitoring process life(Threads, start, exit).\n"+
		"--shm              Calls for syscalls shmget(2), shmat (2), shmdt (2), and shmctl (2).\n"+
		"--socket           Monitoring for TCP and UDP traffic.\n"+
		"--dns              Monitoring DNS traffic with socket/dns_filter and local aggregation.\n"+
		"--softirq          Latency for soft IRQ.\n"+
		"--swap             Monitor the exact time that processes try to execute IO events in swap.\n"+
		"--vfs              Monitor Virtual Filesystem functions.\n"+
		"--nfs              Latency for Network Filesystem NFS.\n"+
		"--xfs              Latency for XFS.\n"+
		"--zfs              Latency for ZFS.\n\n"+
		"Exit status:\n"+
		"0  if OK.\n"+
		"1  if kernel version cannot load eBPF programs.\n"+
		"2  if software cannot adjust memory or cannot start unit tests.\n"+
		"When --unit-test is used, the process returns the go test exit status.\n", exe)
}

func setCommonFlag() uint64 {
	return flagCollectors & ^(flagFS | flagLoadBinary | flagMDFlush | flagContent)
}

func parseArguments(args []string, kernelVersion int, rhfVersion int, logger *logState) (options, int) {
	opts := options{
		iterations: 1,
		mapLevel:   0,
		dnsPorts:   []uint16{netdataDNSDefaultPort},
	}

	moduleOptions := map[string]uint64{
		"btrfs":          flagBtrfs,
		"cachestat":      flagCachestat,
		"dc":             flagDC,
		"disk":           flagDisk,
		"ext4":           flagExt4,
		"filedescriptor": flagFD,
		"sync":           flagSync,
		"hardirq":        flagHardIRQ,
		"mdflush":        flagMDFlush,
		"mount":          flagMount,
		"networkviewer":  flagNetworkViewer,
		"oomkill":        flagOOMKill,
		"process":        flagProcess,
		"shm":            flagSHM,
		"socket":         flagSocket,
		"dns":            flagDNS,
		"softirq":        flagSoftIRQ,
		"swap":           flagSwap,
		"vfs":            flagVFS,
		"nfs":            flagNFS,
		"xfs":            flagXFS,
		"zfs":            flagZFS,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			continue
		}

		name := strings.TrimPrefix(arg, "--")
		value := ""
		if idx := strings.IndexByte(name, '='); idx >= 0 {
			value = name[idx+1:]
			name = name[:idx]
		}

		if flagValue, ok := moduleOptions[name]; ok {
			opts.flags |= flagValue
			continue
		}

		switch name {
		case "help":
			fmt.Fprint(os.Stdout, helpText(filepath.Base(os.Args[0])))
			opts.showHelp = true
			return opts, 0
		case "unit-test":
			opts.unitTest = true
		case "all":
			opts.flags |= flagCollectors | flagContent
		case "common":
			opts.flags |= setCommonFlag()
		case "load-binary":
			value, i = optionValue(args, i, value)
			opts.specificEBPF = value
			opts.flags |= flagLoadBinary
		case "dns-port":
			value, i = optionValue(args, i, value)
			opts.dnsPorts = parseDNSPortList(os.Stderr, value, opts.dnsPorts)
		case "netdata-path":
			value, i = optionValue(args, i, value)
			opts.netdataPath = value
		case "log-path":
			value, i = optionValue(args, i, value)
			opts.logPath = value
			file, err := os.OpenFile(value, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				logger.writer = os.Stderr
				fmt.Fprintf(os.Stderr, "Cannot open log path %q: %v\n", value, err)
			} else {
				logger.file = file
				logger.writer = file
			}
		case "content":
			opts.flags |= flagContent
		case "iteration":
			value, i = optionValue(args, i, value)
			iteration, err := strconv.Atoi(value)
			if err != nil || iteration < 1 {
				fmt.Fprintf(os.Stderr, "Invalid --iteration value %q; using 1.\n", value)
				iteration = 1
			}
			opts.iterations = iteration
		case "pid":
			value, i = optionValue(args, i, value)
			pidLevel, err := strconv.Atoi(value)
			if err != nil || pidLevel < 0 || pidLevel >= 4 {
				fmt.Fprintf(os.Stderr, "Invalid --pid value %q; using 0 (Real Parent).\n", value)
				pidLevel = 0
			}
			opts.mapLevel = pidLevel
		case "buffer":
			opts.bufferMode = true
			opts.flags |= flagContent
		case "arena":
			opts.arenaMode = true
			opts.flags |= flagContent
		}
	}

	if !opts.unitTest && opts.flags&flagCollectors == 0 {
		opts.flags |= setCommonFlag()
	}

	if !opts.unitTest && kernelVersion < netdataEBPFKernel414 {
		opts.flags &^= flagOOMKill
	}

	if opts.bufferMode && rhfVersion == -1 && kernelVersion < netdataEBPFKernel58 {
		fmt.Fprintln(os.Stderr, "Ring buffer support requires kernel >= 5.8; current kernel is not supported.")
		return opts, 1
	}

	if opts.arenaMode && rhfVersion == -1 && kernelVersion < netdataEBPFKernel69 {
		fmt.Fprintln(os.Stderr, "Arena support requires kernel >= 6.9; current kernel is not supported.")
		return opts, 1
	}

	return opts, 0
}

func optionValue(args []string, idx int, inline string) (string, int) {
	if inline != "" {
		return inline, idx
	}
	if idx+1 >= len(args) {
		return "", idx
	}
	return args[idx+1], idx + 1
}

func parseDNSPortList(w io.Writer, input string, existing []uint16) []uint16 {
	ports := make([]uint16, 0, len(existing))
	seen := map[uint16]bool{}

	for _, token := range strings.Split(input, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		portValue, err := strconv.ParseUint(token, 10, 16)
		if err != nil || portValue == 0 {
			fmt.Fprintf(w, "Invalid DNS port value %q; ignoring it.\n", token)
			continue
		}

		port := uint16(portValue)
		if seen[port] {
			continue
		}
		if len(ports) >= netdataDNSMaxPorts {
			fmt.Fprintf(w, "Maximum number of DNS ports (%d) reached; ignoring remaining ports.\n", netdataDNSMaxPorts)
			break
		}

		seen[port] = true
		ports = append(ports, port)
	}

	if len(ports) == 0 {
		return []uint16{netdataDNSDefaultPort}
	}

	return ports
}

func resolveBinaryDir(netdataPath string) string {
	if netdataPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "."
		}

		return cwd
	}

	resolved, err := filepath.Abs(netdataPath)
	if err == nil {
		return resolved
	}

	return netdataPath
}

func modeSuffix(bufferMode bool, arenaMode bool) string {
	if arenaMode {
		return "_arena"
	}
	if bufferMode {
		return "_buffer"
	}
	return ""
}

func effectiveModeFlags(moduleName string, kernelVersion int, isDebian bool, bufferMode bool, arenaMode bool) (bool, bool) {
	if bufferMode || arenaMode {
		return bufferMode, arenaMode
	}

	if moduleName == "cachestat" {
		if kernelVersion >= netdataEBPFKernel510 {
			return true, false
		}

		return false, false
	}

	if moduleHasBuffer(moduleName) && kernelVersion >= netdataEBPFKernel510 {
		return true, false
	}

	return false, false
}

func candidateMatches(filename string, moduleName string, isReturn bool, version string, rhfVersion int, bufferMode bool, arenaMode bool) bool {
	prefix := fmt.Sprintf("%cnetdata_ebpf_%s%s.", map[bool]rune{true: 'r', false: 'p'}[isReturn], moduleName, modeSuffix(bufferMode, arenaMode))
	if !strings.HasPrefix(filename, prefix) || !strings.HasSuffix(filename, ".o") {
		return false
	}

	rest := strings.TrimSuffix(strings.TrimPrefix(filename, prefix), ".o")
	if !strings.HasPrefix(rest, version) {
		return false
	}
	if len(rest) > len(version) && rest[len(version)] != '.' {
		return false
	}

	hasRHF := strings.Contains(rest, ".rhf")
	if rhfVersion != -1 {
		return hasRHF
	}

	return !hasRHF
}

func candidateVersionIndex(filename string, moduleName string, isReturn bool, rhfVersion int, kernels uint32, maxIndex uint32, bufferMode bool, arenaMode bool) int {
	if rhfVersion == -1 {
		kernels &^= netdataV514
	}

	for idx := int(maxIndex); idx >= 0; idx-- {
		if kernels&(1<<uint32(idx)) == 0 {
			continue
		}
		if candidateMatches(filename, moduleName, isReturn, selectKernelName(uint32(idx)), rhfVersion, bufferMode, arenaMode) {
			return idx
		}
	}

	return -1
}

func discoverCandidates(moduleName string, isReturn bool, rhfVersion int, kernels uint32, maxIndex uint32, netdataPath string, bufferMode bool, arenaMode bool) []string {
	path := resolveBinaryDir(netdataPath)
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}

	candidates := make([]string, 0, len(entries))
	bestIndex := -1
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		candidateIndex := candidateVersionIndex(entry.Name(), moduleName, isReturn, rhfVersion, kernels, maxIndex, bufferMode, arenaMode)
		if candidateIndex < 0 {
			continue
		}
		if candidateIndex > bestIndex {
			candidates = candidates[:0]
			bestIndex = candidateIndex
		} else if candidateIndex < bestIndex {
			continue
		}

		candidates = append(candidates, filepath.Join(path, entry.Name()))
	}

	sort.Strings(candidates)
	return candidates
}

func fallbackPerCPUMapSupport(_ int, kernelVersion int) bool {
	return kernelVersion >= netdataMinimumEBPFKernel
}

func detectSupportedMapTypes(rhfVersion int, kernelVersion int) map[uint32]bool {
	supported := map[uint32]bool{
		bpfMapTypeHash:        kernelVersion >= netdataMinimumEBPFKernel || rhfVersion > 0,
		bpfMapTypeArray:       kernelVersion >= netdataMinimumEBPFKernel || rhfVersion > 0,
		bpfMapTypePerCPUHash:  fallbackPerCPUMapSupport(rhfVersion, kernelVersion),
		bpfMapTypePerCPUArray: fallbackPerCPUMapSupport(rhfVersion, kernelVersion),
		bpfMapTypeRingBuf:     false,
		bpfMapTypeUserRingBuf: false,
		bpfMapTypeArena:       false,
	}

	for _, mapType := range []uint32{
		bpfMapTypeHash,
		bpfMapTypeArray,
		bpfMapTypePerCPUHash,
		bpfMapTypePerCPUArray,
		bpfMapTypeRingBuf,
		bpfMapTypeUserRingBuf,
		bpfMapTypeArena,
	} {
		if probe := probeMapTypeSupport(mapType); probe >= 0 {
			supported[mapType] = probe > 0
		}
	}

	return supported
}

func mapTypeName(mapType uint32) string {
	switch mapType {
	case bpfMapTypeHash:
		return "hash"
	case bpfMapTypeArray:
		return "array"
	case bpfMapTypePerCPUHash:
		return "percpu_hash"
	case bpfMapTypePerCPUArray:
		return "percpu_array"
	case bpfMapTypeRingBuf:
		return "ringbuf"
	case bpfMapTypeUserRingBuf:
		return "user_ringbuf"
	case bpfMapTypeArena:
		return "arena"
	default:
		return fmt.Sprintf("type_%d", mapType)
	}
}

func writeSupportedMapTypes(w io.Writer, supported map[uint32]bool) {
	names := make([]string, 0, 6)
	for _, mapType := range []uint32{
		bpfMapTypeHash,
		bpfMapTypeArray,
		bpfMapTypePerCPUHash,
		bpfMapTypePerCPUArray,
		bpfMapTypeRingBuf,
		bpfMapTypeUserRingBuf,
		bpfMapTypeArena,
	} {
		if supported[mapType] {
			names = append(names, fmt.Sprintf("\"%s\"", mapTypeName(mapType)))
		}
	}

	fmt.Fprintf(w, "[%s]", strings.Join(names, ", "))
}

func writeObjectMapTypes(w io.Writer, obj *bpfObject, members *jsonMemberState) {
	seen := map[uint32]bool{}
	names := make([]string, 0, 4)

	if obj != nil {
		for m := obj.firstMap(); m != nil; m = obj.nextMap(m) {
			mapType := m.meta().Type
			if seen[mapType] {
				continue
			}

			seen[mapType] = true
			names = append(names, fmt.Sprintf("\"%s\"", mapTypeName(mapType)))
		}
	}

	members.prefix(w)
	fmt.Fprintf(w, "        \"Map Types Used\" : [%s]", strings.Join(names, ", "))
}

func firstUnsupportedMapType(mapTypes []uint32, supported map[uint32]bool) (uint32, bool) {
	for _, mapType := range mapTypes {
		if allowed, ok := supported[mapType]; ok && !allowed {
			return mapType, true
		}
	}

	return 0, false
}

func candidateMapTypes(filename string) ([]uint32, int) {
	obj, errCode := openBPFObject(filename)
	if errCode != 0 {
		return nil, errCode
	}
	defer obj.close()

	mapTypes := make([]uint32, 0, 8)
	for m := obj.firstMap(); m != nil; m = obj.nextMap(m) {
		mapTypes = append(mapTypes, m.meta().Type)
	}

	return mapTypes, 0
}

func filterCompatibleCandidates(candidates []string, supported map[uint32]bool) ([]string, string, uint32) {
	compatible := make([]string, 0, len(candidates))
	var incompatible string
	var unsupportedType uint32

	for _, candidate := range candidates {
		mapTypes, errCode := candidateMapTypes(candidate)
		if errCode != 0 {
			compatible = append(compatible, candidate)
			continue
		}

		if mapType, ok := firstUnsupportedMapType(mapTypes, supported); ok {
			if incompatible == "" {
				incompatible = candidate
				unsupportedType = mapType
			}
			continue
		}

		compatible = append(compatible, candidate)
	}

	return compatible, incompatible, unsupportedType
}

func writeMapCompatibilityDebug(w io.Writer, unsupportedType uint32, supported map[uint32]bool, members *jsonMemberState) {
	errCode := -int(syscall.EOPNOTSUPP)
	members.prefix(w)
	fmt.Fprintf(w,
		"        \"Debug\" : {\n"+
			"            \"Info\" : { \"Stage\" : \"map_compatibility\",\n"+
			"                       \"Error Code\" : %d,\n"+
			"                       \"Error Message\" : \"%s\",\n"+
			"                       \"Unsupported Map Type\" : \"%s\",\n"+
			"                       \"Supported Map Types\" : ",
		errCode, describeError(errCode), mapTypeName(unsupportedType))
	writeSupportedMapTypes(w, supported)
	fmt.Fprint(w, ",\n                       \"Programs\" : []\n                      }\n        }")
}

func fillNames() {
	updateNames(dcOptionalNames)
	updateNames(swapOptionalNames)
	updateNames(fdOptionalNames)
	updateNames(zfsOptionalNames)
}

func updateNames(names []specifyName) {
	if len(names) == 0 {
		return
	}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return
	}
	defer file.Close()

	remaining := 0
	for i := range names {
		if names[i].optional == "" {
			remaining++
		}
	}
	if remaining == 0 {
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) <= 19 {
			continue
		}

		data := line[19:]
		for i := range names {
			if names[i].optional != "" {
				continue
			}

			candidates := []string{names[i].functionToAttach, names[i].fallbackFunction}
			for _, candidate := range candidates {
				if candidate == "" || !strings.HasPrefix(data, candidate) {
					continue
				}

				// Reject prefix-only matches (e.g. "swap_read_folio_bdev_sync" != "swap_read_folio")
				if len(data) > len(candidate) && data[len(candidate)] != ' ' && data[len(candidate)] != '\t' {
					continue
				}

				end := strings.IndexAny(data, " \n")
				if end < 0 {
					end = len(data)
				}

				names[i].optional = data[:end]
				remaining--
				if remaining == 0 {
					return
				}
				break
			}
		}
	}
}

func moduleHasBuffer(name string) bool {
	bufferModules := map[string]bool{
		"cachestat": true,
		"dc":        true,
		"fd":        true,
		"oomkill":   true,
		"process":   true,
		"shm":       true,
		"swap":      true,
		"vfs":       true,
		"dns":       true,
		"socket":    true,
	}
	return bufferModules[name]
}

func moduleHasArena(name string) bool {
	arenaModules := map[string]bool{
		"cachestat": true,
		"dc":        true,
		"fd":        true,
		"oomkill":   true,
		"process":   true,
		"shm":       true,
		"swap":      true,
		"vfs":       true,
		"dns":       true,
		"socket":    true,
	}
	return arenaModules[name]
}

func runNetdataTests(w io.Writer, rhfVersion int, kernelVersion int, isReturn bool, opts options, nprocesses int) {
	supportedMapTypes := detectSupportedMapTypes(rhfVersion, kernelVersion)
	isDebian := IsDebianFlavor()

	for _, mod := range ebpfModules {
		if opts.flags&mod.flags == 0 {
			skippedModules = appendUnique(skippedModules, skippedModule{Module: mod.name, Reason: "not selected by flags"})
			continue
		}
		if mod.name == "disk" && rhfVersion <= 0 && kernelVersion >= netdataEBPFKernel616 {
			skippedModules = appendUnique(skippedModules, skippedModule{Module: mod.name, Reason: "disabled on generic kernels >= 6.16"})
			continue
		}

		bufferMode, arenaMode := effectiveModeFlags(mod.name, kernelVersion, isDebian, opts.bufferMode, opts.arenaMode)

		if arenaMode && !moduleHasArena(mod.name) {
			skippedModules = appendUnique(skippedModules, skippedModule{Module: mod.name, Reason: "arena flavor unavailable"})
			continue
		}

		if bufferMode && !moduleHasBuffer(mod.name) {
			skippedModules = appendUnique(skippedModules, skippedModule{Module: mod.name, Reason: "buffer flavor unavailable"})
			continue
		}

		kernels := mod.kernels
		if arenaMode && mod.arenaKernels != 0 {
			kernels = mod.arenaKernels
		} else if bufferMode && mod.bufferKernels != 0 {
			kernels = mod.bufferKernels
		}
		if isRHEL10Kernel612Stream(rhfVersion, kernelVersion) {
			kernels |= netdataV612
		}
		maxIndex := selectModuleMaxIndex(mod.name, rhfVersion, kernelVersion)
		if maxIndex == ^uint32(0) {
			skippedModules = appendUnique(skippedModules, skippedModule{Module: mod.name, Reason: "legacy disk unsupported for this Red Hat kernel"})
			continue
		}
		idx := selectIndexFromMax(kernels, rhfVersion, maxIndex)
		candidates := discoverCandidates(mod.name, isReturn, rhfVersion, kernels, maxIndex, opts.netdataPath, bufferMode, arenaMode)
		compatible, incompatible, unsupportedType := filterCompatibleCandidates(candidates, supportedMapTypes)

		if len(compatible) == 0 {
			if incompatible != "" {
				flavor, reason := selectionFlavor(bufferMode, arenaMode, opts)
				selectedIndex := idx
				if candidateIndex := candidateVersionIndex(filepath.Base(incompatible), mod.name, isReturn, rhfVersion, kernels, maxIndex, bufferMode, arenaMode); candidateIndex >= 0 {
					selectedIndex = uint32(candidateIndex)
				}
				members := startNetdataJSON(w, incompatible, isReturn, mod.name, selectedIndex, flavor, reason)
				writeMapCompatibilityDebug(w, unsupportedType, supportedMapTypes, members)
				fmt.Fprintf(w, "    },\n    \"Status\" : \"%s\"\n}", "Fail")
				continue
			}

			compatible = []string{mountName(idx, mod.name, isReturn, rhfVersion, opts.netdataPath, bufferMode, arenaMode)}
		}

		for _, filename := range compatible {
			flavor, reason := selectionFlavor(bufferMode, arenaMode, opts)
			selectedIndex := idx
			if candidateIndex := candidateVersionIndex(filepath.Base(filename), mod.name, isReturn, rhfVersion, kernels, maxIndex, bufferMode, arenaMode); candidateIndex >= 0 {
				selectedIndex = uint32(candidateIndex)
			}
			members := startNetdataJSON(w, filename, isReturn, mod.name, selectedIndex, flavor, reason)
			result := ebpfTester(w, filename, mod.updateNames, opts.flags&flagContent != 0, mod.ctrlTable, opts, nprocesses, kernelVersion, members)
			fmt.Fprintf(w, "    },\n    \"Status\" : \"%s\"\n}", result)
		}
	}
}

func selectKernelName(selector uint32) string {
	kernelNames := []string{"3.10", "4.14", "4.16", "4.18", "5.4", "5.10", "5.11", "5.14", "5.15", "5.16", "6.8", "6.12", "7.0", "5.17"}
	if int(selector) >= len(kernelNames) {
		return "unknown"
	}
	return kernelNames[selector]
}

func appendUnique(values []skippedModule, value skippedModule) []skippedModule {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func selectModuleMaxIndex(moduleName string, rhfVersion int, kernelVersion int) uint32 {
	if moduleName == "disk" && rhfVersion > 0 && kernelVersion >= netdataEBPFKernel517 {
		if isRHEL10Kernel612Stream(rhfVersion, kernelVersion) {
			return 11
		}
		return ^uint32(0) // No supported Red Hat legacy disk object in this kernel range.
	}
	if isRHEL10Kernel612Stream(rhfVersion, kernelVersion) {
		return 11
	}
	if moduleName == "disk" && rhfVersion <= 0 {
		switch {
		case kernelVersion >= netdataEBPFKernel68:
			return 10
		case kernelVersion >= netdataEBPFKernel517:
			return 13
		case kernelVersion >= netdataEBPFKernel516:
			return 9
		case kernelVersion >= netdataEBPFKernel511:
			return 6
		}
	}

	return selectMaxIndex(rhfVersion, kernelVersion)
}

func isRHEL10Kernel612Stream(rhfVersion int, kernelVersion int) bool {
	return rhfVersion >= 10*256 && rhfVersion < 11*256 &&
		kernelVersion >= netdataEBPFKernel612 && kernelVersion < 6*65536+13*256
}

func selectMaxIndex(rhfVersion int, kernelVersion int) uint32 {
	if rhfVersion > 0 {
		switch {
		case isRHEL10Kernel612Stream(rhfVersion, kernelVersion):
			return 11
		case kernelVersion >= netdataEBPFKernel514:
			return 7
		case kernelVersion >= netdataEBPFKernel54:
			return 4
		case kernelVersion >= netdataMinimumEBPFKernel:
			return 3
		}
	} else {
		switch {
		case kernelVersion >= netdataEBPFKernel70:
			return 12
		case kernelVersion >= netdataEBPFKernel612:
			return 11
		case kernelVersion >= netdataEBPFKernel68:
			return 10
		case kernelVersion >= netdataEBPFKernel516:
			return 9
		case kernelVersion >= netdataEBPFKernel515:
			return 8
		case kernelVersion >= netdataEBPFKernel511:
			return 6
		case kernelVersion >= netdataEBPFKernel510:
			return 5
		case kernelVersion >= netdataEBPFKernel417:
			return 4
		case kernelVersion >= netdataEBPFKernel415:
			return 2
		case kernelVersion >= netdataMinimumEBPFKernel:
			return 1
		}
	}

	return 0
}

func selectIndex(kernels uint32, rhfVersion int, kernelVersion int) uint32 {
	return selectIndexFromMax(kernels, rhfVersion, selectMaxIndex(rhfVersion, kernelVersion))
}

func selectIndexFromMax(kernels uint32, rhfVersion int, start uint32) uint32 {
	if rhfVersion == -1 {
		kernels &^= netdataV514
	}

	for idx := start; idx > 0; idx-- {
		if kernels&(1<<idx) != 0 {
			return idx
		}
	}

	return 0
}

func mountName(kernelIndex uint32, name string, isReturn bool, rhfVersion int, netdataPath string, bufferMode bool, arenaMode bool) string {
	version := selectKernelName(kernelIndex)
	path := netdataPath
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			path = "."
		} else {
			path = cwd
		}
	} else {
		resolved, err := filepath.Abs(path)
		if err == nil {
			path = resolved
		}
	}

	prefix := 'p'
	if isReturn {
		prefix = 'r'
	}

	suffix := ""
	if rhfVersion != -1 {
		suffix = ".rhf"
	}

	return fmt.Sprintf("%s/%cnetdata_ebpf_%s%s.%s%s.o", path, prefix, name, modeSuffix(bufferMode, arenaMode), version, suffix)
}

func startExternalJSON(w io.Writer, filename string) *jsonMemberState {
	testsStarted++
	fmt.Fprintf(w, ",\n  %s : {\n    \"Tables\" : {\n", jsonString(filename))
	return &jsonMemberState{first: true}
}

func selectionFlavor(bufferMode bool, arenaMode bool, opts options) (string, string) {
	if arenaMode {
		return "arena", "explicit --arena"
	}
	if bufferMode {
		if opts.bufferMode {
			return "buffer", "explicit --buffer"
		}
		return "buffer", "production default buffer"
	}
	return "base", "base flavor"
}

func startNetdataJSON(w io.Writer, filename string, isReturn bool, module string, index uint32, flavor string, reason string) *jsonMemberState {
	testsStarted++
	testType := "entry"
	if isReturn {
		testType = "return"
	}
	fmt.Fprintf(w, ",\n  %s : {\n    \"Test\" : \"%s\",\n    \"Selected\" : {\"Module\" : %q, \"Index\" : %d, \"Kernel\" : %q, \"Flavor\" : %q, \"Reason\" : %q},\n    \"Tables\" : {\n", jsonString(filename), testType, module, index, selectKernelName(index), flavor, reason)
	return &jsonMemberState{first: true}
}

func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func ebpfTester(w io.Writer, filename string, names *[]specifyName, maps bool, ctrl string, opts options, nprocesses int, kernelVersion int, members *jsonMemberState) string {
	const (
		success = "Success"
		failure = "Fail"
	)
	mapsRequested := maps

	obj, errCode := openBPFObject(filename)
	if errCode != 0 {
		writeFailureDebug(w, nil, "open_file", errCode, false, 0, attachSummary{}, members)
		return failure
	}
	defer obj.close()

	writeObjectMapTypes(w, obj, members)

	total := obj.countPrograms()
	socketFilterDetected := obj.hasSocketFilter()
	if socketFilterDetected {
		return runDNSSocketFilterTester(obj, true, w, opts.iterations, opts.dnsPorts, members)
	}

	loadErr := obj.load()
	if loadErr != 0 {
		writeFailureDebug(w, obj, "object_load", loadErr, socketFilterDetected, total, attachSummary{}, members)
		return failure
	}

	summary := attachPrograms(obj, names, kernelVersion)
	if summary.fail > 0 {
		writeFailureDebug(w, obj, "attach_programs", summary.lastError, socketFilterDetected, total, summary, members)
	}
	if summary.fail == 0 {
		maps = true
	}

	if maps {
		if hasSocketTable(obj) {
			time.Sleep(mapCaptureDuration(obj))
			runSocketTableTester(w, obj, opts.iterations, members)
		} else {
			if ctrl != "" && mapsRequested {
				fillCtrl(obj, ctrl, opts.mapLevel, nprocesses)
			}
			time.Sleep(mapCaptureDuration(obj))
			testMaps(w, obj, ctrl, opts.iterations, nprocesses, members)
		}
	}

	for _, link := range summary.links {
		link.destroy()
	}

	if summary.fail == 0 {
		return success
	}

	return failure
}

func attachPrograms(obj *bpfObject, names *[]specifyName, kernelVersion int) attachSummary {
	var summary attachSummary

	for prog := obj.firstProgram(); prog != nil; prog = obj.nextProgram(prog) {
		if skipProgramForKernel(prog.sectionName(), kernelVersion) {
			summary.skipped++
			continue
		}

		var (
			link *bpfLink
			err  int
		)

		if retprobe, target, ok := syscallAttachTarget(prog.sectionName(), kernelVersion); ok {
			link, err = prog.attachKprobe(retprobe, target)
		} else {
			override := findOptionalName(names, prog.name())
			if override != nil && prog.progType() == bpfProgTypeKprobe {
				target := override.optional
				if target == "" && override.required {
					target = override.functionToAttach
				}
				if target == "" {
					summary.skipped++
					continue
				}
				link, err = prog.attachKprobe(override.retprobe, target)
			} else {
				link, err = prog.attach()
			}
		}

		if err != 0 {
			summary.lastError = err
			summary.failedProgramName = prog.name()
			summary.failedProgramType = prog.progType()
			summary.fail++
			continue
		}

		summary.links = append(summary.links, link)
		summary.success++

		switch prog.name() {
		case "netdata_block_rq_issue":
			if link, err := prog.attachKprobe(false, "blk_start_request"); err == 0 {
				summary.links = append(summary.links, link)
			} else {
				summary.skipped++
			}
		case "netdata_block_rq_complete":
			link, err := prog.attachKprobe(false, "__blk_mq_end_request")
			if err != 0 {
				link, err = prog.attachKprobe(false, "blk_mq_free_request")
			}
			if err == 0 {
				summary.links = append(summary.links, link)
			} else {
				summary.skipped++
			}
		}
	}

	return summary
}

func skipProgramForKernel(section string, kernelVersion int) bool {
	if section != "kprobe/blk_complete_request" {
		return false
	}

	// blk_complete_request is not available in the older kernels covered by
	// the 4.x artifacts, and was removed from newer kernels in favor of the
	// blk_mq completion path.
	return kernelVersion < netdataEBPFKernel54 || kernelVersion >= netdataEBPFKernel60
}

func syscallAttachTarget(section string, kernelVersion int) (bool, string, bool) {
	retprobe := false
	target := ""

	switch {
	case strings.HasPrefix(section, "ksyscall/"):
		target = strings.TrimPrefix(section, "ksyscall/")
	case strings.HasPrefix(section, "kretsyscall/"):
		retprobe = true
		target = strings.TrimPrefix(section, "kretsyscall/")
	case strings.HasPrefix(section, "kprobe/"):
		target = strings.TrimPrefix(section, "kprobe/")
	case strings.HasPrefix(section, "kretprobe/"):
		retprobe = true
		target = strings.TrimPrefix(section, "kretprobe/")
	default:
		return false, "", false
	}

	syscallName := ""
	for _, prefix := range []string{"__x64_sys_", "__arm64_sys_", "__s390x_", "sys_"} {
		if strings.HasPrefix(target, prefix) {
			syscallName = strings.TrimPrefix(target, prefix)
			break
		}
	}
	if syscallName == "" {
		// kprobe sections for ordinary kernel functions must use libbpf's
		// normal auto-attach path.
		if strings.HasPrefix(section, "ksyscall/") || strings.HasPrefix(section, "kretsyscall/") {
			syscallName = target
		} else {
			return false, "", false
		}
	}
	if _, ok := netdataSyscalls[syscallName]; !ok &&
		!strings.HasPrefix(section, "ksyscall/") && !strings.HasPrefix(section, "kretsyscall/") {
		return false, "", false
	}

	prefix := "sys_"
	if kernelVersion >= netdataEBPFKernel417 {
		switch runtime.GOARCH {
		case "amd64":
			prefix = "__x64_sys_"
		case "arm64":
			prefix = "__arm64_sys_"
		case "s390x":
			prefix = "__s390x_"
		}
	}

	return retprobe, prefix + syscallName, true
}

func findOptionalName(names *[]specifyName, programName string) *specifyName {
	if names == nil {
		return nil
	}

	for i := range *names {
		if (*names)[i].programName == programName {
			return &(*names)[i]
		}
	}

	return nil
}

func writeFailureDebug(w io.Writer, obj *bpfObject, stage string, err int, socketFilterDetected bool, total int, summary attachSummary, members *jsonMemberState) {
	members.prefix(w)
	fmt.Fprintf(w,
		"        \"Debug\" : {\n"+
			"            \"Info\" : { \"Stage\" : \"%s\",\n"+
			"                       \"Error Code\" : %d,\n"+
			"                       \"Error Message\" : \"%s\",\n"+
			"                       \"Socket Filter Detected\" : %d,\n"+
			"                       \"Program Count\" : %d,\n"+
			"                       \"Attach Success\" : %d,\n"+
			"                       \"Attach Fail\" : %d",
		stage, err, describeError(err), boolToInt(socketFilterDetected), total, summary.success, summary.fail)

	if summary.failedProgramName != "" {
		fmt.Fprintf(w,
			",\n"+
				"                       \"Failed Program\" : \"%s\",\n"+
				"                       \"Failed Program Type\" : %d",
			summary.failedProgramName, summary.failedProgramType)
	}

	fmt.Fprint(w, ",\n                       \"Programs\" : ")
	writeProgramInventory(w, obj)
	fmt.Fprint(w, "\n                      }\n        }\n")
}

func writeProgramInventory(w io.Writer, obj *bpfObject) {
	fmt.Fprint(w, "[")
	first := true
	if obj != nil {
		for prog := obj.firstProgram(); prog != nil; prog = obj.nextProgram(prog) {
			if !first {
				fmt.Fprint(w, ", ")
			}
			fmt.Fprintf(w, "{ \"Name\" : \"%s\", \"Type\" : %d }", prog.name(), prog.progType())
			first = false
		}
	}
	fmt.Fprint(w, "]")
}

func isPerCPUMapType(mapType uint32) bool {
	return mapType == bpfMapTypePerCPUArray || mapType == bpfMapTypePerCPUHash
}

func isRingBufferMapType(mapType uint32) bool {
	return mapType == bpfMapTypeRingBuf || mapType == bpfMapTypeUserRingBuf || mapType == bpfMapTypeArena
}

func isUserRingBufferMapType(mapType uint32) bool {
	return mapType == bpfMapTypeUserRingBuf
}

func supportsMapKeyValueIO(mapType uint32) bool {
	return !isRingBufferMapType(mapType)
}

func roundUpSize(value int, align int) int {
	return ((value + align - 1) / align) * align
}

func mapValueStride(meta mapMeta) int {
	if !isPerCPUMapType(meta.Type) {
		return int(meta.ValueSize)
	}

	return roundUpSize(int(meta.ValueSize), 8)
}

func mapValueLength(meta mapMeta, nprocesses int) int {
	if !isPerCPUMapType(meta.Type) {
		return int(meta.ValueSize)
	}

	if nprocesses < 1 {
		nprocesses = 1
	}

	return mapValueStride(meta) * nprocesses
}

func mapValueCPUCount(meta mapMeta, nprocesses int) int {
	if !isPerCPUMapType(meta.Type) {
		return 1
	}
	if nprocesses < 1 {
		return 1
	}
	return nprocesses
}

func controllerEntryLimit(meta mapMeta) int {
	limit := netdataControllerEnd

	if meta.MaxEntries > 0 && int(meta.MaxEntries) < limit {
		limit = int(meta.MaxEntries)
	}

	return limit
}

func fillScalarValue(dst []byte, valueSize uint32, value uint64) {
	switch {
	case valueSize >= 8 && len(dst) >= 8:
		binary.LittleEndian.PutUint64(dst, value)
	case valueSize >= 4 && len(dst) >= 4:
		binary.LittleEndian.PutUint32(dst, uint32(value))
	}
}

func allocateTableData(meta mapMeta, nprocesses int) *tableData {
	valueLength := mapValueLength(meta, nprocesses)
	return &tableData{
		key:         make([]byte, meta.KeySize),
		nextKey:     make([]byte, meta.KeySize),
		value:       make([]byte, valueLength),
		defValue:    make([]byte, valueLength),
		keyLength:   int(meta.KeySize),
		valueLength: valueLength,
	}
}

func readGenericTable(values *tableData, fd int) {
	// Passing a nil key to bpf_map_get_next_key retrieves the first entry,
	// which correctly includes key 0 in array-type maps. The previous pattern
	// starting from a zero-initialized key skipped key 0 in arrays and
	// double-counted the last entry in every map type.
	if bpfMapGetNextKey(fd, nil, values.nextKey) != 0 {
		return
	}

	for {
		for i := range values.value {
			values.value[i] = 0
		}
		if bpfMapLookupElem(fd, values.nextKey, values.value) == 0 {
			if bytes.Equal(values.value, values.defValue) {
				values.zero++
			} else {
				values.filled++
			}
		}
		copy(values.key, values.nextKey)
		if bpfMapGetNextKey(fd, values.key, values.nextKey) != 0 {
			break
		}
	}
}

func writeCommonJSONVector(w io.Writer, values *tableData, fd int, iterations int) {
	for i := 0; i < iterations; i++ {
		readGenericTable(values, fd)
		if i > 0 {
			fmt.Fprint(w, ",\n")
		}
		fmt.Fprintf(w, "                                    { \"Iteration\" :  %d, \"Total\" : %d, \"Filled\" : %d, \"Zero\" : %d }",
			i, values.filled+values.zero, values.filled, values.zero)
	}
	fmt.Fprint(w, "\n")
}

type diskHistogram struct {
	dev  uint32
	bins [diskHistogramBins]uint64
}

var filesystemHistogramMaps = map[string]struct{}{
	"tbl_btrfs": {},
	"tbl_ext4":  {},
	"tbl_nfs":   {},
	"tbl_xfs":   {},
	"tbl_zfs":   {},
}

func isFilesystemHistogramMap(name string) bool {
	_, ok := filesystemHistogramMaps[name]
	return ok
}

func mapCaptureDuration(obj *bpfObject) time.Duration {
	duration := time.Duration(0)
	for m := obj.firstMap(); m != nil; m = obj.nextMap(m) {
		if m.name() == "socket_events" {
			if duration < 5*time.Second {
				duration = 5 * time.Second
			}
			continue
		}
		if !supportsMapKeyValueIO(m.meta().Type) {
			return 10 * time.Second
		}
		if duration < 5*time.Second {
			duration = 5 * time.Second
		}
	}
	return duration
}

func writeDiskHistogram(w io.Writer, meta mapMeta, ncpus int) {
	rows := make(map[uint32]*diskHistogram)
	key := make([]byte, meta.KeySize)
	nextKey := make([]byte, meta.KeySize)
	stride := mapValueStride(meta)
	value := make([]byte, mapValueLength(meta, ncpus))

	if meta.KeySize < 8 || meta.ValueSize < 8 || stride*mapValueCPUCount(meta, ncpus) > len(value) {
		fmt.Fprint(w, "\n")
		return
	}
	if bpfMapGetNextKey(meta.FD, nil, nextKey) == 0 {
		for {
			clear(value)
			if bpfMapLookupElem(meta.FD, nextKey, value) == 0 {
				bin := int(binary.NativeEndian.Uint32(nextKey[:4]))
				dev := binary.NativeEndian.Uint32(nextKey[4:8])
				if bin < diskHistogramBins {
					row := rows[dev]
					if row == nil {
						row = &diskHistogram{dev: dev}
						rows[dev] = row
					}
					for cpu := 0; cpu < mapValueCPUCount(meta, ncpus); cpu++ {
						start := cpu * stride
						row.bins[bin] += binary.NativeEndian.Uint64(value[start : start+8])
					}
				}
			}
			copy(key, nextKey)
			if bpfMapGetNextKey(meta.FD, key, nextKey) != 0 {
				break
			}
		}
	}

	devices := make([]uint32, 0, len(rows))
	for dev := range rows {
		devices = append(devices, dev)
	}
	sort.Slice(devices, func(i, j int) bool {
		majorI, majorJ := diskDeviceMajor(devices[i]), diskDeviceMajor(devices[j])
		if majorI != majorJ {
			return majorI < majorJ
		}
		return diskDeviceMinor(devices[i]) < diskDeviceMinor(devices[j])
	})

	fmt.Fprint(w, "                                    ")
	for deviceIndex, dev := range devices {
		if deviceIndex > 0 {
			fmt.Fprint(w, ",\n                                    ")
		}
		fmt.Fprintf(w, "{ \"Device\" : \"%d:%d\", \"Histogram\" : [\n", diskDeviceMajor(dev), diskDeviceMinor(dev))
		for bin, count := range rows[dev].bins {
			if bin > 0 {
				fmt.Fprint(w, ",\n")
			}
			minUS := uint64(1) << bin
			maxUS := (uint64(1) << (bin + 1)) - 1
			if bin == 0 {
				minUS = 0
			}
			if bin == diskHistogramBins-1 {
				fmt.Fprintf(w, "                                        { \"Bin\" : %d, \"Latency_us\" : \">=%d\", \"Count\" : %d }", bin, minUS, count)
			} else {
				fmt.Fprintf(w, "                                        { \"Bin\" : %d, \"Latency_us\" : \"%d-%d\", \"Count\" : %d }", bin, minUS, maxUS, count)
			}
		}
		fmt.Fprint(w, "\n                                    ] }")
	}
	fmt.Fprint(w, "\n")
}

func writeFilesystemHistogram(w io.Writer, meta mapMeta, ncpus int) {
	const operations = 4
	operationNames := [...]string{"read", "write", "open", "sync"}
	if meta.Name == "tbl_nfs" {
		operationNames[3] = "getattr"
	}
	if meta.KeySize < 4 || meta.ValueSize < 8 || meta.MaxEntries < operations*diskHistogramBins || ncpus < 1 {
		fmt.Fprint(w, "\n")
		return
	}

	stride := mapValueStride(meta)
	value := make([]byte, mapValueLength(meta, ncpus))
	var histogram [operations][diskHistogramBins]uint64
	key := make([]byte, meta.KeySize)
	for index := 0; index < operations*diskHistogramBins; index++ {
		clear(key)
		binary.NativeEndian.PutUint32(key[:4], uint32(index))
		clear(value)
		if bpfMapLookupElem(meta.FD, key, value) != 0 {
			continue
		}
		operation, bin := index/diskHistogramBins, index%diskHistogramBins
		for cpu := 0; cpu < mapValueCPUCount(meta, ncpus); cpu++ {
			start := cpu * stride
			histogram[operation][bin] += binary.NativeEndian.Uint64(value[start : start+8])
		}
	}

	fmt.Fprint(w, "                                    ")
	for operation, name := range operationNames {
		if operation > 0 {
			fmt.Fprint(w, ",\n                                    ")
		}
		fmt.Fprintf(w, "{ \"Operation\" : \"%s\", \"Histogram\" : [\n", name)
		for bin, count := range histogram[operation] {
			if bin > 0 {
				fmt.Fprint(w, ",\n")
			}
			minUS := uint64(1) << bin
			maxUS := (uint64(1) << (bin + 1)) - 1
			if bin == 0 {
				minUS = 0
			}
			if bin == diskHistogramBins-1 {
				fmt.Fprintf(w, "                                        { \"Bin\" : %d, \"Latency_us\" : \">=%d\", \"Count\" : %d }", bin, minUS, count)
			} else {
				fmt.Fprintf(w, "                                        { \"Bin\" : %d, \"Latency_us\" : \"%d-%d\", \"Count\" : %d }", bin, minUS, maxUS, count)
			}
		}
		fmt.Fprint(w, "\n                                    ] }")
	}
	fmt.Fprint(w, "\n")
}

func diskDeviceMajor(dev uint32) uint32 {
	return (dev >> 8) & 0xfff
}

func diskDeviceMinor(dev uint32) uint32 {
	return (dev & 0xff) | ((dev >> 12) & 0xffffff00)
}

func controllerJSON(w io.Writer, fd int, meta mapMeta, nprocesses int) {
	var filled, zero uint32
	key := make([]byte, meta.KeySize)
	value := make([]byte, mapValueLength(meta, nprocesses))
	for idx := 0; idx < controllerEntryLimit(meta); idx++ {
		putUint32(key, uint32(idx))
		if bpfMapLookupElem(fd, key, value) != 0 {
			zero++
		} else {
			filled++
		}
	}
	fmt.Fprintf(w, "                                    { \"Iteration\" : 1, \"Total\" : %d, \"Filled\" : %d, \"Zero\" : %d }\n",
		filled+zero, filled, zero)
}

func testRingBufferMap(w io.Writer, meta mapMeta, iterations int, members *jsonMemberState) {
	mode := "ringbuf_consumer"
	var (
		rb       *ringBuffer
		urb      *userRingBuffer
		setupErr int
	)

	if isUserRingBufferMapType(meta.Type) {
		mode = "user_ringbuf_producer"
		urb, setupErr = newUserRingBuffer(meta.FD)
	} else {
		rb, setupErr = newRingBuffer(meta.FD)
	}

	members.prefix(w)
	fmt.Fprintf(w,
		"        \"%s\" : {\n            \"Info\" : { \"Length\" : { \"Key\" : %d, \"Value\" : %d},\n"+
			"                       \"Type\" : %d,\n"+
			"                       \"FD\" : %d,\n"+
			"                       \"Data\" : [\n",
		meta.Name, meta.KeySize, meta.ValueSize, meta.Type, meta.FD)

	var prevSamples uint64
	var prevBytes uint64
	for i := 0; i < iterations; i++ {
		opErr := setupErr
		opResult := 0
		var iterSamples uint64
		var iterBytes uint64
		var availData uint64
		var ringSize uint64

		if rb != nil {
			opResult = rb.poll(0)
			if opResult < 0 {
				opErr = opResult
			}

			samples := rb.samples()
			bytes := rb.bytes()
			iterSamples = samples - prevSamples
			iterBytes = bytes - prevBytes
			prevSamples = samples
			prevBytes = bytes
			availData = rb.availData()
			ringSize = rb.size()
		} else if urb != nil {
			opResult = urb.submitUint64(uint64(i + 1))
			if opResult < 0 {
				opErr = opResult
			}
		}

		if i > 0 {
			fmt.Fprint(w, ",\n")
		}
		fmt.Fprintf(w,
			"                                    { \"Iteration\" : %d, \"Mode\" : \"%s\", \"Setup\" : %d, "+
				"\"Operation Result\" : %d, \"Samples\" : %d, \"Bytes\" : %d, "+
				"\"Available\" : %d, \"Ring Size\" : %d, \"Error Code\" : %d, "+
				"\"Error Message\" : \"%s\" }",
			i, mode, boolToInt(setupErr == 0), opResult, iterSamples, iterBytes,
			availData, ringSize, opErr, describeError(opErr))
	}
	fmt.Fprint(w, "\n")

	if rb != nil {
		rb.free()
	}
	if urb != nil {
		urb.free()
	}
}

func testMaps(w io.Writer, obj *bpfObject, ctrl string, iterations int, nprocesses int, members *jsonMemberState) {
	tables := 0
	for m := obj.firstMap(); m != nil; m = obj.nextMap(m) {
		meta := m.meta()
		if meta.Name == "socket_events" {
			runSocketRingBufferTester(w, obj, iterations, members)
			fmt.Fprint(w, "                                ]\n                      }\n        }")
			tables++
			continue
		}
		if !supportsMapKeyValueIO(meta.Type) {
			testRingBufferMap(w, meta, iterations, members)
			fmt.Fprint(w, "                                ]\n                      }\n        }")
			tables++
			continue
		}

		values := allocateTableData(meta, nprocesses)
		members.prefix(w)
		fmt.Fprintf(w,
			"        \"%s\" : {\n            \"Info\" : { \"Length\" : { \"Key\" : %d, \"Value\" : %d},\n"+
				"                       \"Type\" : %d,\n"+
				"                       \"FD\" : %d,\n"+
				"                       \"Data\" : [\n",
			meta.Name, meta.KeySize, meta.ValueSize, meta.Type, meta.FD)

		if meta.Name == "tbl_disk_iocall" {
			writeDiskHistogram(w, meta, nprocesses)
		} else if isFilesystemHistogramMap(meta.Name) {
			writeFilesystemHistogram(w, meta, nprocesses)
		} else if ctrl == "" || ctrl != meta.Name {
			writeCommonJSONVector(w, values, meta.FD, iterations)
		} else {
			controllerJSON(w, meta.FD, meta, nprocesses)
		}

		fmt.Fprint(w, "                                ]\n                      }\n        }")
		tables++
	}

	members.prefix(w)
	fmt.Fprintf(w, "        \"Total tables\" : %d\n", tables)
}

func fillCtrl(obj *bpfObject, ctrl string, mapLevel int, nprocesses int) {
	m := obj.findMapByName(ctrl)
	if m == nil {
		return
	}

	meta := m.meta()
	if !supportsMapKeyValueIO(meta.Type) {
		return
	}
	values := []uint64{1, uint64(mapLevel), 0, 0, 0, 0}
	key := make([]byte, meta.KeySize)
	value := make([]byte, mapValueLength(meta, nprocesses))
	stride := mapValueStride(meta)
	cpuCount := 1

	if stride > 0 {
		cpuCount = len(value) / stride
	}

	for i := uint32(0); i < meta.MaxEntries && int(i) < len(values); i++ {
		for j := range value {
			value[j] = 0
		}

		for cpu := 0; cpu < cpuCount; cpu++ {
			offset := cpu * stride
			fillScalarValue(value[offset:], meta.ValueSize, values[i])
		}

		putUint32(key, i)
		bpfMapUpdateElem(meta.FD, key, value, 0)
	}
}

func putUint16(dst []byte, value uint16) {
	if len(dst) >= 2 {
		binary.LittleEndian.PutUint16(dst, value)
	}
}

func putUint32(dst []byte, value uint32) {
	if len(dst) >= 4 {
		binary.LittleEndian.PutUint32(dst, value)
	}
}

func writeErrorExit(w io.Writer, msg string) {
	fmt.Fprintf(w, ",\n  \"Error\" : %q,\n  \"End\" : \"Good bye!!!\" }\n", msg)
}

func describeError(err int) string {
	if err == 0 {
		return "No error information"
	}

	if err < 0 {
		err = -err
	}

	return syscall.Errno(err).Error()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func dnsFormatIP(family uint8, raw [16]byte) string {
	size := dnsIPSize(family)
	ip := net.IP(raw[:size])
	if family == syscall.AF_INET6 {
		ip = net.IP(raw[:16])
	}
	if ip == nil {
		return "invalid"
	}

	return ip.String()
}

const gotestsModuleName = "github.com/netdata/kernel-collector/gotests"

func runUnitTests() int {
	workDir, err := locateUnitTestDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot locate gotests module directory: %v\n", err)
		return 2
	}

	goBinary, err := exec.LookPath("go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot find go tool: %v\n", err)
		return 2
	}

	cmd := exec.Command(goBinary, "test", "./...")
	cmd.Dir = workDir
	cmd.Env = unitTestEnv(os.Environ())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}

		fmt.Fprintf(os.Stderr, "cannot run go test: %v\n", err)
		return 2
	}

	return 0
}

func locateUnitTestDir() (string, error) {
	cwd, _ := os.Getwd()
	executable, _ := os.Executable()
	return resolveUnitTestDir(cwd, executable)
}

func resolveUnitTestDir(cwd string, executable string) (string, error) {
	candidates := []string{cwd}
	if cwd != "" {
		candidates = append(candidates, filepath.Join(cwd, "gotests"))
	}

	if executable != "" {
		exeDir := filepath.Dir(executable)
		candidates = append(candidates, exeDir, filepath.Join(exeDir, "gotests"))
	}

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}

		candidate = filepath.Clean(candidate)
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}

		if dir, ok := findGoModuleDir(candidate, gotestsModuleName); ok {
			return dir, nil
		}
	}

	return "", fmt.Errorf("module %s not found from cwd=%q executable=%q", gotestsModuleName, cwd, executable)
}

func findGoModuleDir(start string, moduleName string) (string, bool) {
	for current := filepath.Clean(start); ; {
		if isGoModuleDir(current, moduleName) {
			return current, true
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}

		current = parent
	}
}

func isGoModuleDir(dir string, moduleName string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}

	moduleLine := "module " + moduleName
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == moduleLine {
			return true
		}
	}

	return false
}

func unitTestEnv(env []string) []string {
	for _, entry := range env {
		if strings.HasPrefix(entry, "GOCACHE=") {
			return env
		}
	}

	cloned := append([]string{}, env...)
	cloned = append(cloned, "GOCACHE="+filepath.Join(os.TempDir(), "kernel-collector-gocache"))
	return cloned
}
