package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
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
	netdataMinimumEBPFKernel    = 264960
	netdataEBPFKernel414        = 265728
	netdataEBPFKernel415        = 265984
	netdataEBPFKernel417        = 266496
	netdataEBPFKernel54         = 328704
	netdataEBPFKernel510        = 330240
	netdataEBPFKernel511        = 330496
	netdataEBPFKernel514        = 331264
	netdataEBPFKernel515        = 331520
	netdataEBPFKernel516        = 331776
	netdataEBPFKernel68         = 395264

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

	flagFS  uint64 = flagBtrfs | flagExt4 | flagVFS | flagNFS | flagXFS | flagZFS
	flagAll uint64 = ^uint64(0)
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
	kernels     uint32
	flags       uint64
	name        string
	updateNames *[]specifyName
	ctrlTable   string
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

var (
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
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV515 | netdataV514 | netdataV516, flags: flagCachestat, name: "cachestat", ctrlTable: "cstat_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagDC, name: "dc", updateNames: &dcOptionalNames, ctrlTable: "dcstat_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagDisk, name: "disk", ctrlTable: "disk_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagExt4, name: "ext4", ctrlTable: "ext4_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV511 | netdataV514, flags: flagFD, name: "fd", ctrlTable: "fd_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "fdatasync"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "fsync"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagHardIRQ, name: "hardirq"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagMDFlush, name: "mdflush"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagMount, name: "mount"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "msync"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSocket, name: "socket", ctrlTable: "socket_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagDNS, name: "dns"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagNFS, name: "nfs", ctrlTable: "nfs_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagNetworkViewer, name: "network_viewer", ctrlTable: "nv_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagOOMKill, name: "oomkill"},
		{kernels: netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514 | netdataV510, flags: flagProcess, name: "process", ctrlTable: "process_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSHM, name: "shm", ctrlTable: "shm_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSoftIRQ, name: "softirq"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "sync"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "syncfs"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagSync, name: "sync_file_range"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514 | netdataV68, flags: flagSwap, name: "swap", updateNames: &swapOptionalNames, ctrlTable: "swap_ctrl"},
		{kernels: netdataV310 | netdataV414 | netdataV416 | netdataV418 | netdataV54 | netdataV514, flags: flagVFS, name: "vfs", ctrlTable: "vfs_ctrl"},
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
	nprocesses := libbpfNumPossibleCPUs()
	if nprocesses < 1 {
		nprocesses = runtime.NumCPU()
	}
	if nprocesses < 1 {
		fmt.Fprintf(os.Stderr, "Cannot find number of process, using the default %d\n", netdataDefaultProcessNumber)
		nprocesses = netdataDefaultProcessNumber
	}

	logger := &logState{writer: os.Stderr}
	opts, parseCode := parseArguments(os.Args[1:], kernelVersion, logger)
	if logger.file != nil {
		defer logger.file.Close()
	}
	if parseCode != 0 || opts.showHelp {
		return parseCode
	}
	if opts.unitTest {
		return runUnitTests()
	}

	writer := bufio.NewWriter(logger.writer)
	defer writer.Flush()

	fmt.Fprint(writer, "{")
	if err := memlockLimit(); err != nil {
		writeErrorExit(writer, "Cannot adjust memory limit.")
		return 2
	}

	if opts.flags&flagLoadBinary == 0 {
		fillNames()
		runNetdataTests(writer, rhfVersion, kernelVersion, true, opts, nprocesses)
		runNetdataTests(writer, rhfVersion, kernelVersion, false, opts, nprocesses)
	} else if opts.specificEBPF != "" {
		startExternalJSON(writer, opts.specificEBPF)
		result := ebpfTester(writer, opts.specificEBPF, nil, opts.flags&flagContent != 0, "", opts, nprocesses)
		fmt.Fprintf(writer, "    },\n    \"Status\" :  \"%s\"\n},\n", result)
	}

	fmt.Fprint(writer, "\"End\" : \"Good bye!!!\" }\n")
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
	if err != nil {
		return -1
	}

	return parseRedHatRelease(string(data))
}

func parseRedHatRelease(release string) int {
	major := 0
	minor := -1

	if len(release) <= 4 {
		return -1
	}

	if idx := strings.IndexByte(release, '.'); idx >= 0 {
		head := release[:idx]
		if idx > 0 {
			major = parseLeadingLong(head[idx-1:])
			tail := release[idx+1:]
			if end := strings.IndexByte(tail, ' '); end >= 0 {
				minor = parseLeadingLong(tail[:end])
			}
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
		"--log-path         Filename to write log information. When this option is not given,\n"+
		"                   software will use stderr.\n\n"+
		"--content          Test content stored inside hash tables.\n"+
		"--iteration        Number of iterations when content is read, default value is 1.\n"+
		"--pid              Specify the number that identifies PID  that will be monitored: 0 - Real Parent PID (Default), 1 - Parent PID, and 2 - All PID \n\n"+
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
	return flagAll & ^(flagFS | flagLoadBinary | flagMDFlush | flagContent)
}

func parseArguments(args []string, kernelVersion int, logger *logState) (options, int) {
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
			opts.flags |= flagAll
		case "common":
			opts.flags |= setCommonFlag()
		case "load-binary":
			value, i = optionValue(args, i, value)
			opts.specificEBPF = value
			opts.flags |= flagLoadBinary
		case "dns-port":
			value, i = optionValue(args, i, value)
			opts.dnsPorts = parseDNSPortList(logger.writer, value, opts.dnsPorts)
		case "netdata-path":
			value, i = optionValue(args, i, value)
			opts.netdataPath = value
		case "log-path":
			value, i = optionValue(args, i, value)
			opts.logPath = value
			file, err := os.OpenFile(value, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
			if err != nil {
				logger.writer = os.Stderr
				fmt.Fprintf(logger.writer, "\"Error\": \"Cannot open %s\",\n", value)
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
				fmt.Fprintf(logger.writer, "\"Error\" : \"Value given (%d) is smaller than the minimum, reseting to default 1.\",\n", iteration)
				iteration = 1
			}
			opts.iterations = iteration
		case "pid":
			value, i = optionValue(args, i, value)
			pidLevel, err := strconv.Atoi(value)
			if err != nil || pidLevel < 0 || pidLevel >= 4 {
				fmt.Fprintf(logger.writer, "\"Error\" : \"Value given (%d) is not valid, reseting to default 0 (Real Parent).\",\n", pidLevel)
				pidLevel = 0
			}
			opts.mapLevel = pidLevel
		}
	}

	if !opts.unitTest && opts.flags&(flagAll&^flagContent) == 0 {
		opts.flags |= setCommonFlag()
	}

	if !opts.unitTest && kernelVersion < netdataEBPFKernel414 {
		opts.flags &^= flagOOMKill
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
			fmt.Fprintf(w, "\"Error\" : \"DNS port value (%s) is not valid.\",\n", token)
			continue
		}

		port := uint16(portValue)
		if seen[port] {
			continue
		}
		if len(ports) >= netdataDNSMaxPorts {
			fmt.Fprintf(w, "\"Error\" : \"Maximum number of DNS ports (%d) reached.\",\n", netdataDNSMaxPorts)
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

func candidateMatches(filename string, moduleName string, isReturn bool, version string, rhfVersion int) bool {
	prefix := fmt.Sprintf("%cnetdata_ebpf_%s.", map[bool]rune{true: 'r', false: 'p'}[isReturn], moduleName)
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

func discoverCandidates(moduleName string, isReturn bool, version string, rhfVersion int, netdataPath string) []string {
	path := resolveBinaryDir(netdataPath)
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}

	candidates := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !candidateMatches(entry.Name(), moduleName, isReturn, version, rhfVersion) {
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
	}

	for _, mapType := range []uint32{bpfMapTypeHash, bpfMapTypeArray, bpfMapTypePerCPUHash, bpfMapTypePerCPUArray} {
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
	default:
		return fmt.Sprintf("type_%d", mapType)
	}
}

func writeSupportedMapTypes(w io.Writer, supported map[uint32]bool) {
	names := make([]string, 0, 4)
	for _, mapType := range []uint32{bpfMapTypeHash, bpfMapTypeArray, bpfMapTypePerCPUHash, bpfMapTypePerCPUArray} {
		if supported[mapType] {
			names = append(names, fmt.Sprintf("\"%s\"", mapTypeName(mapType)))
		}
	}

	fmt.Fprintf(w, "[%s]", strings.Join(names, ", "))
}

func writeObjectMapTypes(w io.Writer, obj *bpfObject) {
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

	fmt.Fprintf(w, "        \"Map Types Used\" : [%s],\n", strings.Join(names, ", "))
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

func writeMapCompatibilityDebug(w io.Writer, unsupportedType uint32, supported map[uint32]bool) {
	errCode := -int(syscall.EOPNOTSUPP)
	fmt.Fprintf(w,
		"        \"Debug\" : {\n"+
			"            \"Info\" : { \"Stage\" : \"map_compatibility\",\n"+
			"                       \"Error Code\" : %d,\n"+
			"                       \"Error Message\" : \"%s\",\n"+
			"                       \"Unsupported Map Type\" : \"%s\",\n"+
			"                       \"Supported Map Types\" : ",
		errCode, describeError(errCode), mapTypeName(unsupportedType))
	writeSupportedMapTypes(w, supported)
	fmt.Fprint(w, ",\n                       \"Programs\" : []\n                      }\n        }\n")
}

func fillNames() {
	updateNames(dcOptionalNames)
	updateNames(swapOptionalNames)
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

func runNetdataTests(w io.Writer, rhfVersion int, kernelVersion int, isReturn bool, opts options, nprocesses int) {
	supportedMapTypes := detectSupportedMapTypes(rhfVersion, kernelVersion)

	for _, mod := range ebpfModules {
		if opts.flags&mod.flags == 0 {
			continue
		}

		idx := selectIndex(mod.kernels, rhfVersion, kernelVersion)
		version := selectKernelName(idx)
		candidates := discoverCandidates(mod.name, isReturn, version, rhfVersion, opts.netdataPath)
		compatible, incompatible, unsupportedType := filterCompatibleCandidates(candidates, supportedMapTypes)

		if len(compatible) == 0 {
			if incompatible != "" {
				startNetdataJSON(w, incompatible, isReturn)
				writeMapCompatibilityDebug(w, unsupportedType, supportedMapTypes)
				fmt.Fprintf(w, "    },\n    \"Status\" :  \"%s\"\n},\n", "Fail")
				continue
			}

			compatible = []string{mountName(idx, mod.name, isReturn, rhfVersion, opts.netdataPath)}
		}

		for _, filename := range compatible {
			startNetdataJSON(w, filename, isReturn)
			result := ebpfTester(w, filename, mod.updateNames, opts.flags&flagContent != 0, mod.ctrlTable, opts, nprocesses)
			fmt.Fprintf(w, "    },\n    \"Status\" :  \"%s\"\n},\n", result)
		}
	}
}

func selectKernelName(selector uint32) string {
	kernelNames := []string{"3.10", "4.14", "4.16", "4.18", "5.4", "5.10", "5.11", "5.14", "5.15", "5.16", "6.8"}
	return kernelNames[selector]
}

func selectMaxIndex(rhfVersion int, kernelVersion int) uint32 {
	if rhfVersion > 0 {
		switch {
		case kernelVersion >= netdataEBPFKernel514:
			return 7
		case kernelVersion >= netdataEBPFKernel54:
			return 4
		case kernelVersion >= netdataMinimumEBPFKernel:
			return 3
		}
	} else {
		switch {
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
	start := selectMaxIndex(rhfVersion, kernelVersion)
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

func mountName(kernelIndex uint32, name string, isReturn bool, rhfVersion int, netdataPath string) string {
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

	return fmt.Sprintf("%s/%cnetdata_ebpf_%s.%s%s.o", path, prefix, name, version, suffix)
}

func startExternalJSON(w io.Writer, filename string) {
	fmt.Fprintf(w, "\n\"%s\" : {\n    \"Tables\" : {\n", filename)
}

func startNetdataJSON(w io.Writer, filename string, isReturn bool) {
	testType := "entry"
	if isReturn {
		testType = "return"
	}
	fmt.Fprintf(w, "\"%s\" : {\n    \"Test\" : \"%s\",\n    \"Tables\" : {\n", filename, testType)
}

func ebpfTester(w io.Writer, filename string, names *[]specifyName, maps bool, ctrl string, opts options, nprocesses int) string {
	const (
		success = "Success"
		failure = "Fail"
	)

	obj, errCode := openBPFObject(filename)
	if errCode != 0 {
		writeFailureDebug(w, nil, "open_file", errCode, false, 0, attachSummary{})
		return failure
	}
	defer obj.close()

	writeObjectMapTypes(w, obj)

	total := obj.countPrograms()
	socketFilterDetected := obj.hasSocketFilter()
	if socketFilterDetected {
		return runDNSSocketFilterTester(obj, maps, w, opts.iterations, opts.dnsPorts)
	}

	loadErr := obj.load()
	if loadErr != 0 {
		writeFailureDebug(w, obj, "object_load", loadErr, socketFilterDetected, total, attachSummary{})
		return failure
	}

	summary := attachPrograms(obj, names)
	if summary.fail > 0 {
		writeFailureDebug(w, obj, "attach_programs", summary.lastError, socketFilterDetected, total, summary)
	}

	if maps {
		if ctrl != "" {
			fillCtrl(obj, ctrl, opts.mapLevel, nprocesses)
		}
		testMaps(w, obj, ctrl, opts.iterations, nprocesses)
	}

	for _, link := range summary.links {
		link.destroy()
	}

	if summary.fail == 0 {
		return success
	}

	return failure
}

func attachPrograms(obj *bpfObject, names *[]specifyName) attachSummary {
	var summary attachSummary

	for prog := obj.firstProgram(); prog != nil; prog = obj.nextProgram(prog) {
		var (
			link *bpfLink
			err  int
		)

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

		if err != 0 {
			summary.lastError = err
			summary.failedProgramName = prog.name()
			summary.failedProgramType = prog.progType()
			summary.fail++
			continue
		}

		summary.links = append(summary.links, link)
		summary.success++
	}

	return summary
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

func writeFailureDebug(w io.Writer, obj *bpfObject, stage string, err int, socketFilterDetected bool, total int, summary attachSummary) {
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
		time.Sleep(5 * time.Second)
		readGenericTable(values, fd)
		if i > 0 {
			fmt.Fprint(w, ",\n")
		}
		fmt.Fprintf(w, "                                    { \"Iteration\" :  %d, \"Total\" : %d, \"Filled\" : %d, \"Zero\" : %d }",
			i, values.filled+values.zero, values.filled, values.zero)
	}
	fmt.Fprint(w, "\n")
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

func testMaps(w io.Writer, obj *bpfObject, ctrl string, iterations int, nprocesses int) {
	tables := 0
	for m := obj.firstMap(); m != nil; m = obj.nextMap(m) {
		meta := m.meta()
		values := allocateTableData(meta, nprocesses)
		fmt.Fprintf(w,
			"        \"%s\" : {\n            \"Info\" : { \"Length\" : { \"Key\" : %d, \"Value\" : %d},\n"+
				"                       \"Type\" : %d,\n"+
				"                       \"FD\" : %d,\n"+
				"                       \"Data\" : [\n",
			meta.Name, meta.KeySize, meta.ValueSize, meta.Type, meta.FD)

		if ctrl == "" || ctrl != meta.Name {
			writeCommonJSONVector(w, values, meta.FD, iterations)
		} else {
			controllerJSON(w, meta.FD, meta, nprocesses)
		}

		fmt.Fprint(w, "                                ]\n                      }\n        },\n")
		tables++
	}

	if tables > 0 {
		fmt.Fprintf(w, "        \"Total tables\" : %d\n", tables)
	}
}

func fillCtrl(obj *bpfObject, ctrl string, mapLevel int, nprocesses int) {
	m := obj.findMapByName(ctrl)
	if m == nil {
		return
	}

	meta := m.meta()
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
	fmt.Fprintf(w, "\"Error\" : \"%s\",\n", msg)
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
