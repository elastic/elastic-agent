// Standalone environment probe (stdlib only) to characterise the execution
// context a Go process runs under. Run via `go run envprobe.go`. The point is to
// diff a buildkite CI job against a manually-provisioned VM and find what's
// different about the CI exec environment (the confound that makes CI crash but
// the same-image idle VM not).
package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	k32                       = syscall.NewLazyDLL("kernel32.dll")
	pGetStdHandle             = k32.NewProc("GetStdHandle")
	pGetFileType              = k32.NewProc("GetFileType")
	pGetConsoleMode           = k32.NewProc("GetConsoleMode")
	pIsProcessInJob           = k32.NewProc("IsProcessInJob")
	pGetCurrentProcess        = k32.NewProc("GetCurrentProcess")
	pGetProcessAffinityMask   = k32.NewProc("GetProcessAffinityMask")
	pGetPriorityClass         = k32.NewProc("GetPriorityClass")
	pCreateToolhelp32Snapshot = k32.NewProc("CreateToolhelp32Snapshot")
	pProcess32NextW           = k32.NewProc("Process32NextW")
	pModule32NextW            = k32.NewProc("Module32NextW")
	pCloseHandle              = k32.NewProc("CloseHandle")
)

func fileType(h uintptr) string {
	r, _, _ := pGetFileType.Call(h)
	switch r {
	case 1:
		return "DISK(file)"
	case 2:
		return "CHAR(console/ConPTY)"
	case 3:
		return "PIPE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", r)
	}
}

func stdHandle(n int32) uintptr {
	h, _, _ := pGetStdHandle.Call(uintptr(uint32(n)))
	return h
}

func isConsole(h uintptr) bool {
	var mode uint32
	r, _, _ := pGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	return r != 0
}

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	HModule      uintptr
	ModuleName   [256]uint16
	ExePath      [260]uint16
}

const (
	th32Process   = 0x2
	th32Module    = 0x8
	th32Module32  = 0x10
	invalidHandle = ^uintptr(0)
)

func procTree() {
	snap, _, _ := pCreateToolhelp32Snapshot.Call(th32Process, 0)
	if snap == invalidHandle {
		fmt.Println("  (process snapshot failed)")
		return
	}
	defer pCloseHandle.Call(snap)
	ppid := map[uint32]uint32{}
	name := map[uint32]string{}
	var e processEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	pFirst := k32.NewProc("Process32FirstW")
	r, _, _ := pFirst.Call(snap, uintptr(unsafe.Pointer(&e)))
	for r != 0 {
		ppid[e.ProcessID] = e.ParentProcessID
		name[e.ProcessID] = syscall.UTF16ToString(e.ExeFile[:])
		r, _, _ = pProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&e)))
	}
	cur := uint32(os.Getpid())
	for i := 0; i < 12 && cur != 0; i++ {
		fmt.Printf("  %d %s\n", cur, name[cur])
		p, ok := ppid[cur]
		if !ok || p == cur {
			break
		}
		cur = p
	}
}

func modules() {
	pid := uint32(os.Getpid())
	snap, _, _ := pCreateToolhelp32Snapshot.Call(th32Module|th32Module32, uintptr(pid))
	if snap == invalidHandle {
		fmt.Println("  (module snapshot failed)")
		return
	}
	defer pCloseHandle.Call(snap)
	var m moduleEntry32
	m.Size = uint32(unsafe.Sizeof(m))
	pFirst := k32.NewProc("Module32FirstW")
	r, _, _ := pFirst.Call(snap, uintptr(unsafe.Pointer(&m)))
	for r != 0 {
		path := syscall.UTF16ToString(m.ExePath[:])
		low := strings.ToLower(path)
		flag := ""
		// flag modules NOT under the Windows dir and not the probe itself -
		// candidate injected EDR/AV hooks.
		if !strings.HasPrefix(low, `c:\windows\`) && !strings.Contains(low, "envprobe") && !strings.Contains(low, `\go-build`) {
			flag = "  <-- non-Windows module (possible injected DLL)"
		}
		fmt.Printf("  %s%s\n", path, flag)
		r, _, _ = pModule32NextW.Call(snap, uintptr(unsafe.Pointer(&m)))
	}
}

// jitter samples wall-clock gaps between consecutive reads on N locked threads;
// long gaps mean the OS/hypervisor descheduled us (vCPU steal / host contention).
func jitter(d time.Duration, threads int) (maxGap time.Duration, over1ms, over10ms int) {
	type res struct {
		max              time.Duration
		o1, o10          int
	}
	ch := make(chan res, threads)
	for t := 0; t < threads; t++ {
		go func() {
			runtime.LockOSThread()
			var r res
			end := time.Now().Add(d)
			prev := time.Now()
			for time.Now().Before(end) {
				now := time.Now()
				g := now.Sub(prev)
				if g > r.max {
					r.max = g
				}
				if g > time.Millisecond {
					r.o1++
				}
				if g > 10*time.Millisecond {
					r.o10++
				}
				prev = now
			}
			ch <- r
		}()
	}
	for t := 0; t < threads; t++ {
		r := <-ch
		if r.max > maxGap {
			maxGap = r.max
		}
		over1ms += r.o1
		over10ms += r.o10
	}
	return
}

func main() {
	fmt.Println("================ ENV PROBE ================")
	fmt.Printf("GOOS/GOARCH=%s/%s  NumCPU=%d  GOMAXPROCS=%d  pid=%d\n",
		runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), os.Getpid())

	fmt.Println("\n-- std handle types (the I/O-path question) --")
	for _, h := range []struct {
		name string
		n    int32
	}{{"stdin", -10}, {"stdout", -11}, {"stderr", -12}} {
		hd := stdHandle(h.n)
		ft := fileType(hd)
		con := ""
		if isConsole(hd) {
			con = " [GetConsoleMode OK => real console/ConPTY]"
		}
		fmt.Printf("  %-7s handle=0x%x type=%s%s\n", h.name, hd, ft, con)
	}

	fmt.Println("\n-- job object / affinity / priority --")
	cur, _, _ := pGetCurrentProcess.Call()
	var inJob int32
	pIsProcessInJob.Call(cur, 0, uintptr(unsafe.Pointer(&inJob)))
	fmt.Printf("  IsProcessInJob=%v\n", inJob != 0)
	var procMask, sysMask uintptr
	pGetProcessAffinityMask.Call(cur, uintptr(unsafe.Pointer(&procMask)), uintptr(unsafe.Pointer(&sysMask)))
	fmt.Printf("  process affinity=0x%x  system affinity=0x%x  (popcount proc=%d sys=%d)\n",
		procMask, sysMask, popcount(procMask), popcount(sysMask))
	pc, _, _ := pGetPriorityClass.Call(cur)
	fmt.Printf("  priority class=0x%x\n", pc)

	fmt.Println("\n-- scheduling jitter / vCPU-steal sample (2s, NumCPU threads) --")
	mg, o1, o10 := jitter(2*time.Second, runtime.NumCPU())
	fmt.Printf("  max gap=%v   gaps>1ms=%d   gaps>10ms=%d   (large/many => contended host)\n", mg, o1, o10)

	fmt.Println("\n-- process tree (this <- parent <- ...) --")
	procTree()

	fmt.Println("\n-- loaded modules (flagging non-Windows = possible injected DLLs) --")
	modules()

	fmt.Println("\n-- environment (sorted) --")
	env := os.Environ()
	sort.Strings(env)
	for _, e := range env {
		fmt.Println("  " + e)
	}
	fmt.Println("================ END PROBE ================")
}

func popcount(x uintptr) int {
	c := 0
	for x != 0 {
		x &= x - 1
		c++
	}
	return c
}
