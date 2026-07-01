// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux && amd64

//TODO: arm64

package quark

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo amd64 LDFLAGS: -Wl,--wrap=fmemopen ${SRCDIR}/libquark_big_amd64.a
#cgo arm64 LDFLAGS: -Wl,--wrap=fmemopen ${SRCDIR}/libquark_big_arm64.a

#include <stdlib.h>
#include "quark.h"

#ifdef __x86_64__
__asm__(".symver fmemopen, fmemopen@GLIBC_2.2.5");
#elif __aarch64__
__asm__(".symver fmemopen, fmemopen@GLIBC_2.17");
#else
#error Add correct desired symbol version for your arch
#endif



FILE *
__wrap_fmemopen(void *buf, size_t size, const char *mode)
{
	return fmemopen(buf, size, mode);
}

static int
get_event_as_ecs(struct quark_queue *qq, char **ecs_buf, size_t *ecs_buf_len)
{
	const struct quark_event	*qev;

	*ecs_buf = NULL;

	qev = quark_queue_get_event(qq);
	if (qev == NULL)
		return (0);

	if (quark_event_to_ecs(qq, qev, ecs_buf, ecs_buf_len) == -1) {
		*ecs_buf = NULL;
		return (-1);
	}

	return (0);

}
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"
	//	"encoding/binary"
)

// Proc carries data on the state of the process. Only vaid if `Valid` is set.
type Proc struct {
	CapInheritable  uint64
	CapPermitted    uint64
	CapEffective    uint64
	CapBset         uint64
	CapAmbient      uint64
	TimeBoot        uint64
	Ppid            uint32
	Uid             uint32
	Gid             uint32
	Suid            uint32
	Sgid            uint32
	Euid            uint32
	Egid            uint32
	Pgid            uint32
	Sid             uint32
	EntryLeader     uint32
	EntryLeaderType uint32
	TtyMajor        uint32
	TtyMinor        uint32
	UtsInonum       uint32
	IpcInonum       uint32
	MntInonum       uint32
	NetInonum       uint32
	Valid           bool
}

// Exit carries data on the exit behavior of the process. Only valid if `Valid` is set.
type Exit struct {
	ExitCode        int32
	ExitTimeProcess uint64
	Valid           bool
}

// Process represents a single process.
type Process struct {
	Pid     uint32 // Always present
	Proc    Proc   // Only meaningful if Proc.Valid (QUARK_F_PROC)
	Exit    Exit   // Only meaningful if Exit.Valid (QUARK_F_EXIT)
	Comm    string
	Exe     string
	Cmdline []string
	Cwd     string
	Cgroup  string
}

// Socket represents a connection between two endpoints
type Socket struct {
	Local           netip.AddrPort
	Remote          netip.AddrPort
	PidOrigin       uint32
	PidLastUse      uint32
	EstablishedTime uint64
	CloseTime       uint64
	BytesSent       uint64
	BytesReceived   uint64
}

type Packet struct {
	Direction int
	Origin    int
	OrigLen   int
}

type File struct {
	Path      string
	OldPath   string
	SymTarget string
	Inode     uint64
	Atime     uint64
	Mtime     uint64
	Ctime     uint64
	Size      uint64
	Mode      uint32
	Uid       uint32
	Gid       uint32
	OpMask    uint32
}

type Ptrace struct {
	ChildPid uint32
	Request  int64
	Addr     uint64
	Data     uint64
}

type ModuleLoad struct {
	Name       string
	Version    string
	SrcVersion string
}

type ShmGet struct {
	Key    int64
	Size   uint64
	Shmflg int64
}

type MemFd struct {
	Flags uint32
	Path  string
	Kind  int
}

type ShmOpen struct {
	Path string
}

type Tty struct {
	Major     uint16
	Minor     uint16
	Cols      uint16
	Rows      uint16
	Cflag     uint32
	Iflag     uint32
	Lflag     uint32
	Oflag     uint32
	Truncated uint64
	Data      [][]byte
}

// Events is a bitmask of QUARK_EV_* and expresses what triggered this
// event, Process is the context of the Event.
type Event struct {
	Events     uint64
	Process    Process
	Socket     *Socket
	Packet     *Packet
	File       *File
	Ptrace     *Ptrace
	ModuleLoad *ModuleLoad
	Shm        *any // ShmGet, MemFd or ShmOpen
	Tty        *Tty
}

// Queue holds the state of a quark instance.
type Queue struct {
	quarkQueue *C.struct_quark_queue // pointer to the queue structure
	epollFd    int
}

const (
	// quark_queue_attr{} flags
	QQ_THREAD_EVENTS = int(C.QQ_THREAD_EVENTS)
	QQ_KPROBE        = int(C.QQ_KPROBE)
	QQ_EBPF          = int(C.QQ_EBPF)
	QQ_MIN_AGG       = int(C.QQ_MIN_AGG)
	QQ_ENTRY_LEADER  = int(C.QQ_ENTRY_LEADER)
	QQ_SOCK_CONN     = int(C.QQ_SOCK_CONN)
	QQ_DNS           = int(C.QQ_DNS)
	QQ_BYPASS        = int(C.QQ_BYPASS)
	QQ_FILE          = int(C.QQ_FILE)
	QQ_SHM           = int(C.QQ_SHM)
	QQ_TTY           = int(C.QQ_TTY)
	QQ_PTRACE        = int(C.QQ_PTRACE)
	QQ_MODULE_LOAD   = int(C.QQ_MODULE_LOAD)
	QQ_ALL_BACKENDS  = int(C.QQ_ALL_BACKENDS)

	// Event.events
	QUARK_EV_FORK             = uint64(C.QUARK_EV_FORK)
	QUARK_EV_EXEC             = uint64(C.QUARK_EV_EXEC)
	QUARK_EV_EXIT             = uint64(C.QUARK_EV_EXIT)
	QUARK_EV_SETPROCTITLE     = uint64(C.QUARK_EV_SETPROCTITLE)
	QUARK_EV_SOCK_CONN_CLOSED = uint64(C.QUARK_EV_SOCK_CONN_CLOSED)
	QUARK_EV_PACKET           = uint64(C.QUARK_EV_PACKET)
	QUARK_EV_BYPASS           = uint64(C.QUARK_EV_BYPASS)
	QUARK_EV_FILE             = uint64(C.QUARK_EV_FILE)
	QUARK_EV_PTRACE           = uint64(C.QUARK_EV_PTRACE)
	QUARK_EV_MODULE_LOAD      = uint64(C.QUARK_EV_MODULE_LOAD)
	QUARK_EV_SHM              = uint64(C.QUARK_EV_SHM)
	QUARK_EV_TTY              = uint64(C.QUARK_EV_TTY)

	// EntryLeaderType
	QUARK_ELT_UNKNOWN   = int(C.QUARK_ELT_UNKNOWN)
	QUARK_ELT_INIT      = int(C.QUARK_ELT_INIT)
	QUARK_ELT_KTHREAD   = int(C.QUARK_ELT_KTHREAD)
	QUARK_ELT_SSHD      = int(C.QUARK_ELT_SSHD)
	QUARK_ELT_SSM       = int(C.QUARK_ELT_SSM)
	QUARK_ELT_CONTAINER = int(C.QUARK_ELT_CONTAINER)
	QUARK_ELT_TERM      = int(C.QUARK_ELT_TERM)
	QUARK_ELT_CONSOLE   = int(C.QUARK_ELT_CONSOLE)

	// File.OpMask
	QUARK_FILE_OP_CREATE = uint32(C.QUARK_FILE_OP_CREATE)
	QUARK_FILE_OP_MODIFY = uint32(C.QUARK_FILE_OP_MODIFY)
	QUARK_FILE_OP_REMOVE = uint32(C.QUARK_FILE_OP_REMOVE)
	QUARK_FILE_OP_MOVE   = uint32(C.QUARK_FILE_OP_MOVE)

	// MemFd.Kind
	QUARK_SHM_MEMFD_CREATE = int(C.QUARK_SHM_MEMFD_CREATE)
	QUARK_SHM_MEMFD_OPEN   = int(C.QUARK_SHM_MEMFD_OPEN)

	// Packet.Direction
	QUARK_PACKET_DIR_INVALID = int(C.QUARK_PACKET_DIR_INVALID)
	QUARK_PACKET_DIR_EGRESS  = int(C.QUARK_PACKET_DIR_EGRESS)
	QUARK_PACKET_DIR_INGRESS = int(C.QUARK_PACKET_DIR_INGRESS)

	// Packet.Origin
	QUARK_PACKET_ORIGIN_INVALID = int(C.QUARK_PACKET_ORIGIN_INVALID)
	QUARK_PACKET_ORIGIN_DNS     = int(C.QUARK_PACKET_ORIGIN_DNS)
)

// QueueAttr defines the attributes for the Quark queue.
type QueueAttr struct {
	Flags          int
	MaxLength      int
	CacheGraceTime int
	HoldTime       int
}

// Documented in https://elastic.github.io/quark/quark_queue_get_stats.3.html.
type Stats struct {
	Insertions         uint64
	Removals           uint64
	Aggregations       uint64
	NonAggregations    uint64
	Lost               uint64
	GarbageCollections uint64
	Backend            int
}

const (
	QUARK_VL_SILENT = int(C.QUARK_VL_SILENT)
	QUARK_VL_WARN   = int(C.QUARK_VL_WARN)
	QUARK_VL_DEBUG  = int(C.QUARK_VL_DEBUG)
)

var ErrUndefined = errors.New("undefined")

func wrapErrno(err error) error {
	if err == nil {
		err = ErrUndefined
	}

	return err
}

// DefaultQueueAttr returns the default attributes for the queue.
func DefaultQueueAttr() QueueAttr {
	var attr C.struct_quark_queue_attr

	C.quark_queue_default_attr(&attr)

	return QueueAttr{
		Flags:          int(attr.flags),
		MaxLength:      int(attr.max_length),
		CacheGraceTime: int(attr.cache_grace_time),
		HoldTime:       int(attr.hold_time),
	}
}

// OpenQueue opens a Quark Queue with the given attributes.
func OpenQueue(attr QueueAttr) (*Queue, error) {
	var queue Queue
	var cattr C.struct_quark_queue_attr

	C.quark_queue_default_attr(&cattr)

	p, err := C.calloc(C.size_t(1), C.sizeof_struct_quark_queue)
	if p == nil {
		return nil, wrapErrno(err)
	}
	queue.quarkQueue = (*C.struct_quark_queue)(p)

	cattr.flags = C.int(attr.Flags)
	cattr.max_length = C.int(attr.MaxLength)
	cattr.cache_grace_time = C.int(attr.CacheGraceTime)
	cattr.hold_time = C.int(attr.HoldTime)
	ok, err := C.quark_queue_open(queue.quarkQueue, &cattr)
	if ok == -1 {
		C.free(unsafe.Pointer(queue.quarkQueue))
		return nil, wrapErrno(err)
	}

	queue.epollFd = int(C.quark_queue_get_epollfd(queue.quarkQueue))

	return &queue, nil
}

// Close closes the queue.
func (queue *Queue) Close() {
	C.quark_queue_close(queue.quarkQueue)
	C.free(unsafe.Pointer(queue.quarkQueue))
	queue.quarkQueue = nil
}

func (queue *Queue) GetEvent() (Event, bool) {
	var event Event

	cev := C.quark_queue_get_event(queue.quarkQueue)
	if cev == nil || cev.process == nil {
		return event, false
	}

	event.Events = uint64(cev.events)
	event.Process = processFromC(cev.process)
	if cev.socket != nil {
		socket := socketFromC(cev.socket)
		event.Socket = &socket
	}
	if cev.file != nil {
		file := fileFromC(cev.file)
		event.File = &file
	}
	if event.Events&QUARK_EV_PTRACE != 0 {
		ptrace := ptraceFromC(&cev.ptrace)
		event.Ptrace = &ptrace
	}
	if cev.module_load != nil {
		ml := moduleLoadFromC(cev.module_load)
		event.ModuleLoad = &ml
	}
	if cev.shm != nil {
		shm, err := shmFromC(cev.shm)
		if err != nil {
			return event, false
		}
		event.Shm = &shm
	}
	if cev.tty != nil {
		tty := ttyFromC(cev.tty)
		event.Tty = &tty
	}

	return event, true
}

func (queue *Queue) GetEventAsECS() ([]byte, bool, error) {
	var ecsBuf *C.char
	var ecsLen C.size_t

	r := C.get_event_as_ecs(queue.quarkQueue, &ecsBuf, &ecsLen)

	if r == -1 {
		return nil, false, fmt.Errorf("can't make ecs")
	} else if ecsBuf == nil {
		return nil, false, nil
	}

	b := C.GoBytes(unsafe.Pointer(ecsBuf), C.int(ecsLen))
	C.free(unsafe.Pointer(ecsBuf))

	return b, true, nil
}

// Lookup looks up for the Process associated with PID in quark's internal cache.
func (queue *Queue) Lookup(pid int) (Process, bool) {
	process, _ := C.quark_process_lookup(queue.quarkQueue, C.int(pid))

	if process == nil {
		return Process{}, false
	}

	return processFromC(process), true
}

// Block blocks until there are events or an undefined timeout
// expires. GetEvent should be called once Block returns.
func (queue *Queue) Block() error {
	event := make([]syscall.EpollEvent, 1)
	_, err := syscall.EpollWait(queue.epollFd, event, 100)
	if err != nil && errors.Is(err, syscall.EINTR) {
		err = nil
	}
	return err
}

// Snapshot returns a snapshot of all processes in the cache.
func (queue *Queue) Snapshot() []Process {
	var processes []Process
	var iter C.struct_quark_process_iter
	var qp *C.struct_quark_process

	C.quark_process_iter_init(&iter, queue.quarkQueue)
	for qp = C.quark_process_iter_next(&iter); qp != nil; qp = C.quark_process_iter_next(&iter) {
		processes = append(processes, processFromC(qp))
	}

	return processes
}

// Stats returns statistics of an active queue.
func (queue *Queue) Stats() Stats {
	var stats Stats
	var cStats C.struct_quark_queue_stats

	C.quark_queue_get_stats(queue.quarkQueue, &cStats)
	stats.Insertions = uint64(cStats.insertions)
	stats.Removals = uint64(cStats.removals)
	stats.Aggregations = uint64(cStats.aggregations)
	stats.NonAggregations = uint64(cStats.non_aggregations)
	stats.Lost = uint64(cStats.lost)
	stats.GarbageCollections = uint64(cStats.garbage_collections)
	stats.Backend = int(cStats.backend)

	return stats
}

// Sets quark verbosity globally, not per queue.
func SetVerbose(level int) {
	C.quark_verbose = C.int(level)
}

// processFromC converts the C process structure to a go process.
func processFromC(cProcess *C.struct_quark_process) Process {
	var process Process

	if cProcess == nil {
		return Process{}
	}

	process.Pid = uint32(cProcess.pid)
	if cProcess.flags&C.QUARK_F_PROC != 0 {
		process.Proc = Proc{
			CapInheritable:  uint64(cProcess.proc_cap_inheritable),
			CapPermitted:    uint64(cProcess.proc_cap_permitted),
			CapEffective:    uint64(cProcess.proc_cap_effective),
			CapBset:         uint64(cProcess.proc_cap_bset),
			CapAmbient:      uint64(cProcess.proc_cap_ambient),
			TimeBoot:        uint64(cProcess.proc_time_boot),
			Ppid:            uint32(cProcess.proc_ppid),
			Uid:             uint32(cProcess.proc_uid),
			Gid:             uint32(cProcess.proc_gid),
			Suid:            uint32(cProcess.proc_suid),
			Sgid:            uint32(cProcess.proc_sgid),
			Euid:            uint32(cProcess.proc_euid),
			Egid:            uint32(cProcess.proc_egid),
			Pgid:            uint32(cProcess.proc_pgid),
			Sid:             uint32(cProcess.proc_sid),
			EntryLeader:     uint32(cProcess.proc_entry_leader),
			EntryLeaderType: uint32(cProcess.proc_entry_leader_type),
			TtyMajor:        uint32(cProcess.proc_tty_major),
			TtyMinor:        uint32(cProcess.proc_tty_minor),
			UtsInonum:       uint32(cProcess.proc_uts_inonum),
			IpcInonum:       uint32(cProcess.proc_ipc_inonum),
			MntInonum:       uint32(cProcess.proc_mnt_inonum),
			NetInonum:       uint32(cProcess.proc_net_inonum),
			Valid:           true,
		}
	}
	if cProcess.flags&C.QUARK_F_EXIT != 0 {
		process.Exit = Exit{
			ExitCode:        int32(cProcess.exit_code),
			ExitTimeProcess: uint64(cProcess.exit_time_event),
			Valid:           true,
		}
	}
	process.Comm = C.GoString(&cProcess.comm[0])
	if cProcess.exe != nil {
		process.Exe = C.GoString(cProcess.exe)
	}
	if cProcess.cmdline != nil && cProcess.cmdline_len > 0 {
		b := C.GoBytes(unsafe.Pointer(cProcess.cmdline), C.int(cProcess.cmdline_len))
		nul := string(byte(0))
		b = bytes.TrimRight(b, nul)
		process.Cmdline = strings.Split(string(b), nul)
	}
	if cProcess.cwd != nil {
		process.Cwd = C.GoString(cProcess.cwd)
	}
	if cProcess.cgroup != nil {
		process.Cgroup = C.GoString(cProcess.cgroup)
	}

	return process
}

func addrPortFromQuarkSockaddr(csa *C.struct_quark_sockaddr) netip.AddrPort {
	var addr netip.Addr

	if csa.af == C.AF_INET {
		var addr4 [4]byte

		addr4[0] = csa.u[0]
		addr4[1] = csa.u[1]
		addr4[2] = csa.u[2]
		addr4[3] = csa.u[3]
		addr = netip.AddrFrom4(addr4)
	} else if csa.af == C.AF_INET6 {
		addr = netip.AddrFrom16(csa.u)
	}

	port := uint16(csa.port)>>8 | uint16(csa.port)<<8

	return netip.AddrPortFrom(addr, port)
}

func socketFromC(cSocket *C.struct_quark_socket) Socket {
	var socket Socket

	socket.Local = addrPortFromQuarkSockaddr(&cSocket.local)
	socket.Remote = addrPortFromQuarkSockaddr(&cSocket.remote)
	socket.PidOrigin = uint32(cSocket.pid_origin)
	socket.PidLastUse = uint32(cSocket.pid_last_use)
	socket.EstablishedTime = uint64(cSocket.established_time)
	socket.CloseTime = uint64(cSocket.close_time)
	socket.BytesSent = uint64(cSocket.bytes_sent)
	socket.BytesReceived = uint64(cSocket.bytes_received)

	return socket
}

func packetFromC(cPacket *C.struct_quark_packet) Packet {
	var packet Packet

	packet.Direction = int(cPacket.direction)
	packet.Origin = int(cPacket.origin)
	packet.OrigLen = int(cPacket.orig_len)

	return packet
}

func fileFromC(cFile *C.struct_quark_file) File {
	var file File

	file.Path = C.GoString(cFile.path)
	file.OldPath = C.GoString(cFile.old_path)
	file.SymTarget = C.GoString(cFile.sym_target)
	file.Inode = uint64(cFile.inode)
	file.Atime = uint64(cFile.atime)
	file.Mtime = uint64(cFile.mtime)
	file.Ctime = uint64(cFile.ctime)
	file.Size = uint64(cFile.size)
	file.Mode = uint32(cFile.mode)
	file.Uid = uint32(cFile.uid)
	file.Gid = uint32(cFile.gid)
	file.OpMask = uint32(cFile.op_mask)

	return file
}

func ptraceFromC(cPtrace *C.struct_quark_ptrace) Ptrace {
	var ptrace Ptrace

	ptrace.ChildPid = uint32(cPtrace.child_pid)
	ptrace.Request = int64(cPtrace.request)
	ptrace.Addr = uint64(cPtrace.addr)
	ptrace.Data = uint64(cPtrace.data)

	return ptrace
}

func moduleLoadFromC(cM *C.struct_quark_module_load) ModuleLoad {
	var ml ModuleLoad

	ml.Name = C.GoString(cM.name)
	ml.Version = C.GoString(cM.version)
	ml.SrcVersion = C.GoString(cM.src_version)

	return ml
}

func shmFromC(cShm *C.struct_quark_shm) (any, error) {
	switch cShm.kind {
	case C.QUARK_SHM_SHMGET:
		var shmget ShmGet

		shmget.Key = int64(cShm.shmget_key)
		shmget.Shmflg = int64(cShm.shmget_shmflg)
		shmget.Size = uint64(cShm.shmget_size)

		return shmget, nil
	case C.QUARK_SHM_SHM_OPEN:
		var shmopen ShmOpen

		shmopen.Path = C.GoString(cShm.path)

		return shmopen, nil
	case C.QUARK_SHM_MEMFD_CREATE:
		fallthrough
	case C.QUARK_SHM_MEMFD_OPEN:
		var memfd MemFd

		memfd.Flags = uint32(cShm.memfd_create_flags)
		memfd.Kind = int(cShm.kind)
		memfd.Path = C.GoString(cShm.path)

		return memfd, nil
	}

	return nil, fmt.Errorf("invalid shm kind")
}

func ttyFromC(cTty *C.struct_quark_tty) Tty {
	var tty Tty
	var t *C.struct_quark_tty

	tty.Major = uint16(cTty.major)
	tty.Minor = uint16(cTty.minor)
	tty.Cols = uint16(cTty.cols)
	tty.Rows = uint16(cTty.rows)
	tty.Cflag = uint32(cTty.cflag)
	tty.Iflag = uint32(cTty.iflag)
	tty.Lflag = uint32(cTty.lflag)
	tty.Oflag = uint32(cTty.oflag)
	tty.Truncated = uint64(cTty.truncated)

	for t = cTty; t != nil; t = t.next {
		data := unsafe.Pointer(uintptr(unsafe.Pointer(t)) + unsafe.Sizeof(*t))
		chunk := C.GoBytes(data, C.int(t.data_len))
		tty.Data = append(tty.Data, chunk)
	}

	return tty
}
