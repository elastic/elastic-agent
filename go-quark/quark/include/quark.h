/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2024-2026 Elastic NV */

#ifndef _QUARK_H_
#define _QUARK_H_

/* Version is shared between library and utilities */
#define QUARK_VERSION "0.7a"

/* Misc types */
#include <sys/socket.h>

#include <netinet/in.h>

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>

/* Compat, tree.h, queue.h */
#include "compat.h"

/* Shared quark_rule definitions are in nova.h */
#include "nova.h"

/* Misc */
#ifndef ALIGN_UP
#define ALIGN_UP(_p, _b) (((u64)(_p) + ((_b) - 1)) & ~((_b) - 1))
#endif

/* Temporary until we have proper env debugging */
extern int	quark_verbose;

/* quark.c */
struct raw_event;
struct quark_event;
struct quark_process;
struct quark_process_iter;
struct quark_cmdline_iter;
struct quark_socket;
struct quark_socket_iter;
struct quark_sockaddr;
struct quark_queue;
struct quark_queue_attr;
struct quark_queue_stats;
struct quark_ruleset;
struct quark_rule;
struct quark_rule_field;
typedef int (*quark_can_aggregate_fn)(struct quark_queue *,
    struct raw_event *, struct raw_event *);
struct raw_event	*raw_event_alloc(int);
void			 raw_event_free(struct raw_event *);
int			 raw_event_insert(struct quark_queue *,
			     struct raw_event *);
void			 quark_queue_default_attr(struct quark_queue_attr *);
int			 quark_queue_open(struct quark_queue *,
			     struct quark_queue_attr *);
void			 quark_queue_close(struct quark_queue *);
int			 quark_queue_populate(struct quark_queue *);
int			 quark_queue_block(struct quark_queue *);
const struct quark_event *quark_queue_get_event(struct quark_queue *);
int			 quark_queue_get_epollfd(struct quark_queue *);
void			 quark_queue_get_stats(struct quark_queue *,
			     struct quark_queue_stats *);
int			 quark_start_kube_talker(const char *, pid_t *);
int			 quark_dump_process_cache_graph(struct quark_queue *,
			     FILE *);
int			 quark_dump_raw_event_graph(struct quark_queue *,
			     FILE *, FILE *);
int			 quark_event_dump(const struct quark_event *, FILE *);
void			 quark_process_iter_init(struct quark_process_iter *,
			     struct quark_queue *);
const struct quark_process *quark_process_iter_next(struct quark_process_iter *);
const struct quark_process *quark_process_lookup(struct quark_queue *, int);
void			 quark_cmdline_iter_init(struct quark_cmdline_iter *,
			     const char *, size_t);
const char		*quark_cmdline_iter_next(struct quark_cmdline_iter *);
void			 quark_socket_iter_init(struct quark_socket_iter *,
			     struct quark_queue *);
const struct quark_socket *quark_socket_iter_next(struct quark_socket_iter *);
const struct quark_socket *quark_socket_lookup(struct quark_queue *,
			     struct quark_sockaddr *, struct quark_sockaddr *);
struct quark_passwd	*quark_passwd_lookup(struct quark_queue *, uid_t);
struct quark_group	*quark_group_lookup(struct quark_queue *, gid_t);
void			 quark_ruleset_init(struct quark_ruleset *);
void			 quark_ruleset_clear(struct quark_ruleset *);
int			 quark_ruleset_parse(struct quark_ruleset *, FILE *,
			     char *, size_t);
struct quark_rule	*quark_ruleset_append_rule(struct quark_ruleset *,
			     int, u64);
int			 quark_rule_match_field(struct quark_rule *,
			     struct quark_rule_field);
struct quark_rule	*quark_ruleset_match(struct quark_ruleset *,
			     struct quark_event *);
int			 quark_queue_set_agg_matrix(struct quark_queue *,
			     int, int, quark_can_aggregate_fn);
/* Can aggregate only one value (sits alone) */
int			 quark_can_aggregate_single(struct quark_queue *,
			     struct raw_event *, struct raw_event *);
/* Can aggregate multiple values (keeps the last one) */
int			 quark_can_aggregate_mult(struct quark_queue *,
			     struct raw_event *, struct raw_event *);
/* Default aggregation for fork+exec events */
int			 quark_can_aggregate_fork_exec(struct quark_queue *,
			     struct raw_event *, struct raw_event *);
/* Default aggregation for file events */
int			 quark_can_aggregate_file(struct quark_queue *,
			     struct raw_event *, struct raw_event *);
/* Default aggregation for tty events */
int			 quark_can_aggregate_tty(struct quark_queue *,
			     struct raw_event *, struct raw_event *);

/* quark.c: These are exported for testing only */
int	 parse_container_cgroup(const char *, char *, size_t);

/* btf.c */
struct quark_btf_target {
	const char	*dotname;
	ssize_t		 offset; /* in bytes, not bits */
};

struct quark_btf {
	char			*kname;
	struct quark_btf_target	 targets[];
};
struct quark_btf	*quark_btf_open(void);
struct quark_btf	*quark_btf_open2(const char *, const char *);
struct quark_btf	*quark_btf_open_hub(const char *);
void			 quark_btf_close(struct quark_btf *);
ssize_t			 quark_btf_offset(struct quark_btf *, const char *);

struct btf;
s32			btf_root_offset(struct btf *, const char *, int);
int			btf_number_of_params(struct btf *, const char *);
int			btf_number_of_params_of_ptr(struct btf *,
			    const char *, const char *);
int			btf_index_of_param(struct btf *, const char *,
			    const char *);

/* bpf_queue.c */
int			 bpf_queue_open(struct quark_queue *);
struct bpf_probes	*quark_get_bpf_probes(struct quark_queue *);
int			 quark_queue_trusted_pid_add(struct quark_queue *, u32);
int			 quark_queue_trusted_pid_reset(struct quark_queue *);

/* kprobe_queue.c */
int			 kprobe_queue_open(struct quark_queue *);

/* nova_queue.c */
int			 nova_queue_open(struct quark_queue *);

ssize_t		 qread(int, void *, size_t);
int		 qwrite(int, const void *, size_t);
ssize_t		 qreadlinkat(int, const char *, char *, size_t);
int		 qclosefrom(int, int);
int		 isnumber(const char *);
ssize_t		 readlineat(int, const char *, char *, size_t);
int		 strtou64(u64 *, const char *, int);
char		*find_line(FILE *, const char *);
char		*find_line_p(const char *, const char *);
char		*load_file_nostat(int, size_t *);
char		*load_file_path_nostat(const char *, size_t *);
int		 ipv6_supported(void);
const char	*safe_basename(const char *);
u64		 fetch_boottime(void);
void		 setup_libbpf_logs(void);

enum quark_verbosity_levels {
	QUARK_VL_SILENT,
	QUARK_VL_WARN,
	QUARK_VL_DEBUG,
};

#define	 qlog(pri, do_errno, fmt, ...)					\
	qlog_func(pri, do_errno, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define	 qlogx(pri, do_errno, fmt, ...)					\
	qlog_func(pri, do_errno, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define	 qwarn(fmt, ...) qlog(QUARK_VL_WARN, 1, fmt, ##__VA_ARGS__)
#define	 qwarnx(fmt, ...) qlog(QUARK_VL_WARN, 0, fmt, ##__VA_ARGS__)
#define	 qdebug(fmt, ...) qlog(QUARK_VL_DEBUG, 1, fmt, ##__VA_ARGS__)
#define	 qdebugx(fmt, ...) qlog(QUARK_VL_DEBUG, 0, fmt, ##__VA_ARGS__)
void	 qlog_func(int, int, const char *, int, const char *, ...)
	     __attribute__((format(printf, 5,6)));

/* hanson.c */
struct hanson;
int	 hanson_add_ascii(struct hanson *, char);
int	 hanson_add_escaped(struct hanson *, const char *);
int	 hanson_add_string(struct hanson *, const char *, int *);
int	 hanson_add_integer(struct hanson *, int64_t, int *);
int	 hanson_add_boolean(struct hanson *h, int, int *);
int	 hanson_add_key_value(struct hanson *, const char *, const char *, int *);
int	 hanson_add_key_value_int(struct hanson *, const char *, int64_t, int *);
int	 hanson_add_key_value_bool(struct hanson *, const char *, int, int *);
int	 hanson_add_array(struct hanson *, const char *, int *);
int	 hanson_close_array(struct hanson *);
int	 hanson_add_object(struct hanson *, const char *, int *);
int	 hanson_close_object(struct hanson *);
int	 hanson_open(struct hanson *);
int	 hanson_close(struct hanson *, char **, size_t *);

struct hanson {
	int	 error;
	char	*buf;
	char	*buf_w;
	size_t	 buf_len;
};

/* ecs.c */
int	quark_event_to_ecs(struct quark_queue *qq,
	    const struct quark_event *qev, char **, size_t *);

/*
 * Time helpers
 */
#ifndef NS_PER_S
#define NS_PER_S	1000000000ULL
#endif /* NS_PER_S */

#ifndef NS_PER_MS
#define NS_PER_MS	1000000ULL
#endif /* NS_PER_MS */

#ifndef MS_TO_NS
#define MS_TO_NS(_x)	((u64)(_x) * NS_PER_MS)
#endif /* MS_TO_NS */

#ifndef NS_TO_S
#define NS_TO_S(_x)	((u64)(_x) / NS_PER_S)
#endif /* NS_TO_S */

/*
 * Generic exported constants
 */
#define QUARK_MAX_PACKET	2048

/*
 * Raw events
 */
enum raw_types {
	RAW_INVALID,
	RAW_EXEC,
	RAW_WAKE_UP_NEW_TASK,
	RAW_EXIT_THREAD,
	RAW_ID_CHANGE,
	RAW_COMM,
	RAW_EXEC_CONNECTOR,
	RAW_SOCK_CONN,
	RAW_PACKET,
	RAW_FILE,
	RAW_PTRACE,
	RAW_MODULE_LOAD,
	RAW_SHM,
	RAW_TTY,
	RAW_GETPID,
	RAW_NUM_TYPES		/* must be last */
};

struct raw_comm {
	char	comm[16];
};

struct raw_task {
	u64	 cap_inheritable;
	u64	 cap_permitted;
	u64	 cap_effective;
	u64	 cap_bset;
	u64	 cap_ambient;
	u64	 start_boottime;
	u32	 uid;
	u32	 gid;
	u32	 suid;
	u32	 sgid;
	u32	 euid;
	u32	 egid;
	u32	 pgid;
	u32	 sid;
	u32	 ppid;
	s32	 exit_code;		/* only available at exit */
	u64	 exit_time_event;	/* only available at exit */
	u32	 tty_major;
	u32	 tty_minor;
	u32	 uts_inonum;
	u32	 ipc_inonum;
	u32	 mnt_inonum;
	u32	 net_inonum;
	char	*cwd;
	char	*cgroup;
	char	 comm[16];
	char	*env;
	size_t	 env_len;
	u32	 id_change;
};

struct raw_exec {
#define RAW_EXEC_F_EXT	(1 << 0)
	int		 flags;
	char		*filename;

	/* available if RAW_EXEC_F_EXT */
	struct {
		char		*args;
		size_t		 args_len;
		struct raw_task	 task;
	} ext;
};

struct raw_exec_connector {
	char		*args;
	size_t		 args_len;
	struct raw_task	 task;
};

/* not like sockaddr{}, we won't use this on sockets anyway */
struct quark_sockaddr {
	int	af;

	union {
		u32	addr4;
		u8	addr6[16];
	} u;

	u16	port;
};

enum sock_conn {
	SOCK_CONN_INVALID,
	SOCK_CONN_CLOSE,
	SOCK_CONN_ACCEPT,
	SOCK_CONN_CONNECT,
	SOCK_CONN_SCRAPE,
};

struct raw_sock_conn {
	struct quark_sockaddr	local;
	struct quark_sockaddr	remote;
	enum sock_conn		conn;
	u64	bytes_received;
	u64	bytes_sent;
};

enum quark_packet_direction {
	QUARK_PACKET_DIR_INVALID,
	QUARK_PACKET_DIR_EGRESS,
	QUARK_PACKET_DIR_INGRESS,
};

enum quark_packet_origin {
	QUARK_PACKET_ORIGIN_INVALID,
	QUARK_PACKET_ORIGIN_DNS,
};

struct quark_packet {
	enum quark_packet_direction	direction;
	enum quark_packet_origin	origin;
	size_t				orig_len;
	size_t				cap_len;
	char				data[];
};

struct raw_packet {
	struct quark_packet	*quark_packet;
};

#define QUARK_FILE_OP_CREATE	(1 << 0)
#define QUARK_FILE_OP_MODIFY	(1 << 1)
#define QUARK_FILE_OP_REMOVE	(1 << 2)
#define QUARK_FILE_OP_MOVE	(1 << 3)

struct quark_file {
	const char	*path;		/* points to storage + 0 */
	const char	*old_path;	/* NULL or points to storage + strlen(path) */
	const char	*sym_target;	/* NULL or points to storage + strlen(path) + strlen(old_path) */
	u64		 inode;		/* as stat.st_inode */
	u64		 atime;
	u64		 mtime;
	u64		 ctime;
	u64		 size;
	u32		 mode;		/* as stat.st_mode */
	u32		 uid;
	u32		 gid;
	u32		 op_mask;	/* mask of QUARK_FILE_OP_* */
	char		 storage[];	/* paths point here */
};

struct raw_file {
	struct quark_file	*quark_file;
};

struct quark_ptrace {
	u32	child_pid;
	s64	request;
	u64	addr;
	u64	data;
};

struct raw_ptrace {
	struct quark_ptrace quark_ptrace;
};

struct quark_module_load {
	char *name;
	char *version;
	char *src_version;
};

struct raw_module_load {
	struct quark_module_load	*quark_module_load;
};

enum shm_kind {
	QUARK_SHM_INVALID,
	QUARK_SHM_SHMGET,	/* sysv shmget */
	QUARK_SHM_SHM_OPEN,	/* posix shared memory */
	QUARK_SHM_MEMFD_CREATE,	/* linux's memfd */
	QUARK_SHM_MEMFD_OPEN,	/* an open(2) on a memfd descriptor */
};

struct quark_shm {
	enum shm_kind	 kind;
	s64		 shmget_key;		/* QUARK_SHM_SHMGET */
	u64		 shmget_size;		/* QUARK_SHM_SHMGET */
	s64		 shmget_shmflg;		/* QUARK_SHM_SHMGET */
	u32		 memfd_create_flags;	/* QUARK_SHM_MEMFD_CREATE */
	char		*path;			/* NULL for QUARK_SHM_SHMGET */
};

struct raw_shm {
	struct quark_shm	*quark_shm;
};

struct quark_tty {
	struct quark_tty	*next;
	size_t			 total_len;	/* total bytes in the agg chain: next */
	u16			 major;
	u16			 minor;
	u16			 cols;
	u16			 rows;
	u32			 cflag;
	u32			 iflag;
	u32			 lflag;
	u32			 oflag;
	size_t			 truncated;	/* how many bytes were truncated (lost) */
	size_t			 data_len;
	char			 data[];
};

struct raw_tty {
	struct quark_tty	*quark_tty;
};

struct raw_event {
	RB_ENTRY(raw_event)			entry_by_time;
	RB_ENTRY(raw_event)			entry_by_pidtime;
	TAILQ_HEAD(agg_queue, raw_event)	agg_queue;
	TAILQ_ENTRY(raw_event)			agg_entry;
	u32					opid;
	u32					pid;
	u32					tid;
	u32					cpu;
	u64					time;
	int					type;
	union {
		struct raw_exec			exec;
		struct raw_comm			comm;
		struct raw_task			task;
		struct raw_exec_connector	exec_connector;
		struct raw_sock_conn		sock_conn;
		struct raw_packet		packet;
		struct raw_file			file;
		struct raw_ptrace		ptrace;
		struct raw_module_load		module_load;
		struct raw_shm			shm;
		struct raw_tty			tty;
	};
};

/*
 * Raw Event Tree by time, where RB_MIN() is the oldest element in the tree, no
 * clustering of pids so we can easily get the oldest event.
 */
RB_HEAD(raw_event_by_time, raw_event);

/*
 * Raw Event Tree by pid and time, this creates clusters of the same pid which
 * are then organized by time, this is used in assembly and aggregation, if we
 * used the 'by_time' tree, we would have to traverse the full tree in case of a
 * miss.
 */
RB_HEAD(raw_event_by_pidtime, raw_event);

struct quark_event {
#define QUARK_EV_FORK			(1 << 0)
#define QUARK_EV_EXEC			(1 << 1)
#define QUARK_EV_EXIT			(1 << 2)
#define QUARK_EV_ID_CHANGE		(1 << 3)
#define QUARK_EV_SETPROCTITLE		(1 << 4)
#define QUARK_EV_SOCK_CONN_ESTABLISHED	(1 << 5)
#define QUARK_EV_SOCK_CONN_CLOSED	(1 << 6)
#define QUARK_EV_PACKET			(1 << 7)
#define QUARK_EV_BYPASS			(1 << 8)
#define QUARK_EV_FILE			(1 << 9)
#define QUARK_EV_PTRACE			(1 << 10)
#define QUARK_EV_MODULE_LOAD		(1 << 11)
#define QUARK_EV_SHM			(1 << 12)
#define QUARK_EV_TTY			(1 << 13)
#define QUARK_EV_GETPID			(1 << 14)
	u64				 events;
	u64				 time;
	const struct quark_process	*process;
	const struct quark_socket	*socket;
	struct quark_packet		*packet;
	const void			*bypass;
	struct quark_file		*file;
	struct quark_ptrace		 ptrace;
	struct quark_module_load	*module_load;
	struct quark_shm		*shm;
	struct quark_tty		*tty;
#define QUARK_ID_CHANGE_SETSID		(1 << 0)
#define QUARK_ID_CHANGE_SETUID		(1 << 1)
#define QUARK_ID_CHANGE_SETGID		(1 << 2)
	u32				 id_change;
};

/*
 * Process cache, used to enrich single events
 */
RB_HEAD(process_by_pid, quark_process);

/*
 * Socket tree, indexed by src and dst
 */
RB_HEAD(socket_by_src_dst, quark_socket);

enum {
	QUARK_TTY_UNKNOWN,
	QUARK_TTY_PTS,
	QUARK_TTY_TTY,
	QUARK_TTY_CONSOLE,
};

/*
 * The values for proc_entry_leader_type
 */
enum {
	QUARK_ELT_UNKNOWN,
	QUARK_ELT_INIT,
	QUARK_ELT_KTHREAD,
	QUARK_ELT_SSHD,
	QUARK_ELT_SSM,
	QUARK_ELT_CONTAINER,
	QUARK_ELT_TERM,
	QUARK_ELT_CONSOLE,
};

enum gc_type {
	GC_INVALID,
	GC_PROCESS,
	GC_SOCKET,
	GC_POD,
};

struct gc_link {
	TAILQ_ENTRY(gc_link)	gc_entry;
	u64			gc_time;
	enum gc_type		gc_type;
};

/*
 * gc queue, after processes or sockets are are marked for deletion, they still
 * get a grace time of qq->cache_grace_time before removal, this is to allow
 * lookups from users on processes and sockets that have just vanished.
 */
TAILQ_HEAD(gc_queue, gc_link);

/*
 * Main external working set, user passes this back and forth, members only have
 * a meaning if its respective flag is set, say proc_cap_inheritable should only
 * be meaningful if flags & QUARK_F_PROC.
 */

struct quark_process {
	struct gc_link			gc;		/* must be first */
	RB_ENTRY(quark_process)		entry_by_pid;
	TAILQ_ENTRY(quark_process)	entry_container;
	/* Always present */
	u32	 pid;

#define QUARK_F_PROC		(1 << 0)
#define QUARK_F_EXIT		(1 << 1)
	u64	 flags;

	u64	 poison_tag;	/* valid if != 0 */

	/* QUARK_F_PROC */
	u64	 proc_cap_inheritable;
	u64	 proc_cap_permitted;
	u64	 proc_cap_effective;
	u64	 proc_cap_bset;
	u64	 proc_cap_ambient;
	u64	 proc_time_boot;
	u32	 proc_ppid;
	u32	 proc_uid;
	u32	 proc_gid;
	u32	 proc_suid;
	u32	 proc_sgid;
	u32	 proc_euid;
	u32	 proc_egid;
	u32	 proc_pgid;
	u32	 proc_sid;
	u32	 proc_tty_major;
	u32	 proc_tty_minor;
	u32	 proc_entry_leader_type;
	u32	 proc_entry_leader;
	u32	 proc_uts_inonum;
	u32	 proc_ipc_inonum;
	u32	 proc_mnt_inonum;
	u32	 proc_net_inonum;
	char	 proc_entity_id[17];	/* Source is base64(96bits), which is 16bytes + NUL */
	/* QUARK_F_EXIT */
	s32	 exit_code;
	u64	 exit_time_event;
	char	 comm[16];
	char	*exe;
	size_t	 cmdline_len;
	char	*cmdline;
	char	*cwd;
	char	*cgroup;
	struct quark_container *container;
	char	*env;
	size_t	 env_len;
};

struct quark_process_iter {
	struct quark_queue	*qq;
	struct quark_process	*qp;
};

struct quark_cmdline_iter {
	const char	*cmdline;
	size_t		 cmdline_len;
	size_t		 off;
};

struct quark_socket {
	struct gc_link		gc;			/* must be first */
	RB_ENTRY(quark_socket)	entry_by_src_dst;
	struct quark_sockaddr	local;
	struct quark_sockaddr	remote;
	u32			pid_origin;
	u32			pid_last_use;
	u64			established_time;
	u64			close_time;
	enum sock_conn		conn_origin;
	u64			bytes_received;
	u64			bytes_sent;
};

struct quark_socket_iter {
	struct quark_queue	*qq;
	struct quark_socket	*qsk;
};

/*
 * A label node
 */
struct label_node {
	RB_ENTRY(label_node)	 entry;
	char			*key;
	char			*value;
	int			 seen;
};

RB_HEAD(label_tree, label_node);
RB_PROTOTYPE(label_tree, label_node, entry, label_node_cmp);

/*
 * A container's lifecycle is tied to its parent quark_pod.
 */
struct quark_container {
	RB_ENTRY(quark_container)	 entry_qkube;	/* our ""global"" linkage */
	RB_ENTRY(quark_container)	 entry_pod;	/* our linkage inside a quark_pod */
	TAILQ_HEAD(, quark_process)	 processes;	/* processes in this container */
	int				 linked_by_id;	/* linked in container_id tree */
	int				 linked_by_pod;	/* linked in pod tree */
	char				*container_id;	/* unique id */
	struct quark_pod		*pod;		/* backpointer to owner */
	char				*name;
	char				*image;
	char				*image_id;
	char				*image_name;
	char				*image_tag;
	char				*image_hash;
};

/*
 * A quark_pod holds multiple containters in pod_containters.
 * The same containers are also linked in containters_by_id inside quark_kube.
 * This is to allow a search by container_id, which then can follow the pod
 * backpointer, to finally find the pod of a containter_id.
 */
RB_HEAD(pod_containers, quark_container);
RB_HEAD(container_by_id, quark_container);

struct quark_pod {
	struct gc_link		 gc;		/* must be first */
	RB_ENTRY(quark_pod)	 entry_by_uid;
	int			 linked;	/* true if entry_by_uid is linked */
	char			*name;
	char			*ns;
	char			*uid;
	struct quark_sockaddr	 addr4;
	char			 addr4_a[INET6_ADDRSTRLEN];
	struct quark_sockaddr	 addr6;
	char			 addr6_a[INET6_ADDRSTRLEN];
	struct label_tree	 labels;
	struct pod_containers	 containers;
	char			*phase;
};

/*
 * A quark_pod indexed by uid, this is the main data structure for quark_kube{}.
 */
RB_HEAD(pod_by_uid, quark_pod);

struct quark_kube_node {
	char	*name;
	char	*uid;
	char	*zone;			/* might be NULL */
	char	*region;		/* might be NULL */
	char	*provider;		/* might be NULL */
	char	*project;		/* might be NULL */
	char	*project_id;		/* might be NULL */
	char	*cluster_name;		/* might be NULL */
	char	*cluster_uid;		/* might be NULL */
	char	*cluster_version;	/* might be NULL */
};

/*
 * The state for all kubernetes metadata.
 */
struct quark_kube {
	int			 fd;			/* input pipe for json data */
	int			 try_read;		/* should we try to read from fd */
	u64			 last_read;		/* last time in ns we read */
	char			*buf;			/* buffer for cJSON */
	size_t			 buf_w;			/* write pointer */
	size_t			 buf_r;			/* read pointer */
	size_t			 buf_len;		/* total length */
	struct quark_kube_node	 node;			/* node we're running on */
	struct pod_by_uid	 pod_by_uid;		/* uid comes from json */
};

/*
 * Passwd database, can't afford to go through glibc in the hotpath
 */
RB_HEAD(passwd_by_uid, quark_passwd);

struct quark_passwd {
	RB_ENTRY(quark_passwd)	 entry;
	uid_t			 uid;
	gid_t			 gid;
	char			*name;
};

/*
 * Group database, can't afford to go through glibc in the hotpath
 */
RB_HEAD(group_by_gid, quark_group);

struct quark_group {
	RB_ENTRY(quark_group)	 entry;
	gid_t			 gid;
	char			*name;
};

/*
 * post points into pre
 */
struct quark_wild {
	char	*pre;		/* user input, like foo*bar */
	size_t	 pre_len;
	char	*post;
	size_t	 post_len;
};

/* Rule Field */
struct quark_rule_field {
	u64		 code;
	union {
		u32			 pid;
		u64			 poison_tag;
		struct quark_wild	 wild;
		u32			 id;
		char			 comm[16];
	};
};

struct quark_rule {
	struct quark_rule_field	*fields;	/* fields that must match */
	size_t			 n_fields;	/* number of fields */
	int			 action;	/* QUARK_RA_* */
	u64			 poison_tag;	/* tag used for SETTING poison */
	u64			 evals;		/* counter */
	u64			 hits;		/* counter */
	u_int			 number;	/* starting from 0 */
};

struct quark_ruleset {
	struct quark_rule	*rules;
	size_t			 n_rules;
};

struct quark_parser_ctx {
	struct quark_ruleset	 *ruleset;		/* parser output */
	struct quark_rule	 *cur_rule;		/* current rule we're processing */
	FILE			 *in;			/* input file */
	char			**allocs;		/* arena for parser allocations */
	size_t			  n_allocs;		/* size of the arena */
	int			  sentnl;		/* if we sent nl uppon EOF */
	u_long			  lineno;		/* line number */
	u_long			  colno;		/* column number */
	int			  error;		/* if the parser errored out */
	char			  errorbuf[1024];	/* the parser error */
};

/*
 * General system information, static and stored in quark_queue.
 */
struct quark_sysinfo {
	char	 *boot_id;
	char	 *hostname;
	char	**ip_addrs;	/* Solely for ECS generation */
	size_t	  ip_addrs_len;
	char	**mac_addrs;	/* Solely for ECS generation */
	size_t	  mac_addrs_len;
	/* uname(2) */
	char	 *uts_sysname;
	char	 *uts_nodename;
	char	 *uts_release;
	char	 *uts_version;
	char	 *uts_machine;
	/* /etc/os-release */
	char	 *os_name;
	char	 *os_version;
	char	 *os_release_type;
	char	 *os_id;
	char	 *os_version_id;
	char	 *os_version_codename;
	char	 *os_pretty_name;
};

struct quark_queue_stats {
	u64	insertions;
	u64	removals;
	u64	aggregations;
	u64	non_aggregations;
	u64	lost;
	u64	garbage_collections;
	int	backend;	/* active backend, QQ_EBPF or QQ_KPROBE */
	/* TODO u64	peak_nodes; */
};

struct quark_queue_ops {
	int	(*open)(struct quark_queue *);
	int	(*populate)(struct quark_queue *);
	int	(*update_stats)(struct quark_queue *);
	void	(*close)(struct quark_queue *);
};

struct quark_queue_attr {
#define QQ_THREAD_EVENTS	(1 << 0)
#define QQ_KPROBE		(1 << 1)
#define QQ_EBPF			(1 << 2)
#define QQ_MIN_AGG		(1 << 3)
#define QQ_ENTRY_LEADER		(1 << 4)
#define QQ_SOCK_CONN		(1 << 5)
#define QQ_DNS			(1 << 6)
#define QQ_BYPASS		(1 << 7)
#define QQ_FILE			(1 << 8)
#define QQ_SHM			(1 << 9)
#define QQ_TTY			(1 << 10)
#define QQ_PTRACE		(1 << 11)
#define QQ_MODULE_LOAD		(1 << 12)
#define QQ_GETPID		(1 << 13)
#define QQ_NOVA			(1 << 14)
#define QQ_ALL_BACKENDS		(QQ_KPROBE | QQ_EBPF)	/* QQ_NOVA excluded for now */
	int			 flags;
	int			 max_length;
	int			 cache_grace_time;	/* in ms */
	int			 hold_time;		/* in ms */
	size_t			 max_env;		/* max process environment in bytes */
	int			 kubefd;		/* quark-kube-talker pipe, -1 disables */
	struct quark_ruleset	*ruleset;		/* active ruleset */
};

/*
 * Quark Queue (qq) is the main structure the user interacts with, it acts as
 * our main storage datastructure.
 */
struct quark_queue {
	struct raw_event_by_time	 raw_event_by_time;
	struct raw_event_by_pidtime	 raw_event_by_pidtime;
	struct process_by_pid		 process_by_pid;
	struct gc_queue			 event_gc;
	struct socket_by_src_dst	 socket_by_src_dst;
	struct passwd_by_uid		 passwd_by_uid;
	struct group_by_gid		 group_by_gid;
	struct container_by_id		 container_by_id;	/* all known containers */
	struct quark_sysinfo		 sysinfo;
	struct quark_event		 event_storage;
	struct quark_queue_stats	 stats;
	struct quark_ruleset		*ruleset;
	quark_can_aggregate_fn		 agg_matrix[RAW_NUM_TYPES][RAW_NUM_TYPES];
	int				 flags;
	int				 length;
	int				 max_length;
	u64				 cache_grace_time;	/* in ns */
	int				 hold_time;		/* in ms */
	size_t				 max_env;		/* max process environment in bytes */
	struct quark_kube		*qkube;			/* NULL if disabled */
	int				 epollfd;
	/* Backend related state */
	struct quark_queue_ops		*queue_ops;
	void				*queue_be;
};

#endif /* _QUARK_H_ */
