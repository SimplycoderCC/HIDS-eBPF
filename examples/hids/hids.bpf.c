#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hids.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PERCPU_BUFSIZE              (1 << 15) // set by the kernel as an upper bound
#define MAX_STRING_SIZE                 4096      // same as PATH_MAX

#define DEBUG_EN
#ifdef DEBUG_EN
#define DEBUG(...) bpf_printk(__VA_ARGS__);
#else
#define DEBUG(...)
#endif

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);              \
        _val;                                                           \
    })

#define READ_USER(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr);         \
        _val;                                                           \
    })

static char syscalltable[MAX_KSYM_NAME_SIZE]= "sys_call_table";

//---------------------------- help func -------------------

// unsafe
static __always_inline int cont_ustr(char *s)
{
    int i = 0;     
	for (i = 0; i < MAX_PATH_NAME_SIZE; i++)
	{
		if ( READ_USER(s[i]) == '\0'){
			break;
		}
	}
    return i;
}

// unsafe
static __always_inline int cpy_ustr(char *s, void* dst)
{
    int str_cont = cont_ustr(s);
	// char *dst_char = (char *)dst;
	int i = 0;
	for (i = 0; i < str_cont; i++)
	{
		*((char *)dst+i) = READ_USER(s[i]);
	}
	*((char *)dst+i+1)='\0';
	return i+1;
}

static __always_inline int cont_str(char *s)
{
    int i = 0;     
	for (i = 0; i < MAX_PATH_NAME_SIZE; i++)
	{
		if ( s[i] == '\0'){
			break;
		}
	}
    return i;
}

// unsafe
static __always_inline int cpy_str(char *s, void* dst)
{
    int str_cont = cont_str(s);
	// char *dst_char = (char *)dst;
	int i = 0;
	for (i = 0; i < str_cont; i++)
	{
		*((char *)dst+i) = s[i];
	}
	*((char *)dst+i+1)='\0';
	return i+1;
}

// ----- struct

struct exit_args {
	struct trace_entry ent;
	int __syscall_nr;
	long ret;
};

struct trace_event_mount {
	struct trace_entry ent;
	int __syscall_nr;
	char * dev_name;
	char * dir_name;  
	char * type;      
	unsigned long flags;
	void * data;      
};

struct trace_event_open {
	struct trace_entry ent;
	int __syscall_nr;
	char * filename;
	long flags;  
	long mode;      
};

struct trace_event_openat {
	struct trace_entry ent;
	int __syscall_nr;
	long dfd;  
	char * filename;
	long flags;  
	long mode;        
};

struct trace_event_execve {
	struct trace_entry ent;
	int __syscall_nr;
	char * filename;
	char * argv;  
	char * envp;        
};

struct trace_event_execveat {
	struct trace_entry ent;
	int __syscall_nr;
	int fd;
	char * filename;
	char * argv;  
	char * envp;     
	int flags;   
};

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

typedef struct path_name2 {
    char dev[MAX_PATH_NAME_SIZE];
	char dir[MAX_PATH_NAME_SIZE];
} mount_t;

typedef struct file_name {
    char filename[MAX_PATH_NAME_SIZE];
} filename_t;

///----------------- map -----------

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, ksym_name_t);
	__type(value, u64); 
} ksymbols_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, u32);
	__type(value, u64); 
} syscall_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, mount_t); 
} mount_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, filename_t); 
} open_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); 
} rb SEC(".maps");

// ----------------------- probe --------------------------------

// SEC("tp/syscalls/sys_enter_write")
SEC("tp/syscalls/sys_exit_finit_module")  // ＜（＾－＾）＞
// SEC("kretprobe/do_init_module")	// ＜（＾－＾）＞
int check_syscall_table()
{
	u32 idx=0;
	struct task_struct *task;
	struct event *e;
	pid_t pid;
	u64 *syscall_table_p ;
	
	syscall_table_p = (u64 *)bpf_map_lookup_elem(&ksymbols_map,&syscalltable);
	if (!syscall_table_p)
	{
		DEBUG("BPF map key:sys_call_table  nofind !\n");
		return 0;
	}else{
		DEBUG("BPF map key:sys_call_table  value: %lx \n",*syscall_table_p);
	}

	unsigned long *syscall_table_addr = (unsigned long *)*syscall_table_p;
	u64 syscall_address;
	for (int i=0; i<335; i++)
	{
		idx = i;
		syscall_address = READ_KERN(syscall_table_addr[idx]);
		// DEBUG("syscall_table_addr[%d]: %lx \n",idx,syscall_address);
		bpf_map_update_elem(&syscall_addrs, &idx, &syscall_address, BPF_ANY);
	}
	
	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
    pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();
    e->event_type = INSERT_MODULE;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	//pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
    // 无file name

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ----------------------------------------- mount ---------------------------------------------------------------

/**
 * @brief 容器挂载
 * 
 */
// tracepoint:syscalls:sys_enter_mount
// tracepoint:syscalls:sys_exit_mount
// name: sys_enter_mount
// ID: 777
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:char * dev_name;  offset:16;      size:8; signed:0;
//         field:char * dir_name;  offset:24;      size:8; signed:0;
//         field:char * type;      offset:32;      size:8; signed:0;
//         field:unsigned long flags;      offset:40;      size:8; signed:0;
//         field:void * data;      offset:48;      size:8; signed:0;

// print fmt: "dev_name: 0x%08lx, dir_name: 0x%08lx, type: 0x%08lx, flags: 0x%08lx, data: 0x%08lx", ((unsigned long)(REC->dev_name)), ((unsigned long)(REC->dir_name)), ((unsigned long)(REC->type)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->data))
SEC("tp/syscalls/sys_enter_mount")
int mount_enter(struct trace_event_mount *mount_ctx)
{
	// DEBUG("[mount_enter]  start ... \n");
	// char dev[MAX_PATH_NAME_SIZE] = {0} ;
	// char dir[MAX_PATH_NAME_SIZE] = {0} ;
	mount_t mount_pkg = {0};
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

	// DEBUG("[mount_enter]  mount_ctx->dev_name %s  mount_ctx->dir_name %s \n",mount_ctx->dev_name, mount_ctx->dir_name);
	// DEBUG("sizeof mount_ctx->dev_name : %d ",cont_ustr(mount_ctx->dev_name));
	// DEBUG("[mount_enter]  dev %s  dir %s \n",dev, dir);

	// cpy_ustr(mount_ctx->dev_name, (void *)mount_pkg.dev);
	// cpy_ustr(mount_ctx->dir_name, (void *)mount_pkg.dir);
	// DEBUG("[cpy_ustr]  dev %s dir %s \n",mount_pkg.dev, mount_pkg.dir);
	bpf_probe_read_str(mount_pkg.dev, sizeof(mount_pkg.dev), (void *)(mount_ctx->dev_name)); 
	bpf_probe_read_str(mount_pkg.dir, sizeof(mount_pkg.dir), (void *)(mount_ctx->dir_name)); 
	DEBUG("[bpf_probe_read_str]  dev %s  dir %s \n",mount_pkg.dev, mount_pkg.dir);
	

	bpf_map_update_elem(&mount_map, &pid ,&mount_pkg, BPF_ANY);
	// bpf_map_update_elem(&mount_dir_map, &pid ,&dir, BPF_ANY);
	// bpf_map_update_elem(&mount_dir_map,);
	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_mount/format 
// name: sys_exit_mount
// ID: 776
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:long ret; offset:16;      size:8; signed:1;
SEC("tp/syscalls/sys_exit_mount")
int mount_exit(struct exit_args *ctx)
{
	struct event *e;
	struct task_struct *task;
	mount_t *mount_pkg;
	pid_t pid;
	
	long ret = ctx->ret;
	if (ret != 0)
	{
		// mount调用失败，不做处理
		return 0;
	}
	
	// DEBUG("[mount_exit] ret :%ld ....................\n",ret);
	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	mount_pkg = (mount_t *)bpf_map_lookup_elem(&mount_map, &pid);
	if (!mount_pkg)
	{
		DEBUG("BPF map key:mount_map  nofind !\n");
		return 0;
	}else{
		DEBUG("[mount_exit]  dev %s  dir %s\n",mount_pkg->dev, mount_pkg->dir);
	}

	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->event_type = MOUNT;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	//pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
    // mount dev dir
	bpf_probe_read_str(e->mount_dir, sizeof(e->mount_dir), (void *)(mount_pkg->dir)); 
	bpf_probe_read_str(e->mount_dev, sizeof(e->mount_dev), (void *)(mount_pkg->dev)); 
	// cpy_str(mount_pkg->dev,e->mount_dev);
	// cpy_ustr(mount_pkg->dir,e->mount_dir);
	DEBUG("[mount_exit]  e->mount_dev %s  e->mount_dir %s\n",e->mount_dev, e->mount_dir);
	// 无file name

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ----------------------------------------- open ---------------------------------------------------------------

// tracepoint:syscalls:sys_enter_open
// name: sys_enter_open
// ID: 635
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:const char * filename;    offset:16;      size:8; signed:0;
//         field:int flags;        offset:24;      size:8; signed:0;
//         field:umode_t mode;     offset:32;      size:8; signed:0;
SEC("tp/syscalls/sys_enter_open")
int open_enter(struct trace_event_open* open_ctx)
{
	filename_t open_pkg = {0};
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

	bpf_probe_read_str(open_pkg.filename, sizeof(open_pkg.filename), (void *)(open_ctx->filename)); 
	// DEBUG("[open_enter]  filename %s   \n",open_pkg.filename);

	bpf_map_update_elem(&open_map, &pid ,&open_pkg, BPF_ANY);
	// bpf_map_update_elem(&mount_dir_map, &pid ,&dir, BPF_ANY);
	// bpf_map_update_elem(&mount_dir_map,);
	return 0;
}

// tracepoint:syscalls:sys_enter_openat
// name: sys_enter_openat
// ID: 633
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:int dfd;  offset:16;      size:8; signed:0;
//         field:const char * filename;    offset:24;      size:8; signed:0;
//         field:int flags;        offset:32;      size:8; signed:0;
//         field:umode_t mode;     offset:40;      size:8; signed:0;
SEC("tp/syscalls/sys_enter_openat")
int openat_enter(struct trace_event_openat* openat_ctx)
{
	filename_t open_pkg = {0};
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

	bpf_probe_read_str(open_pkg.filename, sizeof(open_pkg.filename), (void *)(openat_ctx->filename)); 
	// DEBUG("[openat_enter]  filename %s   \n",open_pkg.filename);

	bpf_map_update_elem(&open_map, &pid ,&open_pkg, BPF_ANY);
	// bpf_map_update_elem(&mount_dir_map, &pid ,&dir, BPF_ANY);
	// bpf_map_update_elem(&mount_dir_map,);
	return 0;
}

// tracepoint:syscalls:sys_exit_open          	erro:-1
SEC("tp/syscalls/sys_exit_open")
int open_exit(struct exit_args *ctx)
{
	struct event *e;
	struct task_struct *task;
	filename_t *open_pkg;
	pid_t pid;
	
	long ret = ctx->ret;
	if (ret == -1)
	{
		return 0;
	}
	
	// DEBUG("[open_exit] ret :%ld ....................\n",ret);
	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	open_pkg = (filename_t *)bpf_map_lookup_elem(&open_map, &pid);
	if (!open_pkg)
	{
		DEBUG("BPF map key:open_map  nofind !\n");
		return 0;
	}else{
		// DEBUG("[open_exit]  filename: %s \n",open_pkg->filename);
	}

	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->event_type = OPEN_FILE;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	//pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
    // file name
	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)(open_pkg->filename)); 
	// DEBUG("[open_exit]  e->filename %s \n",e->filename);
	// uts node name
	bpf_probe_read_str(e->utsnodename, sizeof(e->utsnodename), (BPF_CORE_READ(task,nsproxy,uts_ns,name.nodename))); 
	// DEBUG("[open_exit]  e->utsnodename %s \n",e->utsnodename);
	// 无mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// tracepoint:syscalls:sys_exit_openat			erro:-1
SEC("tp/syscalls/sys_exit_openat")
int openat_exit(struct exit_args *ctx)
{
	struct event *e;
	struct task_struct *task;
	filename_t *open_pkg;
	pid_t pid;
	
	long ret = ctx->ret;
	if (ret == -1)
	{
		return 0;
	}
	
	// DEBUG("[open_exit] ret :%ld ....................\n",ret);
	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	open_pkg = (filename_t *)bpf_map_lookup_elem(&open_map, &pid);
	if (!open_pkg)
	{
		DEBUG("BPF map key:open_map  nofind !\n");
		return 0;
	}else{
		// DEBUG("[open_exit]  filename: %s \n",open_pkg->filename);
	}

	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->event_type = OPEN_FILE;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	//pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
    // file name
	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)(open_pkg->filename)); 
	// DEBUG("[open_exit]  e->filename %s \n",e->filename);
	// uts node name
	bpf_probe_read_str(e->utsnodename, sizeof(e->utsnodename), (BPF_CORE_READ(task,nsproxy,uts_ns,name.nodename))); 
	// DEBUG("[open_exit]  e->utsnodename %s \n",e->utsnodename);
	// 无mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// tracepoint:syscalls:sys_exit_openat2
// tracepoint:syscalls:sys_enter_openat2

// ----------------------------------------- execve ---------------------------------------------------------------
// name: sys_enter_execve
// ID: 716
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:const char * filename;    offset:16;      size:8; signed:0;
//         field:const char *const * argv; offset:24;      size:8; signed:0;
//         field:const char *const * envp; offset:32;      size:8; signed:0;
// print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))

SEC("tp/syscalls/sys_enter_execve")
int execve_enter(struct trace_event_execve* execve_ctx)
{
	struct event *e;
	struct task_struct *task;
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

	task = (struct task_struct *)bpf_get_current_task();

	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->event_type = EXEC;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	//pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
    // file name
	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)(execve_ctx->filename)); 
	DEBUG("[exec_enter]  e->filename %s \n",e->filename);
	// uts node name
	bpf_probe_read_str(e->utsnodename, sizeof(e->utsnodename), (BPF_CORE_READ(task,nsproxy,uts_ns,name.nodename))); 
	DEBUG("[exec_enter]  e->utsnodename %s \n",e->utsnodename);
	// cap_effective
	e->cap_effective[0] = BPF_CORE_READ(task,real_cred,cap_effective.cap[0]);
	e->cap_effective[1] = BPF_CORE_READ(task,real_cred,cap_effective.cap[1]);
	DEBUG("[exec_enter]  e->cap_effective[0]:%d e->cap_effective[1]:%d \n",e->cap_effective[0], e->cap_effective[1]);
	// 无mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// --------------------------------------------------------------------------------------------------
// name: sys_enter_execveat
// ID: 714
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:int fd;   offset:16;      size:8; signed:0;
//         field:const char * filename;    offset:24;      size:8; signed:0;
//         field:const char *const * argv; offset:32;      size:8; signed:0;
//         field:const char *const * envp; offset:40;      size:8; signed:0;
//         field:int flags;        offset:48;      size:8; signed:0;
// print fmt: "fd: 0x%08lx, filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp)), ((unsigned long)(REC->flags))

SEC("tp/syscalls/sys_enter_execveat")
int execveat_enter(struct trace_event_execveat* execveat_ctx)
{
	struct event *e;
	struct task_struct *task;
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

	task = (struct task_struct *)bpf_get_current_task();

	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->event_type = EXEC;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	//pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
    // file name
	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)(execveat_ctx->filename)); 
	DEBUG("[execveat_enter]  e->filename %s \n",e->filename);
	// uts node name
	bpf_probe_read_str(e->utsnodename, sizeof(e->utsnodename), (BPF_CORE_READ(task,nsproxy,uts_ns,name.nodename))); 
	DEBUG("[execveat_enter]  e->utsnodename %s \n",e->utsnodename);
	// cap_effective
	e->cap_effective[0] = BPF_CORE_READ(task,real_cred,cap_effective.cap[0]);
	e->cap_effective[1] = BPF_CORE_READ(task,real_cred,cap_effective.cap[1]);
	DEBUG("[execveat_enter]  e->cap_effective[0]:%d e->cap_effective[1]:%d \n",e->cap_effective[0], e->cap_effective[1]);
	// 无mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}