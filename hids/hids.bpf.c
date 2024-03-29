#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "hids.h"
#include "utils.h"

// ----------------------- kernel hook probe --------------------------------

SEC("tp/module/module_load")
// int module_load() //struct trace_event_module_load *module_load_ctx
int module_load(struct trace_event_module_load *module_load_ctx)
{
	char str[MAX_KSYM_NAME_SIZE] = {0} ;
	struct event *e;
	pid_t pid;
	struct task_struct *task;
	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();
  	unsigned long offset = (unsigned long)(module_load_ctx->data_loc_name & 0xFFFF);
  	unsigned int length = (unsigned long)(module_load_ctx->data_loc_name >> 16);
  	unsigned long base = (unsigned long)module_load_ctx;
	bpf_probe_read_str(str, MAX_KSYM_NAME_SIZE, (void *)(base+offset));  
	DEBUG("[data_loc_name] module_name:%s! \n",str);
	DEBUG("module_load !\n");
	// DEBUG("module_load, module name is: %s !\n", args->name);
	// lkm_map
	bpf_map_update_elem(&lkm_map, &pid, str, BPF_ANY);

	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
    e->event_type = MODULE_LOAD;
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
	// uts node name
	bpf_probe_read_str(e->utsnodename, sizeof(e->utsnodename), (BPF_CORE_READ(task,nsproxy,uts_ns,name.nodename))); 
	// DEBUG("[mount_exit]  e->utsnodename %s \n",e->utsnodename);
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
	long fd = ret > 0 ? ret : -1;
	if (fd == -1)
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

	// if (fd == -1)
	// {
	// 	DEBUG("[open_exit]  filename: %s \n",open_pkg->filename);
	// 	return 0;
	// }
	// DEBUG("[open_exit]  filename: %s   fd :%ld \n",open_pkg->filename,fd);
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
	long fd = ret > 0 ? ret : -1;
	if (fd == -1)
	{
		return 0;
	}
	
	// DEBUG("[openat_exit] ret :%ld ....................\n",ret);
	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	open_pkg = (filename_t *)bpf_map_lookup_elem(&open_map, &pid);
	if (!open_pkg)
	{
		DEBUG("BPF map key:open_map  nofind !\n");
		return 0;
	}else{
		// DEBUG("[openat_exit]  filename: %s \n",open_pkg->filename);
	}
	// if (fd == -1)
	// {
	// 	DEBUG("[openat_exit]  filename: %s \n",open_pkg->filename);
	// 	return 0;
	// }
	// DEBUG("[openat_exit]  filename: %s   fd :%ld \n",open_pkg->filename,fd);
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
	// DEBUG("[exec_enter]  e->filename %s \n",e->filename);
	// uts node name
	bpf_probe_read_str(e->utsnodename, sizeof(e->utsnodename), (BPF_CORE_READ(task,nsproxy,uts_ns,name.nodename))); 
	// DEBUG("[exec_enter]  e->utsnodename %s \n",e->utsnodename);
	// cap_effective
	e->cap_effective[0] = BPF_CORE_READ(task,real_cred,cap_effective.cap[0]);
	e->cap_effective[1] = BPF_CORE_READ(task,real_cred,cap_effective.cap[1]);
	// DEBUG("[exec_enter]  e->cap_effective[0]:%d e->cap_effective[1]:%d \n",e->cap_effective[0], e->cap_effective[1]);
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
	// DEBUG("[execveat_enter]  e->filename %s \n",e->filename);
	// uts node name
	bpf_probe_read_str(e->utsnodename, sizeof(e->utsnodename), (BPF_CORE_READ(task,nsproxy,uts_ns,name.nodename))); 
	// DEBUG("[execveat_enter]  e->utsnodename %s \n",e->utsnodename);
	// cap_effective
	e->cap_effective[0] = BPF_CORE_READ(task,real_cred,cap_effective.cap[0]);
	e->cap_effective[1] = BPF_CORE_READ(task,real_cred,cap_effective.cap[1]);
	// DEBUG("[execveat_enter]  e->cap_effective[0]:%d e->cap_effective[1]:%d \n",e->cap_effective[0], e->cap_effective[1]);
	// 无mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

//  ------------------------------ kprobe kfun hook ------------------

// ---------------------------------  kprobe use check ---------------------
// kprobe:kprobe_lookup_name
// kprobe:arm_kprobe, 		
// kprobe:__disarm_kprobe_ftrace 	// don't work
// SEC("kretprobe/arm_kprobe")	
SEC("kretprobe/kprobe_lookup_name")	
int kprobe_lookup_name_ret(){
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	// DEBUG("[openat_enter]  filename %s   \n",open_pkg.filename);
	
	unsigned long *host_pid_p ;
	host_pid_p = (unsigned long *)bpf_map_lookup_elem(&ksymbols_map,&host_pid_s);
	if(!host_pid_p){
		return 0;
	}

	// 不跟踪host ebpf程序自身对kprobe的调用
	if((unsigned long)pid == *host_pid_p){
		return 0;
	}
	DEBUG("[kprobe] kretprobe/kprobe_lookup_name, check point 1 \n");
	int kprobe = INSN_INIT_OR_KPROBE;
	bpf_map_update_elem(&kprobe_map, &pid ,&kprobe, BPF_ANY);
	// bpf_map_update_elem(&mount_dir_map, &pid ,&dir, BPF_ANY);
	// bpf_map_update_elem(&mount_dir_map,);
	return 0;
}

// SEC("kprobe/__disarm_kprobe_ftrace")	// failed to create kprobe
SEC("kretprobe/arm_kprobe") 
int arm_kprobe_ret(){
	struct event *e;
	struct task_struct *task;
	pid_t pid;
	unsigned long *host_pid_p ;
	int *is_kprobe ;

	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	is_kprobe = (int *)bpf_map_lookup_elem(&kprobe_map, &pid);
	if (!is_kprobe)
	{
		// DEBUG("BPF map key:open_map  nofind !\n");
		return 0;
	}
	// 未满足 Kprobe 敏感序列, 直接返回
	if(*is_kprobe != INSN_INIT_OR_KPROBE){
		return 0;
	}

	// 不跟踪host ebpf程序自身对kprobe的调用
	host_pid_p = (unsigned long *)bpf_map_lookup_elem(&ksymbols_map,&host_pid_s);
	if(!host_pid_p){
		return 0;
	}
	if((unsigned long)pid == *host_pid_p){
		return 0;
	}
	DEBUG("[kprobe] kretprobe/arm_kprobe, check point 2 \n");
	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->event_type = KPROBE;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	//pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
    // 无 file name
	// 无需 uts node name
	// 无 mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---------------------------------  khook check ------------------------------------------
// kprobe:insn_init, 		获取某个地址的指令 -> 返回结构体
// kprobe:insn_get_length 	获取这种指令的长度 -> 参数为结构体
SEC("kretprobe/insn_init")	
int insn_init_ret(){
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	int *is_insn_init ;
	// 不跟踪host ebpf程序自身对kprobe的调用
	unsigned long *host_pid_p ;
	host_pid_p = (unsigned long *)bpf_map_lookup_elem(&ksymbols_map,&host_pid_s);
	if(!host_pid_p){
		return 0;
	}
	if((unsigned long)pid == *host_pid_p){
		return 0;
	}

	// 若没有load—module ,不进行序列检测
	char *lkm_name = bpf_map_lookup_elem(&lkm_map, &pid);
	if (!lkm_name){
		return 0;
	}

	// 对同一PID仅进行一次异常指令操作序列检测
	is_insn_init = (int *)bpf_map_lookup_elem(&khook_map, &pid);
	if (!is_insn_init)
	{
		// 仅 key对应的value为空时, 进行一次更新
		DEBUG("[KHOOK] kretprobe/insn_init, check point 1 \n");
		int insn_init = INSN_INIT_OR_KPROBE;
		bpf_map_update_elem(&khook_map, &pid ,&insn_init, BPF_ANY);
	}
	
	return 0;
}

SEC("kretprobe/insn_get_length")	
int insn_get_length_ret(){
	struct event *e;
	struct task_struct *task;
	pid_t pid;
	int *is_insn_init ;
	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	// 不跟踪host ebpf程序自身对kprobe的调用
	unsigned long *host_pid_p ;
	host_pid_p = (unsigned long *)bpf_map_lookup_elem(&ksymbols_map,&host_pid_s);
	if(!host_pid_p){
		return 0;
	}
	if((unsigned long)pid == *host_pid_p){
		return 0;
	}

	// 未满足KHOOK敏感序列, 直接返回
	is_insn_init = (int *)bpf_map_lookup_elem(&khook_map, &pid);
	if (!is_insn_init)
	{
		// DEBUG("BPF map key:open_map  nofind !\n");
		return 0;
	}
	if(*is_insn_init != INSN_INIT_OR_KPROBE){
		return 0;
	}

	// 满足一次KHOOK序列检测标记当前PID，之后不再进行重复检测
	int insn_init = HOOK_CHECK_FINISH;
	bpf_map_update_elem(&khook_map, &pid ,&insn_init, BPF_ANY);
	DEBUG("[KHOOK] kretprobe/insn_get_length, check point 2 \n");
	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->event_type = KHOOK;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	//pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
    // 无 file name
	// 无需 uts node name
	// 无 mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

//  ------------------------------ get kill event ------------------

SEC("tp/syscalls/sys_enter_kill")
int kill_enter(struct trace_event_kill* kill_ctx)
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
	e->event_type = KILL;
	e->pid = pid;
    // 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    // comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
	// sig 
	e->sig = kill_ctx->sig;
    // no file name
	// no uts node name
	// no cap_effective
	// 无 mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

//  ------------------------------ <commit_creds>  Detection of privilege escalation ------------------

/**
 * commit_creds - Install new credentials upon the current task
 * @new: The credentials to be assigned
 *
 * Install a new set of credentials to the current task, using RCU to replace
 * the old set.  Both the objective and the subjective credentials pointers are
 * updated.  This function may not be called if the subjective credentials are
 * in an overridden state.
 *
 * This function eats the caller's reference to the new credentials.
 *
 * Always returns 0 thus allowing this function to be tail-called at the end
 * of, say, sys_setgid().
 */
// int commit_creds(struct cred *new)

// // Detection of privilege escalation
// SEC("kprobe/commit_creds")
// int handle_commit_creds(struct cred *new)
// {
// 	struct event *e;
// 	struct task_struct *task;
// 	pid_t pid;
// 	pid = bpf_get_current_pid_tgid() >> 32;

// 	task = (struct task_struct *)bpf_get_current_task();
// 	// struct cred *new = (struct cred *)PT_REGS_PARM1(ctx);
//     // struct cred *old = (struct cred *)get_task_real_cred(task);
// 	struct cred *old = (struct cred *)READ_KERN(task->real_cred);

// 	unsigned int new_uid = READ_KERN(new->uid.val);
//     unsigned int old_uid = READ_KERN(old->uid.val);

// 	// // in Elkeid: privilege escalation only detect uid none zero to zero
//     // // But in tracee, any uid changes will lead to detection of this
//     if (new_uid == 0 && old_uid != 0)
//     {
// 		/* 保存事件结构体  reserve sample from BPF ringbuf */
// 		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 		if (!e)
// 			return 0;
// 		e->event_type = COMMIT_CREDS;
// 		e->pid = pid;
// 		e->old_uid = old_uid;
// 		e->new_uid = new_uid;
// 		// 父进程PID task->real_parent->tgid 
// 		e->ppid = BPF_CORE_READ(task, real_parent, tgid);
// 		// comm
// 		bpf_get_current_comm(&e->comm, sizeof(e->comm));
// 		// pid_ns
// 		e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
// 		// no sig 
// 		// no file name
// 		// no uts node name
// 		// no cap_effective
// 		// 无 mount file path
// 		/* successfully submit it to user-space for post-processing */
// 		bpf_ringbuf_submit(e, 0);
//         // void *exe = get_exe_from_task(data.task);
//         return 1;
//     }
// 	return 0;
// }


// ---------------------------------      无文件攻击   ------------------------

// name: sys_enter_memfd_create
// ID: 626
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:const char * uname;       offset:16;      size:8; signed:0;
//         field:unsigned int flags;       offset:24;      size:8; signed:0;

// print fmt: "uname: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->uname)), ((unsigned long)(REC->flags))

// https://xeldax.top/article/linux_no_file_elf_mem_execute
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int sys_enter_memfd_create(struct trace_event_memfd_create *ctx)
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
	e->event_type = SYS_ENTER_MEMFD_CREATE;
	e->pid = pid;
	// 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	// comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
	// no sig 
	// file name
	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)(ctx->uname)); 
	// no uts node name
	// no cap_effective
	// 无 mount file path

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------   文件检查  file-fop check   ------------------------
/* fops checks
 * https://github.com/chriskaliX/Hades/blob/fdfbcabb68d48262b09e8bfc03bf44f2bdcf5c9a/plugins/ebpfdriver/kern/include/hades_rootkit.h
 * In tracee, security_file_permission is hooked for file
 * file_operations iterater detection, but in tyton(or Elkeid)
 * only detect the /proc dir, which may be evaded. There are
 * more than one way to hide from the proc file, set SUSPEND
 * flag just like Reptile do can also evade detection like
 * this one. PAY ATTENTION TO list kernel
 * 
 * Reference:
 * https://vxug.fakedoma.in/papers/h2hc/H2HC%20-%20Matveychikov%20&%20f0rb1dd3%20-%20Kernel%20Rootkits.pdf
 * tracee: https://blog.aquasec.com/detect-drovorub-kernel-rootkit-attack-tracee
 * rootkit-demo: https://github.com/Unik-lif/rootkit-hide
 * evasion: https://blog.csdn.net/dog250/article/details/105939822
 *
 * Warning: This function is under full test, PERFORMANCE IS UNKNOWN
 * from tracee. filldir
 * 
 */
#define PROC_SUPER_MAGIC       0x9fa0

SEC("kprobe/security_file_permission")
int BPF_KPROBE(kprobe_security_file_permission)
{
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);
    if (file == NULL)
        return 0;
    struct inode *f_inode = READ_KERN(file->f_inode);
    struct super_block *i_sb = READ_KERN(f_inode->i_sb);
    unsigned long s_magic = READ_KERN(i_sb->s_magic);

    if (s_magic != PROC_SUPER_MAGIC) {
        return 0;
    }

    struct file_operations *fops = (struct file_operations *) READ_KERN(f_inode->i_fop);
    if (fops == NULL)
        return 0;

    // kernel version 4.10 iterate_shared
    unsigned long iterate_shared_addr = (unsigned long) READ_KERN(fops->iterate_shared);
    unsigned long iterate_addr = (unsigned long) READ_KERN(fops->iterate);
    
    if (iterate_shared_addr == 0 && iterate_addr == 0)
        return 0;
    
    // get configuration from bpf_map, if not contained, skip
    unsigned long *_stext ;
	_stext = (unsigned long *)bpf_map_lookup_elem(&ksymbols_map,&stext_s);
	if(!_stext){
		return 0;
	}
	unsigned long *_etext ;
	_etext = (unsigned long *)bpf_map_lookup_elem(&ksymbols_map,&etext_s);
	if(!_etext){
		return 0;
	}

    // Add detections for module address
    // In tracee, the address is checked in userspace from _stext to _etext
    // more details about memory
    // https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
    // It's ok to use the hook check for kernel text section or the module addr sec
    // for now, we just hardcode those, for experimental
    // 
    // for now, we do not use MODULE_VADDR, since we need to get this address from
    // userspace also.
    if (iterate_shared_addr > 0) {
        if (iterate_shared_addr >= *_stext && iterate_shared_addr <= *_etext) {
            return 0;
        }
    }
    if (iterate_addr > 0) {
        if (iterate_addr >= *_stext && iterate_addr <= *_etext) {
            return 0;
        }
    }

	// fop 异常
	struct event *e;
	struct task_struct *task;
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

	task = (struct task_struct *)bpf_get_current_task();
	/* 保存事件结构体  reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->event_type = RKT_FOPS;
	e->pid = pid;
	// 父进程PID task->real_parent->tgid 
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	// comm
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// pid_ns
	e->pid_ns = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,ns.inum);
	// no sig 
	// no file name
	// no uts node name
	// no cap_effective
	// 无 mount file path

    /* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
    return 0;
}