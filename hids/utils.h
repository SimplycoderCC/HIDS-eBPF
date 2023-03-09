#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hids.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PERCPU_BUFSIZE              (1 << 15) // set by the kernel as an upper bound
#define MAX_STRING_SIZE                 4096      // same as PATH_MAX

#define INSN_INIT_OR_KPROBE 			1
#define HOOK_CHECK_FINISH 				2

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
static char host_pid_s[MAX_KSYM_NAME_SIZE]= "host_pid";

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

struct trace_event_module_load {
	struct trace_entry ent;
	unsigned int taints;
    int data_loc_name;
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

struct trace_event_kill {
	struct trace_entry ent;
	int __syscall_nr;
	long pid;
	long sig;
};

struct trace_event_memfd_create {
	struct trace_entry ent;
	int __syscall_nr;
	char * uname;     
	unsigned long flags;     
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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32 * 1024);
	__type(key, u32);
	__type(value, u32); 
} judge_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32 * 1024);
	__type(key, u32);
	__type(value, filename_t); 
} pid_conid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8 * 1024);
	__type(key, u32);
	__type(value, u32); 
} khook_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8 * 1024);
	__type(key, u32);
	__type(value, u32); 
} kprobe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, ksym_name_t); 
} lkm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); 
} rb SEC(".maps");