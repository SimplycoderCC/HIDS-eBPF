#ifndef __CHECKSYSCALL_H
#define __CHECKSYSCALL_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define MAX_KSYM_NAME_SIZE 64
#define MAX_PATH_NAME_SIZE 128

#define NOMAL 0
#define SYSCALL_TABLE_HOOK 1
#define INSERT_MODULE 2
#define MOUNT 3
#define OPEN_FILE 4
#define EXEC 5
#define KHOOK 6
#define KPROBE 7
#define MODULE_LOAD 8

struct event {
    unsigned int event_type;
	int pid;
	int ppid;
	unsigned long pid_ns;
	int cap_effective[2];
	char comm[TASK_COMM_LEN];
	char utsnodename[MAX_KSYM_NAME_SIZE];
	char filename[MAX_FILENAME_LEN];
	char mount_dir[MAX_PATH_NAME_SIZE];
	char mount_dev[MAX_PATH_NAME_SIZE];
};

#define DEFAULT_CAP 				0x00000000a80425fb
#define PRIVILEGED_CAP 				0x0000003fffffffff

#define BIT_CAP_CHOWN 				0
#define BIT_CAP_DAC_OVERRIDE		1
#define BIT_CAP_DAC_READ_SEARCH		2
#define BIT_CAP_FOWNER				3	
#define BIT_CAP_FSETID				4
#define BIT_CAP_KILL				5
#define BIT_CAP_SETGID				6
#define BIT_CAP_SETUID				7
#define BIT_CAP_SETPCAP				8
#define BIT_CAP_LINUX_IMMUTABLE		9
#define BIT_CAP_NET_BIND_SERVICE 	10
#define BIT_CAP_NET_BROADCAST 		11
#define BIT_CAP_NET_ADMIN			12
#define BIT_CAP_NET_RAW				13
#define BIT_CAP_IPC_LOCK			14
#define BIT_CAP_IPC_OWNER			15
#define BIT_CAP_SYS_MODULE			16
#define BIT_CAP_SYS_RAWIO			17
#define BIT_CAP_SYS_CHROOT			18
#define BIT_CAP_SYS_PTRACE			19
#define BIT_CAP_SYS_PACCT			20
#define BIT_CAP_SYS_ADMIN			21
#define BIT_CAP_SYS_BOOT			22
#define BIT_CAP_SYS_NICE			23
#define BIT_CAP_SYS_RESOURCE		24
#define BIT_CAP_SYS_TIME			25
#define BIT_CAP_SYS_TTY_CONFIG		26
#define BIT_CAP_MKNOD				27
#define BIT_CAP_LEASE				28
#define BIT_CAP_AUDIT_WRITE			29
#define BIT_CAP_AUDIT_CONTROL		30
#define BIT_CAP_SETFCAP				31
#define BIT_CAP_MAC_OVERRIDE		32
#define BIT_CAP_MAC_ADMIN			33
#define BIT_CAP_SYSLOG				34
#define BIT_CAP_WAKE_ALARM			35
#define BIT_CAP_BLOCK_SUSPEND		36
#define BIT_CAP_AUDIT_READ			37
#define BIT_CAP_PERFMON				38
#define BIT_CAP_BPF					39
#define BIT_CAP_CHECKPOINT_RESTORE	40 

#endif /* __CHECKSYSCALL_H */
