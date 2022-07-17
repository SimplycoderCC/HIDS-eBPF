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

struct event {
    unsigned int event_type;
	int pid;
	int ppid;
	unsigned long pid_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	char mount_dir[MAX_PATH_NAME_SIZE];
	char mount_dev[MAX_PATH_NAME_SIZE];
};


#endif /* __CHECKSYSCALL_H */
