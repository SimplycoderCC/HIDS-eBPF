#include <linux/kernel.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "check_syscall_table.h"
#include "check_syscall_table.skel.h"
// #include "const_u.h"

#define DEBUG_EN
#ifdef DEBUG_EN
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

// 输出所有mount //是否只检测不同命名空间的mount
#define ONLY_MOUNT_DOCKER

// 是否进行 preload 检测, 在mount的时候触发。  todo: 更好地触发形式？  
#define PRE_LOAD

// 打印所有事件
// #define NORMAL

#define MAX_LEN_ENTRY 256
#define MAX_PROC_PIDNS 64

struct bpf_map * syscall_addrs_u;

unsigned long _stext,_etext;
unsigned long host_pidns;

//----------------------------------------- Mount event -------------------------------------------------
static int Count_sensitive_mount_pre = 6;
static char *sensitive_mount_pre[] = {"cgroup","/dev/sd","/etc","/root",
            "/var/run","/proc/sys/kernel"};

static int Count_sensitive_mount_all = 1;
static char *sensitive_mount_all[] = {"/proc"};

//---------------------------------------  LaZagne   -----------------------------------------------------------
static int Count_monitorfiles = 22;
static char *monitorfiles = {
    "signons.sqlite", "logins.json", "Login Data",          //browsers                   
    "/.purple/accounts.xml",                                //chats
    "/.git-credentials", "/.config/git/credentials",         //git
    "/.dbvis/config70/dbvis.xml", "/.sqldeveloper/SQL Developer/connections.xml", "/.squirrel-sql/SQLAliases23.xml", //databases
    
    // "/.claws-mail/accountrc","/.claws-mail/accountrc/passwordstorerc",  //#mails 
    "/.claws-mail",  //#"/.thunderbird",    //#mails   -test_ok     由于未发现指定文件夹所以不再往下搜索                 
    "/etc/NetworkManager/system-connections/", "/etc/wpa_supplicant/wpa_supplicant.conf", // #wifi
    //# "/etc/shadow",                                          #!!!但是易误检!!! sysadmin-shadow    TODO
    
    //# ".config/keepassx/config.ini",".config/KeePass/KeePass.config.xml",    #sysadmin-keepassconfig
    ".config/keepassx", ".config/KeePass",               //#sysadmin-keepassconfig    -test_ok  由于未发现指定文件夹所以不再往下搜索
    "/boot/grub/menu.lst", "/boot/grub/grub.conf", "/boot/grub/grub.cfg" ,     //#sysadmin-grup
    
    //# ".gftp/bookmarks",".gftp/bookmarks/gftprc",                            #sysadmin-gftp 
    ".gftp",                        //#!!!但是易误检!!!  sysadmin-gftp  -test_ok   由于未发现指定文件夹所以不再往下搜索   TODO
    //# "/etc/fstab",                   //#!!!但是易误检!!!  sysadmin-fstab    TODO
    ".docker/config.json",          //#sysadmin-docker
    
    //# ".history",".sh_history",".bash_history",".zhistory",   #sysadmin-cli  -cli 无法运行单个参数 dhz todo: all need?
    ".local/share/mc/history",
    ".aws/credentials",                //  #sysadmin-aws  
     
    //# ".ApacheDirectoryStudio/.metadata/.plugins/org.apache.directory.studio.connection.core/connections.xml"         #sysadmin-apachedirectorystudio 
    ".ApacheDirectoryStudio",            //  #sysadmin-apachedirectorystudio   -test_ok 由于未发现指定文件夹所以不再往下搜索
};

static char *key = {".ssh/id_rsa",".ssh/id_dsa",".ssh/id_ecdsa",".ssh/id_ed25519",};        // #sysadmin-ssh
static char *key_after = {".ssh/config",".ssh/config",".ssh/config",".ssh/config",};

//------------------------------------------------------------ help fun ----------------------------------------------

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	// if (level == LIBBPF_DEBUG)
	// 	return 0;
	return vfprintf(stderr, format, args);
}

void read_pidns(void)
{
	char buf[MAX_PROC_PIDNS]  = {0};  
	char *buf_p				  = buf ; // 作为strsep的第一个参数
	char *strtoul_end_ptr     = NULL;
	// char *strsep_ret 		  = NULL;

	int result = readlink("/proc/self/ns/pid",buf,MAX_PROC_PIDNS-1);
	DEBUG("\n\nfn-[read_pidns] buf : %s  result: %d \n",buf,result);
	// strsep_ret = strsep(&buf_p, "[" );
	strsep(&buf_p, "[" );
	// fprintf(stderr, "strsep_ret : %s \n" ,strsep_ret);
	// fprintf(stderr, "buf_p : %s \n" ,buf_p);
	// host_pidns = strtoul(&buf[5], &strtoul_end_ptr, 10);
	host_pidns = strtoul(buf_p, &strtoul_end_ptr, 10);
	DEBUG("fn-[read_pidns] host_pidns: %ld \n \n",host_pidns);
	return ;
}

unsigned long * obtain_syscall_table_by_proc(void)
// static void obtain_syscall_table_by_proc(void)
{
	char *file_name                       = "/proc/kallsyms";
	// int i                                 = 0;         /* Read Index */
	FILE *proc_ksyms               		  = NULL;      /* struct file the '/proc/kallsyms' or '/proc/ksyms' */
	// char *sct_addr_str                    = NULL;      /* buffer for save sct addr as str */
	char proc_ksyms_entry[MAX_LEN_ENTRY]  = {0};       /* buffer for each line at file */
	char *strtoul_end_ptr;
	unsigned long *syscall_table_addr_p      = 0;         /* return value */ 
	char *proc_ksyms_entry_ptr            = NULL;
	char *read                            = NULL;

	DEBUG("=================================================\n");
		
	proc_ksyms = fopen(file_name, "r");
	if( proc_ksyms == NULL ){
		fprintf(stderr, "Open /proc/kallsyms fail\n");
		goto CLEAN_UP;
	}
		
	read = fgets(proc_ksyms_entry, MAX_LEN_ENTRY, proc_ksyms);//从输入文件读取一行字符串
	
	while( read )
	{
		// fprintf(stderr, "Line is:%s\n", proc_ksyms_entry);
		// if(proc_ksyms_entry[i] == '\n' || i == MAX_LEN_ENTRY)
		// {
		if(strstr(proc_ksyms_entry, "sys_call_table") != NULL)
		{
			if (strstr(proc_ksyms_entry, "ia32_sys_call_table") == NULL && strstr(proc_ksyms_entry, "x32_sys_call_table") == NULL)
			{
				DEBUG("Found Syscall table\n");
				DEBUG("Line is:%s\n", proc_ksyms_entry);

				proc_ksyms_entry_ptr = proc_ksyms_entry;
				// strncpy(sct_addr_str, strsep(&proc_ksyms_entry_ptr, " "), MAX_LEN_ENTRY);
				// fprintf(stderr, "sct_addr_str is:%s\n", sct_addr_str);
				syscall_table_addr_p = (unsigned long*)malloc(sizeof(unsigned long));
				if(syscall_table_addr_p == NULL)
					goto CLEAN_UP;
				*syscall_table_addr_p = strtoul(proc_ksyms_entry_ptr, &strtoul_end_ptr, 16);
				DEBUG("sys_call_table : %lx \n",*syscall_table_addr_p);
				// fprintf(stderr, "字符串部分是 |%s|", strtoul_end_ptr);

			}
		}
		if(strstr(proc_ksyms_entry, "_stext") != NULL)
		{
			DEBUG("Found _stext\n");
			DEBUG("Line is:%s\n", proc_ksyms_entry);

			proc_ksyms_entry_ptr = proc_ksyms_entry;
			_stext = strtoul(proc_ksyms_entry_ptr, &strtoul_end_ptr, 16);
			DEBUG("_stext : %lx \n",_stext);
			// fprintf(stderr, "字符串部分是 |%s|", strtoul_end_ptr);
		}
		if(strstr(proc_ksyms_entry, "_etext") != NULL)
		{
			DEBUG("Found _etext\n");
			DEBUG("Line is:%s\n", proc_ksyms_entry);

			proc_ksyms_entry_ptr = proc_ksyms_entry;
			_etext = strtoul(proc_ksyms_entry_ptr, &strtoul_end_ptr, 16);
			DEBUG("_etext : %lx \n",_etext);
			// fprintf(stderr, "字符串部分是 |%s|", strtoul_end_ptr);
		}
		// memset(proc_ksyms_entry, 0, MAX_LEN_ENTRY);
		read = fgets(proc_ksyms_entry, MAX_LEN_ENTRY, proc_ksyms);//从输入文件读取一行字符串
	}

CLEAN_UP:
	// if(sct_addr_str != NULL)
	// 	free(sct_addr_str);
	if(proc_ksyms != NULL)
		fclose(proc_ksyms);
	fprintf(stderr, "=================================================\n");
	return (unsigned long *)syscall_table_addr_p;
	// return ;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	bool print_flag = true;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	switch (e->event_type)
	{
	case INSERT_MODULE:
		{
			// fprintf(stderr, "do check \n");
			unsigned int idx;
			unsigned long syscalladdr;
			// bpf_map__lookup_elem(syscall_addrs_u, &idx, sizeof(idx), &syscalladdr, sizeof(syscalladdr), BPF_ANY);
			// fprintf(stderr, "bpf_map__lookup_elem syscalltable[%d] : %lx \n",idx,syscalladdr);
			for (int i = 0; i < 335; i++)
			{
				idx = i;
				// ???
				bpf_map__lookup_elem(syscall_addrs_u, &idx, sizeof(idx), &syscalladdr, sizeof(syscalladdr), BPF_ANY);
				// fprintf(stderr, "bpf_map__lookup_elem syscalltable[%d] : %lx \n",idx,syscalladdr);
				if (syscalladdr>_etext || syscalladdr<_stext)
				{
					DEBUG("syscalladdr out of range \n");
					printf("%-8s %-16s %-16s %-7d %-7d %-10ld syscall[%d]: be changed \n",
					ts, "SYSCALL_TABLE_HOOK", e->comm, e->pid, e->ppid, e->pid_ns, idx);
					print_flag = false;
					// e->event_type = SYSCALL_TABLE_HOOK;
				}
				// bpf_map__update_elem(skel->maps.ksymbols_map,&syscalltable,sizeof(syscalltable),systable_p,sizeof(*systable_p),BPF_ANY);
			}
		}
		/* code */
		break;
	case MOUNT:
	{
#ifdef PRE_LOAD
		if(getenv("LD_PRELOAD")) {
			printf("... LD_PRELOAD is visible in the local environment variables.. little warning\n");
			printf("%-8s %-18s %-12s %-7s %-7s %-10s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "PID_NS" ,"DESCRIBE");
		}
    	if(access("/etc/ld.so.preload", F_OK) != -1) {
			printf("... /etc/ld.so.preload DOES definitely exist.. little warning\n");
			printf("%-8s %-18s %-12s %-7s %-7s %-10s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "PID_NS" ,"DESCRIBE");
		}
#endif

#ifdef ONLY_MOUNT_DOCKER
		if (host_pidns == e->pid_ns)
		{
			// DEBUG("host MOUNT \n");
			break;
		}
#endif
		// pre fit
		for (int i = 0; i < Count_sensitive_mount_pre; i++)
		{
			// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
			if (strncmp(e->mount_dev,sensitive_mount_pre[i], strlen(sensitive_mount_pre[i])) == 0)
			{	
				printf("%-8s %-16s %-16s %-7d %-7d %-10ld  docker mount dev:%s dir:%s\n",
				ts, "MOUNT", e->comm, e->pid, e->ppid, e->pid_ns,e->mount_dev,e->mount_dir);
				print_flag = false;
			}
		}
		// all fit
		for (int i = 0; i < Count_sensitive_mount_all; i++)
		{
			// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
			if (strcmp(e->mount_dev,sensitive_mount_all[i]) == 0)
			{	
				printf("%-8s %-16s %-16s %-7d %-7d %-10ld  docker mount dev:%s dir:%s\n",
				ts, "MOUNT", e->comm, e->pid, e->ppid, e->pid_ns,e->mount_dev,e->mount_dir);
				print_flag = false;
			}
		}
		break;
	}
	case OPEN_FILE:
	{

	}
	default:
		break;
	}

	// if(e->event_type==INSERT_MODULE){
	// 	// fprintf(stderr, "do check \n");
	// 	unsigned int idx;
	// 	unsigned long syscalladdr;
	// 	// bpf_map__lookup_elem(syscall_addrs_u, &idx, sizeof(idx), &syscalladdr, sizeof(syscalladdr), BPF_ANY);
	// 	// fprintf(stderr, "bpf_map__lookup_elem syscalltable[%d] : %lx \n",idx,syscalladdr);
	// 	for (int i = 0; i < 335; i++)
	// 	{
	// 		idx = i;
	// 		// ???
	// 		bpf_map__lookup_elem(syscall_addrs_u, &idx, sizeof(idx), &syscalladdr, sizeof(syscalladdr), BPF_ANY);
	// 		// fprintf(stderr, "bpf_map__lookup_elem syscalltable[%d] : %lx \n",idx,syscalladdr);
	// 		if (syscalladdr>_etext || syscalladdr<_stext)
	// 		{
	// 			DEBUG("syscalladdr out of range \n");
	// 			printf("%-8s %-16s %-16s %-7d %-7d %-10ld syscall[%d]: be changed \n",
	// 			ts, "SYSCALL_TABLE_HOOK", e->comm, e->pid, e->ppid, e->pid_ns, idx);
	// 			print_flag = false;
	// 			// e->event_type = SYSCALL_TABLE_HOOK;
	// 		}
	// 		// bpf_map__update_elem(skel->maps.ksymbols_map,&syscalltable,sizeof(syscalltable),systable_p,sizeof(*systable_p),BPF_ANY);
	// 	}
	// }


	if (print_flag){
#ifdef NORMAL
		printf("%-8s %-16s %-16s %-7d %-7d %-10ld %s\n",
	       	ts, "NORMAL", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
#endif
	}


	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct check_syscall_table_bpf *skel;
	int err;
	unsigned long * systable_p;
	// unsigned int syscalltable= 0;
	char syscalltable[MAX_KSYM_NAME_SIZE]= "sys_call_table";

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = check_syscall_table_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = check_syscall_table_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	
	read_pidns();

	syscall_addrs_u = skel->maps.syscall_addrs;
	//get sys_call_table addr
	// system("cat /proc/kallsyms | grep -w sys_call_table | awk '{print $1}'");
	systable_p = obtain_syscall_table_by_proc();
	DEBUG("[main] sys_call_table : %lx \n",*systable_p);
	
	int fd = bpf_map__fd(skel->maps.ksymbols_map);
	DEBUG("[fd]ksymbols_map  : %d \n",fd);
	bpf_map__update_elem(skel->maps.ksymbols_map,&syscalltable,sizeof(syscalltable),systable_p,sizeof(*systable_p),BPF_ANY);
	// ring_buffer__new
	// bpf_map_update_elem(, &pid, &ts, BPF_ANY);
	
	/* Attach tracepoints */
	err = check_syscall_table_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-18s %-12s %-7s %-7s %-10s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "PID_NS" ,"DESCRIBE");
	while (1) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	check_syscall_table_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}


