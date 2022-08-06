#include <linux/kernel.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <ctype.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "hids.h"
#include "hids.skel.h"

// com_funaddr.c 中的库函数
int do_so_check(void);

#define DEBUG_EN
#ifdef DEBUG_EN
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

// 输出所有mount //是否只检测不同命名空间的mount
#define ONLY_MOUNT_DOCKER

// 是否进行 preload 检测, 在mount的时候触发。  todo: 更好地触发形式？  
// #define PRE_LOAD

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
static char *monitorfiles[] = {
    "signons.sqlite", "logins.json", "Login Data",          //browsers                   
    "/.purple/accounts.xml",                                //chats
    "/.git-credentials", "/.config/git/credentials",         //git
    "/.dbvis/config70/dbvis.xml", "/.sqldeveloper/SQL Developer/connections.xml", "/.squirrel-sql/SQLAliases23.xml", //databases
    
    // "/.claws-mail/accountrc","/.claws-mail/accountrc/passwordstorerc",  //#mails 
    "/.claws-mail",  //#"/.thunderbird",    //#mails   -test_ok     由于未发现指定文件夹所以不再往下搜索                 
    "/etc/NetworkManager/system-connections/", "/etc/wpa_supplicant/wpa_supplicant.conf", // #wifi
    // "/etc/shadow",                                          #!!!但是易误检!!! sysadmin-shadow    TODO
    
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

// chats模块  笛卡尔积
static int Count_prefix = 5;
static int Count_suffix = 4;
static char *prefix[] =    {".config/psi/profiles",".local/psi+/profiles",          //  chats
                "sitemanager.xml", "recentservers.xml", "filezilla.xml",          //    |    filezilla                                                          
            };                                                                    //    |        |
static char *suffix[]  =   {"accounts.xml","accounts.xml",                          //  chats      |
                ".filezilla", ".config/filezilla",                                //         filezilla  
            }; 

static int ssh_state = 2;
static int Count_ssh_key = 4;
static char *sysadmin_ssh_key[] = {".ssh/id_rsa",".ssh/id_dsa",".ssh/id_ecdsa",".ssh/id_ed25519",};        // #sysadmin-ssh
static char *sysadmin_ssh_after = ".ssh/config";

// memorpy python库检测序列
static int memory_state = 3 ;
static char *regx_proc_mem = "/proc/[1-9]+/mem" ;
static char *regx_proc_maps = "/proc/[1-9]+/maps" ;

// shadow白名单
static int Count_shadow_whitelist = 1;
static char *shadow_whitelist[] = {"sudo"}; 

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

// if(status==REG_NOMATCH) :::: No match
// if(0 == status)         :::: Matched
static int my_match(char* pattern,const char* buf){
  	int status;
	// int i;
  	int flag=REG_EXTENDED;
  	regmatch_t pmatch[1];
  	const size_t nmatch=1;
  	regex_t  reg;
  	//编译正则模式
  	regcomp(&reg,pattern,flag);
  	//执行正则表达式和缓存的比较
  	status=regexec(&reg,buf,nmatch,pmatch,0);
  	//打印匹配的字符串
  	// for(i=pmatch[0].rm_so;i<pmatch[0].rm_eo;++i){
  	//   putchar(buf[i]);
  	// }
  	// // printf("\n");
  	regfree(&reg);
  	return status;
}

// char str[100] = ""
static void get_proc_pid(const char* buf, char* pid){
	int i = 0, j = 0;
	while (buf[i] != '\0' && i<MAX_PATH_NAME_SIZE)
	{
		if (isdigit(buf[i])) {
			pid[j]=buf[i];
			j++;
		}
		i++;
	}
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
		do_so_check();   //TODO
		// if(getenv("LD_PRELOAD")) {
		// 	printf("... LD_PRELOAD is visible in the local environment variables.. little warning\n");
		// 	printf("%-8s %-18s %-12s %-9s %-9s %-12s %s\n",
	    //    "TIME", "EVENT", "COMM", "PID", "PPID", "PID_NS" ,"DESCRIBE");
		// }
    	// if(access("/etc/ld.so.preload", F_OK) != -1) {
		// 	printf("... /etc/ld.so.preload DOES definitely exist.. little warning\n");
		// 	printf("%-8s %-18s %-12s %-9s %-9s %-12s %s\n",
	    //    "TIME", "EVENT", "COMM", "PID", "PPID", "PID_NS" ,"DESCRIBE");
		// }
#endif

#ifdef ONLY_MOUNT_DOCKER
		if (host_pidns == e->pid_ns)
		{
			// DEBUG("host MOUNT \n");
			break;
		}
#endif
		// pre fit 前缀匹配
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
		// all fit 完全匹配
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
		// 单目录特征检测
		for (int i = 0; i < Count_monitorfiles; i++)
		{
			// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
			// if (strcmp(e->filename,monitorfiles[i]) == 0)
			if (strstr(e->filename,monitorfiles[i]))
			{	
				printf("%-8s %-16s %-16s %-7d %-7d %-10ld  sensitive file open:%s \n",
				ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
				print_flag = false;
			}
		}
		// 
		for (int i = 0; i < Count_prefix; i++)
		{
			for (int j= 0; j < Count_suffix; j++)
			{
				// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
				if (strstr(e->filename,prefix[i]) && strstr(e->filename,suffix[j]))
				{	
					printf("%-8s %-16s %-16s %-7d %-7d %-10ld  sensitive file open:%s \n",
					ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
					print_flag = false;
				}
			}
		}
		// # memorpy库检测序列  memorpy state -> 3 -2 -1
		{
			if ( (strcmp(e->filename,"/proc/sys/kernel/yama/ptrace_scope")==0) && memory_state==3 ){
				// 可不打印
				printf("%-8s %-16s %-16s %-7d %-7d %-10ld  sensitive file open:%s \n",
					ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
					print_flag = false;
				memory_state--;
			}

			int status=my_match(regx_proc_mem,e->filename);
			if(0 == status){
				char pid[10] = "";
				get_proc_pid(e->filename,pid);
				// printf(" get_proc_pid  proc:%s  pid:%s atoi(pid):%d \n",e->filename,pid,atoi(pid));
				if (atoi(pid) != e->pid){
					printf("%-8s %-16s %-16s %-7d %-7d %-10ld  detect program open other program's /proc/%s/mem \n",
					ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,pid);
					print_flag = false;
				}
			}
			if((0 == status)&& memory_state==2){
				// char pid[10] = "";
				// get_proc_pid(e->filename,pid);
				// printf(" get_proc_pid  proc:%s  pid:%s \n",e->filename,pid);
				memory_state--;
			}

			status=my_match(regx_proc_maps,e->filename);
			if(0 == status){
				char pid[10] = "";
				get_proc_pid(e->filename,pid);
				// printf(" get_proc_pid  proc:%s  pid:%s atoi(pid):%d \n",e->filename,pid,atoi(pid));
				if (atoi(pid) != e->pid){
					printf("%-8s %-16s %-16s %-7d %-7d %-10ld  detect program open other program's /proc/%d/maps \n",
					ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,atoi(pid));
					print_flag = false;
				}
			}
			if(0 == status && memory_state==1){
				memory_state--;
			}

			if (memory_state == 0){
				printf("%-8s %-16s %-16s %-7d %-7d %-10ld  program's memory may be rewrite! \n",
					ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns);
					print_flag = false;
				memory_state=3;
			}
		}
		// # seq 基于读取序列 seq_1 -> seq_2  -- ssh-sysadmin
		{
			for (int i = 0; i < Count_ssh_key; i++)
			{
				// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
				if (strstr(e->filename,sysadmin_ssh_key[i]) && (ssh_state==2) )
				{	
					ssh_state = 1;
				}
			}  
			if (strstr(e->filename,sysadmin_ssh_after) &&(ssh_state==1) ){
				ssh_state = 2;
				printf("%-8s %-16s %-16s %-7d %-7d %-10ld  SSH-sysadmin sensitive file open:%s \n",
					ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
					print_flag = false;
			} 
		}
		// TODO 支持更多文件 --- 使用一个字符串数组存储白名单可访问的文件 
		// shadow 程序白名单
		// "/etc/shadow"
		if( strcmp(e->filename,"/etc/shadow") ==0 ){
			int shadow_perm = 0;
			for (int i = 0; i < Count_shadow_whitelist; i++)
			{
				// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
				if (  strcmp(e->comm, shadow_whitelist[i]) ==0 )
				{	
					shadow_perm = 1;
				}
			}  
			if (!shadow_perm){
				// printf("%-8s %-16s %-16s %-7d %-7d %-10ld  no permission open /etc/shadow \n",
				printf("%-8s %-16s %-16s %-7d %-7d %-10ld  no permission open %s \n",
					ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
					print_flag = false;
			}
		}

		break;
	}
	case EXEC :
	{
		unsigned long cap = e->cap_effective[1] & ((unsigned long)e->cap_effective[0]<<32);
		// printf("%lx \n",cap);
		if (cap == PRIVILEGED_CAP && strcmp(e->comm, "runc:[2:INIT]")==0){
			printf("cap_effective:%lx \n",cap);
			printf("%-8s %-16s %-16s %-7d %-7d %-10ld  container-id: %s, cap_effective:%x%x , The privileged container start \n",
					ts, "EXEC", e->comm, e->pid, e->ppid, e->pid_ns,e->utsnodename, e->cap_effective[1], e->cap_effective[0]);
			print_flag = false;
			break ;
		}

		if (cap != DEFAULT_CAP && strcmp(e->comm, "runc:[2:INIT]")==0){
			printf("cap_effective:%lx \n",cap);
			printf("%-8s %-16s %-16s %-7d %-7d %-10ld  container-id: %s, cap_effective:%x%x , The container starts with all the capabilities set too large \n",
					ts, "EXEC", e->comm, e->pid, e->ppid, e->pid_ns,e->utsnodename, e->cap_effective[1], e->cap_effective[0]);
			print_flag = false;
			break ;
		}
		
		if (host_pidns == e->pid_ns)
		{
			break;
		}
		printf("cap_effective:%lx \n",cap);
		printf("%-8s %-16s %-16s %-7d %-7d %-10ld  container-id: %s, cap_effective:%x%x \n",
					ts, "EXEC", e->comm, e->pid, e->ppid, e->pid_ns,e->utsnodename, e->cap_effective[1], e->cap_effective[0]);
		print_flag = false;

		// TODO 
		// 支持bash监控
		// if ( strcmp(e->comm, "bash")==0
		// 			 || strcmp(e->comm, "sh")==0
		// 			 || strcmp(e->comm, "csh")==0
		// 			 || strcmp(e->comm, "tcsh")==0
		// 			 || strcmp(e->comm, "ash")==0
		// 			 || strcmp(e->comm, "zsh")==0 ) {

		// }

	}
	default:
		break;
	}

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
	struct hids_bpf *skel;
	int err;
	unsigned long * systable_p;
	// unsigned int syscalltable= 0;
	char syscalltable[MAX_KSYM_NAME_SIZE]= "sys_call_table";

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = hids_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = hids_bpf__load(skel);
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
	err = hids_bpf__attach(skel);
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
	printf("%-8s %-18s %-12s %-9s %-9s %-12s %s\n",
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
	hids_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}


