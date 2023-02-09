#include <linux/kernel.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <ctype.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "hids.h"
#include "config.h"
#include "hids.skel.h"

// com_funaddr.c 中的库函数
int do_so_check(void);

// #define DEBUG_EN
#ifdef DEBUG_EN
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

// 输出所有mount //是否只检测不同命名空间的mount
#define ONLY_MOUNT_DOCKER

// 打印所有事件
// #define NORMAL

// 是否检测LAZAGNE 敏感目录
// #define LAZAGNE

#define MAX_LEN_ENTRY 256
#define MAX_PROC_PIDNS 64

struct bpf_map * syscall_addrs_u;
struct bpf_map * judge_map_u;
struct bpf_map * pid_conid_map_u;
struct bpf_map * lkm_map_u;

unsigned long _stext,_etext;
unsigned long host_pidns;

//----------------------------------------- Mount event -------------------------------------------------
static int Count_sensitive_mount_pre = 6;
static char *sensitive_mount_pre[] = {"cgroup","/dev/sd","/etc","/root",
            "/var/run","/proc/sys/kernel","/etc/ssh"};

static int Count_sensitive_mount_all = 1;
static char *sensitive_mount_all[] = {"/proc"};

//----------------------------------------- Open event -------------------------------------------------
static int Count_sensitive_file_c = 2;
static char *sensitive_file_c[] = {"shadow","crontab","sshd_config"};

#ifdef LAZAGNE
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

#endif

//------------------------------------------------------------ help fun ----------------------------------------------

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
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

/// 根据PID对应的进程是否运行在容器中 0:不运行于容器中 1：运行于容器中
static int judge_run_in_docker(int pid, unsigned long pid_ns){
	// 进程PID-ns与主机侧相同，不运行在容器中
	if(pid_ns == host_pidns){
		return 0;
	}
	// 打开并读取 PID对应的Cgroup   /proc/$(PID)/Cgroup
	char cgroup_path[MAX_LEN_ENTRY]  = {0}; 
	char *path = strcat(cgroup_path,"/proc/");
	char pid_s[33] = {0};
	// char* pid_str=itoa(pid, pid_s, 10); // linux中无itoa
	int ret = sprintf(pid_s, "%d", pid);
	if(ret < 0){
		DEBUG("sprintf pid:%d to string fail\n",pid);
		// fprintf(stderr, "sprintf pid:%d to string fail\n",pid);
		return 0;
	}
	path = strcat(path, pid_s);
	path = strcat(path, "/cgroup");
	// DEBUG("Cgroup path : %s \n",path);
	FILE *cgroup_file = fopen(path, "r");
	if( cgroup_file == NULL ){
		DEBUG("[judge_run_in_docker] Open %s fail , default : treat as running in docker \n",path);
		// fprintf(stderr, "[judge_run_in_docker] Open %s fail\n",path);
		return 1;
	}
	char *read                            = NULL;
	char *start_p                         = NULL;
	char str_line[MAX_LEN_ENTRY]  = {0}; 
	char containerid[MAX_PATH_NAME_SIZE]  = {0};
	read = fgets(str_line, MAX_LEN_ENTRY, cgroup_file);//从输入文件读取一行字符串
	while(read){
		start_p = strstr(str_line, "::/docker/");
		if(start_p != NULL)
		{
			// DEBUG("Found ::/docker/\n");
			// DEBUG("Line is:%s\n", str_line);
			// fprintf(stderr, "start_p %s\n",start_p);
			char *containerid_s = start_p + sizeof("::/docker/") - 1;
			// fprintf(stderr, "CONTARNER-IS %s\n",containerid_s);
			// 将pid - CONTARNER-ID 对应关系存入 map中
			strcpy(containerid,containerid_s);
			bpf_map__update_elem(pid_conid_map_u, &pid, sizeof(pid), containerid, MAX_PATH_NAME_SIZE, BPF_ANY);
			return 1;
			
		}
		// DEBUG("Line is:%s\n", str_line);
		read = fgets(str_line, MAX_LEN_ENTRY, cgroup_file);//从输入文件读取一行字符串
	}
	return 0;
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
	case MODULE_LOAD:
		{
			int pid = e->pid;
			char module_name[MAX_KSYM_NAME_SIZE]  = {0};
			bpf_map__lookup_elem(lkm_map_u, &pid, sizeof(pid), module_name, MAX_KSYM_NAME_SIZE, BPF_ANY);
			fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  load module, module-name is %s !\n",
				ts, "MODULE_LOAD", e->comm, e->pid, e->ppid, e->pid_ns, module_name);
			// bpf_map__lookup_elem(pid_conid_map_u, &pid, sizeof(pid), containerid, MAX_PATH_NAME_SIZE, BPF_ANY);
			print_flag = false;
		}
		break;
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
					fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld syscall[%d]: be changed. May have been attacked by kernel rootkit !\n",
						ts, "SYSCALL_TABLE_HOOK", e->comm, e->pid, e->ppid, e->pid_ns, idx);
					
					// e->event_type = SYSCALL_TABLE_HOOK;
				}
				// bpf_map__update_elem(skel->maps.ksymbols_map,&syscalltable,sizeof(syscalltable),systable_p,sizeof(*systable_p),BPF_ANY);
			}
			// print module name
			int pid = e->pid;
			char module_name[MAX_KSYM_NAME_SIZE]  = {0};
			bpf_map__lookup_elem(lkm_map_u, &pid, sizeof(pid), module_name, MAX_KSYM_NAME_SIZE, BPF_ANY);
			fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  insert module finished, module-name is %s ! \n",
				ts, "INSERT_MODULE_FINISH", e->comm, e->pid, e->ppid, e->pid_ns, module_name);
			for (int i = 0; i < LKM_ROOTKIT_CNT; i++)
			{
				// fprintf(stderr, /*printf(*/"rootkit list %s ! \n",lkm_sensitive_names[i]);
				if (strncmp(module_name,lkm_sensitive_names[i], MAX_KSYM_NAME_SIZE) == 0){
					fprintf(stderr, /*printf(*/"Discover LKM-RootKits!!!  rootkit name is %s ! \n",module_name);
				}
			}
			print_flag = false;
		}
		break;
	case KHOOK:
		{
			// using Kernel instruction operation function
			fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  using Kernel instruction operation function!\n",
					ts, "KHOOK", e->comm, e->pid, e->ppid, e->pid_ns);
			print_flag = false;
		}
		break;
	case KPROBE:
		{
			// using Kernel KPROBE operation function
			fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  using Kernel KPROBE framework!\n",
					ts, "KPROBE", e->comm, e->pid, e->ppid, e->pid_ns);
			print_flag = false;
		} 
		break;
	case KILL:
		{
			int sig = e->sig;
			// printf("kill event %d \n",sig);
			if(sig == USER_ROOTKIT){
				// printf("++++++++++++++ kill sig: 44  ++++++++++++ \n");
				do_so_check();   //TODO
				if(getenv("LD_PRELOAD")) {
					printf("... LD_PRELOAD is visible in the local environment variables.. little warning\n");
					printf("%-8s %-18s %-12s %-9s %-9s %-12s %s\n",
				"TIME", "EVENT", "COMM", "PID", "PPID", "PID_NS" ,"DESCRIBE");
				}
				if(access("/etc/ld.so.preload", F_OK) != -1) {
					printf("... /etc/ld.so.preload DOES definitely exist.. little warning\n");
					printf("%-8s %-18s %-12s %-9s %-9s %-12s %s\n",
				"TIME", "EVENT", "COMM", "PID", "PPID", "PID_NS" ,"DESCRIBE");
				}
			}
		}
		break;
	case MOUNT:
	{
		DEBUG("mount start \n");
#ifdef ONLY_MOUNT_DOCKER
		// 简单namespace判断当前进程是否运行在docker
		// if (host_pidns == e->pid_ns)
		// DEBUG("host_pidns: %ld, e->pid_ns: %ld \n",host_pidns,e->pid_ns);
		// 使用 judge函数判断当前进程是否运行在docker  ---- 有问题的，要依据judge_map_u判断
		// if (judge_run_in_docker(e->pid, e->pid_ns) == 0)
		// {
		// 	DEBUG("host MOUNT \n");
		// 	break;
		// }else{
			// DEBUG("check start \n");
			int pid = e->pid;
			unsigned long pid_ns = e->pid_ns;
			int result = 0 ; 
			char containerid[MAX_PATH_NAME_SIZE]  = {0};
			// DEBUG("1 \n");
			// bpf_map__update_elem(judge_map_u, &pid, sizeof(pid), &result, sizeof(result), BPF_ANY);
			int ret = bpf_map__lookup_elem(judge_map_u, &pid, sizeof(pid), &result, sizeof(result), BPF_ANY);
			// DEBUG("2 \n");
			if (!ret)
			{
				// 在judge_map中查找成功
				DEBUG("[1] bpf_map__lookup_elem process-pid:[%d], judge_run_in_docker result: %d \n",pid,result);
			}else{
				// 在judge_map中查找失败, TODO 则对相应PID重新判读再存入map中
				DEBUG("[1] bpf_map__lookup_elem process-pid:[%d], on found \n",pid);
				break ;
			}
			// key:PID对应的value指不为0时，表示
			if (result){
				// DEBUG("docker MOUNT \n");
#endif
				for (int i = 0; i < Count_sensitive_mount_pre; i++)
				{
					// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
					if (strncmp(e->mount_dev,sensitive_mount_pre[i], strlen(sensitive_mount_pre[i])) == 0)
					{	
						fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  Container-id:%s mount dev:%s dir:%s\n",
						ts, "[Sensitive directory mount]", e->comm, e->pid, e->ppid, e->pid_ns, e->utsnodename,e->mount_dev,e->mount_dir);
						// char containerid[MAX_PATH_NAME_SIZE]  = {0};
						ret = bpf_map__lookup_elem(pid_conid_map_u, &pid, sizeof(pid), containerid, MAX_PATH_NAME_SIZE, BPF_ANY);
						if (!ret)
							fprintf(stderr, /*printf(*/"container is: %s \n",
							containerid);
						print_flag = false;
					}
				}
				// all fit 完全匹配
				for (int i = 0; i < Count_sensitive_mount_all; i++)
				{
					// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
					if (strcmp(e->mount_dev,sensitive_mount_all[i]) == 0)
					{	
						fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld   Container-id:%s mount dev:%s dir:%s\n",
						ts, "[Sensitive directory mount]", e->comm, e->pid, e->ppid, e->pid_ns, e->utsnodename, e->mount_dev,e->mount_dir);
						// char containerid[MAX_PATH_NAME_SIZE]  = {0};
						ret = bpf_map__lookup_elem(pid_conid_map_u, &pid, sizeof(pid), containerid, MAX_PATH_NAME_SIZE, BPF_ANY);
						if (!ret)
							fprintf(stderr, /*printf(*/"container is: %s \n",
							containerid);
						print_flag = false;
					}
				}
#ifdef ONLY_MOUNT_DOCKER
			}
		// }
#endif
		// // pre fit 前缀匹配
		// for (int i = 0; i < Count_sensitive_mount_pre; i++)
		// {
		// 	// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
		// 	if (strncmp(e->mount_dev,sensitive_mount_pre[i], strlen(sensitive_mount_pre[i])) == 0)
		// 	{	
		// 		fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  Container-id:%s mount dev:%s dir:%s\n",
		// 		ts, "[Sensitive directory mount]", e->comm, e->pid, e->ppid, e->pid_ns, e->utsnodename,e->mount_dev,e->mount_dir);
		// 		print_flag = false;
		// 	}
		// }
		// // all fit 完全匹配
		// for (int i = 0; i < Count_sensitive_mount_all; i++)
		// {
		// 	// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
		// 	if (strcmp(e->mount_dev,sensitive_mount_all[i]) == 0)
		// 	{	
		// 		fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld   Container-id:%s mount dev:%s dir:%s\n",
		// 		ts, "[Sensitive directory mount]", e->comm, e->pid, e->ppid, e->pid_ns, e->utsnodename, e->mount_dev,e->mount_dir);
		// 		print_flag = false;
		// 	}
		// }
		break;
	}
	case OPEN_FILE:
	{
		int pid = e->pid;
		unsigned long pid_ns = e->pid_ns;
		int result = 0 ; 
		char containerid[MAX_PATH_NAME_SIZE]  = {0};
		// DEBUG("1 \n");
		// bpf_map__update_elem(judge_map_u, &pid, sizeof(pid), &result, sizeof(result), BPF_ANY);
		int ret = bpf_map__lookup_elem(judge_map_u, &pid, sizeof(pid), &result, sizeof(result), BPF_ANY);
		// DEBUG("2 \n");
		if (!ret)
		{
			// 在judge_map中查找成功
			// DEBUG("[1] bpf_map__lookup_elem process-pid:[%d], judge_run_in_docker result: %d \n",pid,result);
		}else{
			// 在judge_map中查找失败, TODO 则对相应PID重新判读再存入map中
			// DEBUG("[1] bpf_map__lookup_elem process-pid:[%d], on found \n",pid);
			break ;
		}
		// key:PID对应的value指不为0时，表示
		if (result){
			// DEBUG("docker OPEN \n");
			for (int i = 0; i < Count_sensitive_file_c; i++)
			{
				// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
				if ( strstr(e->filename,sensitive_file_c[i]) )
				{	
					fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  container-id: %s,Container file escape attack : %s \n",
					ts, "[File open]", e->comm, e->pid, e->ppid, e->pid_ns, e->utsnodename,e->filename);
					// char containerid[MAX_PATH_NAME_SIZE]  = {0};
					ret = bpf_map__lookup_elem(pid_conid_map_u, &pid, sizeof(pid), containerid, MAX_PATH_NAME_SIZE, BPF_ANY);
					if (!ret)
						fprintf(stderr, /*printf(*/"container is: %s \n",
						containerid);
					print_flag = false;
				}
			}
		}	
		// printf("%-8s %-20s %-20s %-7d %-7d %-10ld  sensitive file open:%s \n",
		// 			ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
		// 			print_flag = false;	

#ifdef LAZAGNE		
		{
			// 单目录特征检测
			for (int i = 0; i < Count_monitorfiles; i++)
			{
				// DEBUG("str: %s  | len:%ld \n",sensitive_mount_pre[i],strlen(sensitive_mount_pre[i]));
				// if (strcmp(e->filename,monitorfiles[i]) == 0)
				if (strstr(e->filename,monitorfiles[i]))
				{	
					printf("%-8s %-20s %-20s %-7d %-7d %-10ld  sensitive file open:%s \n",
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
						printf("%-8s %-20s %-20s %-7d %-7d %-10ld  sensitive file open:%s \n",
						ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
						print_flag = false;
					}
				}
			}
			// # memorpy库检测序列  memorpy state -> 3 -2 -1
			{
				if ( (strcmp(e->filename,"/proc/sys/kernel/yama/ptrace_scope")==0) && memory_state==3 ){
					// 可不打印
					printf("%-8s %-20s %-20s %-7d %-7d %-10ld  sensitive file open:%s \n",
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
						printf("%-8s %-20s %-20s %-7d %-7d %-10ld  detect program open other program's /proc/%s/mem \n",
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
						printf("%-8s %-20s %-20s %-7d %-7d %-10ld  detect program open other program's /proc/%d/maps \n",
						ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,atoi(pid));
						print_flag = false;
					}
				}
				if(0 == status && memory_state==1){
					memory_state--;
				}

				if (memory_state == 0){
					printf("%-8s %-20s %-20s %-7d %-7d %-10ld  program's memory may be rewrite! \n",
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
					printf("%-8s %-20s %-20s %-7d %-7d %-10ld  SSH-sysadmin sensitive file open:%s \n",
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
					// printf("%-8s %-20s %-20s %-7d %-7d %-10ld  no permission open /etc/shadow \n",
					printf("%-8s %-20s %-20s %-7d %-7d %-10ld  no permission open %s \n",
						ts, "FILE-OPEN", e->comm, e->pid, e->ppid, e->pid_ns,e->filename);
						print_flag = false;
				}
			}
		}
#endif

		break;
	}
	case EXEC :
	{
		// 在execve时,进行容器判读并存入Map中
		int pid = e->pid;
		unsigned long pid_ns = e->pid_ns;
		int result = 0;
		char containerid[MAX_PATH_NAME_SIZE]  = {0};
		if(judge_run_in_docker(pid, pid_ns)){
			result = 1;
			bpf_map__update_elem(judge_map_u, &pid, sizeof(pid), &result, sizeof(result), BPF_ANY);
			// bpf_map__lookup_elem(judge_map_u, &pid, sizeof(pid), &result, sizeof(result), BPF_ANY);
			// DEBUG("[0] bpf_map__update_elem process-pid:[%d], judge_run_in_docker result: %d \n",pid,result);
		}else{
			result = 0;
			bpf_map__update_elem(judge_map_u, &pid, sizeof(pid), &result, sizeof(result), BPF_ANY);
			// bpf_map__lookup_elem(judge_map_u, &pid, sizeof(pid), &result, sizeof(result), BPF_ANY);
			// DEBUG("[0] bpf_map__update_elem process-pid:[%d], judge_run_in_docker result: %d \n",pid,result);
		}

		// 容器权限检测
		// printf("cap_effective[0]:%x  e->cap_effective[1]:%x \n",e->cap_effective[0],e->cap_effective[1]);
		// printf("cap_effective[0]:%x  e->cap_effective[1]:%lx \n",e->cap_effective[0],((unsigned long)e->cap_effective[1])<<32);
		unsigned long cap = ((unsigned long)e->cap_effective[0] & 0x00000000ffffffff) | ((((unsigned long)e->cap_effective[1])<<32));
		// printf("%lx \n",cap);
		if (cap == PRIVILEGED_CAP && strcmp(e->comm, "runc:[2:INIT]")==0){
			// printf("  ---  cap_effective:%lx  ---  \n",cap);
			fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  container-id: %s, cap_effective:%x%x , The privileged container start \n",
					ts, "[Container start]", e->comm, e->pid, e->ppid, e->pid_ns,e->utsnodename, e->cap_effective[1], e->cap_effective[0]);
			int ret = bpf_map__lookup_elem(pid_conid_map_u, &pid, sizeof(pid), containerid, MAX_PATH_NAME_SIZE, BPF_ANY);
			if (!ret)
				fprintf(stderr, /*printf(*/"container is: %s \n",
				containerid);
			print_flag = false;
			break ;
		}

		if (cap != DEFAULT_CAP && strcmp(e->comm, "runc:[2:INIT]")==0){
			// printf("cap_effective[0]:%x  e->cap_effective[1]:%x \n",e->cap_effective[0],e->cap_effective[1]);
			// printf("cap_effective[0]:%lx  e->cap_effective[1]:%lx \n",(unsigned long)e->cap_effective[0]& 0x00000000ffffffff,((unsigned long)e->cap_effective[1])<<32);
			// printf("cap_effective:%lx ---",cap);
			fprintf(stderr, /*printf(*/"%-8s %-20s %-20s %-7d %-7d %-10ld  container-id: %s, cap_effective:%x%x , The container starts with all the capabilities set too large \n",
					ts, "[Container start]", e->comm, e->pid, e->ppid, e->pid_ns,e->utsnodename, e->cap_effective[1], e->cap_effective[0]);
			int ret = bpf_map__lookup_elem(pid_conid_map_u, &pid, sizeof(pid), containerid, MAX_PATH_NAME_SIZE, BPF_ANY);
			if (!ret)
				fprintf(stderr, /*printf(*/"container is: %s \n",
				containerid);
			print_flag = false;
			break ;
		}
		// if (host_pidns == e->pid_ns)
		// {
		// 	break;
		// }
		// printf("cap_effective:%lx ---",cap);
		// printf("%-8s %-20s %-20s %-7d %-7d %-10ld  container-id: %s, cap_effective:%x%x \n",
		// 			ts, "EXEC", e->comm, e->pid, e->ppid, e->pid_ns,e->utsnodename, e->cap_effective[1], e->cap_effective[0]);
		// print_flag = false;

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
		printf("%-8s %-20s %-20s %-7d %-7d %-10ld %s\n",
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
	char syscalltable[MAX_KSYM_NAME_SIZE]	= "sys_call_table";
	char host_pid_s[MAX_KSYM_NAME_SIZE]		= "host_pid";
	unsigned long host_pid = (unsigned long)getpid();
	// pid_t getpid(void);

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

	// 存储 map指针
	syscall_addrs_u = skel->maps.syscall_addrs;
	judge_map_u = skel->maps.judge_map;
	pid_conid_map_u = skel->maps.pid_conid_map;
	lkm_map_u = skel->maps.lkm_map;

	//get sys_call_table addr
	// system("cat /proc/kallsyms | grep -w sys_call_table | awk '{print $1}'");
	systable_p = obtain_syscall_table_by_proc();
	DEBUG("[main] sys_call_table : %lx \n",*systable_p);
	
	int fd = bpf_map__fd(skel->maps.ksymbols_map);
	DEBUG("[fd]ksymbols_map  : %d \n",fd);
	bpf_map__update_elem(skel->maps.ksymbols_map,&syscalltable,sizeof(syscalltable),systable_p,sizeof(*systable_p),BPF_ANY);
	// ring_buffer__new
	// bpf_map_update_elem(, &pid, &ts, BPF_ANY);
	
	// 保存 host_pid 到 ksymbols_map 中
	bpf_map__update_elem(skel->maps.ksymbols_map,&host_pid_s,sizeof(host_pid_s),&host_pid,sizeof(host_pid),BPF_ANY);

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
	fprintf(stderr, /*printf(*/"%-8s %-18s %-12s %-9s %-9s %-12s %s\n",
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


