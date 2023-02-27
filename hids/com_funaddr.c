#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <link.h>
#include <dlfcn.h>

// add your own libc symbols to check if you wish
static const char *symbols[] = {
     "accept","ftrace", "access", "execve", "link", "__lxstat", "__lxstat64", 
   "open", "rmdir", "unlink", "unlinkat", "__xstat", "__xstat64",
   "fopen", "fopen64", "opendir", "readdir", "readdir64",
   "pam_authenticate", "pam_open_session", "pam_acct_mgmt",
   "getpwnam", "pam_sm_authenticate", "getpwnam_r", "pcap_loop",
    NULL
};

int dladdr_check(void)
{
    void *dls_handle;
    const char *symbol;
    int i = 0, hooked_funcs = 0;

    if(!(dls_handle = dlopen("/lib/x86_64-linux-gnu/libc.so.6", RTLD_LAZY))) {
        return -1;
    }

 
    printf("[+] beginning dlsym/dladdr check.\n");


    while((symbol = symbols[i++]))
    {

        // printf("[+] checking \033[1;32m%s\033[0m.\n", symbol);

        void *real_symbol_addr, *curr_symbol_addr;
        real_symbol_addr = dlsym(dls_handle, symbol);
        curr_symbol_addr = dlsym(RTLD_NEXT, symbol);

        if(real_symbol_addr != curr_symbol_addr)
        {
            Dl_info real_nfo, curr_nfo;
            // 获取地址的符号信息
            dladdr(real_symbol_addr, &real_nfo);
            dladdr(curr_symbol_addr, &curr_nfo);
            printf("[-] function %s possibly \033[1;31mhijacked\033[0m / location of shared object file: %s\n", symbol, curr_nfo.dli_fname);

            hooked_funcs++;
        }
    }

    dlclose(dls_handle);
    printf("[+] dlsym/dladdr check finished.\n");

    return hooked_funcs;
}

void dlinfo_check(void)
{
    struct link_map *lm;
    dlinfo(dlopen(NULL, RTLD_LAZY), 2, &lm);
    printf("[+] beginning dlinfo check.\n");


    while(lm != NULL)
    {
        // if(strlen(lm->l_name) > 0) printf("%p %s\n", (void *)lm->l_addr, lm->l_name);
        lm = lm->l_next;
    }

    printf("[+] dlinfo check finished.\n");

}

int do_so_check(void)
{
    printf("===========================================user mod rootkit check bdginning =======================================================\n");
    if(getenv("LD_PRELOAD")) printf("... LD_PRELOAD is visible in the local environment variables.. little warning\n");
    if(access("/etc/ld.so.preload", F_OK) != -1) printf("... /etc/ld.so.preload DOES definitely exist.. little warning\n");
    printf("[+] finished basic checks\n\n");

    dlinfo_check();
    //  printf("\n");

    int hooked_funcs = dladdr_check();
    if(hooked_funcs > 0) printf("[!] the dladdr check revealed that there are %d possibly hooked functions. YOUR MALWARE SUUUUCKS.\n", hooked_funcs);
    if(hooked_funcs == 0) printf("[+] no modifications to any libc functions were found. no LD_PRELOAD malware loaded, or your malware is decent.\n");

    printf("===========================================user mod rootkit check finished =========================================================\n");
    return 0;
}