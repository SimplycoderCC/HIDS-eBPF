#include "hids.h"


#define LKM_ROOTKIT_CNT 3
static char lkm_sensitive_names [LKM_ROOTKIT_CNT][MAX_KSYM_NAME_SIZE] = {
// char lkm_sensitive_names [LKM_ROOTKIT_CNT][MAX_KSYM_NAME_SIZE] = {    
    "diamorphine",
    "brokepkg",
    "reveng_rtkit"
};