#ifndef __XT_DPI_H_
#define __XT_DPI_H_

#include "dpi_types.h"

#define NF_DPI_BUILD_INFO   ""
#define DPI_VERSION         "0.01"
#define DPI_LIB_VERSION     "DPI01R01"

#define MAX_FILE_NAME_LEN       256
#define MAX_DEV_NUM             16 
#define MAX_DEV_NAME_LEN        8 

typedef struct _ipt_dpi_info {
    CHAR arrDpiLibFile[MAX_FILE_NAME_LEN]; 
    CHAR arrDpiCfgFile[MAX_FILE_NAME_LEN]; 
    UINT32 uInnerDevNum; 
    CHAR arrInnerDevArr[MAX_DEV_NUM][MAX_DEV_NAME_LEN];
} IPT_DPI_INFO_S;


#endif
