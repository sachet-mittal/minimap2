/*
 * CSNVMe header file
 *
 * Author: Subrahmaya Lingappa, subrahmanya.lingappa@wdc.com
 * date: 26 June, 2019
 * */
#define  __USE_GNU
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/ioctl.h>
#include<unistd.h>
#include<linux/nvme_ioctl.h>
#include<fcntl.h>
#include<sys/uio.h>
#include<linux/types.h>

#include "orcs_bitops.h"

extern FILE *g_dbgstream;
//#define SPDK_NVME_OPC_CSNVME 0x85

#define CSS_UNUSED     __attribute__ ((unused))

#define xstr(a) str(a)
#define str(a) #a

#define BIT(nr) (1UL << (nr))

uint64_t get_time_in_us(void);

#define XFER_TO_TARGET BIT(0)
#define XFER_FROM_TARGET BIT(1)
#define DATA_DIR_TO_TARGET BIT(2)
#define DATA_DIR_FM_TARGET BIT(3)
#define DATA_DIR_BOTH (DATA_DIR_TO_TARGET|DATA_DIR_FM_TARGET)


#define NVM_ITEM_TYPE_NODE 0
#define NVM_ITEM_TYPE_CTRL 1
#define NVM_ITEM_TYPE_NS 2
#define NVM_ITEM_TYPE_STRUCT 3

#if 0
//#define DLOG(...)
#define XFER_LOG(...)
//#define DLOG printf
#define DLOG(msg, ...) do {\
                        fprintf(stdout, "%s : %d : "msg, \
                                __func__, __LINE__, ##__VA_ARGS__);\
                    } while (0)

#else
/* expression to convert microseconds to HH:MM:SS:MS:US format for debug prints*/
#define XPR(n) n/60/60/1000/1000,n/60/1000/1000%60,n/1000/1000%60,n/1000%1000,n%1000

//#define dbgstream g_dbgstream

#define LOG_TO_FILE
#define DBG_FILE "csn.log"
#define dbgfd stdout
#define KNRM  0
#define KRED  1
#define KGRN  2
#define KYEL  3
#define KBLU  4
#define KMAG  5
#define KCYN  6
#define KWHT  7

extern uint32_t  debug_level;
extern uint32_t log_to_file;
extern char tcols[KWHT+1][20];


#define CLOG_ERR     (1<<0)
#define CLOG_INFO    (1<<1)
#define CLOG_DBG     (1<<2)
#define CLOG_XFER    (1<<3)
#define CLOG_PROF    (1<<4)


#define LOG(level, ...) do {  \
                            if ((level) & (debug_level)) { \
                                FILE *dbgstream; \
                                if(log_to_file)\
                                {dbgstream = fopen(DBG_FILE, "a+");} \
                                else \
                                {dbgstream = dbgfd;} \
                                fprintf(dbgstream,"%s", tcols[level>>16]); \
                                fprintf(dbgstream,\
					"[ %02ld:%02ld:%02ld:%03ld:%03ld ] : ",\
					XPR(get_time_in_us()) , __func__); \
                                /*if((CLOG_DBG) & (debug_level)) */\
                                    fprintf(dbgstream,"%10s : %03d : ",\
					    __func__, __LINE__); \
                                fprintf(dbgstream, __VA_ARGS__); \
                                fprintf(dbgstream,"%s", tcols[KNRM]); \
                                fflush(dbgstream); \
                            } \
                        } while (0)
#define XFER_LOG(...)   LOG( CLOG_XFER, __VA_ARGS__)
#define ELOG(...)   LOG( (CLOG_ERR) | (KRED << 16), __VA_ARGS__)
#define ILOG(...)   LOG( (CLOG_INFO)|(KGRN << 16), __VA_ARGS__)
#define DLOG(...)   LOG( (CLOG_DBG) , __VA_ARGS__)
#define PLOG(...)   LOG( (CLOG_PROF) , __VA_ARGS__)

#endif

#define TRACE() DLOG("%s:%d Trace ... \n", __func__, __LINE__)

#define WAIT(...) { ILOG(" \n\n %s:%s: line#%d\n", __FILE__, __FUNCTION__, __LINE__); while(1);}

#define BUG_ON(fmt, args...) \
{ \
    ELOG(" \n\n %s:%s: line#%d: ---BUG--- ", __FILE__, __FUNCTION__, __LINE__); \
    printf(fmt, ## args);\
    while(1); \
}

#define ASSERT(expr) \
        if (!(expr)) {\
            ELOG(" \n\n %s:%s: line#%d\n", __FILE__, __FUNCTION__, __LINE__);\
            BUG_ON("%s: Assertion failed!\n", #expr); \
        }
#define ASSERTF(A, ...) if(!(A)) {ELOG(__VA_ARGS__); ASSERT(A); }

#define MIN(a, b)                \
    ({ __typeof__ (a) _a = (a);        \
        __typeof__ (b) _b = (b);    \
        _a < _b ? _a : _b; })

#define MAX(a, b)                \
    ({ __typeof__ (a) _a = (a);        \
        __typeof__ (b) _b = (b);    \
        _a > _b ? _a : _b; })

/*TODO: detect/input args ? */
//#define CSS_NVME_DEV    "/dev/nvme0n1"
#define CSS_IMG_ARCHIVE "cs.tar"
#define CSS_UBPF_OBJ    "bpf.o"
#define CSS_INFR_OBJS   "objs.txt"
#define CSS_BLOCK_SIZE  4096

#define CSS_STR_LEN     256
#define TEXT_OFFSET      0x100 //(1MB/4096)
#define DATA_OFFSET     0x10000 //(256MB/4096)
#define RSLT_OFFSET     0x20000 //(512MB/4096)

#define CSS_ENG_TYPE_GZIP   1
#define CSS_ENG_TYPE_DOCK   2
#define CSS_ENG_TYPE_UBPF   3
#define CSS_ENG_TYPE_OSSL   4
#define CSS_ENG_TYPE_INFR   5
#define CSS_ENG_TYPE_ECRS   6
#define CSS_ENG_TYPE_LZMA   7
#define CSS_ENG_TYPE_MINIMAP   8

#define DATA_TYPE_STRM   0
#define DATA_TYPE_FILE   1


typedef struct {
    /* flags */
    int32_t flags;

    /* host block size */
    int32_t block_sz;
    /* executable image length */
    int64_t exe_len;
    /* nvme device  file-name */
    uint8_t  dfile_name[CSS_STR_LEN];
    /* executable image file-name */
    uint8_t  efile_name[CSS_STR_LEN];
    /* executable arguments */
    uint8_t  exe_args[2*CSS_STR_LEN];
    /* executable image offset */
    int64_t exe_offset;
    /* input file name */
    uint8_t  ifile_name[CSS_STR_LEN];
    /* output file name */
    uint8_t  ofile_name[CSS_STR_LEN];
    /* data offset */
    int64_t data_offset;
    /* data length */
    int64_t data_len;
    /* executed results offset */
    int64_t result_offset;
}hdata_t;

typedef struct {
    /* execution status */
    int32_t status;
    /* executed results length */
    int64_t result_len;
}tdata_t;

typedef struct{
    // minimap related parameters
    int qlen;
    int tlen;
    int8_t m;
    int8_t q;
    int8_t e;
    int8_t q2;
    int8_t e2;
    int w;
    int zdrop;
    int end_bonus;
    int flag;
    // ksw_extz_t *ez expanded
    uint32_t ez_max:31, ez_zdropped:1;
    int ez_max_q, ez_max_t;      // max extension coordinate
    int ez_mqe, ez_mqe_t;        // max score when reaching the end of query
    int ez_mte, ez_mte_q;        // max score when reaching the end of target
    int ez_score;             // max score reaching both ends; may be KSW_NEG_INF
    int ez_m_cigar, ez_n_cigar;
    int ez_reach_end;

} mmdata_t;

#define DATA_SET_TYPE_INSITU   0
#define DATA_SET_TYPE_STREAM   1

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE-1))

#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)

typedef struct {
    int8_t type;
    int8_t flags;
    struct iovec iov;
    int32_t offset_block;
    int32_t num_blocks;
    int8_t *tbuf;
    //uint8_t file_name[CSS_STR_LEN];
}data_set_t;

/* for 1GB CSN device lets partition it to 1024 blocks each of 1M size */
#define MAX_MEM_BLOCK_SIZE   CSS_BLOCK_SIZE
#define MAX_MEM_SIZE   (1024*1024*1024ULL)
#define MAX_MEM_BLOCKS (MAX_MEM_SIZE/MAX_MEM_BLOCK_SIZE)

typedef struct {

    char *item;
    uint8_t node_name[CSS_STR_LEN];
    uint32_t maj_num;
    uint32_t min_num;
    /*FIXME: dynamically detect MAX_MEM_BLOCKS, by looking into NS data*/
    DECLARE_BITMAP(free_mem_blocks, MAX_MEM_BLOCKS);
    /* mutext to protect mem allocation bitmap */
    pthread_mutex_t free_mem_blocks_mutex;
}cs_node_t;

typedef struct cs_nodes_data_s
{
    uint64_t g_op_tag;
}cs_nodes_data_t;


#define EC_OPC_INIT 1
#define EC_OPC_ENCD 2
#define EC_OPC_ENUP 3

/** Supported file formats */
typedef enum {
    ELZMA_lzip, /**< the lzip format which includes a magic number and
                 *   CRC check */
    ELZMA_lzma  /**< the LZMA-Alone format, originally designed by
                 *   Igor Pavlov and in widespread use due to lzmautils,
                 *   lacking both aforementioned features of lzip */
/* XXX: future, potentially   ,
    ELZMA_xz
*/
} elzma_file_format;

#define LZ_OPC_CMPR 1
#define LZ_OPC_DCMP 2


#define EC_MAX_ARGS 64

typedef struct {
    int8_t opc;
    int32_t num_args;
    int64_t args[EC_MAX_ARGS];
    int32_t num_data_sets;
    data_set_t data_sets[EC_MAX_ARGS];
}job_t;

/* CSS command structure */
typedef struct css_cmd_s {

    union {
        uint8_t buf[4096];

        struct {
            /* Unique CSS signature 0xC550D0CC*/
            uint32_t signature;

            /* Unique engine tag to identify the compute type */
            uint32_t engine;

            /* Unique operation tag */
            uint64_t op_tag;

            /* allocated node number */
            uint64_t node_num;

            /* host block size */
            int32_t block_sz;

            /* device block offset */
            int32_t offset_block;
            /* nvme device  file-name */
            uint8_t  dfile_name[CSS_STR_LEN];

            /* executable arguments */
            uint8_t  exe_args[2*CSS_STR_LEN];

            union {
                hdata_t hdata;
                job_t   job;

            };
            union{
                tdata_t tdata;
                mmdata_t mmdata;
            };

            int64_t mem_start_block;

            int64_t mem_num_blocks;

            /* checksum of the structure */
            uint32_t crc;
        };
    };

}css_cmd_t;

void dump_css_cmd(css_cmd_t *cmd);
int32_t copy_data(char *ifile, char* ofile, uint32_t if_offset, uint32_t of_offset, int32_t if_len );
int32_t get_file_len(uint8_t *fname);
void wait_for_op_status(css_cmd_t *cmd);

/*in-situ CS APIs */
css_cmd_t * css_job_init(
        int engine,
        char *device_name,
        char *efile_name,
        char *ifile,
        char *ofile,
        char *args);
void css_job_free(css_cmd_t *cmd);
void send_job_cmd(css_cmd_t *cmd);
int32_t retrieve_results(css_cmd_t *cmd );
//void copy_buff_data_to_file(uint8_t *data_buf, char* ifile, uint32_t buf_offset, uint32_t fd_offset, int32_t len, int8_t dir );
void copy_buff_data_to_file(uint8_t *data_buf,
        int fd,
        //char* ifile,
        uint32_t buf_offset, uint32_t fd_offset, int32_t len, int8_t dir );
//void copy_buff_data_to_file(uint8_t *data_buf, int fd1, char* dfile_name, uint32_t buf_offset, uint32_t fd_offset, int32_t len, int8_t dir );
void truncate_file(uint8_t* ofile, int64_t len);
void send_job_cmd(css_cmd_t *cmd);
int32_t send_input_data( css_cmd_t *cmd );
int32_t send_image_data( css_cmd_t *cmd );

/*Streaming CS API's */

/* format shoulds always be 1, all other values are reserved*/
int cs_simple_compress(char format, const unsigned char * inData,
               size_t inLen, unsigned char ** outData,
               size_t * outLen);
int cs_simple_decompress(char format, const unsigned char * inData,
                 size_t inLen, unsigned char ** outData,
                 size_t * outLen);
