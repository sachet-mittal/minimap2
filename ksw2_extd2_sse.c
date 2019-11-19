#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include "ksw2.h"
#include "kalloc.h"
#include "csn.h"

#define BIT(nr) (1UL << (nr))


#define XFER_TO_TARGET BIT(0)
#define XFER_FROM_TARGET BIT(1)
#define DATA_DIR_TO_TARGET BIT(2)
#define DATA_DIR_FM_TARGET BIT(3)
#define DATA_DIR_BOTH (DATA_DIR_TO_TARGET|DATA_DIR_FM_TARGET)

#ifdef __SSE2__
#include <emmintrin.h>

#ifdef KSW_SSE2_ONLY
#undef __SSE4_1__
#endif

#ifdef __SSE4_1__
#include <smmintrin.h>
#endif

#ifdef KSW_CPU_DISPATCH
#ifdef __SSE4_1__
void ksw_extd2_sse41(void *km, int qlen, uint8_t *query, int tlen, const uint8_t *target, int8_t m, const int8_t *mat,
				   int8_t q, int8_t e, int8_t q2, int8_t e2, int w, int zdrop, int end_bonus, int flag, ksw_extz_t *ez)
#else
void ksw_extd2_sse2(void *km, int qlen, uint8_t *query, int tlen, const uint8_t *target, int8_t m, const int8_t *mat,
				   int8_t q, int8_t e, int8_t q2, int8_t e2, int w, int zdrop, int end_bonus, int flag, ksw_extz_t *ez)
#endif
#else
void ksw_extd2_sse(void *km, int qlen,  uint8_t *query, int tlen, const uint8_t *target, int8_t m, const int8_t *mat,
				   int8_t q, int8_t e, int8_t q2, int8_t e2, int w, int zdrop, int end_bonus, int flag, ksw_extz_t *ez)
#endif // ~KSW_CPU_DISPATCH
{
    //printf("Sachet - Orcs test \n");

    printf("Sachet Start\n");
    //unsigned char *cigar_out;
    //unsigned char *cigar_out = NULL;


    size_t  mem_size = (qlen + tlen + m) * sizeof(uint8_t) + sizeof(css_cmd_t)+ 50000;
    //cmd_sa = css_stream_init(8, NULL, mem_size);
    int32_t csp_num_nodes;
    cs_node_t *csp_nodes;
    cs_nodes_data_t *csp_nodes_data;
    csp_num_nodes = scan_engines(&csp_nodes, &csp_nodes_data);
    css_cmd_t *cmd_sa = NULL;
    cmd_sa = calloc(sizeof(css_cmd_t), 1);

	ASSERTF(cmd_sa != NULL, "calloc failed!");
	if (sizeof(css_cmd_t) > 4096) {
		printf("cmd_sa size: %d\n", sizeof(css_cmd_t));
		ASSERTF(cmd_sa <= 4096, "cmd_sa structure > 4096");
	}

	memset(cmd_sa, 0, sizeof(css_cmd_t));
	cmd_sa->signature = 0xC550D0CC;
	cmd_sa->engine = 8;
	cmd_sa->op_tag = csp_nodes_data->g_op_tag++;
	/*
	 * FIXME: for now allocating jobs to all available nodes in
	 * round-robin fashion, should we load balance it ?
	* why do we need while loop ?
	 */
	do {
		cmd_sa->node_num = rand() % csp_num_nodes;
	}while(0 == csp_nodes[cmd_sa->node_num].min_num);


    cmd_sa->block_sz = 4096;

    sprintf(cmd_sa->dfile_name, "/dev/nvme%dn%d",
		csp_nodes[cmd_sa->node_num].maj_num,
		csp_nodes[cmd_sa->node_num].min_num);
    int req_mem_blocks = (mem_size / 4096) + 3;
    //int req_mem_blocks = (req_mem_sz / 4096) + 3;

    // skipped somethings
    cmd_sa->mem_num_blocks = req_mem_blocks;
	cmd_sa->offset_block = cmd_sa->mem_start_block;


    ASSERT(cmd_sa != NULL);
    //printf("sachet 1000\n");
    cmd_sa->job.opc = 1;

    job_add_data(cmd_sa, query, qlen, DATA_DIR_TO_TARGET);
    //printf("num_data_sets=%" PRId32 "\n", cmd_sa->job.num_data_sets);

    //printf("sachet 2\n");
    //printf("tlen=%d", tlen);
    //job_add_arg(cmd_sa, tlen);
    printf("Sachet 0 \n");
    job_add_data(cmd_sa, target, tlen, DATA_DIR_TO_TARGET);

    //job_add_arg(cmd_sa, m);
    job_add_data(cmd_sa, mat, m, DATA_DIR_TO_TARGET);
    job_add_data(cmd_sa, ez, sizeof(*ez), DATA_DIR_BOTH);
    printf("Sachet 1 \n");
    uint8_t *target_cpy;
    target_cpy = (uint8_t *)malloc(tlen * sizeof(uint8_t));
    for (int i=0; i<tlen; i++){
        target_cpy[i] = target[i];
    }

    //char cigar[4] = {'a', 'a', 'a', 'a'};
    uint32_t *l_out_data = NULL;
    uint32_t *cigar = NULL;
    if (ez->m_cigar==0){
        printf("Sachet 21 \n");

        cigar = calloc(4 * sizeof(uint32_t), 1);
        l_out_data = calloc(4 * sizeof(uint32_t), 1);

        ASSERT(l_out_data != NULL);
        ASSERT(cigar != NULL);

        //job_add_data(cmd_sa, l_out_data, 4, DATA_DIR_FM_TARGET);
        //job_add_data(cmd_sa, cigar, 4 * sizeof(uint32_t), DATA_DIR_BOTH);
        job_add_data(cmd_sa, l_out_data, 4 * sizeof(uint32_t), DATA_DIR_BOTH);
        //cigar = (uint32_t *)calloc(4 * sizeof(uint32_t), 0);
        //job_add_data(cmd_sa, cigar, 4, DATA_DIR_BOTH);
        //job_add_data(cmd_sa, target_cpy, tlen, DATA_DIR_BOTH);
    }else{
        printf("Sachet 22 \n");
        uint32_t *cigar = NULL;
        //cigar = calloc(4 * sizeof(uint32_t), 1);
        cigar = ez->cigar;
        job_add_data(cmd_sa, (unsigned char *) cigar, ez->m_cigar, DATA_DIR_BOTH);
    }



    printf("Sachet 2 \n");
    transfer_data_streams(cmd_sa, XFER_TO_TARGET, cmd_sa->job.num_data_sets);
    printf("Sachet3 \n");
    abort();

    ksw_reset_extz(ez);
cmd_sa->mmdata.qlen=qlen ;
cmd_sa->mmdata.tlen=tlen ;
cmd_sa->mmdata.m=m ;
cmd_sa->mmdata.q=q ;
cmd_sa->mmdata.e=e ;
cmd_sa->mmdata.q2=q2 ;
cmd_sa->mmdata.e2=e2 ;
cmd_sa->mmdata.w=w ;
cmd_sa->mmdata.zdrop=zdrop ;
    /*
 cmd_sa->mmdata.ez_max=ez->max ;
 cmd_sa->mmdata.ez_zdropped =ez->zdropped ;
 cmd_sa->mmdata.ez_max_q =ez->max_q ;
 cmd_sa->mmdata.ez_max_t =ez->max_t ;
 cmd_sa->mmdata.ez_mqe =ez->mqe ;
 cmd_sa->mmdata.ez_mqe_t =ez->mqe_t ;
 cmd_sa->mmdata.ez_mte  =ez->mte ;
 cmd_sa->mmdata.ez_mte_q =ez->mte_q ;
 cmd_sa->mmdata.ez_score =ez->score ;
 cmd_sa->mmdata.ez_m_cigar =ez->m_cigar ;
 cmd_sa->mmdata.ez_n_cigar =ez->n_cigar ;
 cmd_sa->mmdata.ez_reach_end =ez->reach_end ;
    */
    send_job_cmd(cmd_sa);


    printf("Sachet 4 \n");
    transfer_data_streams(cmd_sa, XFER_FROM_TARGET, cmd_sa->job.num_data_sets);
    printf("Sachet 5 \n");

    //ez->cigar = cigar;
    printf("Sachet 6 \n");

    /*
    ez->max = cmd_sa->mmdata.ez_max;
    ez->zdropped = cmd_sa->mmdata.ez_zdropped ;
    ez->max_q = cmd_sa->mmdata.ez_max_q ;
    ez->max_t = cmd_sa->mmdata.ez_max_t ;
    ez->mqe = cmd_sa->mmdata.ez_mqe ;
    ez->mqe_t = cmd_sa->mmdata.ez_mqe_t ;
    ez->mte = cmd_sa->mmdata.ez_mte  ;
    ez->mte_q = cmd_sa->mmdata.ez_mte_q ;
    ez->score = cmd_sa->mmdata.ez_score ;
    ez->m_cigar = cmd_sa->mmdata.ez_m_cigar ;
    ez->n_cigar = cmd_sa->mmdata.ez_n_cigar ;
    ez->reach_end = cmd_sa->mmdata.ez_reach_end ;
    printf("Sachet cmd_sa->mmdata.ez_m_cigar: %d \n", cmd_sa->mmdata.ez_m_cigar);
    printf("Sachet m_cigar: %d \n", ez->m_cigar);
    printf("Sachet Before XFER_FROM_TARGET num_data_sets=%" PRId32 "\n", cmd_sa->job.num_data_sets);
    transfer_data_streams(cmd_sa, XFER_FROM_TARGET, cmd_sa->job.num_data_sets);
    */
    //printf("Sachet 5 \n");

    /*
    if (cigar_out != NULL){
        printf("Sachet Data Trsnsfer SUCCESS \n");
        ez->cigar = cigar_out;
        memcpy(ez->cigar, cigar_out, ez->n_cigar * sizeof(uint32_t));
        printf("Sachet 6 \n");
    }
    */
    //printf("Sachet ez->n_cigar: %d \n", ez->n_cigar);
    //printf("Sachet ez1->m_cigar: %d \n", ez1->m_cigar);
    //css_job_free(cmd_sa);
    printf("Sachet - Orcs test End\n");
}
#endif // __SSE2__
