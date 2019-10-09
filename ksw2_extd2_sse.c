#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "ksw2.h"
#include "csn.h"
//#include "orcs_bitops.h"


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
    printf("Sachet - Orcs test \n");
    const char *sampleData = "hello world";
    int len = strlen(sampleData);
    unsigned char *compressed = NULL;
    unsigned char *compressed1 = NULL;
    unsigned char *decompressed = NULL;
    size_t sz = 0;

    cs_simple_compress(1, (unsigned char *) query, qlen, &compressed, &sz);
    abort();
    /*
    css_cmd_t *cmd = NULL;

    size_t sz;
    int format = 1;
    char opc=LZ_OPC_CMPR; // Maybe un-needed

    unsigned char *l_out_data = NULL;
    size_t *l_out_len = calloc(sizeof(size_t), 1);
    // test_buf = calloc(sizeof(size_t), 1);
    //  worst compression being eaqual to input
    size_t req_mem_sz = 2 * qlen;

    cmd = css_stream_init(CSS_ENG_TYPE_LZMA, NULL, req_mem_sz);
    ASSERT(cmd != NULL);
    printf("Sachet 0 \n");
    */
    /*
    printf("job.num_args %d \n", &cmd->job.num_args);
    for (int i=0; i<&cmd->job.num_args; i++){
        printf("%d %d \n", i, &cmd->job.args[i]);
    }
    printf("Sachet 1 \n");
    job_add_arg(cmd, format);
    printf("Sachet 2 \n");
    job_add_arg(cmd, qlen);
    printf("Sachet 3 \n");
    job_add_data(cmd, (unsigned char *) l_out_len, sizeof(size_t),
             DATA_DIR_FM_TARGET);

    job_add_data(cmd, query, qlen, DATA_DIR_TO_TARGET);
    printf("Sachet 4 \n");

    hex_dump("in_data: ", query, 64);
    printf("Sachet 5 \n");

    //dump_css_cmd(cmd);

    //cmd->job.opc = 1; // LZ_OPC_CMPR
    /// write all the data streams device
    transfer_data_streams(cmd, (1UL << (0)), cmd->job.num_data_sets);
    //dump_css_cmd(cmd);
    //send_job_cmd(cmd);

    printf("Sachet 10 \n");
    css_job_free(cmd);
    hex_dump("out_data: ", l_out_data, 64);
    */

    // copy_buff_data_to_file(query, get_fd("/root/smittal2/serialize.out"), 0, 0 , qlen, (1UL << (0)));
    /*
    uint8_t *query_out;
    copy_buff_data_to_file(query_out, get_fd("/root/smittal2/serialize.out"), 0, 0 , qlen, (1UL << (1)));
    if (sizeof(query_out) == sizeof(query)){
        printf("Transfer success\n");
    }
    else{
        printf("Transfer not a success\n");
    }
    */
    css_cmd_t *cmd_sa =NULL;
    char *args = NULL,
    *device_file = "/dev/nvme1n1",
    //*image_file = NULL,
    *image_file = "/root/smittal2/orcs_host/dog.jpg",
    *image_name = NULL,
    *data_file = "/root/smittal2/orcs_host/dog.jpg",
    *input_file = "/root/smittal2/orcs_host/dog.jpg",
    //*input_file = NULL,
    *output_file = NULL;
    //*output_file = "/root/smittal2/orcs_host/output.txt";

    cmd_sa = css_job_init(8, device_file, image_file, input_file, output_file, args);
    //sprintf(cmd_sa->hdata.ifile_name, "/root/smittal2/serialize.out");
    // TODO send the query, target and m  somehow

    cmd_sa->job.num_data_sets = 2; // 0 for query and 1 for target
    printf("Sachet cmd_sa->job.data_sets[0].num_blocks= %d", cmd_sa->job.data_sets[0].num_blocks);

    uint8_t query_orcs[qlen], target_orcs[tlen];
    for (int i=0; i < qlen; i++){
        query_orcs[i] = query[i];
    }

    cmd_sa->mmdata.qlen = qlen;
    cmd_sa->mmdata.tlen = tlen;
    cmd_sa->mmdata.m = m ;
    cmd_sa->mmdata.q = q;
    cmd_sa->mmdata.e = e;
    cmd_sa->mmdata.q2 = q2;
    cmd_sa->mmdata.e2 = e2;
    cmd_sa->mmdata.w = w;
    cmd_sa->mmdata.zdrop = zdrop;
    cmd_sa->mmdata.end_bonus = end_bonus;
    cmd_sa->mmdata.flag = flag;

    //reset ez
    ksw_reset_extz(ez);
    cmd_sa->mmdata.ez_max = ez->max;
    cmd_sa->mmdata.ez_zdropped = ez->zdropped;
    cmd_sa->mmdata.ez_max_q = ez->max_q;
    cmd_sa->mmdata.ez_max_t = ez->max_t;
    cmd_sa->mmdata.ez_mqe = ez->mqe;
    cmd_sa->mmdata.ez_mqe_t = ez->mqe_t;
    cmd_sa->mmdata.ez_mte = ez->mte;
    cmd_sa->mmdata.ez_mte_q = ez->mte_q;
    cmd_sa->mmdata.ez_score = ez->score;
    cmd_sa->mmdata.ez_m_cigar = ez->m_cigar;
    cmd_sa->mmdata.ez_n_cigar = ez->n_cigar;
    cmd_sa->mmdata.ez_reach_end = ez->reach_end;
    cmd_sa->mmdata.ez_zdropped = ez->zdropped;

    send_job_cmd(cmd_sa);

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
    ez->zdropped = cmd_sa->mmdata.ez_zdropped ;
    printf("Sachet - Orcs test End\n");

	abort();
    /*for (int z=0;z<qlen; z++){
		printf("%d \n",query[z]);
	}
    char *args = NULL,
    *device_file = "/dev/nvme1n1",
    //*image_file = NULL,
    *image_file = "/root/smittal2/orcs_host/dog.jpg",
    *image_name = NULL,
    *data_file = "/root/smittal2/orcs_host/dog.jpg",
    *input_file = "/root/smittal2/orcs_host/dog.jpg",
    //*input_file = NULL,
    *output_file = NULL;
    //*output_file = "/root/smittal2/orcs_host/output.txt";


    printf("Grabbing input data file: %s\n", cmd_sa->hdata.ifile_name);
    //write_data_to_file(bdev, cmd, cmd->hdata.ifile_name, cmd->hdata.data_offset, cmd->hdata.data_len);

    if (cmd_sa==NULL){
        printf("Unable to create command---------------------\n");
    }
    else{printf ("Sachet     Command created ----------------\n");}
    //wait_for_op_status(cmd_sa);

    dump_css_cmd(cmd_sa);
    cmd_sa->hdata.flags |= DATA_TYPE_FILE;
    unsigned char *compressed = NULL;
    size_t sz = 0;
    //cs_simple_compress(1, (unsigned char *) query, qlen, &compressed, &sz);
    //send_image_data(cmd_sa);

    wait_for_op_status(cmd_sa);

    //dump_css_cmd(cmd_sa);
    css_job_free(cmd_sa);

    */
}
#endif // __SSE2__
