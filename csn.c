/*
 * ORCS user app
 *
 * Author: Subrahmaya Lingappa, subrahmanya.lingappa@wdc.com
 * date: 26 June, 2019
 *
 * Usage:
 * sudo $APP --engine 1 --device_file /dev/nvme0n1 --input_file input_gz.dat
 * --output_file output.tar.gz
 */
#include "csn.h"
#include "zlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "data.h"

/* Flag set by ‘--verbose’. */
static int verbose_flag;
static int streaming_flag;
static int fs_flag;

int engine = -1;
char *args = NULL,
	*device_file = NULL,
	*image_file = NULL,
	*image_name = NULL,
	*data_file = NULL, *input_file = NULL, *output_file = NULL;


void
usage(void)
{
	printf(" Usage ./css [options]\n"
	" Options:\n"
	" --args <argumens>\n"
	" --engine <engine_number> , 1|2|3|4|5 for GZIP|DOCK|UBPF|OSSL|INFR respectively\n"
	" --device_file < device_file_name > node_name from nvme-cli list output\n"
	" --data_file <data_file>\n"
	" --image_file < executable_file_name >\n"
	" --input_file < input_file_name >\n"
	" --output_file < output_file_name >\n"
	" -s streaming tests, this is the only argument required\n"
	"\n see ./scripts/sanity_tests.sh for examples\n");
	exit(-1);
}

void check_file(char *file_name)
{
	if(access( file_name, F_OK ) == -1 && (fs_flag == 0))
	{
		ELOG("input file: %s read error !\n",
		     file_name);
		usage();
		exit(-1);
	}
}

int
opts_main(int argc, char **argv)
{
	int c;

	while (1) {
		static struct option long_options[] = {

			{"verbose", no_argument, &verbose_flag, 1},
			{"args", required_argument, NULL, 'a'},
			{"engine", required_argument, NULL, 'e'},
			{"fs", required_argument, NULL, 'f'},
			{"data_file", required_argument, NULL, 'd'},
			{"device_file", required_argument, NULL, 'v'},
			{"image_file", required_argument, NULL, 'm'},
			{"input_file", required_argument, NULL, 'n'},
			{"output_file", required_argument, NULL, 't'},
			{"streaming_test", required_argument, NULL, 's'},
			{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, ":a:e:fd:hm:n:st:v",
				 long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0)
				break;
			printf("option %s", long_options[option_index].name);
			if (optarg)
				printf(" with arg %s", optarg);
			printf("\n");
			break;

		case 'a':
			args = optarg;
			DLOG("args: %s\n", args);
			break;
		case 'e':
			engine = atoi(optarg);
			DLOG("engine: %d\n", engine);
			break;

		case 'f':
			DLOG("filesystem CS demo:\n");
			fs_flag = 1;
			break;

		case 'd':
			data_file = optarg;
			DLOG("data_file: %s\n", data_file);
			check_file(data_file);
			break;

		case 'm':
			image_file = optarg;
			DLOG("image_file: %s\n", image_file);
			check_file(image_file);

			break;

		case 'n':
			input_file = optarg;
			DLOG("input_file: %s\n", input_file);
			check_file(input_file);
			break;

		case 's':
			DLOG("Streaming CS demo:\n");
			streaming_flag = 1;
			break;

		case 't':
			output_file = optarg;
			DLOG("output_file: %s\n", output_file);
			break;

		case 'v':
			device_file = optarg;
			DLOG("device_file: %s\n", device_file);
			break;

		case 'h':
		case '?':
			/* getopt_long already printed an error message. */
			usage();
			break;

		default:
			usage();
			exit(-1);
		}
	}

	if (verbose_flag)
		DLOG("verbose_flag: %x\n", verbose_flag);

	/* Print any remaining command line arguments (not options). */
	if (optind < argc) {
		DLOG("non-option ARGV-elements: ");
		while (optind < argc)
			DLOG("%s ", argv[optind++]);
		putchar ('\n');
	}

}

void
do_insitu_job(void)
{
	css_cmd_t *cmd = NULL;

	ILOG("In-situ: filesystem operation ...\n");
	/* initialize the job command structure */
	cmd = css_job_init(engine, device_file, image_file,
		input_file, output_file, args);
	if (cmd == NULL)
		usage();

	if (fs_flag == 0)
		cmd->hdata.flags |= DATA_TYPE_STRM;
	else
		cmd->hdata.flags |= DATA_TYPE_FILE;

	dump_css_cmd(cmd);


	if (fs_flag == 0) {
		/* Send the image data for the compute job over */
		send_image_data(cmd);

		/* Send the image data for the compute job over */
		send_input_data(cmd);
	}

	/* Send the job command to work on the data by the compute engine */
	send_job_cmd(cmd);

	if (fs_flag == 0) {
		/* Wait here for the compute job to finish */
		wait_for_op_status(cmd);

		/* copy the data into results file provided by user */
		retrieve_results(cmd);
	}

	css_job_free(cmd);
	ILOG("Compute job DONE!\n");
}

double gettime(void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (double)((int64_t)tv.tv_sec * 1000000 + tv.tv_usec) / 1000000.;
}

#define TEST_OK 0
static int
roundTripTest(int format)
{
	int rc;
	unsigned char *compressed = NULL;
	unsigned char *compressed1 = NULL;
	unsigned char *decompressed = NULL;
	size_t sz = 0, sz1 = 0;

	int len = strlen(sampleData);
	int i, j, loopcount = 10,
	    innerloopcount, n;
	double t1, t2;
	double speed, maxspeed;


	PLOG("%s: data len: %d \n", __func__, len);

	t1 = gettime();
	for (i = 0; i < loopcount; i++)
		rc = cs_simple_compress(format, (unsigned char *) sampleData,
					len, &compressed, &sz);
	t2 = gettime();
	if (rc != TEST_OK)
		return rc;

	speed = (double)len * loopcount / (t2 - t1) / 1000000.;

	PLOG("%s: compress:  size MB, speed MB/s, latency s : %2.1f, %02.4f, %02.6f \n",
	   __func__,
	   ((double)len * loopcount)/(1024*1024), speed, (t2-t1)/loopcount);


	/* gross assurance that compression is actually compressing */
	if (sz > len) {
		free(compressed);
		return 1;
	}

	t1 = gettime();
	for (i = 0; i < loopcount; i++)
		rc = cs_simple_decompress(format, compressed, sz, &decompressed,
					  &sz);
	t2 = gettime();
	speed = (double)len * loopcount / (t2 - t1) / 1000000.;

	PLOG("%s: uncompress:  size MB, speed MB/s, latency s : %2.1f, %02.4f, %02.6f \n",
	   __func__,
	   ((double)len * loopcount)/(1024*1024), speed, (t2-t1)/loopcount);

	free(compressed);

	if (rc != TEST_OK)
		return rc;

	if ((sz != len) ||
	    (memcmp(decompressed, sampleData, sz) != 0)) {
		ELOG("%s: test failed!  %x, sz: %d, strlen: %d\n", __func__,
		memcmp(decompressed, sampleData, sz), sz, strlen(sampleData));
		free(decompressed);
		exit(1);
		return 1;
	}

	return TEST_OK;
}

#define Z_OK 0
#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        exit(1); \
    } \
}

void
streaming_compression_test(void)
{
	unsigned int i;

	int rc = 0;

	DLOG("round trip Streaming compression test: start\n");
	fflush(stdout);
	/* format shoulds always be 1, all other values are reserved */
	rc = roundTripTest(1);
	if (rc)
		ELOG(" Compression test fail! (%d)\n", rc);
	else
		ILOG(" Compression test pass! (%d)\n", rc);

	DLOG("round trip Streaming compression test: Done\n");

	fflush(stdout);
	exit(0);
}


void zlib_compr_test(char *data)
{
    int err;
    Byte *compr, *uncompr;
    uLong comprLen = 1024*2048;
    uLong uncomprLen = comprLen;

    int i, j, loopcount = 10,
	innerloopcount, n;
    double t1, t2;
    double speed, maxspeed;

    compr    = (Byte*)calloc((uInt)comprLen, 1);
    uncompr  = (Byte*)calloc((uInt)uncomprLen, 1);
    /* compr and uncompr are cleared to avoid reading uninitialized
     * data and to ensure that uncompr compresses well.
     */
    if (compr == Z_NULL || uncompr == Z_NULL) {
        printf("out of memory\n");
        exit(1);
    }

    uLong len = (uLong)strlen(data)+1;
    PLOG("%s: data len: %d \n", __func__, len);

    t1 = gettime();
    for (i = 0; i < loopcount; i++)
	    err = compress(compr, &comprLen, (const Bytef*)data, len);
    t2 = gettime();
    CHECK_ERR(err, "compress");

    speed = (double)len * loopcount / (t2 - t1) / 1000000.;

    PLOG("%s: compress:  size MB, speed MB/s, latency s : %2.1f, %02.4f, %02.6f \n",
	   __func__,
	   ((double)len * loopcount)/(1024*1024), speed, (t2-t1)/loopcount);
    strcpy((char*)uncompr, "garbage");

    t1 = gettime();
    for (i = 0; i < loopcount; i++)
	    err = uncompress(uncompr, &uncomprLen, compr, comprLen);
    t2 = gettime();
    CHECK_ERR(err, "uncompress");
    speed = (double)len * loopcount / (t2 - t1) / 1000000.;

    PLOG("%s: uncompress:  size MB, speed MB/s, latency s : %2.1f, %02.4f, %02.6f \n",
	   __func__,
	   ((double)len * loopcount)/(1024*1024), speed, (t2-t1)/loopcount);


    if (strncmp((char*)uncompr, data, len)) {
        fprintf(stderr, "bad uncompress\n");
        exit(1);
    } else {
        /* printf("uncompress(): %s\n", (char *)uncompr); */
        /* printf("uncompress(): test OK!\n"); */
    }

    free(compr);
    free(uncompr);
}

void
do_descrete_job(void)
{
	zlib_compr_test( sampleData );
	streaming_compression_test();
}

int
main(int argc, char *argv[])
{

	opts_main(argc, argv);

	ILOG("Compute job starting...\n");
	if (streaming_flag == 0)
		do_insitu_job();
	else
		do_descrete_job();

	return 0;
}

