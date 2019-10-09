/*
 * ORCS: target library functions.
 *
 * Author: Subrahmaya Lingappa, subrahmanya.lingappa@wdc.com
 * date: 26 June, 2019
 */

#include "spdk/stdinc.h"
#include "../../lib/bdev/malloc/bdev_malloc.h"
#include "spdk/bdev.h"
#include "spdk/conf.h"
#include "spdk/endian.h"
#include "spdk/env.h"
#include "spdk/copy_engine.h"
#include "spdk/json.h"
#include "spdk/thread.h"
#include "spdk/queue.h"
#include "spdk/string.h"

#include "spdk/bdev_module.h"
#include "spdk_internal/log.h"
#include "spdk/stdinc.h"

#include "nvmf_internal.h"
#include "transport.h"

#include "spdk/bit_array.h"
#include "spdk/endian.h"
#include "spdk/thread.h"
#include "spdk/trace.h"
#include "spdk/nvme_spec.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk/version.h"

#include "spdk_internal/log.h"

#include "csn.h"
#include <stdint.h>

#define __SSE2__ 2
#include <emmintrin.h>
#include <ksw2.h>

//#include <smmintrin.h>

#define KSW_NEG_INF -0x40000000

#define KSW_EZ_SCORE_ONLY  0x01 // don't record alignment path/cigar
#define KSW_EZ_RIGHT       0x02 // right-align gaps
#define KSW_EZ_GENERIC_SC  0x04 // without this flag: match/mismatch only; last symbol is a wildcard
#define KSW_EZ_APPROX_MAX  0x08 // approximate max; this is faster with sse
#define KSW_EZ_APPROX_DROP 0x10 // approximate Z-drop; faster with sse
#define KSW_EZ_EXTZ_ONLY   0x40 // only perform extension
#define KSW_EZ_REV_CIGAR   0x80 // reverse CIGAR in the output
#define KSW_EZ_SPLICE_FOR  0x100
#define KSW_EZ_SPLICE_REV  0x200
#define KSW_EZ_SPLICE_FLANK 0x400


void write_data_to_file(struct spdk_bdev *bdev, css_cmd_t *cmd, char *ifile,
			int32_t offset, uint32_t len);
void *execute_css_job(void *ctxt);

struct malloc_disk {
	struct spdk_bdev disk;
	void *malloc_buf;

	TAILQ_ENTRY(malloc_disk) link;
};



void
do_docker(uint8_t *img_archive, uint8_t *d_args)
{
	uint8_t command[CSS_STR_LEN * 4];
	int32_t ret = -1;

	sprintf(command, "docker load < %s; %s", img_archive, d_args);
	/*
	 * system("docker load < cs.tar; docker run hello-world");
	 */
	ILOG("System command : %s\n", command);
	ret = system(command);
	ASSERTF(ret == 0, "system command returned non-zero value : %x\n", ret);
	ILOG("**** RUNNING DOCKER IMAGE, DONE!, ret: %x ****\n", ret);

}


void
write_data_to_file(struct spdk_bdev *bdev, css_cmd_t *cmd, char *ifile,
			int32_t offset, uint32_t len)
{
	uint8_t *mem = NULL;
	uint32_t block_size = cmd->hdata.block_sz;
	/*  open for writing */
	int32_t bytes = 0, fd = open(ifile, O_TRUNC | O_RDWR | O_CREAT, 0777);

	if (fd < 0) {
		perror("write_data_to_file");
		ELOG("File does not exists, failed to create file: %s,"
		     " err: %x\n", ifile, fd);
		return;
	}

	ILOG("ifile: %s, offset: %d, len: %d\n",
	     ifile, offset * block_size, len);
	mem = (uint8_t *) (((struct malloc_disk *) bdev->ctxt)->malloc_buf +
				(offset * block_size));
	XFER_LOG
		("\n\n mem: 0x%08lx, malloc_buf: 0x%08lx, offset: 0x%08x,"
		 " len: 0x%x, DATA: 0x%08x\n\n",
		 (uintptr_t) mem,
		 (uintptr_t) ((struct malloc_disk *) bdev->ctxt)->malloc_buf,
		 (offset * block_size), len, *(uint32_t *) mem);


	lseek(fd, 0, SEEK_SET);
	bytes = write(fd, mem, len);
	ASSERTF(bytes > 0, "non-positive bytes value : %x\n", bytes);
	close(fd);
}

void
compute_container(css_cmd_t *cmd, struct spdk_bdev *bdev)
{

	if (cmd->hdata.flags & DATA_TYPE_FILE) {
		ILOG("Filesystem based: Executing INFERENCE engine ...\n");
		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;

		sprintf(command,
			"sudo mount `sudo nvme list | grep %s | "
			"awk '{print $1}'` /mnt/%s;"
			"cd /mnt/%s;"
			"docker load < %s; %s ; "
			"cd  ~/; "
			"sudo umount /mnt/%s > /dev/null",
			bdev->name, bdev->name,
			bdev->name,
			cmd->hdata.efile_name, cmd->hdata.exe_args, bdev->name);

		ELOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ILOG("**** RUNNING GZIP ENGINE, DONE!, ret: %x ****\n", ret);

		/*cmd->tdata.result_len = get_file_len(filename); */

	} else{
		uint8_t *mem = NULL;
		uint32_t block_size = cmd->hdata.block_sz;

		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;

		/* Grab the docker image */
		ILOG("Grabbing image archive file: %s\n", CSS_IMG_ARCHIVE);
		write_data_to_file(bdev, cmd, CSS_IMG_ARCHIVE,
				   cmd->hdata.exe_offset,
				   cmd->hdata.exe_len);

		/* Grab the docker image */
		ILOG("Grabbing input data file: %s\n", cmd->hdata.ifile_name);
		write_data_to_file(bdev, cmd, cmd->hdata.ifile_name,
					cmd->hdata.data_offset,
					cmd->hdata.data_len);

		/*
		 * import teh docker image and execute it with user
		 * arguments recieved from host
		 */
		ILOG("Executing Docker image ...\n");

		/*
		 * do_docker(CSS_IMG_ARCHIVE, cmd->hdata.exe_args);
		 */

		sprintf(command, "docker load < %s; %s",
			CSS_IMG_ARCHIVE, cmd->hdata.exe_args);
		/*
		 * system("docker load < cs.tar; docker run hello-world");
		 */
		ILOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ILOG("**** RUNNING DOCKER IMAGE, DONE!, ret: %x ****\n", ret);


		ILOG("Executing Docker image: Done!\n");

		ILOG("Saving results into device...\n");
		mem = (uint8_t *) (((struct malloc_disk *)
				    bdev->ctxt)->malloc_buf +
				   (cmd->hdata.result_offset * block_size));
		copy_buff_data_to_file(mem, get_fd(cmd->hdata.ofile_name), 0, 0,
					get_file_len(cmd->hdata.ofile_name),
					XFER_FROM_TARGET);
		ILOG("Saving results into device: Done!\n");

		/* mark this compute job as done */
		cmd->tdata.result_len = get_file_len(cmd->hdata.ofile_name);
		cmd->tdata.status = 0xA5;
		sync();
		dump_css_cmd(cmd);
	}

}

void
compute_ubpf(css_cmd_t *cmd, struct spdk_bdev *bdev)
{
	if (cmd->hdata.flags & DATA_TYPE_FILE) {
		ILOG("Filesystem based: Executing uBPF engine ...\n");
		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;

		sprintf(command,
			"sudo mount `sudo nvme list | grep %s |"
			" awk '{print $1}'` /mnt/%s;"
			"./ubpf/vm/test -m /mnt/%s/%s /mnt/%s/%s ; "
			"sudo umount /mnt/%s > /dev/null",
			bdev->name, bdev->name,
			bdev->name, cmd->hdata.ifile_name, bdev->name,
			cmd->hdata.efile_name, bdev->name);

		ILOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ILOG("**** RUNNING UBPF ENGINE, DONE!, ret: %x ****\n", ret);

		/*cmd->tdata.result_len = get_file_len(filename); */

	} else{
		uint8_t *mem = NULL;
		uint32_t block_size = cmd->hdata.block_sz;

		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;

		ILOG("Blocks based: Executing uBPF engine ...\n");
		/* Grab the docker image */
		ILOG("Grabbing BPF object code file: %s, len: %ld\n",
			cmd->hdata.efile_name, cmd->hdata.exe_len);
		write_data_to_file(bdev, cmd, cmd->hdata.efile_name,
					cmd->hdata.exe_offset,
					cmd->hdata.exe_len);

		/* Grab the docker image */
		ILOG("Grabbing input data file: %s, len: %ld\n",
			cmd->hdata.ifile_name, cmd->hdata.data_len);
		write_data_to_file(bdev, cmd, cmd->hdata.ifile_name,
					cmd->hdata.data_offset,
					cmd->hdata.data_len);

		/*
		 * import teh docker image and execute it with user arguments
		 * recieved from host
		 */
		ILOG("Executing UBPF code ...\n");
		/*do_docker(cmd->hdata.efile_name, cmd->hdata.exe_args); */

		sprintf(command, "./ubpf/vm/test -m %s %s",
			cmd->hdata.ifile_name, cmd->hdata.efile_name);
		/*
		 * system("docker load < cs.tar; docker run hello-world");
		 */
		ILOG("System command : %s\n", command);
		ret = system(command);
		/*
		 * ASSERTF(ret == 0,
		 * "system command returned non-zero value : %x\n",
		 * ret);
		 */
		ILOG("**** RUNNING UBPF code, DONE!, ret: %x ****\n", ret);
		ILOG("Executing UBPF code: Done!\n");

		/*
		 * As bpf code can only take one buffer, assumption here
		 * is bpf code might have modified the memory data given
		 * by the input file we'll just copy whole of the input
		 * file into results area for the host to interpret
		 */
		ILOG("Saving results into device...\n");
		mem = (uint8_t *) (((struct malloc_disk *)
				    bdev->ctxt)->malloc_buf +
				   (cmd->hdata.result_offset * block_size));
		copy_buff_data_to_file(mem, get_fd(cmd->hdata.ifile_name), 0, 0,
					get_file_len(cmd->hdata.ifile_name),
					XFER_FROM_TARGET);
		ILOG("Saving results into device: Done!\n");

		/* mark this compute job as done */
		cmd->tdata.result_len = get_file_len(cmd->hdata.ifile_name);
	}
	cmd->tdata.status = 0xA5;
	sync();
	dump_css_cmd(cmd);

}


void
compute_ossl(css_cmd_t *cmd, struct spdk_bdev *bdev)
{

	uint8_t *mem = NULL;
	uint32_t block_size = cmd->hdata.block_sz;

	if (cmd->hdata.flags & DATA_TYPE_FILE) {
		ILOG("Filesystem based: Executing OSSL engine ...\n");
		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;


		sprintf(command,
			"sudo mount `sudo nvme list | grep %s | awk '{print $1}'` /mnt/%s;"
			"cd /mnt/%s; "
			"%s ; "
			"cd ~/; sudo umount /mnt/%s > /dev/null",
			bdev->name, bdev->name,
			bdev->name, cmd->hdata.exe_args, bdev->name);

		ILOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ILOG("**** RUNNING UBPF ENGINE, DONE!, ret: %x ****\n", ret);

		/*cmd->tdata.result_len = get_file_len(filename); */

	} else{
		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;

		/* Grab the input file */
		ILOG("Grabbing input data file: %s\n", cmd->hdata.ifile_name);
		write_data_to_file(bdev, cmd, cmd->hdata.ifile_name,
					cmd->hdata.data_offset,
					cmd->hdata.data_len);

		/*
		 * execute openssl engine with user arguments recieved
		 * from host
		 */
		ILOG("Executing OSSL engine ...\n");

		sprintf(command, "%s", cmd->hdata.exe_args);
		/*
		 * system("docker load < cs.tar; docker run hello-world");
		 */
		ILOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ILOG("**** RUNNING OSSL ENGINE, DONE!, ret: %x ****\n", ret);

		ILOG("Executing OSSL engine: Done!\n");

		/* save the results */
		ILOG("Saving results into device...\n");
		mem = (uint8_t *) (((struct malloc_disk *)
				    bdev->ctxt)->malloc_buf +
				   (cmd->hdata.result_offset * block_size));
		copy_buff_data_to_file(mem, get_fd(cmd->hdata.ofile_name), 0, 0,
				       get_file_len(cmd->hdata.ofile_name),
				       XFER_FROM_TARGET);
		ILOG("Saving results into device: Done!\n");

		/* mark this compute job as done */
		cmd->tdata.result_len = get_file_len(cmd->hdata.ofile_name);

	}
	cmd->tdata.status = 0xA5;
	sync();
	dump_css_cmd(cmd);


}

void
compute_gzip(css_cmd_t *cmd, struct spdk_bdev *bdev)
{
	uint8_t file_name[CSS_STR_LEN * 4];
	uint8_t *mem = NULL;
	uint32_t block_size = cmd->hdata.block_sz;

	if (cmd->hdata.flags & DATA_TYPE_FILE) {
		ILOG("Filesystem based: Executing GZIP engine ...\n");
		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;

		sprintf(command,
			"sudo mount `sudo nvme list | grep %s | awk '{print $1}'` /mnt/%s;"
			"cd /mnt/%s;"
			"tar -Pczf %s %s; "
			"cd ~/;"
			"sudo umount /mnt/%s > /dev/null",
			bdev->name,
			bdev->name,
			bdev->name,
			cmd->hdata.ofile_name, cmd->hdata.ifile_name,
			bdev->name);
		ILOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ILOG("**** RUNNING GZIP ENGINE, DONE!, ret: %x ****\n", ret);
		sprintf(file_name, "/mnt/%s/%s", bdev->name,
			cmd->hdata.ofile_name);
		cmd->tdata.result_len = get_file_len(file_name);
	} else{
		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;

		ILOG("Blocks based: Executing GZIP engine ...\n");
		/* Grab the input file */
		ILOG("Grabbing input data file: %s\n", cmd->hdata.ifile_name);
		write_data_to_file(bdev, cmd, cmd->hdata.ifile_name,
				   cmd->hdata.data_offset, cmd->hdata.data_len);
		sprintf(command, "tar -czf %s %s",
			cmd->hdata.ofile_name, cmd->hdata.ifile_name);
		ILOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ILOG("**** RUNNING GZIP ENGINE, DONE!, ret: %x ****\n", ret);
		ILOG("Saving results into device...\n");
		mem = (uint8_t *) (((struct malloc_disk *)
				    bdev->ctxt)->malloc_buf +
				   (cmd->hdata.result_offset * block_size));
		copy_buff_data_to_file(mem, get_fd(cmd->hdata.ofile_name), 0, 0,
				       get_file_len(cmd->hdata.ofile_name),
				       XFER_FROM_TARGET);
		ILOG("Saving results into device: Done!\n");
		cmd->tdata.result_len = get_file_len(cmd->hdata.ofile_name);
	}
	ILOG("Executing GZIP engine: Done!\n");
	/* mark this compute job as done */
	cmd->tdata.status = 0xA5;
	sync();
	dump_css_cmd(cmd);

}

void
compute_inference(css_cmd_t *cmd, struct spdk_bdev *bdev)
{

	uint8_t *mem = NULL;
	uint32_t block_size = cmd->hdata.block_sz;

	/*
	 * import teh docker image and execute it with user arguments recieved
	 * from host
	 */
	ILOG("Executing INFERENCE engine ...\n");
	if (cmd->hdata.flags & DATA_TYPE_FILE) {
		ELOG("Filesystem based: Executing INFERENCE engine ...\n");
		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;

		sprintf(command,
			"sudo mount `sudo nvme list | grep %s | awk '{print $1}'` /mnt/%s;"
			"./darknet detect cfg/yolov3.cfg cfg/yolov3.weights /mnt/%s/%s; "
			"cp %s /mnt/%s/%s ; "
			"sudo umount /mnt/%s > /dev/null",
			bdev->name, bdev->name,
			bdev->name, cmd->hdata.ifile_name,
			CSS_INFR_OBJS, bdev->name, cmd->hdata.ofile_name,
			bdev->name);

		ELOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ELOG("**** RUNNING GZIP ENGINE, DONE!, ret: %x ****\n", ret);

		cmd->tdata.result_len = get_file_len(CSS_INFR_OBJS);

	} else{
		uint8_t command[CSS_STR_LEN * 4];
		int32_t ret = -1;
		/* Grab the input file */
		ELOG("Grabbing input data file: %s\n", cmd->hdata.ifile_name);
		write_data_to_file(bdev, cmd, cmd->hdata.ifile_name,
				   cmd->hdata.data_offset, cmd->hdata.data_len);
		sprintf(command,
			"./darknet detect cfg/yolov3.cfg cfg/yolov3.weights %s",
			cmd->hdata.ifile_name);
		/*
		 * system("docker load < cs.tar; docker run hello-world");
		 */
		ELOG("System command : %s\n", command);
		ret = system(command);
		ASSERTF(ret == 0,
			"system command returned non-zero value : %x\n",
			ret);
		ELOG("**** RUNNING INFERENCE ENGINE, DONE!, ret: %x ****\n",
		     ret);


		ELOG("Saving results into device...\n");
		mem = (uint8_t *) (((struct malloc_disk *)
				    bdev->ctxt)->malloc_buf +
				   (cmd->hdata.result_offset * block_size));
		copy_buff_data_to_file(mem, get_fd(CSS_INFR_OBJS), 0, 0,
				       get_file_len(CSS_INFR_OBJS),
				       XFER_FROM_TARGET);
		ELOG("Saving results into device: Done!\n");

		/* mark this compute job as done */
		cmd->tdata.result_len = get_file_len(CSS_INFR_OBJS);
	}
	ELOG("Executing INFERENCE engine: Done!\n");

	cmd->tdata.status = 0xA5;

	sync();
	dump_css_cmd(cmd);

}

uint8_t *
get_mem(struct spdk_bdev *bdev, int32_t offset, int32_t block_size)
{
	uint8_t *mem =
		(uint8_t *) (((struct malloc_disk *) bdev->ctxt)->malloc_buf +
				(offset * block_size));
	return mem;
}

void
compute_erasure(css_cmd_t *cmd, struct spdk_bdev *bdev)
{

	int cnt, ret;
	uint8_t *malloc_buf =
		(uint8_t *) ((struct malloc_disk *) bdev->ctxt)->malloc_buf;
	for (cnt = 0; cnt < cmd->job.num_args; cnt++)
		DLOG("arg[%d]: %d\n", cnt, cmd->job.args[cnt]);

	ILOG("Executing ECRS engine ...\n");
	if (cmd->job.opc == EC_OPC_INIT) {
		uint8_t *mem1 =	get_mem(bdev,
					cmd->job.data_sets[0].offset_block,
					cmd->block_sz);
		uint8_t *mem2 =	get_mem(bdev,
					cmd->job.data_sets[1].offset_block,
					cmd->block_sz);

		ILOG("EC_OPC_INIT: ...\n");
		ec_init_tables(cmd->job.args[0],	/* k2 */
			       cmd->job.args[1],	/* p2 */
			       mem1,	/* encode_matrix */
			       mem2	/* g_tbls */
			       );

	} else if (cmd->job.opc == EC_OPC_ENCD) {
		int i, j;
		int lenb2 = cmd->job.args[0];
		int len = 2 * lenb2;
		int k = cmd->job.args[1];
		int p = cmd->job.args[2];
		int p2 = p * 2;
#define MMAX 255
#define KMAX 255
		unsigned char *gftbls;
		unsigned char *data[MMAX], *data1[MMAX];
		unsigned char *coding[KMAX], *coding1[KMAX];

		ILOG("EC_OPC_ENCD: ...\n");
		ILOG("lenb2: %d, k: %d, p: %d\n", lenb2, k, p);

		i = 0;
		j = 0;
		gftbls = get_mem(bdev,
				 cmd->job.data_sets[j].offset_block,
				 cmd->block_sz);
		DLOG("i: %d, addr: %p, off: %d, data: %x\n", i, gftbls,
		     cmd->job.data_sets[j].offset_block, *((int *) gftbls));
		/*hex_dump("gftbls: ", gftbls[i], 64); */

		j++;
		for (i = 0; i < k; i++, j++) {
			data[i] = get_mem(bdev,
					  cmd->job.data_sets[j].offset_block,
					  cmd->block_sz);
			DLOG("i: %d, addr: %p, off: %d\n", i, data[i],
			     cmd->job.data_sets[j].offset_block);
			hex_dump("frag: ", data[i], 64);
		}

		for (i = 0; i < p2; i++, j++) {
			coding[i] = get_mem(bdev,
					    cmd->job.data_sets[j].offset_block,
					    cmd->block_sz);
			DLOG("i: %d, addr: %p, off: %d, data: %x\n",
			     i,
			     coding[i],
			     cmd->job.data_sets[j].offset_block,
			     *((int *) coding[i]));
		}


		ec_encode_data(lenb2, k, p, gftbls, data, coding);

		for (i = 0; i < p2; i++, j++) {
			DLOG("i: %d, addr: %p, off: %d, data: %x\n",
			     i,
			     coding[i],
			     cmd->job.data_sets[j].offset_block,
			     *((int *) coding[i]));
			hex_dump("coding: ", coding[i], 64);
		}
		/*hex_dump("g_tbls2: ", mem2, 64); */

	}

	ILOG("**** RUNNING ECRS ENGINE, DONE!, ret: %x ****\n", ret);
	ILOG("Executing ECRS engine: Done!\n");

	/* mark this compute job as done */
	cmd->tdata.result_len = get_file_len(cmd->hdata.ofile_name);
	cmd->tdata.status = 0xA5;
	sync();
	/*dump_css_cmd(cmd); */

}

char *
cs_malloc(size_t num_blocks, size_t block_size)
{
	char *buf = spdk_zmalloc(num_blocks * block_size, 2 * 1024 * 1024, NULL,
				 SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
	ILOG("buf: %p, size: %d bytes\n", buf, num_blocks * block_size);
	if (!buf) {
		SPDK_ERRLOG("malloc_buf spdk_zmalloc() failed\n");
		ASSERT(buf != NULL);
		return NULL;
	}
	return buf;
}

char *
get_malloc_bdev_buf(struct spdk_bdev *bdev)
{
	/*return  (uint8_t *)((struct malloc_disk *)bdev->ctxt)->malloc_buf; */
	return (uint8_t *) (cs_malloc(4096, 1024));

}

void
compute_minimap_kernel(css_cmd_t *cmd, struct spdk_bdev *bdev)
{

    ILOG("Target SACHET EXECUTING MINIMAP KERNEL\n");
	uint32_t block_size = cmd->hdata.block_sz;

    uint8_t command[CSS_STR_LEN * 4];
    int32_t ret = -1;
    /* Grab the input file */
    //ILOG("Grabbing query input data file: %s\n", cmd->hdata.ifile_name);
    //sprintf(command, "du -sh %s",cmd->hdata.ifile_name);
    //ELOG("System command : %s\n", command);
    //ret = system(command);
    //ASSERTF(ret == 0,
      //  "system command returned non-zero value : %x\n",
        //ret);

    /*
    ILOG("Saving results into device...\n");
    mem = (uint8_t *) (((struct malloc_disk *)
                bdev->ctxt)->malloc_buf +
               (cmd->hdata.result_offset * block_size));
    copy_buff_data_to_file(mem, get_fd(CSS_INFR_OBJS), 0, 0,
                   get_file_len(CSS_INFR_OBJS),
                   XFER_FROM_TARGET);
    ILOG("Saving results into device: Done!\n");
    */
    /* mark this compute job as done */
    //cmd->tdata.result_len = get_file_len(CSS_INFR_OBJS);
    ILOG("Sachet - 0 \n");
    void *km = NULL;
    int qlen = cmd->mmdata.qlen;
    uint8_t *query=NULL; //TODO solve this
    int tlen = cmd->mmdata.tlen;
    uint8_t *target = NULL; //TODO
    int8_t m = cmd->mmdata.m;
    int8_t *mat = NULL;
    int8_t q = cmd->mmdata.q;
    int8_t e = cmd->mmdata.e;
    int8_t q2 = cmd->mmdata.q2;
    int8_t e2 = cmd->mmdata.e2;
    int w = cmd->mmdata.w;
    int zdrop = cmd->mmdata.zdrop;
    int end_bonus = cmd->mmdata.end_bonus;
    int flag = cmd->mmdata.flag;
    ksw_extz_t *ez; //TODO
    ILOG("Sachet - 1 \n");
    ez = (ksw_extz_t *) malloc(sizeof(ksw_extz_t));
    ez->max = cmd->mmdata.ez_max;
    ez->zdropped = cmd->mmdata.ez_zdropped ;
    ez->max_q = cmd->mmdata.ez_max_q ;
    ez->max_t = cmd->mmdata.ez_max_t ;
    ez->mqe = cmd->mmdata.ez_mqe ;
    ez->mqe_t = cmd->mmdata.ez_mqe_t ;
    ez->mte = cmd->mmdata.ez_mte  ;
    ez->mte_q = cmd->mmdata.ez_mte_q ;
    ez->score = cmd->mmdata.ez_score ;
    ez->m_cigar = cmd->mmdata.ez_m_cigar ;
    ez->n_cigar = cmd->mmdata.ez_n_cigar ;
    ez->reach_end = cmd->mmdata.ez_reach_end ;
    ez->zdropped = cmd->mmdata.ez_zdropped ;

    mat = (int8_t *)malloc(m * sizeof(int8_t));
    for (int i = 0; i < m; i++){
        mat[i] = 0;
    }
    query = (uint8_t *)malloc(qlen * sizeof(uint8_t));
    for (int i = 0; i < qlen; i++){
        query[i] = 0;
    }
    target = (uint8_t *)malloc(tlen * sizeof(uint8_t));
    for (int i = 0; i < tlen; i++){
        target[i] = 0;
    }
#define __dp_code_block1 \
	z = _mm_load_si128(&s[t]); \
	xt1 = _mm_load_si128(&x[t]);                     /* xt1 <- x[r-1][t..t+15] */ \
	tmp = _mm_srli_si128(xt1, 15);                   /* tmp <- x[r-1][t+15] */ \
	xt1 = _mm_or_si128(_mm_slli_si128(xt1, 1), x1_); /* xt1 <- x[r-1][t-1..t+14] */ \
	x1_ = tmp; \
	vt1 = _mm_load_si128(&v[t]);                     /* vt1 <- v[r-1][t..t+15] */ \
	tmp = _mm_srli_si128(vt1, 15);                   /* tmp <- v[r-1][t+15] */ \
	vt1 = _mm_or_si128(_mm_slli_si128(vt1, 1), v1_); /* vt1 <- v[r-1][t-1..t+14] */ \
	v1_ = tmp; \
	a = _mm_add_epi8(xt1, vt1);                      /* a <- x[r-1][t-1..t+14] + v[r-1][t-1..t+14] */ \
	ut = _mm_load_si128(&u[t]);                      /* ut <- u[t..t+15] */ \
	b = _mm_add_epi8(_mm_load_si128(&y[t]), ut);     /* b <- y[r-1][t..t+15] + u[r-1][t..t+15] */ \
	x2t1= _mm_load_si128(&x2[t]); \
	tmp = _mm_srli_si128(x2t1, 15); \
	x2t1= _mm_or_si128(_mm_slli_si128(x2t1, 1), x21_); \
	x21_= tmp; \
	a2= _mm_add_epi8(x2t1, vt1); \
	b2= _mm_add_epi8(_mm_load_si128(&y2[t]), ut);

#define __dp_code_block2 \
	_mm_store_si128(&u[t], _mm_sub_epi8(z, vt1));    /* u[r][t..t+15] <- z - v[r-1][t-1..t+14] */ \
	_mm_store_si128(&v[t], _mm_sub_epi8(z, ut));     /* v[r][t..t+15] <- z - u[r-1][t..t+15] */ \
	tmp = _mm_sub_epi8(z, q_); \
	a = _mm_sub_epi8(a, tmp); \
	b = _mm_sub_epi8(b, tmp); \
	tmp = _mm_sub_epi8(z, q2_); \
	a2= _mm_sub_epi8(a2, tmp); \
	b2= _mm_sub_epi8(b2, tmp);

	int r, t, qe = q + e, n_col_, *off = 0, *off_end = 0, tlen_, qlen_, last_st, last_en, wl, wr, max_sc, min_sc, long_thres, long_diff;
	int with_cigar = 0; // Sachet modified this
    int approx_max = !!(flag&KSW_EZ_APPROX_MAX);
	int32_t *H = 0, H0 = 0, last_H0_t = 0;
	uint8_t *qr, *sf, *mem, *mem2 = 0;
	__m128i q_, q2_, qe_, qe2_, zero_, sc_mch_, sc_mis_, m1_, sc_N_;
	__m128i *u, *v, *x, *y, *x2, *y2, *s, *p = 0;

    ILOG("Sachet - 20 \n");
    ksw_reset_extz(ez);
	if (m <= 1 || qlen <= 0 || tlen <= 0)
        return;

    ILOG("Sachet - 3 \n");
	if (q2 + e2 < q + e)
        t = q, q = q2, q2 = t, t = e, e = e2, e2 = t; // make sure q+e no larger than q2+e2

    ILOG("Sachet - 31 \n");
    zero_   = _mm_set1_epi8(0);
	q_      = _mm_set1_epi8(q);
	q2_     = _mm_set1_epi8(q2);
	qe_     = _mm_set1_epi8(q + e);
	qe2_    = _mm_set1_epi8(q2 + e2);
	sc_mch_ = _mm_set1_epi8(mat[0]);
	sc_mis_ = _mm_set1_epi8(mat[1]);
	sc_N_   = mat[m*m-1] == 0? _mm_set1_epi8(-e2) : _mm_set1_epi8(mat[m*m-1]);
	m1_     = _mm_set1_epi8(m - 1); // wildcard


    ILOG("Sachet - 4 \n");
	if (w < 0) w = tlen > qlen? tlen : qlen;
	wl = wr = w;
	tlen_ = (tlen + 15) / 16;
	n_col_ = qlen < tlen? qlen : tlen;
	n_col_ = ((n_col_ < w + 1? n_col_ : w + 1) + 15) / 16 + 1;
	qlen_ = (qlen + 15) / 16;
    ILOG("Sachet - 41 \n");
	for (t = 1, max_sc = mat[0], min_sc = mat[1]; t < m * m; ++t) {
		max_sc = max_sc > mat[t]? max_sc : mat[t];
		min_sc = min_sc < mat[t]? min_sc : mat[t];
	}
    ILOG("Sachet - 42 \n");
	//if (-min_sc > 2 * (q + e)) return; // otherwise, we won't see any mismatches
    ILOG("Sachet - 43 \n");

	long_thres = e != e2? (q2 - q) / (e - e2) - 1 : 0;
	if (q2 + e2 + long_thres * e2 > q + e + long_thres * e)
		++long_thres;
	long_diff = long_thres * (e - e2) - (q2 - q) - e2;

    ILOG("Sachet - 5 \n");
	mem = (uint8_t*)calloc(tlen_ * 8 + qlen_ + 1, 16);
	//mem = (uint8_t*)kcalloc(km, tlen_ * 8 + qlen_ + 1, 16);
	u = (__m128i*)(((size_t)mem + 15) >> 4 << 4); // 16-byte aligned
	v = u + tlen_, x = v + tlen_, y = x + tlen_, x2 = y + tlen_, y2 = x2 + tlen_;
	s = y2 + tlen_, sf = (uint8_t*)(s + tlen_), qr = sf + tlen_ * 16;
	memset(u,  -q  - e,  tlen_ * 16);
	memset(v,  -q  - e,  tlen_ * 16);
	memset(x,  -q  - e,  tlen_ * 16);
	memset(y,  -q  - e,  tlen_ * 16);
	memset(x2, -q2 - e2, tlen_ * 16);
	memset(y2, -q2 - e2, tlen_ * 16);
	if (!approx_max) {
		H = (int32_t*)malloc(tlen_ * 16 * 4);
		//H = (int32_t*)kmalloc(km, tlen_ * 16 * 4);
		for (t = 0; t < tlen_ * 16; ++t) H[t] = KSW_NEG_INF;
	}
	if (with_cigar) {
		mem2 = (uint8_t*)malloc(((size_t)(qlen + tlen - 1) * n_col_ + 1) * 16);
		//mem2 = (uint8_t*)kmalloc(km, ((size_t)(qlen + tlen - 1) * n_col_ + 1) * 16);
		p = (__m128i*)(((size_t)mem2 + 15) >> 4 << 4);
		off = (int*)malloc((qlen + tlen - 1) * sizeof(int) * 2);
		//off = (int*)kmalloc(km, (qlen + tlen - 1) * sizeof(int) * 2);
		off_end = off + qlen + tlen - 1;
	}

    ILOG("Sachet - 6 \n");
	for (t = 0; t < qlen; ++t) qr[t] = query[qlen - 1 - t];
	memcpy(sf, target, tlen);

	for (r = 0, last_st = last_en = -1; r < qlen + tlen - 1; ++r) {
		int st = 0, en = tlen - 1, st0, en0, st_, en_;
		int8_t x1, x21, v1;
		uint8_t *qrr = qr + (qlen - 1 - r);
		int8_t *u8 = (int8_t*)u, *v8 = (int8_t*)v, *x8 = (int8_t*)x, *x28 = (int8_t*)x2;
		__m128i x1_, x21_, v1_;
		// find the boundaries
		if (st < r - qlen + 1) st = r - qlen + 1;
		if (en > r) en = r;
		if (st < (r-wr+1)>>1) st = (r-wr+1)>>1; // take the ceil
		if (en > (r+wl)>>1) en = (r+wl)>>1; // take the floor
		if (st > en) {
			ez->zdropped = 1;
			break;
		}
		st0 = st, en0 = en;
		st = st / 16 * 16, en = (en + 16) / 16 * 16 - 1;
		// set boundary conditions
		if (st > 0) {
			if (st - 1 >= last_st && st - 1 <= last_en) {
				x1 = x8[st - 1], x21 = x28[st - 1], v1 = v8[st - 1]; // (r-1,s-1) calculated in the last round
			} else {
				x1 = -q - e, x21 = -q2 - e2;
				v1 = -q - e;
			}
		} else {
			x1 = -q - e, x21 = -q2 - e2;
			v1 = r == 0? -q - e : r < long_thres? -e : r == long_thres? long_diff : -e2;
		}
		if (en >= r) {
			((int8_t*)y)[r] = -q - e, ((int8_t*)y2)[r] = -q2 - e2;
			u8[r] = r == 0? -q - e : r < long_thres? -e : r == long_thres? long_diff : -e2;
		}
		// loop fission: set scores first
        ILOG("Sachet - 7 \n");
		if (!(flag & KSW_EZ_GENERIC_SC)) {
			for (t = st0; t <= en0; t += 16) {
				__m128i sq, st, tmp, mask;
				sq = _mm_loadu_si128((__m128i*)&sf[t]);
				st = _mm_loadu_si128((__m128i*)&qrr[t]);
				mask = _mm_or_si128(_mm_cmpeq_epi8(sq, m1_), _mm_cmpeq_epi8(st, m1_));
				tmp = _mm_cmpeq_epi8(sq, st);
#ifdef __SSE4_1__
				tmp = _mm_blendv_epi8(sc_mis_, sc_mch_, tmp);
				tmp = _mm_blendv_epi8(tmp,     sc_N_,   mask);
#else
				tmp = _mm_or_si128(_mm_andnot_si128(tmp,  sc_mis_), _mm_and_si128(tmp,  sc_mch_));
				tmp = _mm_or_si128(_mm_andnot_si128(mask, tmp),     _mm_and_si128(mask, sc_N_));
#endif
				_mm_storeu_si128((__m128i*)((int8_t*)s + t), tmp);
			}
		} else {
			for (t = st0; t <= en0; ++t)
				((uint8_t*)s)[t] = mat[sf[t] * m + qrr[t]];
		}
		// core loop
        ILOG("Sachet - 6 \n");
		x1_  = _mm_cvtsi32_si128((uint8_t)x1);
		x21_ = _mm_cvtsi32_si128((uint8_t)x21);
		v1_  = _mm_cvtsi32_si128((uint8_t)v1);
		st_ = st / 16, en_ = en / 16;
		assert(en_ - st_ + 1 <= n_col_);
		if (!with_cigar) { // score only
			for (t = st_; t <= en_; ++t) {
				__m128i z, a, b, a2, b2, xt1, x2t1, vt1, ut, tmp;
				__dp_code_block1;
#ifdef __SSE4_1__
				z = _mm_max_epi8(z, a);
				z = _mm_max_epi8(z, b);
				z = _mm_max_epi8(z, a2);
				z = _mm_max_epi8(z, b2);
				z = _mm_min_epi8(z, sc_mch_);
				__dp_code_block2; // save u[] and v[]; update a, b, a2 and b2
				_mm_store_si128(&x[t],  _mm_sub_epi8(_mm_max_epi8(a,  zero_), qe_));
				_mm_store_si128(&y[t],  _mm_sub_epi8(_mm_max_epi8(b,  zero_), qe_));
				_mm_store_si128(&x2[t], _mm_sub_epi8(_mm_max_epi8(a2, zero_), qe2_));
				_mm_store_si128(&y2[t], _mm_sub_epi8(_mm_max_epi8(b2, zero_), qe2_));
#else
				tmp = _mm_cmpgt_epi8(a,  z);
				z = _mm_or_si128(_mm_andnot_si128(tmp, z), _mm_and_si128(tmp, a));
				tmp = _mm_cmpgt_epi8(b,  z);
				z = _mm_or_si128(_mm_andnot_si128(tmp, z), _mm_and_si128(tmp, b));
				tmp = _mm_cmpgt_epi8(a2, z);
				z = _mm_or_si128(_mm_andnot_si128(tmp, z), _mm_and_si128(tmp, a2));
				tmp = _mm_cmpgt_epi8(b2, z);
				z = _mm_or_si128(_mm_andnot_si128(tmp, z), _mm_and_si128(tmp, b2));
				tmp = _mm_cmplt_epi8(sc_mch_, z);
				z = _mm_or_si128(_mm_and_si128(tmp, sc_mch_), _mm_andnot_si128(tmp, z));
				__dp_code_block2;
				tmp = _mm_cmpgt_epi8(a, zero_);
				_mm_store_si128(&x[t],  _mm_sub_epi8(_mm_and_si128(tmp, a),  qe_));
				tmp = _mm_cmpgt_epi8(b, zero_);
				_mm_store_si128(&y[t],  _mm_sub_epi8(_mm_and_si128(tmp, b),  qe_));
				tmp = _mm_cmpgt_epi8(a2, zero_);
				_mm_store_si128(&x2[t], _mm_sub_epi8(_mm_and_si128(tmp, a2), qe2_));
				tmp = _mm_cmpgt_epi8(b2, zero_);
				_mm_store_si128(&y2[t], _mm_sub_epi8(_mm_and_si128(tmp, b2), qe2_));
#endif
			}
		} else if (!(flag&KSW_EZ_RIGHT)) { // gap left-alignment
			__m128i *pr = p + (size_t)r * n_col_ - st_;
			off[r] = st, off_end[r] = en;
			for (t = st_; t <= en_; ++t) {
				__m128i d, z, a, b, a2, b2, xt1, x2t1, vt1, ut, tmp;
				__dp_code_block1;
#ifdef __SSE4_1__
				d = _mm_and_si128(_mm_cmpgt_epi8(a, z), _mm_set1_epi8(1));       // d = a  > z? 1 : 0
				z = _mm_max_epi8(z, a);
				d = _mm_blendv_epi8(d, _mm_set1_epi8(2), _mm_cmpgt_epi8(b,  z)); // d = b  > z? 2 : d
				z = _mm_max_epi8(z, b);
				d = _mm_blendv_epi8(d, _mm_set1_epi8(3), _mm_cmpgt_epi8(a2, z)); // d = a2 > z? 3 : d
				z = _mm_max_epi8(z, a2);
				d = _mm_blendv_epi8(d, _mm_set1_epi8(4), _mm_cmpgt_epi8(b2, z)); // d = a2 > z? 3 : d
				z = _mm_max_epi8(z, b2);
				z = _mm_min_epi8(z, sc_mch_);
#else // we need to emulate SSE4.1 intrinsics _mm_max_epi8() and _mm_blendv_epi8()
				tmp = _mm_cmpgt_epi8(a,  z);
				d = _mm_and_si128(tmp, _mm_set1_epi8(1));
				z = _mm_or_si128(_mm_andnot_si128(tmp, z), _mm_and_si128(tmp, a));
				tmp = _mm_cmpgt_epi8(b,  z);
				d = _mm_or_si128(_mm_andnot_si128(tmp, d), _mm_and_si128(tmp, _mm_set1_epi8(2)));
				z = _mm_or_si128(_mm_andnot_si128(tmp, z), _mm_and_si128(tmp, b));
				tmp = _mm_cmpgt_epi8(a2, z);
				d = _mm_or_si128(_mm_andnot_si128(tmp, d), _mm_and_si128(tmp, _mm_set1_epi8(3)));
				z = _mm_or_si128(_mm_andnot_si128(tmp, z), _mm_and_si128(tmp, a2));
				tmp = _mm_cmpgt_epi8(b2, z);
				d = _mm_or_si128(_mm_andnot_si128(tmp, d), _mm_and_si128(tmp, _mm_set1_epi8(4)));
				z = _mm_or_si128(_mm_andnot_si128(tmp, z), _mm_and_si128(tmp, b2));
				tmp = _mm_cmplt_epi8(sc_mch_, z);
				z = _mm_or_si128(_mm_and_si128(tmp, sc_mch_), _mm_andnot_si128(tmp, z));
#endif
				__dp_code_block2;
				tmp = _mm_cmpgt_epi8(a, zero_);
				_mm_store_si128(&x[t],  _mm_sub_epi8(_mm_and_si128(tmp, a),  qe_));
				d = _mm_or_si128(d, _mm_and_si128(tmp, _mm_set1_epi8(0x08))); // d = a > 0? 1<<3 : 0
				tmp = _mm_cmpgt_epi8(b, zero_);
				_mm_store_si128(&y[t],  _mm_sub_epi8(_mm_and_si128(tmp, b),  qe_));
				d = _mm_or_si128(d, _mm_and_si128(tmp, _mm_set1_epi8(0x10))); // d = b > 0? 1<<4 : 0
				tmp = _mm_cmpgt_epi8(a2, zero_);
				_mm_store_si128(&x2[t], _mm_sub_epi8(_mm_and_si128(tmp, a2), qe2_));
				d = _mm_or_si128(d, _mm_and_si128(tmp, _mm_set1_epi8(0x20))); // d = a > 0? 1<<5 : 0
				tmp = _mm_cmpgt_epi8(b2, zero_);
				_mm_store_si128(&y2[t], _mm_sub_epi8(_mm_and_si128(tmp, b2), qe2_));
				d = _mm_or_si128(d, _mm_and_si128(tmp, _mm_set1_epi8(0x40))); // d = b > 0? 1<<6 : 0
				_mm_store_si128(&pr[t], d);
			}
		} else { // gap right-alignment
			__m128i *pr = p + (size_t)r * n_col_ - st_;
			off[r] = st, off_end[r] = en;
			for (t = st_; t <= en_; ++t) {
				__m128i d, z, a, b, a2, b2, xt1, x2t1, vt1, ut, tmp;
				__dp_code_block1;
#ifdef __SSE4_1__
				d = _mm_andnot_si128(_mm_cmpgt_epi8(z, a), _mm_set1_epi8(1));    // d = z > a?  0 : 1
				z = _mm_max_epi8(z, a);
				d = _mm_blendv_epi8(_mm_set1_epi8(2), d, _mm_cmpgt_epi8(z, b));  // d = z > b?  d : 2
				z = _mm_max_epi8(z, b);
				d = _mm_blendv_epi8(_mm_set1_epi8(3), d, _mm_cmpgt_epi8(z, a2)); // d = z > a2? d : 3
				z = _mm_max_epi8(z, a2);
				d = _mm_blendv_epi8(_mm_set1_epi8(4), d, _mm_cmpgt_epi8(z, b2)); // d = z > b2? d : 4
				z = _mm_max_epi8(z, b2);
				z = _mm_min_epi8(z, sc_mch_);
#else // we need to emulate SSE4.1 intrinsics _mm_max_epi8() and _mm_blendv_epi8()
				tmp = _mm_cmpgt_epi8(z, a);
				d = _mm_andnot_si128(tmp, _mm_set1_epi8(1));
				z = _mm_or_si128(_mm_and_si128(tmp, z), _mm_andnot_si128(tmp, a));
				tmp = _mm_cmpgt_epi8(z, b);
				d = _mm_or_si128(_mm_and_si128(tmp, d), _mm_andnot_si128(tmp, _mm_set1_epi8(2)));
				z = _mm_or_si128(_mm_and_si128(tmp, z), _mm_andnot_si128(tmp, b));
				tmp = _mm_cmpgt_epi8(z, a2);
				d = _mm_or_si128(_mm_and_si128(tmp, d), _mm_andnot_si128(tmp, _mm_set1_epi8(3)));
				z = _mm_or_si128(_mm_and_si128(tmp, z), _mm_andnot_si128(tmp, a2));
				tmp = _mm_cmpgt_epi8(z, b2);
				d = _mm_or_si128(_mm_and_si128(tmp, d), _mm_andnot_si128(tmp, _mm_set1_epi8(4)));
				z = _mm_or_si128(_mm_and_si128(tmp, z), _mm_andnot_si128(tmp, b2));
				tmp = _mm_cmplt_epi8(sc_mch_, z);
				z = _mm_or_si128(_mm_and_si128(tmp, sc_mch_), _mm_andnot_si128(tmp, z));
#endif
				__dp_code_block2;
				tmp = _mm_cmpgt_epi8(zero_, a);
				_mm_store_si128(&x[t],  _mm_sub_epi8(_mm_andnot_si128(tmp, a),  qe_));
				d = _mm_or_si128(d, _mm_andnot_si128(tmp, _mm_set1_epi8(0x08))); // d = a > 0? 1<<3 : 0
				tmp = _mm_cmpgt_epi8(zero_, b);
				_mm_store_si128(&y[t],  _mm_sub_epi8(_mm_andnot_si128(tmp, b),  qe_));
				d = _mm_or_si128(d, _mm_andnot_si128(tmp, _mm_set1_epi8(0x10))); // d = b > 0? 1<<4 : 0
				tmp = _mm_cmpgt_epi8(zero_, a2);
				_mm_store_si128(&x2[t], _mm_sub_epi8(_mm_andnot_si128(tmp, a2), qe2_));
				d = _mm_or_si128(d, _mm_andnot_si128(tmp, _mm_set1_epi8(0x20))); // d = a > 0? 1<<5 : 0
				tmp = _mm_cmpgt_epi8(zero_, b2);
				_mm_store_si128(&y2[t], _mm_sub_epi8(_mm_andnot_si128(tmp, b2), qe2_));
				d = _mm_or_si128(d, _mm_andnot_si128(tmp, _mm_set1_epi8(0x40))); // d = b > 0? 1<<6 : 0
				_mm_store_si128(&pr[t], d);
			}
		}
		if (!approx_max) { // find the exact max with a 32-bit score array
			int32_t max_H, max_t;
			// compute H[], max_H and max_t
			if (r > 0) {
				int32_t HH[4], tt[4], en1 = st0 + (en0 - st0) / 4 * 4, i;
				__m128i max_H_, max_t_;
				max_H = H[en0] = en0 > 0? H[en0-1] + u8[en0] : H[en0] + v8[en0]; // special casing the last element
				max_t = en0;
				max_H_ = _mm_set1_epi32(max_H);
				max_t_ = _mm_set1_epi32(max_t);
				for (t = st0; t < en1; t += 4) { // this implements: H[t]+=v8[t]-qe; if(H[t]>max_H) max_H=H[t],max_t=t;
					__m128i H1, tmp, t_;
					H1 = _mm_loadu_si128((__m128i*)&H[t]);
					t_ = _mm_setr_epi32(v8[t], v8[t+1], v8[t+2], v8[t+3]);
					H1 = _mm_add_epi32(H1, t_);
					_mm_storeu_si128((__m128i*)&H[t], H1);
					t_ = _mm_set1_epi32(t);
					tmp = _mm_cmpgt_epi32(H1, max_H_);
#ifdef __SSE4_1__
					max_H_ = _mm_blendv_epi8(max_H_, H1, tmp);
					max_t_ = _mm_blendv_epi8(max_t_, t_, tmp);
#else
					max_H_ = _mm_or_si128(_mm_and_si128(tmp, H1), _mm_andnot_si128(tmp, max_H_));
					max_t_ = _mm_or_si128(_mm_and_si128(tmp, t_), _mm_andnot_si128(tmp, max_t_));
#endif
				}
				_mm_storeu_si128((__m128i*)HH, max_H_);
				_mm_storeu_si128((__m128i*)tt, max_t_);
				for (i = 0; i < 4; ++i)
					if (max_H < HH[i]) max_H = HH[i], max_t = tt[i] + i;
				for (; t < en0; ++t) { // for the rest of values that haven't been computed with SSE
					H[t] += (int32_t)v8[t];
					if (H[t] > max_H)
						max_H = H[t], max_t = t;
				}
			} else H[0] = v8[0] - qe, max_H = H[0], max_t = 0; // special casing r==0
			// update ez
			if (en0 == tlen - 1 && H[en0] > ez->mte)
				ez->mte = H[en0], ez->mte_q = r - en;
			if (r - st0 == qlen - 1 && H[st0] > ez->mqe)
				ez->mqe = H[st0], ez->mqe_t = st0;
			if (ksw_apply_zdrop(ez, 1, max_H, r, max_t, zdrop, e2)) break;
			if (r == qlen + tlen - 2 && en0 == tlen - 1)
				ez->score = H[tlen - 1];
		} else { // find approximate max; Z-drop might be inaccurate, too.
			if (r > 0) {
				if (last_H0_t >= st0 && last_H0_t <= en0 && last_H0_t + 1 >= st0 && last_H0_t + 1 <= en0) {
					int32_t d0 = v8[last_H0_t];
					int32_t d1 = u8[last_H0_t + 1];
					if (d0 > d1) H0 += d0;
					else H0 += d1, ++last_H0_t;
				} else if (last_H0_t >= st0 && last_H0_t <= en0) {
					H0 += v8[last_H0_t];
				} else {
					++last_H0_t, H0 += u8[last_H0_t];
				}
			} else H0 = v8[0] - qe, last_H0_t = 0;
			if ((flag & KSW_EZ_APPROX_DROP) && ksw_apply_zdrop(ez, 1, H0, r, last_H0_t, zdrop, e2)) break;
			if (r == qlen + tlen - 2 && en0 == tlen - 1)
				ez->score = H0;
		}
		last_st = st, last_en = en;
		//for (t = st0; t <= en0; ++t) printf("(%d,%d)\t(%d,%d,%d,%d)\t%d\n", r, t, ((int8_t*)u)[t], ((int8_t*)v)[t], ((int8_t*)x)[t], ((int8_t*)y)[t], H[t]); // for debugging
	}
    ILOG("Sachet - 7 \n");
	//kfree(km, mem);
	//if (!approx_max) kfree(km, H);
	if (with_cigar) { // backtrack
		int rev_cigar = !!(flag & KSW_EZ_REV_CIGAR);
		if (!ez->zdropped && !(flag&KSW_EZ_EXTZ_ONLY)) {
			ksw_backtrack(km, 1, rev_cigar, 0, (uint8_t*)p, off, off_end, n_col_*16, tlen-1, qlen-1, &ez->m_cigar, &ez->n_cigar, &ez->cigar);
		} else if (!ez->zdropped && (flag&KSW_EZ_EXTZ_ONLY) && ez->mqe + end_bonus > (int)ez->max) {
			ez->reach_end = 1;
			ksw_backtrack(km, 1, rev_cigar, 0, (uint8_t*)p, off, off_end, n_col_*16, ez->mqe_t, qlen-1, &ez->m_cigar, &ez->n_cigar, &ez->cigar);
		} else if (ez->max_t >= 0 && ez->max_q >= 0) {
			ksw_backtrack(km, 1, rev_cigar, 0, (uint8_t*)p, off, off_end, n_col_*16, ez->max_t, ez->max_q, &ez->m_cigar, &ez->n_cigar, &ez->cigar);
		}
		//kfree(km, mem2); kfree(km, off);
	}

    cmd->mmdata.ez_max = ez->max;
    cmd->mmdata.ez_zdropped = ez->zdropped;
    cmd->mmdata.ez_max_q = ez->max_q;
    cmd->mmdata.ez_max_t = ez->max_t;
    cmd->mmdata.ez_mqe = ez->mqe;
    cmd->mmdata.ez_mqe_t = ez->mqe_t;
    cmd->mmdata.ez_mte = ez->mte;
    cmd->mmdata.ez_mte_q = ez->mte_q;
    cmd->mmdata.ez_score = ez->score;
    cmd->mmdata.ez_m_cigar = ez->m_cigar;
    cmd->mmdata.ez_n_cigar = ez->n_cigar;
    cmd->mmdata.ez_reach_end = ez->reach_end;
    cmd->mmdata.ez_zdropped = ez->zdropped;
    ILOG("SACHET EXECUTING MINIMAP KERNEL ----------------- END\n");

	/* mark this compute job as done */
	cmd->tdata.status = 0xA5;
	sync();
	/*dump_css_cmd(cmd); */

}
void
compute_lzma(css_cmd_t *cmd, struct spdk_bdev *bdev)
{

	int cnt, ret = -1;
	char format = cmd->job.args[0];
	size_t in_len = cmd->job.args[1];
	unsigned char *compressed;
	uint8_t *malloc_buf =
		(uint8_t *) ((struct malloc_disk *) bdev->ctxt)->malloc_buf;
	for (cnt = 0; cnt < cmd->job.num_args; cnt++)
		DLOG("arg[%d]: %d\n", cnt, cmd->job.args[cnt]);

	ILOG("cmd args ..., %d %d\n", cmd->job.args[0], cmd->job.args[1]);
	data_set_t *ds = &cmd->job.data_sets[0];

	for (cnt = 0; cnt < cmd->job.num_data_sets; cnt++) {
		ILOG("cmd ds[%d] offset: %d,  blocks: %d\n",
		     cnt,
		     cmd->job.data_sets[cnt].offset_block,
		     cmd->job.data_sets[cnt].num_blocks);
		dump_ds(ds);
		ds++;
	}

	ILOG("Executing LZMA engine ...\n");

	/*
	 * for some reason direct access of bdev buffer, is not always
	 * reflected with latest data using memcpy workaround for now.
	 * FIXME: investigate and remove these extra memory copies
	 */
#define LZMA_MEM_CACHE_WA

#ifndef LZMA_MEM_CACHE_WA
	size_t *out_len = get_mem(bdev, cmd->job.data_sets[0].offset_block,
				  cmd->block_sz);
	uint8_t *in_data = get_mem(bdev, cmd->job.data_sets[1].offset_block,
				   cmd->block_sz);
	uint8_t **out_data = get_mem(bdev, cmd->job.data_sets[2].offset_block,
				     cmd->block_sz);
#else
	size_t *dev_out_len = get_mem(bdev, cmd->job.data_sets[0].offset_block,
				      cmd->block_sz);
	uint8_t *dev_in_data = get_mem(bdev, cmd->job.data_sets[1].offset_block,
				       cmd->block_sz);
	uint8_t **dev_out_data = get_mem(bdev,
					 cmd->job.data_sets[2].offset_block,
					 cmd->block_sz);

	size_t *out_len = cs_malloc(cmd->job.data_sets[0].num_blocks,
				    cmd->block_sz);
	uint8_t *in_data = cs_malloc(cmd->job.data_sets[1].num_blocks,
				     cmd->block_sz);
	uint8_t **out_data = cs_malloc(cmd->job.data_sets[2].num_blocks,
				       cmd->block_sz);

	memcpy(out_len, dev_out_len,
	       cmd->job.data_sets[0].num_blocks * cmd->block_sz);
	memcpy(in_data, dev_in_data,
	       cmd->job.data_sets[1].num_blocks * cmd->block_sz);
	memcpy(out_data, dev_out_data,
	       cmd->job.data_sets[2].num_blocks * cmd->block_sz);
#endif

	*out_len = 0;
	memset(out_data, 0, 4096);

	hex_dump("in_data: ", in_data, 64);
	if (cmd->job.opc == LZ_OPC_CMPR) {
		ILOG("LZ_OPC_CMPR: op_tag: %x ...\n", cmd->op_tag);
		ret = simpleCompress(format, in_data,
				     in_len, &compressed, out_len);
	} else if (cmd->job.opc == LZ_OPC_DCMP) {
		ILOG("LZ_OPC_DCMP: op_tag: %x ...\n", cmd->op_tag);
		ret = simpleDecompress(format, in_data,
				       in_len, &compressed, out_len);
	} else{
		ELOG("LZMA: Unknown opcode: %x\n", cmd->job.opc);
		ASSERT(0);
	}
	memcpy(out_data, compressed, *out_len);

	hex_dump("out_len: ", out_len, 8);
	hex_dump("out_data: ", out_data, 64);
	ILOG("LZ lib returned : %d, out_len: %d\n", ret, *out_len);
	cmd->tdata.result_len = *out_len;
	if (ret == 0)
		free(compressed);

#ifdef LZMA_MEM_CACHE_WA
	memcpy(dev_out_len, out_len,
	       cmd->job.data_sets[0].num_blocks * cmd->block_sz);
	memcpy(dev_in_data, in_data,
	       cmd->job.data_sets[1].num_blocks * cmd->block_sz);
	memcpy(dev_out_data, out_data,
	       cmd->job.data_sets[2].num_blocks * cmd->block_sz);

	spdk_free(out_len);
	spdk_free(in_data);
	spdk_free(out_data);
#endif


	DLOG("**** RUNNING LZMA ENGINE, DONE!, ret: %x ****\n", ret);
	DLOG("Executing LZMA engine: Done!\n");

	/* mark this compute job as done */
	cmd->tdata.status = 0xA5;
	sync();
	/*dump_css_cmd(cmd); */

}



void *
execute_css_job(void *ctxt)
{

	uint8_t *mem = NULL;
	struct spdk_nvmf_request *req = ctxt;
	struct spdk_nvmf_ns *ns;
	struct spdk_bdev *bdev;

	struct spdk_nvmf_ctrlr *ctrlr = req->qpair->ctrlr;

	struct spdk_nvme_cmd *ncmd = &req->cmd->nvme_cmd;
	struct spdk_nvme_cpl *response = &req->rsp->nvme_cpl;

	css_cmd_t *cmd = req->data;

	ns = _spdk_nvmf_subsystem_get_ns(ctrlr->subsys, ncmd->nsid);
	bdev = ns->bdev;


	/* detect the CSS command by tapping one LBA write on 0th LBA */
	/* css_cmd_t *cmd = (css_cmd_t *)(((struct malloc_disk *)
	 * bdev->ctxt)->malloc_buf +
	 * bdev_io->u.bdev.offset_blocks * block_size);
	 */

	DLOG("**** CS Control command recieved !! ****, device: %s, nsid: %x\n",
		 bdev->name, ns->nsid);

	dump_css_cmd(cmd);

	if (cmd->signature != 0xC550D0CC) {
		ELOG("**** CS Control command corrupted, skipping,%x ****\n",
		     cmd->signature);
		cmd->tdata.status = 0xA5;
		cmd->tdata.result_len = 0;
		return NULL;
	}

	switch (cmd->engine) {
	case CSS_ENG_TYPE_DOCK:
		compute_container(cmd, bdev);
		break;

	case CSS_ENG_TYPE_UBPF:
		compute_ubpf(cmd, bdev);
		break;

	case CSS_ENG_TYPE_OSSL:
		compute_ossl(cmd, bdev);
		break;

	case CSS_ENG_TYPE_GZIP:
		compute_gzip(cmd, bdev);
		break;

	case CSS_ENG_TYPE_INFR:
		compute_inference(cmd, bdev);
		break;

	case CSS_ENG_TYPE_ECRS:
		compute_erasure(cmd, bdev);
		break;

	case CSS_ENG_TYPE_LZMA:
		compute_lzma(cmd, bdev);
		break;
    case CSS_ENG_TYPE_MINIMAP:
        compute_minimap_kernel(cmd, bdev);
        break;
	default:
		ELOG("invalid compute engine: %x\n", cmd->engine);
		dump_css_cmd(cmd);
		break;
	}


	if (0 == (cmd->hdata.flags & DATA_TYPE_FILE)) {
		/* write the results back to device */
		mem =
		(uint8_t *)(((struct malloc_disk *)bdev->ctxt)->malloc_buf);
		memcpy(mem, cmd, sizeof(css_cmd_t));
	}

	DLOG("completing request ...:\n");
	response->cdw0 = 0;
	spdk_nvmf_request_complete(req);

	return NULL;

}

int
execute_csnvme(struct spdk_nvmf_request *req)
{
	pthread_t thread_id;

	DLOG("CNVME:***********************************\n");
	pthread_create(&thread_id, NULL, execute_css_job, (void *) req);
	return SPDK_NVMF_REQUEST_EXEC_STATUS_ASYNCHRONOUS;
}

