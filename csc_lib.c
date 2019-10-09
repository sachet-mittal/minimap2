/*
 * ORCS: client library functions.
 *
 * Author: Subrahmaya Lingappa, subrahmanya.lingappa@wdc.com
 * date: 26 June, 2019
 */
#define _GNU_SOURCE
#include "csn.h"
#include "orcs_bitops.h"
#include "spdk/nvme_spec.h"
#include "nvme-ioctl.h"


int32_t csp_num_nodes;
cs_node_t *csp_nodes;
cs_nodes_data_t *csp_nodes_data;

char tcols[KWHT + 1][20] = {
	"\x1B[0m",
	"\x1B[31m",
	"\x1B[32m",
	"\x1B[33m",
	"\x1B[34m",
	"\x1B[35m",
	"\x1B[36m",
	"\x1B[37m"
};

FILE *g_dbgstream;
uint32_t debug_level = CLOG_ERR
                        | CLOG_INFO
                        | CLOG_DBG
                        | CLOG_PROF
;
uint32_t log_to_file;

void
seg_fault_handler (int sig)
{
	void *array[10];
	size_t size;

	/* get void*'s for all entries on the stack */
	size = backtrace(array, 10);

	/* print out all the frames to stderr */
	fprintf(stderr, "Error: signal %d:\n", sig);
	backtrace_symbols_fd(array, size, STDERR_FILENO);
	exit(1);
}

void
hex_dump(char *desc, void *addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char *) addr;

	if (!(CLOG_DBG & debug_level))
		return;
	/* Output description if given. */
	if (desc != NULL)
		printf("%s:\n", desc);

	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n", len);
		return;
	}

	/* Process every byte in the data. */
	for (i = 0; i < len; i++) {
		/* Multiple of 16 means new line (with line offset). */

		if ((i % 16) == 0) {
			/* Just don't print ASCII for the zeroth line. */
			if (i != 0)
				printf("  %s\n", buff);

			/* Output the offset. */
			printf("  %016llx:%04x ", pc, i);
		}

		/* Now the hex code for the specific character. */
		printf(" %02x", pc[i]);

		/* And store a printable ASCII character for later. */
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	/* Pad out last line if not exactly 16 characters. */
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	/* And print the final ASCII bit. */
	printf("  %s\n", buff);
}

int
get_fd(char *dfile_name)
{
	int fd = -1;

	fd = open(dfile_name, O_RDWR);
	/* create if it doesnt exist */
	if (fd < 0)
		fd = open(dfile_name, O_RDWR | O_CREAT | O_TRUNC, 0777);

	if (fd < 0) {
		perror("failed to get fd : ");
		ELOG("File does not exists, failed to create file: %s\n",
		     dfile_name);
		return -1;
	}

	DLOG("%s: file: %s, fd: %x\n", __func__, dfile_name, fd);
	return fd;
}

void
dump_css_cmd(css_cmd_t *cmd)
{
	int i = 0;

	DLOG("Signature --------: 0x%08x\n", cmd->signature);
	DLOG("tag --------------: 0x%08lx\n", cmd->op_tag);
	DLOG("engine -----------: 0x%08x\n", cmd->engine);
#if 0
	DLOG("dfile_name -------: %s\n", cmd->hdata.dfile_name);
	DLOG("block_sz----------: 0x%08x\n", cmd->hdata.block_sz);
	DLOG("efile_name ---------: %s\n", cmd->hdata.efile_name);
	DLOG("exe_len ----------: 0x%08lx\n", cmd->hdata.exe_len);
	DLOG("exe_args ---------: %s\n", cmd->hdata.exe_args);
	DLOG("ifile_name -------: %s\n", cmd->hdata.ifile_name);
	DLOG("ofile_name -------: %s\n", cmd->hdata.ofile_name);
	DLOG("exe_offset -------: 0x%08lx\n", cmd->hdata.exe_offset);
	DLOG("data_offset ------: 0x%08lx\n", cmd->hdata.data_offset);
	DLOG("data_len ---------: 0x%08lx\n", cmd->hdata.data_len);
	DLOG("result_offset ----: 0x%08lx\n", cmd->hdata.result_offset);
#else
	DLOG("dfile_name -------: %s\n", cmd->dfile_name);
	DLOG("block_sz----------: 0x%08x\n", cmd->block_sz);
	DLOG("opc --------------: 0x%08x\n", cmd->job.opc);
	DLOG("num_args----------: 0x%08x\n", cmd->job.num_args);
	/*for(i =0; i< cmd->job.num_args; i++) */
	for (i = 0; i < 5; i++)
		DLOG("\targ[%d]-------: 0x%08x\n", i, cmd->job.args[i]);
	DLOG("num_data_sets-----: 0x%08x\n", cmd->job.num_data_sets);
	for (i = 0; i < cmd->job.num_data_sets; i++) {
		DLOG("\tds[%d].type --------: 0x%08x\n", i,
		     cmd->job.data_sets[i].type);
		DLOG("\tds[%d].iov.iov_base : 0x%08llx\n", i,
		     cmd->job.data_sets[i].iov.iov_base);
		DLOG("\tds[%d].iov.iov_len  : 0x%08x\n", i,
		     cmd->job.data_sets[i].iov.iov_len);
		DLOG("\tds[%d].offset_block : 0x%08x\n", i,
		     cmd->job.data_sets[i].offset_block);
		DLOG("\tds[%d].num_blocks   : 0x%08x\n", i,
		     cmd->job.data_sets[i].num_blocks);
	}
#endif

	DLOG("status -----------: 0x%08x\n", cmd->tdata.status);
	DLOG("result_len -------: 0x%08lx\n", cmd->tdata.result_len);
}

int32_t
send_input_data(css_cmd_t *cmd)
{
	int32_t ret;

	/* Send the input data for the compute job over */
	DLOG("Sending input file: %s, size: %ld MB...\n",
	     cmd->hdata.ifile_name, cmd->hdata.data_len / (1024 * 1024));
	ret = copy_data(cmd->hdata.ifile_name, cmd->hdata.dfile_name,
			0, (cmd->hdata.data_offset * cmd->hdata.block_sz),
			cmd->hdata.data_len);
	DLOG("input data xfer DONE.\n");
	return ret;


}

int32_t
send_image_data(css_cmd_t *cmd)
{
	int32_t ret;

	/* we need to send compute code only for Docker and uBPF engines */
	if ((cmd->engine == CSS_ENG_TYPE_DOCK) ||
	    (cmd->engine == CSS_ENG_TYPE_UBPF)) {
		/* Send the compute image file over */
		DLOG("Sending image file: %s, size: %ld MB....\n",
		     cmd->hdata.efile_name, cmd->hdata.exe_len / (1024 * 1024));
		ret = copy_data(cmd->hdata.efile_name, cmd->hdata.dfile_name,
				0,
				(cmd->hdata.exe_offset * cmd->hdata.block_sz),
				cmd->hdata.exe_len);
		DLOG("image xfer DONE.\n");
	}

	return ret;
}

css_cmd_t *
css_job_init(int engine,
	     char *device_name,
	     char *efile_name, char *ifile, char *ofile, char *args)
{

	signal(SIGSEGV, seg_fault_handler);	/* install our handler */

	css_cmd_t *cmd = calloc(sizeof(css_cmd_t), 1);

	ASSERTF(cmd != NULL, "calloc failed!");

	memset(cmd, 0, sizeof(css_cmd_t));
	cmd->signature = 0xC550D0CC;
	cmd->engine = engine;
	/*cmd->op_tag = g_op_tag++; */
	cmd->hdata.exe_len = get_file_len(efile_name);
	cmd->hdata.data_len = get_file_len(ifile);
	cmd->hdata.block_sz = CSS_BLOCK_SIZE;
	if (device_name) {
		strcpy(cmd->hdata.dfile_name, device_name);
		strcpy(cmd->dfile_name, device_name);
	} else{
		ELOG("device name not provided\n");
		return NULL;
	}
	if (efile_name)
		strcpy(cmd->hdata.efile_name, efile_name);
	if (args)
		strcpy(cmd->hdata.exe_args, args);

	if (ifile)
		strcpy(cmd->hdata.ifile_name, ifile);
	if (ofile)
		strcpy(cmd->hdata.ofile_name, ofile);
	cmd->hdata.exe_offset = TEXT_OFFSET;
	cmd->hdata.data_offset = DATA_OFFSET;
	cmd->hdata.result_offset = RSLT_OFFSET;

	PLOG("initialized cmd: %p\n", cmd);
	return cmd;
}

void
css_job_free(css_cmd_t *cmd)
{
	DLOG("freeing cmd: %p\n", cmd);
	pthread_mutex_lock(&csp_nodes[cmd->node_num].free_mem_blocks_mutex);
	bitmap_release_region(&csp_nodes[cmd->node_num].free_mem_blocks,
			      cmd->mem_start_block,
			      get_count_order(cmd->mem_num_blocks));
	pthread_mutex_unlock(&csp_nodes[cmd->node_num].free_mem_blocks_mutex);
	free(cmd);
}

int32_t
retrieve_results(css_cmd_t *cmd)
{
	int32_t ret;

	DLOG("Retrieving result data ...., len: %ld, name: %s\n",
	     cmd->tdata.result_len, cmd->hdata.ofile_name);
	ret =
		copy_data(cmd->hdata.dfile_name, cmd->hdata.ofile_name,
			  (cmd->hdata.result_offset * cmd->hdata.block_sz), 0,
			  cmd->tdata.result_len);
	truncate_file(cmd->hdata.ofile_name, cmd->tdata.result_len);


	return ret;
}



void
send_job_cmd(css_cmd_t *cmd)
{
	/*int32_t fd = open(cmd->hdata.dfile_name, O_RDWR ); */
	int32_t fd = open(cmd->dfile_name, O_RDWR);
	int32_t bytes = 0, ret = -1;

	css_cmd_t cmd1;

	memcpy(&cmd1, cmd, sizeof(cmd1));

	/*hex_dump("cs data: ", &cmd1, 64); */

	ILOG("Sending for CSS job command to compute engine ..., %s\n",
	     cmd->dfile_name);
	if (fd < 0) {
		ELOG("failed to open file, %d, filename: %s\n!",
		     fd, cmd->dfile_name);
	}

#if 0
	lseek(fd, 0, SEEK_SET);
	bytes = write(fd, &cmd->buf, cmd->hdata.block_sz);
	ASSERTF(bytes > 0, "nonzero bytes: %x\n", bytes);
#else
	struct nvme_admin_cmd cs_cmd = {
		.opcode = SPDK_NVME_OPC_CSNVME,
		.nsid = nvme_get_nsid(fd),
		.addr = (__u64) (intptr_t) &cmd1,
		/*.data_len = cmd->hdata.block_sz, */
		.data_len = 4096,
		.cdw10 = 0,
	};

	/*hex_dump("cs data: ", &cmd1, 64); */

	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cs_cmd);
	if (ret != 0) {
		perror("ioctl");
		DLOG("IOCTL returned  %d, file: %s\n",
		     ret, &cmd1.hdata.dfile_name);
		/*ASSERTF(ret==0, "nonzero stat: %x\n", ret); */
		exit(-1);
	}

	/*hex_dump("cs data: ", &cmd, 64); */


#endif
	close(fd);

}

void
wait_for_op_status(css_cmd_t *cmd)
{
	uint32_t ret = 0;
	int32_t fd = -1;
	int32_t bytes = 0;
	uint32_t block_sz = CSS_BLOCK_SIZE;

	ILOG("Waiting for CSS job to complete ...\n");
	do {

		sleep(1);

		/*memset(cmd, 0, sizeof(css_cmd_t)); */
		cmd->tdata.status = 0;
		fd = open(cmd->hdata.dfile_name, O_RDWR);
		if (fd > 0) {
			lseek(fd, 0, SEEK_SET);
			bytes = read(fd, &cmd->buf, block_sz);
			ASSERTF(bytes > 0, "nonzero bytes: %x\n", bytes);
			ret = cmd->tdata.status;
			/*dump_css_cmd(cmd); */

			close(fd);
		} else{
			perror("device open: ");
			ELOG("device open returned: %di, file: %s\n", fd,
			     cmd->hdata.dfile_name);
		}
		DLOG("operation Status : 0x%08x \r", cmd->tdata.status);
	} while (ret != 0xA5);
	XFER_LOG("\n");
	dump_css_cmd(cmd);
	ILOG("\n");

}

void
truncate_file(uint8_t *ofile, int64_t len)
{
	int32_t ret = -1, of_fd = open(ofile, O_RDWR);

	ret = ftruncate(of_fd, len);
	ASSERTF((ret == 0), "ftruncate nonzero status: %x\n", ret);
}

int32_t
copy_data(char *ifile, char *ofile, uint32_t if_offset, uint32_t of_offset,
	  int32_t if_len)
{
	uint8_t buf[4096];
	uint32_t xfer_sz = 4096;
	int32_t rem = if_len;
	int32_t if_fd = open(ifile, O_RDWR);
	int32_t of_fd = open(ofile, O_RDWR);
	int32_t rd_bytes = 0, wr_bytes = 0;

	DLOG("ifile: %s, ofile: %s, if_off: %d, of_off: %d, if_len: %d\n",
	     ifile, ofile, if_offset, of_offset, if_len);
	/* create if it doesnt exist */
	if (of_fd < 0)
		of_fd = open(ofile, O_RDWR | O_CREAT | O_TRUNC, 0777);

	if (0 > if_fd || 0 > of_fd) {
		ELOG("failed to open files, %d[%s], %d[%s]\n!",
		     if_fd, ifile, of_fd, ofile);
		return -1;
	}


	lseek(if_fd, if_offset, SEEK_SET);
	lseek(of_fd, of_offset, SEEK_SET);
	do {
		XFER_LOG("image xfer: bytes: total: %04d, remaining: %04d \r",
			 if_len, rem);
		rd_bytes = read(if_fd, &buf, xfer_sz);
		wr_bytes = write(of_fd, &buf, xfer_sz);
		ASSERTF((rd_bytes) > 0
			&& (wr_bytes > 0), "nonzero bytes: %x:%x\n", wr_bytes,
			rd_bytes);
		rem -= xfer_sz;
	} while (rem > 0);
	XFER_LOG("\n");
	close(if_fd);
	close(of_fd);
}

void
copy_buff_data_to_file(uint8_t *data_buf, int fd,
		       /*char* dfile_name, */
		       uint32_t buf_offset, uint32_t fd_offset, int32_t len,
		       int8_t dir)
{
	int32_t xfer_sz = 4096, rem = len, blk = 0;
	/*int32_t fd = open(dfile_name, O_RDWR  ); */
	int32_t bytes = 0;

#if 0
	/* create if it doesnt exist */
	if (fd < 0)
		fd = open(dfile_name, O_RDWR | O_CREAT | O_TRUNC, 0777);

	if (fd < 0) {
		ELOG("File does not exists, failed to create file: %s\n",
		     dfile_name);
		return;
	}
#endif
	lseek(fd, fd_offset * xfer_sz, SEEK_SET);
	do {
		int try = 0;

		DLOG("data xfer: ptr: %p, data: %x, bytes: total: %04d,"
		     " remaining: %04d, blk: %d , dir: %s....\n",
			 data_buf + buf_offset + (blk * xfer_sz),
			 *((int *) (data_buf + buf_offset + (blk * xfer_sz))),
			 len, rem, blk,
			 dir == XFER_TO_TARGET ?
			 "BUF_TO_FILE" : "XFER_FROM_TARGET");
		do {
			if (XFER_TO_TARGET & dir)
				bytes =	write(fd, (data_buf + buf_offset +
					       (blk * xfer_sz)),
						MIN(rem, xfer_sz));
			else if (XFER_FROM_TARGET & dir)
				bytes =
					read(fd,
					     (data_buf + buf_offset +
					      (blk * xfer_sz)),
					     MIN(rem, xfer_sz));
			hex_dump("copy_buff_data_to_file: ",
				 data_buf + buf_offset + (blk * xfer_sz), 64);
			if (bytes <= 0) {
				perror("copy_buff_data_to_file, rd/wr");
				ELOG("%s, rd/wr: %d, try: %x\n", __func__,
				     bytes, try);
				ELOG("data xfer: ptr: %p, data: %x, bytes: total: %04d,"
				     "remaining: %04d, blk: %d , dir: %s...."
				     "fd_offset: %d, xfer_sz: %d, blk: %d \n",
				     data_buf + buf_offset + (blk * xfer_sz),
				     *((int *) (data_buf + buf_offset +
						(blk * xfer_sz))),
				     len, rem, blk,
				     dir == XFER_TO_TARGET ?
				     "BUF_TO_FILE" : "XFER_FROM_TARGET",
				     fd_offset, xfer_sz, blk);

			}
		} while ((try++ < 5) && (bytes <= 0));
		ASSERTF(bytes > 0, "nonzero bytes: %x\n", bytes);
		rem -= xfer_sz;
		blk++;
	} while (rem > 0);
	XFER_LOG("\n");
}



int32_t
get_file_len(uint8_t *fname)
{
	int f_d = 0;
	struct stat st;
	int size = -1;

	f_d = open(fname, O_RDONLY);

	memset(&st, 0, sizeof(st));
	/*Check if open() was successful */
	if (-1 == f_d) {
		/*perror("get_file_len"); */
		/*ELOG("\n NULL File descriptor, %s\n", fname); */
		return -1;
	}

	/* set the errno to default value */
	errno = 0;
	if (fstat(f_d, &st)) {
		ELOG("\nfstat error: [%s]\n", strerror(errno));
		close(f_d);
		return -1;
	}

	/*
	 * DLOG("Stats : size: 0x%lx, blocks: 0x%lx, bl_sz: 0x%lx\n",
	 * st.st_size, st.st_blocks, st.st_blksize);
	 */
	size = st.st_size;

	/* Close the file */
	close(f_d);

	ILOG("get_file_len: file: %s, len: %x\n", fname, size);
	ASSERTF(size >= 0, "st.st_size error: %x\n", size);
	return size;

}

/* SKL */
CSS_UNUSED static void
get_pattern(uint8_t *buf, uint64_t size, uint32_t offset)
{
	uint64_t count = 0;
	uint32_t *intptr = (uint32_t *) buf;

	for (count = 0; count < size / 4; count++)
		*intptr++ = offset;
}

uint64_t
get_time_in_us(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (tv.tv_sec) * 1000000 + (tv.tv_usec);
}

char *csn_engines_names[] = {
	str(CSS_ENG_TYPE_DOCK),
	str(CSS_ENG_TYPE_UBPF),
	str(CSS_ENG_TYPE_GZIP),
	str(CSS_ENG_TYPE_OSSL),
	str(CSS_ENG_TYPE_INFR),
	str(CSS_ENG_TYPE_ECRS),
	str(CSS_ENG_TYPE_LZMA),
	str(CSS_ENG_TYPE_MINIMAP)
};

uint32_t
css_get_caps()
{

	return (BIT(CSS_ENG_TYPE_DOCK) |
		BIT(CSS_ENG_TYPE_UBPF) |
		BIT(CSS_ENG_TYPE_GZIP) |
		BIT(CSS_ENG_TYPE_OSSL) |
		BIT(CSS_ENG_TYPE_INFR) |
		BIT(CSS_ENG_TYPE_MINIMAP)|
		BIT(CSS_ENG_TYPE_ECRS) | BIT(CSS_ENG_TYPE_LZMA));
}

css_cmd_t *
css_stream_init(int engine,
		/*char *device_name, */
		char *args, size_t req_mem_sz)
{

	size_t req_mem_blocks = 0;

	g_dbgstream = fopen(DBG_FILE, "a");
	if (g_dbgstream <= 0) {
		printf("fopen returned : %x\n", g_dbgstream);
		perror("fopen: g_dbgstream");
	}

	signal(SIGSEGV, seg_fault_handler);	/* install our handler */

#if 1
	if (csp_num_nodes == 0)
		csp_num_nodes = scan_engines(&csp_nodes, &csp_nodes_data);
	else
		ILOG("skipping scan, already found nodes: %d\n", csp_num_nodes);
	/*exit(1); */
#else
	csp_num_nodes = scan_engines(&csp_nodes, &csp_nodes_data);
#endif
	css_cmd_t *cmd = calloc(sizeof(css_cmd_t), 1);

	ASSERTF(cmd != NULL, "calloc failed!");
	if (sizeof(css_cmd_t) > 4096) {
		ELOG("cmd size: %d\n", sizeof(css_cmd_t));
		ASSERTF(cmd <= 4096, "cmd structure > 4096");
	}

	memset(cmd, 0, sizeof(css_cmd_t));
	cmd->signature = 0xC550D0CC;
	cmd->engine = engine;
	cmd->op_tag = csp_nodes_data->g_op_tag++;
	/*
	 * FIXME: for now allocating jobs to all available nodes in
	 * round-robin fashion, should we load balance it ?
	* why do we need while loop ?
	 */
	do {
		cmd->node_num = rand() % csp_num_nodes;
	}while(0 == csp_nodes[cmd->node_num].min_num);

	ILOG("op_tag: %x, node_num: %x[max: %d], device : %s [%d:%d]\n",
	     cmd->op_tag,
	     cmd->node_num, csp_num_nodes,
	     csp_nodes[cmd->node_num].node_name,
	     csp_nodes[cmd->node_num].maj_num,
	     csp_nodes[cmd->node_num].min_num);

	cmd->block_sz = CSS_BLOCK_SIZE;
	/*strcpy(cmd->dfile_name, csp_nodes[cmd->node_num].node_name); */
	sprintf(cmd->dfile_name, "/dev/nvme%dn%d",
		csp_nodes[cmd->node_num].maj_num,
		csp_nodes[cmd->node_num].min_num);
	ILOG("NVMe device name populated : %s\n", cmd->dfile_name);
	if (args)
		strcpy(cmd->exe_args, args);

	/* lets allocate input and output buffer space on the device */
	req_mem_blocks = (req_mem_sz / MAX_MEM_BLOCK_SIZE) + 3;

	pthread_mutex_lock(&csp_nodes[cmd->node_num].free_mem_blocks_mutex);
	/*FIXME: add wait loop for bitmap_find_free_region fail case */
	cmd->mem_start_block = TEXT_OFFSET +
		bitmap_find_free_region(
				&csp_nodes[cmd->node_num].free_mem_blocks,
				MAX_MEM_BLOCKS,
				get_count_order(req_mem_blocks));
	pthread_mutex_unlock(&csp_nodes[cmd->node_num].free_mem_blocks_mutex);
	cmd->mem_num_blocks = req_mem_blocks;
	cmd->offset_block = cmd->mem_start_block;

	ILOG("req_mem_sz: %d, offset_block: %d, mem_start_block: %d,"
	     " mem_num_blocks: %d, offset: %x\n",
	     req_mem_sz, cmd->offset_block, cmd->mem_start_block,
	     cmd->mem_num_blocks);

	DLOG("initialized cmd: %p\n", cmd);
	return cmd;
}

void transfer_data_streams(css_cmd_t *cmd, int8_t dir, int data_sets)
{
	int32_t cnt = 0;
	int fd = get_fd(cmd->dfile_name);

	for (cnt = 0; cnt < data_sets; cnt++) {
		data_set_t *ds = &cmd->job.data_sets[cnt];

		ILOG("ds: %p, base: %p, off: %d, len: %d, flags: %x, dir: %d\n",
		     ds,
		     ds->iov.iov_base,
		     ds->offset_block, ds->iov.iov_len, ds->flags, dir);

		hex_dump("ds data: ",
			 ds->iov.iov_base, MIN(64, ds->iov.iov_len));
		/* check directional access */
		if (((dir == XFER_TO_TARGET) &&
		     (ds->flags & DATA_DIR_TO_TARGET)) ||
		    ((dir == XFER_FROM_TARGET) &&
		     (ds->flags & DATA_DIR_FM_TARGET))) {
			copy_buff_data_to_file(ds->iov.iov_base, fd,
					       /*cmd->dfile_name, */
					       0, ds->offset_block,
					       ds->iov.iov_len, dir);
		} else
			DLOG("Skipping data trasnfer ...\n");
	}
	fsync(fd);
	close(fd);
}

void
job_add_arg(css_cmd_t *cmd, int arg)
{
	DLOG("adding arg: %d\n", arg);
	cmd->job.args[cmd->job.num_args] = arg;
	cmd->job.num_args++;
	ASSERT(cmd->job.num_args < EC_MAX_ARGS);
}

void
dump_ds(data_set_t *ds)
{
	DLOG("Dumping ds:\n");
	DLOG("ds    : %p\n", ds);
	DLOG("type  : %p\n", ds->type);
	DLOG("base  : %p\n", ds->iov.iov_base);
	DLOG("len   : %d\n", ds->iov.iov_len);
	DLOG("offset_block  : %d\n", ds->offset_block);
	DLOG("num_blocks    : %d\n", ds->num_blocks);
}

void
job_add_data(css_cmd_t *cmd, unsigned char *data, int len, int flags)
{
	data_set_t *ds = &cmd->job.data_sets[cmd->job.num_data_sets];

	DLOG("adding data...\n");
	if (data == NULL) {
		ELOG("data is null !\n");
		ASSERT(data);
	}
	ds->type = DATA_TYPE_STRM;
	ds->flags = flags;
	ds->iov.iov_base = data;
	ds->iov.iov_len = len;
	ds->offset_block = cmd->offset_block;
	ds->num_blocks = PAGE_ALIGN(len) / PAGE_SIZE;
	cmd->offset_block += ds->num_blocks;

	cmd->job.num_data_sets++;
	ILOG("cmd: offset_block: %d, mem_start_block: %d, mem_num_blocks: %d\n",
	     cmd->offset_block, cmd->mem_start_block, cmd->mem_num_blocks);
	ILOG("ds : offset_block: %d, num_blocks: %d\n",
	     ds->offset_block, ds->num_blocks);

	ASSERT((ds->offset_block + ds->num_blocks) <=
	       (cmd->mem_start_block + cmd->mem_num_blocks));
	DLOG("num_data_sets: %d\n", cmd->job.num_data_sets);
	dump_ds(ds);
	ASSERT(cmd->job.num_data_sets < EC_MAX_ARGS);
}

/*
 * erasure_code
 * Implementation erasure code utilities based on ISA-L library.
 *
 */

void
cs_ec_init_tables(int k2, int p2,
		  unsigned char *encode_matrix, unsigned char *g_tbls)
{
	/*ec_init_tables(k, rows, a, gftbls); */
	/*ec_init_tables(k2, p2, &encode_matrix[k2 * k2], g_tbls); */

	css_cmd_t *cmd = NULL;

	int k = k2 / 2;
	int p = p2 / 2;
	int m = k + p;
	int m2 = m * 2;
	size_t req_mem_sz = (m2 * k2) + (k2 * p2 * 32);

	cmd = css_stream_init(CSS_ENG_TYPE_ECRS,
			      /*"/dev/nvme0n1", */
			      NULL, req_mem_sz);
	ASSERT(cmd != NULL);

	ILOG("******* EC_OPC_INIT *********\n");
	DLOG(" encode_matrix: %p, g_tbls: %p\n", encode_matrix, g_tbls);
	DLOG("cmd sz: %d\n", sizeof(css_cmd_t));


	cmd->job.opc = EC_OPC_INIT;

	job_add_arg(cmd, k2);
	job_add_arg(cmd, p2);
	job_add_data(cmd, encode_matrix, (m2 * k2), DATA_DIR_TO_TARGET);
	/*hex_dump("encode_matrix: ", encode_matrix, 64); */
	job_add_data(cmd, g_tbls, (k2 * p2 * 32), DATA_DIR_FM_TARGET);
	/*hex_dump("g_tbls: ", g_tbls, 64); */

	dump_css_cmd(cmd);

	/* write all the data streams device */
	transfer_data_streams(cmd, XFER_TO_TARGET, cmd->job.num_data_sets);
	dump_css_cmd(cmd);
	send_job_cmd(cmd);
	transfer_data_streams(cmd, XFER_FROM_TARGET, cmd->job.num_data_sets);

	css_job_free(cmd);

}

void
cs_ec_encode_data(int lenb2, int k, int p, unsigned char *gftbls,
		  unsigned char **data, unsigned char **coding)
{
	/*ec_encode_data(len, k, rows, gftbls, data, coding); */
	css_cmd_t *cmd = NULL;

	int len = lenb2 * 2;
	int i;
	int m = k + p;
	int m2 = m * 2;
	int k2 = k * 2;
	int p2 = p * 2;
	size_t req_mem_sz = (k2 * p2 * 32) + (len * k) + ((len / 2) * p2);



	cmd = css_stream_init(CSS_ENG_TYPE_ECRS, NULL, req_mem_sz);
	ASSERT(cmd != NULL);

	ILOG("******* EC_OPC_ENCD *********\n");
	/*hex_dump("gftbls: ", gftbls, 64); */
	/*hex_dump("data: ", data, 64); */
	/*hex_dump("coding: ", coding, 64); */


	cmd->job.opc = EC_OPC_ENCD;

	job_add_arg(cmd, lenb2);
	job_add_arg(cmd, k);
	job_add_arg(cmd, p);
	job_add_data(cmd, gftbls, (k2 * p2 * 32), DATA_DIR_TO_TARGET);
	for (i = 0; i < k; i++) {
		DLOG("i: %d, k: %d, ptr: %p\n", i, k, data[i]);
		job_add_data(cmd, data[i], len, DATA_DIR_TO_TARGET);
	}
	for (i = 0; i < p2; i++) {
		if (i == p2)
			break;
		DLOG("i: %d, p2: %d, ptr: %p\n", i, p, coding[i]);
		if (coding[i]) {
			job_add_data(cmd, coding[i], len / 2,
				     DATA_DIR_FM_TARGET);
		}
		/*else */
		/*    ASSERT(coding[i] != NULL); */
	}
	dump_css_cmd(cmd);

	/* write all the data streams device */
	transfer_data_streams(cmd, XFER_TO_TARGET, cmd->job.num_data_sets);
	dump_css_cmd(cmd);
	send_job_cmd(cmd);
	/*sync(); */
	transfer_data_streams(cmd, XFER_FROM_TARGET, cmd->job.num_data_sets);

	css_job_free(cmd);

}

static void
lzmadec_header_uncompressed(unsigned long long *size,
			    unsigned char *is_streamed,
			    const unsigned char *buffer)
{
	unsigned int i;

	/*
	 * Streamed files have all 64 bits set in the size field.
	 * We don't know the uncompressed size beforehand.
	 */
	*is_streamed = 1;		/* Assume streamed. */
	*size = 0;
	for (i = 0; i < 8; i++) {
		*size += (unsigned long long) buffer[i] << (i * 8);
		if (buffer[i] != 255)
			*is_streamed = 0;
	}
	assert((*is_streamed == 1 && *size == UINT64_MAX)
	       || (*is_streamed == 0 && *size < UINT64_MAX));
}


int
cs_simple_lzma(char opc, char format, const unsigned char *in_data,
	       size_t in_len, unsigned char **out_data, size_t *out_len)
{
	css_cmd_t *cmd = NULL;
	size_t sz;

	unsigned char *l_out_data = NULL;
	size_t *l_out_len = calloc(sizeof(size_t), 1);
	/*test_buf = calloc(sizeof(size_t), 1); */
	uint64_t uncompressed_size = in_len;
	uint8_t is_streamed;
	/* worst compression being eaqual to input */
	size_t req_mem_sz = 2 * in_len;

	if (opc == LZ_OPC_DCMP) {
		/*uncompressed_size = *((uint32_t*)(in_data+5)); */
		lzmadec_header_uncompressed(&uncompressed_size,
					    &is_streamed, in_data + 5);

		ASSERT(uncompressed_size != 0);
		req_mem_sz = in_len + uncompressed_size;
	}


	cmd = css_stream_init(CSS_ENG_TYPE_LZMA, NULL, req_mem_sz);

	ASSERT(cmd != NULL);


	DLOG("******* LZMA *********\n");
	ILOG(" node_num: %x, op_tag: %x, format: %d, in_len: %d, out_len: %d\n",
	     cmd->node_num, cmd->op_tag, format, in_len, uncompressed_size);
	DLOG(" in_data: %p, out_data: %p, out_len: %p\n",
	     in_data, out_data, out_len);




	cmd->job.opc = opc;

	job_add_arg(cmd, format);
	job_add_arg(cmd, in_len);
	job_add_data(cmd, (unsigned char *) l_out_len, sizeof(size_t),
		     DATA_DIR_FM_TARGET);
	job_add_data(cmd, in_data, in_len, DATA_DIR_TO_TARGET);

	hex_dump("in_data: ", in_data, 64);

	l_out_data = calloc(uncompressed_size, 1);
	ASSERT(l_out_data != NULL);
	job_add_data(cmd, l_out_data, uncompressed_size, DATA_DIR_FM_TARGET);

	dump_css_cmd(cmd);


	/* write all the data streams device */
	transfer_data_streams(cmd, XFER_TO_TARGET, cmd->job.num_data_sets);
	dump_css_cmd(cmd);
	send_job_cmd(cmd);

	transfer_data_streams(cmd, XFER_FROM_TARGET, cmd->job.num_data_sets);

	*out_len = *l_out_len;
	if (opc == LZ_OPC_DCMP) {
		/*fixme: why do we need this special case? */
		*out_len = uncompressed_size;
	}

	if (*out_data == NULL) {
		/*ELOG("*out_data : %p\n", *out_data); */
		*out_data = l_out_data;
	} else{
		/* caller has already allocated the o/p buffer */
		DLOG("*out_data : %p\n", *out_data);
		memcpy(*out_data, l_out_data, *out_len);
		free(l_out_data);
	}

	ILOG("%s: node_num: %x, op_tag: %x, in_len: %d out_len: %d\n",
	     opc == LZ_OPC_DCMP ? "LZ_OPC_DCMP" : "LZ_OPC_CMPR",
	     cmd->node_num, cmd->op_tag, in_len, *out_len);

	free(l_out_len);
	css_job_free(cmd);

	hex_dump("out_data: ", l_out_data, 64);

	return 0;

}

#define CS_MAX_RETRIES 5
int
cs_simple_lzma_retries(char opc, char format, const unsigned char *in_data,
		       size_t in_len, unsigned char **out_data,
		       size_t *out_len)
{
	int try = 0;
	int ret = -1;
	/*
	 * TODO: hardcoding format to ELZMA_lzma,
	 * until we make otehr formats work
	 */
	DLOG("******* LZMA: %s *********\n",
	     opc == LZ_OPC_CMPR ? str(LZ_OPC_CMPR) : str(LZ_OPC_DCMP));
	do {
		if (try) {
			/* Looks like target went bonkers, lets retry */
			ELOG("try: %d, in_len: %d, out_len: %d, ret: %d\n",
			     try, in_len, *out_len, ret);
		}
		ret = cs_simple_lzma(opc, format, in_data, in_len, out_data,
				     out_len);
	} while ((try++ < CS_MAX_RETRIES) && (*out_len == 0));
	return ret;
}


int
cs_simple_compress(char format, const unsigned char *in_data,
		   size_t in_len, unsigned char **out_data, size_t *out_len)
{
	/*
	 * TODO: hardcoding format to ELZMA_lzma,
	 * until we make otehr formats work
	 */
	DLOG("******* LZMA: %s *********\n", str(LZ_OPC_CMPR));
	return cs_simple_lzma_retries(LZ_OPC_CMPR, ELZMA_lzma, in_data, in_len,
				      out_data, out_len);
}

int
cs_simple_decompress(char format, const unsigned char *in_data,
		     size_t in_len, unsigned char **out_data,
		     size_t *out_len)
{
	/*
	 * TODO: hardcoding format to ELZMA_lzma, until we make other
	 * formats work
	 */
	DLOG("******* LZMA: %s *********\n", str(LZ_OPC_DCMP));
	return cs_simple_lzma_retries(LZ_OPC_DCMP, ELZMA_lzma, in_data, in_len,
				      out_data, out_len);
}

