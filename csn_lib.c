/*
 * ORCS: nvme library functions.
 *
 * Author: Subrahmaya Lingappa, subrahmanya.lingappa@wdc.com
 * date: 26 June, 2019
 */

#include "csn.h"
#include "orcs_bitops.h"
#include "spdk/nvme_spec.h"
#include "nvme-ioctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#define SHM_SIZE (sizeof(cs_shm_t))


#define MAX_CSP_NODES 256
typedef struct csp_nodes_s {
	struct list_item g_csp_nodes[MAX_CSP_NODES];
	int32_t g_num_csp_nodes;
} csp_nodes_t;

typedef struct cs_shm_s {
	csp_nodes_t csp_nodes;
	cs_node_t cs_nodes[MAX_CSP_NODES];
	cs_nodes_data_t cs_nodes_data;
} cs_shm_t;
char *
get_mem_from_node_list(struct list_item *nodes, int32_t index, int32_t type)
{
	char *ret = NULL;

	switch (type) {
	case NVM_ITEM_TYPE_NODE:
		ret = &nodes[index].node;
		break;

	case NVM_ITEM_TYPE_CTRL:
		ret = &nodes[index].ctrl;
		break;

	case NVM_ITEM_TYPE_NS:
		ret = &nodes[index].ns;
		break;

	case NVM_ITEM_TYPE_STRUCT:
		ret = &nodes[index];
		break;

	default:
		printf("Wrong item type passed : %x\n", type);

	}

	return ret;
}

int
nvme_get_nsid(int fd)
{
	static struct stat nvme_stat;
	int err = fstat(fd, &nvme_stat);

	if (err < 0)
		return -errno;

	if (!S_ISBLK(nvme_stat.st_mode)) {
		fprintf(stderr,
			"Error: req namespace-id from non-block device\n");
		errno = ENOTBLK;
		return -errno;
	}
	return ioctl(fd, NVME_IOCTL_ID);
}

static int
nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd)
{
	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
}

int
nvme_identify13(int fd, __u32 nsid, __u32 cdw10, __u32 cdw11, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode = nvme_admin_identify,
		.nsid = nsid,
		.addr = (__u64) (uintptr_t) data,
		.data_len = NVME_IDENTIFY_DATA_SIZE,
		.cdw10 = cdw10,
		.cdw11 = cdw11,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int
nvme_identify(int fd, __u32 nsid, __u32 cdw10, void *data)
{
	return nvme_identify13(fd, nsid, cdw10, 0, data);
}

int
nvme_identify_ctrl(int fd, void *data)
{
	return nvme_identify(fd, 0, 1, data);
}

int
nvme_identify_ns(int fd, __u32 nsid, bool present, void *data)
{
	int cns = present ? NVME_ID_CNS_NS_PRESENT : NVME_ID_CNS_NS;

	return nvme_identify(fd, nsid, cns, data);
}

int
nvme_identify_ns_list(int fd, __u32 nsid, bool all, void *data)
{
	int cns = all ? NVME_ID_CNS_NS_PRESENT_LIST :
		NVME_ID_CNS_NS_ACTIVE_LIST;

	return nvme_identify(fd, nsid, cns, data);
}

void
send_nvme_cmd(int32_t nvme_cmd_type, int32_t nvme_cmd, char *device_name,
	      char *data)
{
	int32_t fd = -1, ret = -1;

	fd = open(device_name, O_RDWR);
	DLOG("Sending for CSS job command to compute engine ..., %s\n",
	     device_name);
	if (fd < 0) {
		ELOG("failed to open file, %d\n!", fd);
		return;
	}

	ret = nvme_identify_ctrl(fd, &data);
	if (ret) {
		fprintf(stderr,
			"ERROR : nvme_identify_ctrl() failed, ret = %d\n",
			ret);
		return -1;
	}
#if 0
	struct nvme_admin_cmd cs_cmd = {
		.opcode = nvme_cmd,
		/*.nsid = nvme_get_nsid(fd), */
		.addr = (__u64) (intptr_t) data,
		.data_len = 4096,
		.cdw10 = 0,
	};


	ret = ioctl(fd, nvme_cmd_type, &cs_cmd);
	if (ret != 0) {
		perror("ioctl");
		ELOG("IOCTL returned  %d, file: %s\n", ret, device_name);

	}
#endif

}

static int
get_nvme_info(int fd, struct list_item *item, const char *node)
{
	int err;

	err = nvme_identify_ctrl(fd, &item->ctrl);
	if (err)
		return err;
	item->nsid = nvme_get_nsid(fd);
	if (item->nsid <= 0)
		return item->nsid;
	err = nvme_identify_ns(fd, item->nsid, 0, &item->ns);
	if (err)
		return err;
	strcpy(item->node, node);

	return 0;
}

static const char *dev = "/dev/";

/* Assume every block device starting with /dev/nvme is an nvme namespace */
static int
scan_dev_filter(const struct dirent *d)
{
	char path[264];
	struct stat bd;
	int ctrl, ns, part;

	if (d->d_name[0] == '.')
		return 0;

	if (strstr(d->d_name, "nvme")) {
		snprintf(path, sizeof(path), "%s%s", dev, d->d_name);
		if (stat(path, &bd))
			return 0;
		if (!S_ISBLK(bd.st_mode))
			return 0;
		if (sscanf(d->d_name, "nvme%dn%dp%d", &ctrl, &ns, &part) == 3)
			return 0;
		return 1;
	}
	return 0;
}

static struct binary_suffix
{
	int shift;
	const char *suffix;
} binary_suffixes[] = {

	{
		50, "Pi"},
	{
		40, "Ti"},
	{
		30, "Gi"},
	{
		20, "Mi"},
	{
		10, "Ki"},
	{
		0, ""}
};

const char *
suffix_binary_get(long long *value)
{
	struct binary_suffix *s;

	for (s = binary_suffixes; s->shift != 0; s++) {
		if (llabs(*value) >= (1LL << s->shift)) {
			*value = (*value + (1LL << (s->shift - 1))) /
				(1LL << s->shift);
			return s->suffix;
		}
	}

	return "";
}


static struct si_suffix
{
	double magnitude;
	const char *suffix;
} si_suffixes[] = {

	{
		1e15, "P"},
	{
		1e12, "T"},
	{
		1e9, "G"},
	{
		1e6, "M"},
	{
		1e3, "k"},
	{
		1e0, ""},
	{
		1e-3, "m"},
	{
		1e-6, "u"},
	{
		1e-9, "n"},
	{
		1e-12, "p"},
	{
		1e-15, "f"},
	{
		0}
};

const char *
suffix_si_get(double *value)
{
	struct si_suffix *s;

	for (s = si_suffixes; s->magnitude != 0; s++) {
		if (*value >= s->magnitude) {
			*value /= s->magnitude;
			return s->suffix;
		}
	}

	return "";
}

extern char *csn_engines_names[];

static void
show_list_item(struct list_item list_item)
{
	long long int lba = 1 <<
		list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ds;
	double nsze = le64_to_cpu(list_item.ns.nsze) * lba;
	double nuse = le64_to_cpu(list_item.ns.nuse) * lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	char usage[128];
	char format[128];

	sprintf(usage, "%6.2f %2sB / %6.2f %2sB", nuse, u_suffix, nsze,
		s_suffix);
	sprintf(format, "%3.0f %2sB + %2d B", (double) lba, l_suffix,
		le16_to_cpu(list_item.ns.lbaf[(list_item.ns.flbas & 0x0f)].ms));
	printf("%-16s %-*.*s %-*.*s %-9d %-26s %-16s %-.*s %s\n",
	       list_item.node,
	       (int) sizeof(list_item.ctrl.sn), (int) sizeof(list_item.ctrl.sn),
	       list_item.ctrl.sn, (int) sizeof(list_item.ctrl.mn),
	       (int) sizeof(list_item.ctrl.mn), list_item.ctrl.mn,
	       list_item.nsid, usage, format, (int) sizeof(list_item.ctrl.fr),
	       list_item.ctrl.fr,
	       csn_engines_names[ffs(list_item.ns.csn_specific.csn_mask) - 2]);
}

void
show_list_items(struct list_item *list_items, unsigned int len)
{
	unsigned int i;

	printf("%-16s %-20s %-40s %-9s %-26s %-16s %-8s %-8s\n",
	       "Node", "SN", "Model", "Namespace", "Usage", "Format", "FW Rev",
	       "CS Engine");
	printf("%-16s %-20s %-40s %-9s %-26s %-16s %-8s %-8s\n",
	       "----------------", "--------------------",
	       "----------------------------------------", "---------",
	       "--------------------------", "----------------", "--------",
	       "--------");
	for (i = 0; i < len; i++)
		show_list_item(list_items[i]);

}

int32_t nvm_list_devs(char show, struct list_item *g_csp_nodes)
{
	char path[264];
	struct dirent **devices;
	unsigned int list_cnt = 0;
	int fmt, ret, fd, i, n;
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	n = scandir(dev, &devices, scan_dev_filter, alphasort);
	if (n < 0) {
		ELOG("no NVMe device(s) detected.\n");
		ret = n;
		goto ret;
	}


	for (i = 0; i < n; i++) {
		snprintf(path, sizeof(path), "%s%s", dev, devices[i]->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			ELOG("Failed to open %s: %s\n", path, strerror(errno));
			ret = -errno;
			goto cleanup_devices;
		}
		ret = get_nvme_info(fd, &g_csp_nodes[list_cnt], path);
		close(fd);
		if ((ret == 0) &&
		    (g_csp_nodes[list_cnt].ns.csn_specific.csn_mask != 0)) {
			list_cnt++;
		} else if (ret > 0) {
			ELOG("identify failed, ret: %x\n", ret);
		} else {
			ELOG("%s: failed to obtain nvme info: %s\n",
			     path, strerror(-ret));
		}
	}

	DLOG("CS NVMe devices detected : %d\n", list_cnt);
	if (show)
		show_list_items(g_csp_nodes, list_cnt);

cleanup_devices:
	for (i = 0; i < n; i++)
		free(devices[i]);
	free(devices);
ret:
	return list_cnt;

}

char *
get_nvme_mem()
{
	key_t key = 0xC550D0CC;
	int shmid;
	char *data;
	int mode;
	int created = 0;

	DLOG("ftok: key: %x\n", key);

	/*  create the segment: */
	shmid = shmget(key, SHM_SIZE, 0644);
	DLOG("shmid: %d\n", shmid);
	if (shmid == -1) {
		/*perror("shmget"); */
		DLOG("creating SHM ....\n");
		/*shm doesnt exists !, lets not scan again */
		shmid = shmget(key, SHM_SIZE, 0644 | IPC_CREAT);
		DLOG("created shmid: %d, key: 0x%x\n", shmid, key);
		if (shmid == -1) {
			perror("shmget");
			return NULL;
		}
		DLOG("Created shmid: %d\n", shmid);
		created = 1;
	} else {
		/*shm exists */
		DLOG("Existing shmid: %d\n", shmid);
	}

	/* attach to the segment to get a pointer to it: */
	data = shmat(shmid, NULL, 0);
	if (data == (char *) (-1)) {
		perror("shmat");
		exit(1);
	}

	/* clear the shared memory of its created new */
	if (created)
		memset(data, 0, SHM_SIZE);

	return data;

}

int32_t
scan_engines(cs_node_t **cs_nodes, cs_nodes_data_t **cs_nodes_data)
{

	int32_t i = 0, ret;
	cs_shm_t *cs_shm;
	char *shm_mem = NULL;
	csp_nodes_t *nodes;
	cs_node_t *node = NULL;

	TRACE();

	shm_mem = get_nvme_mem();

	if (shm_mem == NULL) {
		ELOG("get_nvme_mem: returned NULL !\n");
		return 0;
	}
	cs_shm = shm_mem;

	nodes = &cs_shm->csp_nodes;
	*cs_nodes = &cs_shm->cs_nodes;
	*cs_nodes_data = &cs_shm->cs_nodes_data;

	if (nodes->g_num_csp_nodes == 0) {
		nodes->g_num_csp_nodes = nvm_list_devs(0, &nodes->g_csp_nodes);
		ILOG("found NVME devices : %d\n", nodes->g_num_csp_nodes);
	} else
		ILOG("Existing  NVME devices : %d\n", nodes->g_num_csp_nodes);

	/**cs_nodes = calloc(nodes->g_num_csp_nodes, sizeof(cs_node_t)); */
	for (i = 0, node = *cs_nodes; i < nodes->g_num_csp_nodes; i++) {
		node->item = &nodes->g_csp_nodes[i];
		ret = sscanf(nodes->g_csp_nodes[i].node, "/dev/nvme%dn%d",
		       &node->maj_num,
		       &node->min_num);
		ILOG("Node name: /dev/nvme%dn%d, csn_mask: %x\n", node->maj_num,
		     node->min_num,
		     nodes->g_csp_nodes[i].ns.csn_specific.csn_mask);
		node++;
	}

	return nodes->g_num_csp_nodes;

}

