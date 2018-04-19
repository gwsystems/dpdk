/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <dirent.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_pci.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>

#include "eal_filesystem.h"
#include "eal_private.h"
#include "eal_pci_init.h"

#include "cos_eal_pci.h"

extern struct cos_pci_device devices[PCI_DEVICE_NUM];
extern int dev_num;

/**
 * @file
 * PCI probing under linux
 *
 * This code is used to simulate a PCI probe by parsing information in sysfs.
 * When a registered device matches a driver, it is then initialized with
 * IGB_UIO driver (or doesn't initialize, if the device wasn't bound to it).
 */

extern struct rte_pci_bus rte_pci_bus;

static int
pci_get_kernel_driver_by_path(const char *filename, char *dri_name)
{
	int count;
	char path[PATH_MAX];
	char *name;

	if (!filename || !dri_name)
		return -1;

	count = readlink(filename, path, PATH_MAX);
	if (count >= PATH_MAX)
		return -1;

	/* For device does not have a driver */
	if (count < 0)
		return 1;

	path[count] = '\0';

	name = strrchr(path, '/');
	if (name) {
		strncpy(dri_name, name + 1, strlen(name + 1) + 1);
		return 0;
	}

	return -1;
}

/* RSK */
/* Map pci device */
int
rte_pci_map_device(struct rte_pci_device *dev)
{
	/* RSK should move logic out of uio */
	return pci_uio_map_resource(dev);
}

/* Unmap pci device */
void
rte_pci_unmap_device(struct rte_pci_device *dev)
{
	/* try unmapping the NIC resources using VFIO if it exists */
	switch (dev->kdrv) {
	case RTE_KDRV_VFIO:
#ifdef VFIO_PRESENT
		if (pci_vfio_is_enabled())
			pci_vfio_unmap_resource(dev);
#endif
		break;
	case RTE_KDRV_IGB_UIO:
	case RTE_KDRV_UIO_GENERIC:
		/* unmap resources for devices that use uio */
		pci_uio_unmap_resource(dev);
		break;
	default:
		RTE_LOG(DEBUG, EAL,
			"  Not managed by a supported kernel driver, skipped\n");
		break;
	}
}

void *
pci_find_max_end_va(void)
{
	const struct rte_memseg *seg = rte_eal_get_physmem_layout();
	const struct rte_memseg *last = seg;
	unsigned i = 0;

	for (i = 0; i < RTE_MAX_MEMSEG; i++, seg++) {
		if (seg->addr == NULL)
			break;

		if (seg->addr > last->addr)
			last = seg;

	}
	return RTE_PTR_ADD(last->addr, last->len);
}

/* parse one line of the "resource" sysfs file (note that the 'line'
 * string is modified)
 */
int
pci_parse_one_sysfs_resource(char *line, size_t len, uint64_t *phys_addr,
	uint64_t *end_addr, uint64_t *flags)
{
	union pci_resource_info {
		struct {
			char *phys_addr;
			char *end_addr;
			char *flags;
		};
		char *ptrs[PCI_RESOURCE_FMT_NVAL];
	} res_info;

	if (rte_strsplit(line, len, res_info.ptrs, 3, ' ') != 3) {
		RTE_LOG(ERR, EAL,
			"%s(): bad resource format\n", __func__);
		return -1;
	}
	errno = 0;
	*phys_addr = strtoull(res_info.phys_addr, NULL, 16);
	*end_addr = strtoull(res_info.end_addr, NULL, 16);
	*flags = strtoull(res_info.flags, NULL, 16);
	if (errno != 0) {
		RTE_LOG(ERR, EAL,
			"%s(): bad resource format\n", __func__);
		return -1;
	}

	return 0;
}

/* parse the "resource" sysfs file */
static int
pci_parse_sysfs_resource(const char *filename, struct rte_pci_device *dev)
{
	FILE *f;
	char buf[BUFSIZ];
	int i;
	uint64_t phys_addr, end_addr, flags;

	f = fopen(filename, "r");
	if (f == NULL) {
		RTE_LOG(ERR, EAL, "Cannot open sysfs resource\n");
		return -1;
	}

	for (i = 0; i<PCI_MAX_RESOURCE; i++) {

		if (fgets(buf, sizeof(buf), f) == NULL) {
			RTE_LOG(ERR, EAL,
				"%s(): cannot read resource\n", __func__);
			goto error;
		}
		if (pci_parse_one_sysfs_resource(buf, sizeof(buf), &phys_addr,
				&end_addr, &flags) < 0)
			goto error;

		if (flags & IORESOURCE_MEM) {
			dev->mem_resource[i].phys_addr = phys_addr;
			dev->mem_resource[i].len = end_addr - phys_addr + 1;
			/* not mapped for now */
			dev->mem_resource[i].addr = NULL;
		}
	}
	fclose(f);
	return 0;

error:
	fclose(f);
	return -1;
}

/* Scan one pci sysfs entry, and fill the devices list from it. */
static int
pci_scan_one(const char *dirname, const struct rte_pci_addr *addr)
{
	char filename[PATH_MAX];
	unsigned long tmp;
	struct rte_pci_device *dev;
	char driver[PATH_MAX];
	int ret;

	dev = cos_mem_alloc(sizeof(*dev), 1);
	if (dev == NULL)
		return -1;

	memset(dev, 0, sizeof(*dev));
	dev->addr = *addr;

	/* get vendor id */
	snprintf(filename, sizeof(filename), "%s/vendor", dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.vendor_id = (uint16_t)tmp;

	/* get device id */
	snprintf(filename, sizeof(filename), "%s/device", dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.device_id = (uint16_t)tmp;

	/* get subsystem_vendor id */
	snprintf(filename, sizeof(filename), "%s/subsystem_vendor",
		 dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.subsystem_vendor_id = (uint16_t)tmp;

	/* get subsystem_device id */
	snprintf(filename, sizeof(filename), "%s/subsystem_device",
		 dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.subsystem_device_id = (uint16_t)tmp;

	/* get class_id */
	snprintf(filename, sizeof(filename), "%s/class",
		 dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	/* the least 24 bits are valid: class, subclass, program interface */
	dev->id.class_id = (uint32_t)tmp & RTE_CLASS_ANY_ID;

	/* get max_vfs */
	dev->max_vfs = 0;
	snprintf(filename, sizeof(filename), "%s/max_vfs", dirname);
	if (!access(filename, F_OK) &&
	    eal_parse_sysfs_value(filename, &tmp) == 0)
		dev->max_vfs = (uint16_t)tmp;
	else {
		/* for non igb_uio driver, need kernel version >= 3.8 */
		snprintf(filename, sizeof(filename),
			 "%s/sriov_numvfs", dirname);
		if (!access(filename, F_OK) &&
		    eal_parse_sysfs_value(filename, &tmp) == 0)
			dev->max_vfs = (uint16_t)tmp;
	}

	/* get numa node, default to 0 if not present */
	snprintf(filename, sizeof(filename), "%s/numa_node",
		 dirname);

	if (access(filename, F_OK) != -1) {
		if (eal_parse_sysfs_value(filename, &tmp) == 0)
			dev->device.numa_node = tmp;
		else
			dev->device.numa_node = -1;
	} else {
		dev->device.numa_node = 0;
	}

	pci_name_set(dev);

	/* parse resources */
	snprintf(filename, sizeof(filename), "%s/resource", dirname);
	if (pci_parse_sysfs_resource(filename, dev) < 0) {
		RTE_LOG(ERR, EAL, "%s(): cannot parse resource\n", __func__);
		free(dev);
		return -1;
	}

	/* parse driver */
	snprintf(filename, sizeof(filename), "%s/driver", dirname);
	ret = pci_get_kernel_driver_by_path(filename, driver);
	if (ret < 0) {
		RTE_LOG(ERR, EAL, "Fail to get kernel driver\n");
		free(dev);
		return -1;
	}

	if (!ret) {
		if (!strcmp(driver, "vfio-pci"))
			dev->kdrv = RTE_KDRV_VFIO;
		else if (!strcmp(driver, "igb_uio"))
			dev->kdrv = RTE_KDRV_IGB_UIO;
		else if (!strcmp(driver, "uio_pci_generic"))
			dev->kdrv = RTE_KDRV_UIO_GENERIC;
		else
			dev->kdrv = RTE_KDRV_UNKNOWN;
	} else
		dev->kdrv = RTE_KDRV_NONE;

	/* device is valid, add in list (sorted) */
	if (TAILQ_EMPTY(&rte_pci_bus.device_list)) {
		rte_pci_add_device(dev);
	} else {
		struct rte_pci_device *dev2;
		int ret;

		TAILQ_FOREACH(dev2, &rte_pci_bus.device_list, next) {
			ret = rte_eal_compare_pci_addr(&dev->addr, &dev2->addr);
			if (ret > 0)
				continue;

			if (ret < 0) {
				rte_pci_insert_device(dev2, dev);
			} else { /* already registered */
				dev2->kdrv = dev->kdrv;
				dev2->max_vfs = dev->max_vfs;
				pci_name_set(dev2);
				memmove(dev2->mem_resource, dev->mem_resource,
					sizeof(dev->mem_resource));
				free(dev);
			}
			return 0;
		}

		rte_pci_add_device(dev);
	}

	return 0;
}

int
pci_update_device(const struct rte_pci_addr *addr)
{
	char filename[PATH_MAX];

	snprintf(filename, sizeof(filename), "%s/" PCI_PRI_FMT,
		 pci_get_sysfs_path(), addr->domain, addr->bus, addr->devid,
		 addr->function);
	/* RSK */
	/* snprintf(filename, sizeof(filename), "%d:%d:%d", addr->bus, addr->devid, addr->function); */
	return pci_scan_one(filename, addr);
}

/* RSK  */
/*  * split up a pci address into its constituent parts. */
/*  *1/ */
/* static int */
/* parse_pci_addr_format(const char *buf, int bufsize, struct rte_pci_addr *addr) */
/* { */
/* 	/1* first split on ':' *1/ */
/* 	union splitaddr { */
/* 		struct { */
/* 			char *domain; */
/* 			char *bus; */
/* 			char *devid; */
/* 			char *function; */
/* 		}; */
/* 		char *str[PCI_FMT_NVAL]; /1* last element-separator is "." not ":" *1/ */
/* 	} splitaddr; */

/* 	char *buf_copy = strndup(buf, bufsize); */
/* 	if (buf_copy == NULL) */
/* 		return -1; */

/* 	if (rte_strsplit(buf_copy, bufsize, splitaddr.str, PCI_FMT_NVAL, ':') */
/* 			!= PCI_FMT_NVAL - 1) */
/* 		goto error; */
/* 	/1* final split is on '.' between devid and function *1/ */
/* 	splitaddr.function = strchr(splitaddr.devid,'.'); */
/* 	if (splitaddr.function == NULL) */
/* 		goto error; */
/* 	*splitaddr.function++ = '\0'; */

/* 	/1* now convert to int values *1/ */
/* 	errno = 0; */
/* 	addr->domain = strtoul(splitaddr.domain, NULL, 16); */
/* 	addr->bus = strtoul(splitaddr.bus, NULL, 16); */
/* 	addr->devid = strtoul(splitaddr.devid, NULL, 16); */
/* 	addr->function = strtoul(splitaddr.function, NULL, 10); */
/* 	if (errno != 0) */
/* 		goto error; */

/* 	free(buf_copy); /1* free the copy made with strdup *1/ */
/* 	return 0; */
/* error: */
/* 	free(buf_copy); */
/* 	return -1; */
/* } */

/* RSK */
/* Need to map config space into userland */
/* Read PCI config space. */
/* As written, cannot read less than 4 bytes at a time */
int rte_pci_read_config(const struct rte_pci_device *device,
		void *buf, size_t len, off_t offset)
{
	uint32_t *buffer;
	unsigned int r;

	if (!buf) return -1;
	buffer = (uint32_t *)buf;

	for (r = 0; r <= len - 4; r += 4) {
		*buffer = cos_pci_read_config(device->addr.bus, device->addr.devid,
				device->addr.function, (uint32_t)offset + r);
	}
	return r;
}

/* Write PCI config space. */
int rte_pci_write_config(const struct rte_pci_device *device,
		const void *buf, size_t len, off_t offset)
{
	const uint32_t *buffer;
	unsigned int w;

	if (!buf) return -1;
	buffer = (const uint32_t *)buf;

	for (w = 0; w <= len - 4; w += 4) {
		cos_pci_write_config(device->addr.bus, device->addr.devid,
				device->addr.function, (uint32_t)offset + w, *buffer);
	}
	return w;
}

#if defined(RTE_ARCH_X86)
static int
pci_ioport_map(struct rte_pci_device *dev, int bar __rte_unused,
		struct rte_pci_ioport *p)
{
	uint16_t start, end;
	FILE *fp;
	char *line = NULL;
	char pci_id[16];
	int found = 0;
	size_t linesz;

	snprintf(pci_id, sizeof(pci_id), PCI_PRI_FMT,
		 dev->addr.domain, dev->addr.bus,
		 dev->addr.devid, dev->addr.function);

	fp = fopen("/proc/ioports", "r");
	if (fp == NULL) {
		RTE_LOG(ERR, EAL, "%s(): can't open ioports\n", __func__);
		return -1;
	}

	while (getdelim(&line, &linesz, '\n', fp) > 0) {
		char *ptr = line;
		char *left;
		int n;

		n = strcspn(ptr, ":");
		ptr[n] = 0;
		left = &ptr[n + 1];

		while (*left && isspace(*left))
			left++;

		if (!strncmp(left, pci_id, strlen(pci_id))) {
			found = 1;

			while (*ptr && isspace(*ptr))
				ptr++;

			sscanf(ptr, "%04hx-%04hx", &start, &end);

			break;
		}
	}

	free(line);
	fclose(fp);

	if (!found)
		return -1;

	dev->intr_handle.type = RTE_INTR_HANDLE_UNKNOWN;
	p->base = start;
	RTE_LOG(DEBUG, EAL, "PCI Port IO found start=0x%x\n", start);

	return 0;
}
#endif

int
rte_pci_ioport_map(struct rte_pci_device *dev, int bar,
		struct rte_pci_ioport *p)
{
	int ret = -1;

	switch (dev->kdrv) {
#ifdef VFIO_PRESENT
	case RTE_KDRV_VFIO:
		if (pci_vfio_is_enabled())
			ret = pci_vfio_ioport_map(dev, bar, p);
		break;
#endif
	case RTE_KDRV_IGB_UIO:
		ret = pci_uio_ioport_map(dev, bar, p);
		break;
	case RTE_KDRV_UIO_GENERIC:
#if defined(RTE_ARCH_X86)
		ret = pci_ioport_map(dev, bar, p);
#else
		ret = pci_uio_ioport_map(dev, bar, p);
#endif
		break;
	case RTE_KDRV_NONE:
#if defined(RTE_ARCH_X86)
		ret = pci_ioport_map(dev, bar, p);
#endif
		break;
	default:
		break;
	}

	if (!ret)
		p->dev = dev;

	return ret;
}

void
rte_pci_ioport_read(struct rte_pci_ioport *p,
		void *data, size_t len, off_t offset)
{
	switch (p->dev->kdrv) {
#ifdef VFIO_PRESENT
	case RTE_KDRV_VFIO:
		pci_vfio_ioport_read(p, data, len, offset);
		break;
#endif
	case RTE_KDRV_IGB_UIO:
		pci_uio_ioport_read(p, data, len, offset);
		break;
	case RTE_KDRV_UIO_GENERIC:
		pci_uio_ioport_read(p, data, len, offset);
		break;
	case RTE_KDRV_NONE:
#if defined(RTE_ARCH_X86)
		pci_uio_ioport_read(p, data, len, offset);
#endif
		break;
	default:
		break;
	}
}

void
rte_pci_ioport_write(struct rte_pci_ioport *p,
		const void *data, size_t len, off_t offset)
{
	switch (p->dev->kdrv) {
#ifdef VFIO_PRESENT
	case RTE_KDRV_VFIO:
		pci_vfio_ioport_write(p, data, len, offset);
		break;
#endif
	case RTE_KDRV_IGB_UIO:
		pci_uio_ioport_write(p, data, len, offset);
		break;
	case RTE_KDRV_UIO_GENERIC:
		pci_uio_ioport_write(p, data, len, offset);
		break;
	case RTE_KDRV_NONE:
#if defined(RTE_ARCH_X86)
		pci_uio_ioport_write(p, data, len, offset);
#endif
		break;
	default:
		break;
	}
}

int
rte_pci_ioport_unmap(struct rte_pci_ioport *p)
{
	int ret = -1;

	switch (p->dev->kdrv) {
#ifdef VFIO_PRESENT
	case RTE_KDRV_VFIO:
		if (pci_vfio_is_enabled())
			ret = pci_vfio_ioport_unmap(p);
		break;
#endif
	case RTE_KDRV_IGB_UIO:
		ret = pci_uio_ioport_unmap(p);
		break;
	case RTE_KDRV_UIO_GENERIC:
#if defined(RTE_ARCH_X86)
		ret = 0;
#else
		ret = pci_uio_ioport_unmap(p);
#endif
		break;
	case RTE_KDRV_NONE:
#if defined(RTE_ARCH_X86)
		ret = 0;
#endif
		break;
	default:
		break;
	}

	return ret;
}

/* RSK
 * create pci_device_list from initial walk */
int
rte_pci_scan(void) {
	int i, j;
	struct rte_pci_device *pci_device_list, *rte_dev;
	struct cos_pci_device *cos_dev;

	/* Be careful about memory here! */
	/* Free this list when pci_bus is closed? */
	pci_device_list = cos_mem_alloc(sizeof(struct rte_pci_device) * dev_num, 1);
	if (!pci_device_list) return -1;
	memset(pci_device_list, 0, sizeof(struct rte_pci_device) * dev_num);
	RTE_LOG(INFO, EAL, "scan called\n");

	for (i = 0; i < dev_num; i++) {
		rte_dev = &pci_device_list[i];
		cos_dev = &devices[i];
		/* rte_dev->device = NULL; */
		rte_dev->addr.bus = cos_dev->bus;
		rte_dev->addr.devid = cos_dev->dev;
		rte_dev->addr.function = cos_dev->func;
		rte_dev->id.class_id = cos_dev->classcode;
		rte_dev->id.vendor_id = cos_dev->vendor;
		rte_dev->id.device_id = cos_dev->device;
		rte_dev->id.subsystem_vendor_id = PCI_ANY_ID;
		rte_dev->id.subsystem_device_id = PCI_ANY_ID;
		for (j = 0; j < PCI_MAX_RESOURCE; j++) {
			rte_dev->mem_resource[j].phys_addr = cos_dev->bar[j].raw & 0xFFFFFFF0;
			if (!cos_dev->bar[j].raw) continue;
			/* RSK Get size of region */
			uint32_t buf = 0;
			uint8_t offset;
			buf = 0xFFFFFFFF;
			offset = (j + 4) << 2;
			rte_pci_write_config(rte_dev, &buf, sizeof(buf), offset);
			rte_pci_read_config(rte_dev, &buf, sizeof(buf), offset);
			buf = ~(buf & ~0xF) + 1;
			rte_dev->mem_resource[j].len = buf;
			buf = cos_dev->bar[j].raw;
			rte_pci_write_config(rte_dev, &buf, sizeof(buf), offset);
			rte_dev->mem_resource[j].addr = NULL; /* Has yet to be mapped */
		}
		rte_dev->max_vfs = 0;
		rte_dev->kdrv = RTE_KDRV_UIO_GENERIC;
		pci_name_set(rte_dev);
		rte_pci_add_device(rte_dev);

		/* device is valid, add in list (sorted) */
		/* if (TAILQ_EMPTY(&rte_pci_bus.device_list)) { */
		/* 	rte_pci_add_device(rte_dev); */
		/* } else { */
		/* 	struct rte_pci_device *dev2; */
		/* 	int ret; */

		/* 	TAILQ_FOREACH(dev2, &rte_pci_bus.device_list, next) { */
		/* 		ret = rte_eal_compare_pci_addr(&rte_dev->addr, &dev2->addr); */
		/* 		if (ret > 0) */
		/* 			continue; */

		/* 		if (ret < 0) { */
		/* 			rte_pci_insert_device(dev2, rte_dev); */
		/* 		} else { /1* already registered *1/ */
		/* 			dev2->kdrv = rte_dev->kdrv; */
		/* 			dev2->max_vfs = rte_dev->max_vfs; */
		/* 			pci_name_set(dev2); */
		/* 			memmove(dev2->mem_resource, rte_dev->mem_resource, */
		/* 					sizeof(rte_dev->mem_resource)); */
		/* 			free(rte_dev); */
		/* 		} */
		/* 	} */
					/* for(k=0; k<PCI_BAR_NUM; k++) { */
				/* 	bar       = &devices[dev_num].bar[k]; */
				/* 	bar->raw  = devices[dev_num].data[4 + k]; */
				/* 	reg       = (k + 4) << 2; */
				/* 	/1* printc("Region %d: %x\n", k, bar->raw); *1/ */
				/* 	cos_pci_write_config(i, j, f, reg, PCI_BITMASK_32); */
				/* 	tmp       = cos_pci_read_config(i, j, f, reg); */
				/* } */	/* } */
	}
	RTE_LOG(INFO, EAL, "Scan found %d devices\n", dev_num);
	return 0;
}
