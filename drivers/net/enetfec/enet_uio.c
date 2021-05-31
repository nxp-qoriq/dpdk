/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include "enet_pmd_logs.h"
#include "enet_uio.h"

static struct uio_job enetfec_uio_job;
int count;

/** @brief Reads first line from a file.
 * Composes file name as: root/subdir/filename
 *
 * @param [in]  root     Root path
 * @param [in]  subdir   Subdirectory name
 * @param [in]  filename File name
 * @param [out] line     The first line read from file.
 *
 * @retval 0 for succes
 * @retval other value for error
 */
static int
file_read_first_line(const char root[], const char subdir[],
			const char filename[], char *line)
{
	char absolute_file_name[FEC_UIO_MAX_ATTR_FILE_NAME];
	int fd = 0, ret = 0;

	/*compose the file name: root/subdir/filename */
	memset(absolute_file_name, 0, sizeof(absolute_file_name));
	snprintf(absolute_file_name, FEC_UIO_MAX_ATTR_FILE_NAME,
		"%s/%s/%s", root, subdir, filename);

	fd = open(absolute_file_name, O_RDONLY);
	if (fd <= 0)
		ENET_PMD_ERR("Error opening file %s", absolute_file_name);

	/* read UIO device name from first line in file */
	ret = read(fd, line, FEC_UIO_MAX_DEVICE_FILE_NAME_LENGTH);
	close(fd);

	/* NULL-ify string */
	line[FEC_UIO_MAX_DEVICE_FILE_NAME_LENGTH - 1] = '\0';

	if (ret <= 0) {
		ENET_PMD_ERR("Error reading from file %s", absolute_file_name);
		return ret;
	}

	return 0;
}

/** @brief Maps rx-tx bd range assigned for a bd ring.
 *
 * @param [in] uio_device_fd    UIO device file descriptor
 * @param [in] uio_device_id    UIO device id
 * @param [in] uio_map_id       UIO allows maximum 5 different mapping for
				each device. Maps start with id 0.
 * @param [out] map_size        Map size.
 * @param [out] map_addr	Map physical address
 * @retval  NULL if failed to map registers
 * @retval  Virtual address for mapped register address range
 */
static void *
uio_map_mem(int uio_device_fd, int uio_device_id,
		int uio_map_id, int *map_size, uint64_t *map_addr)
{
	void *mapped_address = NULL;
	unsigned int uio_map_size = 0;
	unsigned int uio_map_p_addr = 0;
	char uio_sys_root[FEC_UIO_MAX_ATTR_FILE_NAME];
	char uio_sys_map_subdir[FEC_UIO_MAX_ATTR_FILE_NAME];
	char uio_map_size_str[32];
	char uio_map_p_addr_str[64];
	int ret = 0;

	/* compose the file name: root/subdir/filename */
	memset(uio_sys_root, 0, sizeof(uio_sys_root));
	memset(uio_sys_map_subdir, 0, sizeof(uio_sys_map_subdir));
	memset(uio_map_size_str, 0, sizeof(uio_map_size_str));
	memset(uio_map_p_addr_str, 0, sizeof(uio_map_p_addr_str));

	/* Compose string: /sys/class/uio/uioX */
	snprintf(uio_sys_root, sizeof(uio_sys_root), "%s/%s%d",
			FEC_UIO_DEVICE_SYS_ATTR_PATH, "uio", uio_device_id);
	/* Compose string: maps/mapY */
	snprintf(uio_sys_map_subdir, sizeof(uio_sys_map_subdir), "%s%d",
			FEC_UIO_DEVICE_SYS_MAP_ATTR, uio_map_id);

	/* Read first (and only) line from file
	 * /sys/class/uio/uioX/maps/mapY/size
	 */
	ret = file_read_first_line(uio_sys_root, uio_sys_map_subdir,
				"size", uio_map_size_str);
	if (ret)
		ENET_PMD_ERR("file_read_first_line() failed");

	ret = file_read_first_line(uio_sys_root, uio_sys_map_subdir,
				"addr", uio_map_p_addr_str);
	if (ret)
		ENET_PMD_ERR("file_read_first_line() failed");

	/* Read mapping size and physical address expressed in hexa(base 16) */
	uio_map_size = strtol(uio_map_size_str, NULL, 16);
	uio_map_p_addr = strtol(uio_map_p_addr_str, NULL, 16);

	if (uio_map_id == 0) {
		/* Map the register address in user space when map_id is 0 */
		mapped_address = mmap(0 /*dynamically choose virtual address */,
				uio_map_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, uio_device_fd, 0);
	} else {
		/* Map the BD memory in user space */
		mapped_address = mmap(NULL, uio_map_size,
				PROT_READ | PROT_WRITE,
				MAP_SHARED, uio_device_fd, (1 * MAP_PAGE_SIZE));
	}

	if (mapped_address == MAP_FAILED) {
		ENET_PMD_ERR("Failed to map! errno = %d uio job fd = %d,"
			"uio device id = %d, uio map id = %d", errno,
			uio_device_fd, uio_device_id, uio_map_id);
		return 0;
	}

	/* Save the map size to use it later on for munmap-ing */
	*map_size = uio_map_size;
	*map_addr = uio_map_p_addr;
	ENET_PMD_INFO("UIO dev[%d] mapped region [id =%d] size 0x%x at %p",
		uio_device_id, uio_map_id, uio_map_size, mapped_address);

	return mapped_address;
}

int
config_enetfec_uio(struct enetfec_private *fep)
{
	char uio_device_file_name[32];
	struct uio_job *uio_job = NULL;

	/* Mapping is done only one time */
	if (count) {
		printf("Mapping already done, can't map again!\n");
		return 0;
	}

	uio_job = &enetfec_uio_job;

	/* Find UIO device created by ENETFEC-UIO kernel driver */
	memset(uio_device_file_name, 0, sizeof(uio_device_file_name));
	snprintf(uio_device_file_name, sizeof(uio_device_file_name), "%s%d",
			FEC_UIO_DEVICE_FILE_NAME, uio_job->uio_minor_number);

	/* Open device file */
	uio_job->uio_fd = open(uio_device_file_name, O_RDWR);
	if (uio_job->uio_fd < 0) {
		printf("US_UIO: Open Failed\n");
		exit(1);
	}

	ENET_PMD_INFO("US_UIO: Open device(%s) file with uio_fd = %d",
			uio_device_file_name, uio_job->uio_fd);

	fep->hw_baseaddr_v = uio_map_mem(uio_job->uio_fd,
		uio_job->uio_minor_number, FEC_UIO_REG_MAP_ID,
		&uio_job->map_size, &uio_job->map_addr);
	fep->hw_baseaddr_p = uio_job->map_addr;
	fep->reg_size = uio_job->map_size;

	fep->bd_addr_v = uio_map_mem(uio_job->uio_fd,
		uio_job->uio_minor_number, FEC_UIO_BD_MAP_ID,
		&uio_job->map_size, &uio_job->map_addr);
	fep->bd_addr_p = uio_job->map_addr;
	fep->bd_size = uio_job->map_size;

	count++;

	return 0;
}
