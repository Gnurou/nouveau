/*
 * Copyright (c) 2015, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef __NVKM_SECURE_BOOT_H__
#define __NVKM_SECURE_BOOT_H__

#include <core/device.h>

#define LSF_FALCON_ID_PMU	0
#define LSF_FALCON_ID_RESERVED	1
#define LSF_FALCON_ID_FECS	2
#define LSF_FALCON_ID_GPCCS	3
#define LSF_FALCON_ID_END	4
#define LSF_FALCON_ID_INVALID   0xffffffff

/**
 * @falcon_id:		falcon that will perform secure boot
 * @wpr_addr:		physical address of the WPR region
 * @wpr_size:		size in bytes of the WPR region
 * @ls_blob:		LS blob of all the LS firmwares, signatures, bootloaders
 * @ls_blob_size:	size of the LS blob
 * @ls_blob_nb_regions:	number of LS firmwares that will be loaded
*/
struct nvkm_secboot {
	const struct nvkm_secboot_func *func;
	struct nvkm_subdev subdev;

	u32 falcon_id;
	u64 wpr_addr;
	u32 wpr_size;

	/* LS FWs, to be loaded by the HS ACR */
	struct nvkm_gpuobj *ls_blob;
	u32 ls_blob_size;
	u16 ls_blob_nb_regions;

	/* HS FW */
	struct nvkm_gpuobj *acr_blob;
	struct nvkm_vma acr_blob_vma;

	/* HS bootloader */
	void *hsbl_blob;

};

int gm200_secboot_new(struct nvkm_device *, int, struct nvkm_secboot **);
int gm20b_secboot_new(struct nvkm_device *, int, struct nvkm_secboot **);

int nvkm_secure_boot(struct nvkm_device *);

bool
nvkm_is_secure(struct nvkm_device *device, unsigned long falcon_id);

#endif
