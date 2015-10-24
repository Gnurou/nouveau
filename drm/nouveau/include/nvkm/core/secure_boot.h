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

int nvkm_secure_boot_init(struct nvkm_device *);
void nvkm_secure_boot_fini(struct nvkm_device *);

int nvkm_secure_boot(struct nvkm_device *);

static inline bool
nvkm_is_secure(struct nvkm_device *device, unsigned long falcon_id)
{
	return device->chip->secure_boot.managed_falcons & BIT(falcon_id);
}

static inline bool
nvkm_need_secure_boot(struct nvkm_device *device)
{
	return device->chip->secure_boot.managed_falcons != 0;
}

#endif
