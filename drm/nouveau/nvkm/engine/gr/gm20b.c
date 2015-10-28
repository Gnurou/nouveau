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
#include "gf100.h"
#include "ctxgf100.h"

#include <subdev/timer.h>

#include <nvif/class.h>

#include <hwref/nv_drf.h>
#include <hwref/gm20b/nv_fb_hwref.h>
#include <hwref/gm20b/nv_graphics_nobundle_hwref.h>

static void
gm20b_gr_init_gpc_mmu(struct gf100_gr *gr)
{
	struct nvkm_device *device = gr->base.engine.subdev.device;
	u32 val;

	/* Bypass MMU check for non-secure boot */
	if (!device->chip->secure_boot.managed_falcons)
		nvkm_wr32(device, drf_reg_offset(PFB, PRI_MMU_PHYS_SECURE),
			  0xffffffff);

	val = nvkm_rd32(device, drf_reg_offset(PFB, PRI_MMU_CTRL));
	val &=
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, VM_PG_SIZE) |
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, VOL_FAULT) |
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, COMP_FAULT) |
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, MISS_GRAN) |
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, CACHE_MODE) |
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, USE_PDB_BIG_PAGE_SIZE) |
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, MMU_APERTURE) |
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, MMU_VOL) |
		drf_fld_mask_placed(PGRAPH, PRI_GPCS_MMU_CTRL, MMU_DISABLE);
	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_MMU_CTRL), val);
	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_MMU_PM_UNIT_MASK), 0);
	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_MMU_PM_REQ_MASK), 0);

	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_MMU_DEBUG_CTRL),
		  nvkm_rd32(device, drf_reg_offset(PFB, PRI_MMU_DEBUG_CTRL)));
	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_MMU_DEBUG_WR),
		  nvkm_rd32(device, drf_reg_offset(PFB, PRI_MMU_DEBUG_WR)));
	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_MMU_DEBUG_RD),
		  nvkm_rd32(device, drf_reg_offset(PFB, PRI_MMU_DEBUG_RD)));

	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_MMU_NUM_ACTIVE_LTCS),
		  nvkm_rd32(device, drf_reg_offset(PFB, FBHUB_NUM_ACTIVE_LTCS)));
}

static void
gm20b_gr_set_hww_esr_report_mask(struct gf100_gr *gr)
{
	struct nvkm_device *device = gr->base.engine.subdev.device;
	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_TPCS_SM_HWW_WARP_ESR_REPORT_MASK),
		  0xdffffe);
	nvkm_wr32(device, drf_reg_offset(PGRAPH, PRI_GPCS_TPCS_SM_HWW_GLOBAL_ESR_REPORT_MASK),
		drf_fld_val_placed(PGRAPH, PRI_GPCS_TPCS_SM_HWW_GLOBAL_ESR_REPORT_MASK, SM_TO_SM_FAULT, REPORT) |
		drf_fld_val_placed(PGRAPH, PRI_GPCS_TPCS_SM_HWW_GLOBAL_ESR_REPORT_MASK, MULTIPLE_WARP_ERRORS, REPORT));
}

static const struct gf100_gr_func
gm20b_gr = {
	.dtor = gk20a_gr_dtor,
	.init = gk20a_gr_init,
	.init_gpc_mmu = gm20b_gr_init_gpc_mmu,
	.set_hww_esr_report_mask = gm20b_gr_set_hww_esr_report_mask,
	.ppc_nr = 1,
	.grctx = &gm20b_grctx,
	.sclass = {
		{ -1, -1, FERMI_TWOD_A },
		{ -1, -1, KEPLER_INLINE_TO_MEMORY_B },
		{ -1, -1, MAXWELL_B, &gf100_fermi },
		{ -1, -1, MAXWELL_COMPUTE_B },
		{}
	}
};

int
gm20b_gr_new(struct nvkm_device *device, int index, struct nvkm_gr **pgr)
{
	return gk20a_gr_new_(&gm20b_gr, device, index, pgr);
}
