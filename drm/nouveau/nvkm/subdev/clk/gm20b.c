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

#include <subdev/clk.h>
#include <subdev/timer.h>
#include <subdev/volt.h>

#include <core/device.h>

#define gm20b_clk(p) container_of((p), struct gm20b_clk, base)
#include "priv.h"

#ifdef __KERNEL__
#include <nouveau_platform.h>
#include <soc/tegra/fuse.h>
#endif

#define KHZ (1000)

#define MASK(w)	((1 << w) - 1)

#define SYS_GPCPLL_CFG_BASE			0x00137000
#define GPC_BCASE_GPCPLL_CFG_BASE		0x00132800

#define GPCPLL_CFG		(SYS_GPCPLL_CFG_BASE + 0)
#define GPCPLL_CFG_ENABLE	BIT(0)
#define GPCPLL_CFG_IDDQ		BIT(1)
#define GPCPLL_CFG_SYNC_MODE	BIT(2)
#define GPCPLL_CFG_LOCK_DET_OFF	BIT(4)
#define GPCPLL_CFG_LOCK		BIT(17)

#define GPCPLL_COEFF		(SYS_GPCPLL_CFG_BASE + 4)
#define GPCPLL_COEFF_M_SHIFT	0
#define GPCPLL_COEFF_M_WIDTH	8
#define GPCPLL_COEFF_N_SHIFT	8
#define GPCPLL_COEFF_N_WIDTH	8
#define GPCPLL_COEFF_P_SHIFT	16
#define GPCPLL_COEFF_P_WIDTH	6

#define GPCPLL_CFG2			(SYS_GPCPLL_CFG_BASE + 0xc)
#define GPCPLL_CFG2_SDM_DIN_SHIFT	0
#define GPCPLL_CFG2_SDM_DIN_WIDTH	8
#define GPCPLL_CFG2_SDM_DIN_NEW_SHIFT	8
#define GPCPLL_CFG2_SDM_DIN_NEW_WIDTH	15
#define GPCPLL_CFG2_SETUP2_SHIFT	16
#define GPCPLL_CFG2_PLL_STEPA_SHIFT	24

#define GPCPLL_DVFS0		(SYS_GPCPLL_CFG_BASE + 0x10)
#define GPCPLL_DVFS0_DFS_COEFF_SHIFT	0
#define GPCPLL_DVFS0_DFS_COEFF_WIDTH	7
#define GPCPLL_DVFS0_DFS_DET_MAX_SHIFT	8
#define GPCPLL_DVFS0_DFS_DET_MAX_WIDTH	7

#define GPCPLL_DVFS1		(SYS_GPCPLL_CFG_BASE + 0x14)
#define GPCPLL_DVFS1_DFS_EXT_DET_SHIFT		0
#define GPCPLL_DVFS1_DFS_EXT_DET_WIDTH		7
#define GPCPLL_DVFS1_DFS_EXT_STRB_SHIFT	7
#define GPCPLL_DVFS1_DFS_EXT_STRB_WIDTH	1
#define GPCPLL_DVFS1_DFS_EXT_CAL_SHIFT		8
#define GPCPLL_DVFS1_DFS_EXT_CAL_WIDTH		7
#define GPCPLL_DVFS1_DFS_EXT_SEL_SHIFT		15
#define GPCPLL_DVFS1_DFS_EXT_SEL_WIDTH		1
#define GPCPLL_DVFS1_DFS_CTRL_SHIFT		16
#define GPCPLL_DVFS1_DFS_CTRL_WIDTH		12
#define GPCPLL_DVFS1_EN_SDM_SHIFT		28
#define GPCPLL_DVFS1_EN_SDM_WIDTH		1
#define GPCPLL_DVFS1_EN_SDM_BIT		BIT(28)
#define GPCPLL_DVFS1_EN_DFS_SHIFT		29
#define GPCPLL_DVFS1_EN_DFS_WIDTH		1
#define GPCPLL_DVFS1_EN_DFS_BIT		BIT(29)
#define GPCPLL_DVFS1_EN_DFS_CAL_SHIFT		30
#define GPCPLL_DVFS1_EN_DFS_CAL_WIDTH		1
#define GPCPLL_DVFS1_EN_DFS_CAL_BIT		BIT(30)
#define GPCPLL_DVFS1_DFS_CAL_DONE_SHIFT	31
#define GPCPLL_DVFS1_DFS_CAL_DONE_WIDTH	1
#define GPCPLL_DVFS1_DFS_CAL_DONE_BIT	BIT(31)

#define GPCPLL_CFG3			(SYS_GPCPLL_CFG_BASE + 0x18)
#define GPCPLL_CFG3_VCO_CTRL_SHIFT		0
#define GPCPLL_CFG3_VCO_CTRL_WIDTH		9
#define GPCPLL_CFG3_PLL_STEPB_SHIFT		16
#define GPCPLL_CFG3_PLL_STEPB_WIDTH		8
#define GPCPLL_CFG3_PLL_DFS_TESTOUT_SHIFT	24
#define GPCPLL_CFG3_PLL_DFS_TESTOUT_WIDTH	7

#define GPCPLL_NDIV_SLOWDOWN			(SYS_GPCPLL_CFG_BASE + 0x1c)
#define GPCPLL_NDIV_SLOWDOWN_NDIV_LO_SHIFT	0
#define GPCPLL_NDIV_SLOWDOWN_NDIV_MID_SHIFT	8
#define GPCPLL_NDIV_SLOWDOWN_STEP_SIZE_LO2MID_SHIFT	16
#define GPCPLL_NDIV_SLOWDOWN_SLOWDOWN_USING_PLL_SHIFT	22
#define GPCPLL_NDIV_SLOWDOWN_EN_DYNRAMP_SHIFT	31

#define SEL_VCO				(SYS_GPCPLL_CFG_BASE + 0x100)
#define SEL_VCO_GPC2CLK_OUT_SHIFT	0

#define GPC2CLK_OUT			(SYS_GPCPLL_CFG_BASE + 0x250)
#define GPC2CLK_OUT_SDIV14_INDIV4_WIDTH	1
#define GPC2CLK_OUT_SDIV14_INDIV4_SHIFT	31
#define GPC2CLK_OUT_SDIV14_INDIV4_MODE	1
#define GPC2CLK_OUT_VCODIV_WIDTH		6
#define GPC2CLK_OUT_VCODIV_SHIFT		8
#define GPC2CLK_OUT_VCODIV1			0
#define GPC2CLK_OUT_VCODIV_MASK		(MASK(GPC2CLK_OUT_VCODIV_WIDTH) << \
					GPC2CLK_OUT_VCODIV_SHIFT)
#define GPC2CLK_OUT_BYPDIV_WIDTH	6
#define GPC2CLK_OUT_BYPDIV_SHIFT	0
#define GPC2CLK_OUT_BYPDIV31		0x3c
#define GPC2CLK_OUT_INIT_MASK	((MASK(GPC2CLK_OUT_SDIV14_INDIV4_WIDTH) << \
		GPC2CLK_OUT_SDIV14_INDIV4_SHIFT)\
		| (MASK(GPC2CLK_OUT_VCODIV_WIDTH) << GPC2CLK_OUT_VCODIV_SHIFT)\
		| (MASK(GPC2CLK_OUT_BYPDIV_WIDTH) << GPC2CLK_OUT_BYPDIV_SHIFT))
#define GPC2CLK_OUT_INIT_VAL	((GPC2CLK_OUT_SDIV14_INDIV4_MODE << \
		GPC2CLK_OUT_SDIV14_INDIV4_SHIFT) \
		| (GPC2CLK_OUT_VCODIV1 << GPC2CLK_OUT_VCODIV_SHIFT) \
		| (GPC2CLK_OUT_BYPDIV31 << GPC2CLK_OUT_BYPDIV_SHIFT))

#define BYPASSCTRL_SYS	(SYS_GPCPLL_CFG_BASE + 0x340)
#define BYPASSCTRL_SYS_GPCPLL_SHIFT	0
#define BYPASSCTRL_SYS_GPCPLL_WIDTH	1

#define GPC_BCAST_GPCPLL_DVFS2	(GPC_BCASE_GPCPLL_CFG_BASE + 0x20)
#define GPC_BCAST_GPCPLL_DVFS2_DFS_EXT_STROBE_BIT	BIT(16)

#define GPC_BCAST_NDIV_SLOWDOWN_DEBUG	(GPC_BCASE_GPCPLL_CFG_BASE + 0xa0)
#define GPC_BCAST_NDIV_SLOWDOWN_DEBUG_PLL_DYNRAMP_DONE_SYNCED_SHIFT	24
#define GPC_BCAST_NDIV_SLOWDOWN_DEBUG_PLL_DYNRAMP_DONE_SYNCED_MASK \
	    (0x1 << GPC_BCAST_NDIV_SLOWDOWN_DEBUG_PLL_DYNRAMP_DONE_SYNCED_SHIFT)

/* FUSE register */
#define FUSE_RESERVED_CALIB0	0x204
#define FUSE_RESERVED_CALIB0_INTERCEPT_FRAC_SHIFT	0
#define FUSE_RESERVED_CALIB0_INTERCEPT_FRAC_WIDTH	4
#define FUSE_RESERVED_CALIB0_INTERCEPT_INT_SHIFT	4
#define FUSE_RESERVED_CALIB0_INTERCEPT_INT_WIDTH	10
#define FUSE_RESERVED_CALIB0_SLOPE_FRAC_SHIFT		14
#define FUSE_RESERVED_CALIB0_SLOPE_FRAC_WIDTH		10
#define FUSE_RESERVED_CALIB0_SLOPE_INT_SHIFT		24
#define FUSE_RESERVED_CALIB0_SLOPE_INT_WIDTH		6
#define FUSE_RESERVED_CALIB0_FUSE_REV_SHIFT		30
#define FUSE_RESERVED_CALIB0_FUSE_REV_WIDTH		2

#define DFS_DET_RANGE	6	/* -2^6 ... 2^6-1 */
#define SDM_DIN_RANGE	12	/* -2^12 ... 2^12-1 */

static inline u32 pl_to_div(u32 pl)
{
	return pl;
}

static inline u32 div_to_pl(u32 div)
{
	return div;
}

/* All frequencies in Khz */
struct gm20b_pllg_params {
	u32 min_vco, max_vco;
	u32 min_u, max_u;
	u32 min_m, max_m;
	u32 min_n, max_n;
	u32 min_pl, max_pl;
	/* NA mode parameters */
	int coeff_slope, coeff_offs;
	u32 vco_ctrl;
};

struct gm20b_pllg_fused_params {
	int uvdet_slope, uvdet_offs;
};

struct gm20b_pll {
	u32 m;
	u32 n;
	u32 pl;
};

struct gm20b_na_dvfs {
	u32 n_int;
	u32 sdm_din;
	u32 dfs_coeff;
	int dfs_det_max;
	int dfs_ext_cal;
	int uv_cal;
	int uv;
};

struct gm20b_gpcpll {
	struct gm20b_pll pll;
	struct gm20b_na_dvfs dvfs;
	u32 rate;	/* gpc2clk */
};

static const struct gm20b_pllg_params gm20b_pllg_params = {
	.min_vco = 1300000, .max_vco = 2600000,
	.min_u = 12000, .max_u = 38400,
	.min_m = 1, .max_m = 255,
	.min_n = 8, .max_n = 255,
	.min_pl = 1, .max_pl = 31,
	.coeff_slope = -165230, .coeff_offs = 214007,
	.vco_ctrl = 0x7 << 3,
};

struct gm20b_clk {
	struct nvkm_clk base;
	const struct gm20b_pllg_params *params;
	struct gm20b_pllg_fused_params fused_params;
	struct gm20b_gpcpll gpcpll;
	struct gm20b_gpcpll last_gpcpll;
	u32 parent_rate;
	int vid;
	bool napll_enabled;
	bool pldiv_glitchless_supported;
	u32 safe_fmax_vmin; /* in KHz */
};

/*
 * Post divider tarnsition is glitchless only if there is common "1" in
 * binary representation of old and new settings.
 */
static u32 gm20b_pllg_get_interim_pldiv(u32 old, u32 new)
{
	if (old & new)
		return 0;

	/* pl never 0 */
	return min(old | BIT(ffs(new) - 1), new | BIT(ffs(old) - 1));
}

static void
gm20b_gpcpll_read_mnp(struct gm20b_clk *clk, struct gm20b_pll *pll)
{
	struct nvkm_device *device = clk->base.subdev.device;
	u32 val;

	if (!pll) {
		WARN(1, "%s() - invalid PLL\n", __func__);
		return;
	}

	val = nvkm_rd32(device, GPCPLL_COEFF);
	pll->m = (val >> GPCPLL_COEFF_M_SHIFT) & MASK(GPCPLL_COEFF_M_WIDTH);
	pll->n = (val >> GPCPLL_COEFF_N_SHIFT) & MASK(GPCPLL_COEFF_N_WIDTH);
	pll->pl = (val >> GPCPLL_COEFF_P_SHIFT) & MASK(GPCPLL_COEFF_P_WIDTH);
}

static void
gm20b_pllg_read_mnp(struct gm20b_clk *clk)
{
	gm20b_gpcpll_read_mnp(clk, &clk->gpcpll.pll);
}

static u32
gm20b_pllg_calc_rate(u32 ref_rate, struct gm20b_pll *pll)
{
	u32 rate;
	u32 divider;

	rate = ref_rate * pll->n;
	divider = pll->m * pl_to_div(pll->pl);
	do_div(rate, divider);

	return rate / 2;
}

static int
gm20b_pllg_calc_mnp(struct gm20b_clk *clk, unsigned long rate)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	u32 target_clk_f, ref_clk_f, target_freq;
	u32 min_vco_f, max_vco_f;
	u32 low_pl, high_pl, best_pl;
	u32 target_vco_f, vco_f;
	u32 best_m, best_n;
	u32 u_f;
	u32 m, n, n2;
	u32 delta, lwv, best_delta = ~0;
	u32 pl;

	target_clk_f = rate * 2 / KHZ;
	ref_clk_f = clk->parent_rate / KHZ;

	max_vco_f = clk->params->max_vco;
	min_vco_f = clk->params->min_vco;
	best_m = clk->params->max_m;
	best_n = clk->params->min_n;
	best_pl = clk->params->min_pl;

	target_vco_f = target_clk_f + target_clk_f / 50;
	if (max_vco_f < target_vco_f)
		max_vco_f = target_vco_f;

	/* min_pl <= high_pl <= max_pl */
	high_pl = div_to_pl((max_vco_f + target_vco_f - 1) / target_vco_f);
	high_pl = min(high_pl, clk->params->max_pl);
	high_pl = max(high_pl, clk->params->min_pl);

	/* min_pl <= low_pl <= max_pl */
	low_pl = div_to_pl(min_vco_f / target_vco_f);
	low_pl = min(low_pl, clk->params->max_pl);
	low_pl = max(low_pl, clk->params->min_pl);

	nvkm_debug(subdev, "low_PL %d(div%d), high_PL %d(div%d)", low_pl,
		   pl_to_div(low_pl), high_pl, pl_to_div(high_pl));

	/* Select lowest possible VCO */
	for (pl = low_pl; pl <= high_pl; pl++) {
		target_vco_f = target_clk_f * pl_to_div(pl);
		for (m = clk->params->min_m; m <= clk->params->max_m; m++) {
			u_f = ref_clk_f / m;

			/* NA mode is supported only at max update rate 38.4 MHz */
			if (clk->napll_enabled && u_f != clk->params->max_u)
				continue;
			if (u_f < clk->params->min_u)
				break;
			if (u_f > clk->params->max_u)
				continue;

			n = (target_vco_f * m) / ref_clk_f;
			n2 = ((target_vco_f * m) + (ref_clk_f - 1)) / ref_clk_f;

			if (n > clk->params->max_n)
				break;

			for (; n <= n2; n++) {
				if (n < clk->params->min_n)
					continue;
				if (n > clk->params->max_n)
					break;

				vco_f = ref_clk_f * n / m;

				if (vco_f >= min_vco_f && vco_f <= max_vco_f) {
					lwv = (vco_f + (pl_to_div(pl) / 2))
						/ pl_to_div(pl);
					delta = abs(lwv - target_clk_f);

					if (delta < best_delta) {
						best_delta = delta;
						best_m = m;
						best_n = n;
						best_pl = pl;

						if (best_delta == 0)
							goto found_match;
					}
					nvkm_debug(subdev, "delta %d @ M %d, N %d, PL %d",
							delta, m, n, pl);
				}
			}
		}
	}

found_match:
	WARN_ON(best_delta == ~0);

	if (best_delta != 0)
		nvkm_debug(subdev,
			   "no best match for target @ %dKHz on gpc_pll",
			   target_clk_f);

	   clk->gpcpll.pll.m = best_m;
	   clk->gpcpll.pll.n = best_n;
	   clk->gpcpll.pll.pl = best_pl;

	target_freq = gm20b_pllg_calc_rate(clk->parent_rate,
			&clk->gpcpll.pll);
	target_freq /= KHZ;
	   clk->gpcpll.rate = target_freq * 2;

	nvkm_debug(subdev, "actual target freq %d KHz, M %d, N %d, PL %d(div%d)\n",
		 target_freq, clk->gpcpll.pll.m, clk->gpcpll.pll.n,
		           clk->gpcpll.pll.pl, pl_to_div(clk->gpcpll.pll.pl));
	return 0;
}

static void
gm20b_clk_calc_dfs_det_coeff(struct gm20b_clk *clk, int uv)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	const struct gm20b_pllg_params *p = clk->params;
	struct gm20b_pllg_fused_params *fp = &clk->fused_params;
	struct gm20b_na_dvfs *d = &clk->gpcpll.dvfs;
	u32 coeff;

	/* coeff = slope * voltage + offset */
	coeff = DIV_ROUND_CLOSEST(uv * p->coeff_slope, 1000 * 1000) +
			p->coeff_offs;
	coeff = DIV_ROUND_CLOSEST(coeff, 1000);
	coeff = min(coeff, (u32)MASK(GPCPLL_DVFS0_DFS_COEFF_WIDTH));
	d->dfs_coeff = coeff;

	d->dfs_ext_cal =
		DIV_ROUND_CLOSEST(uv - fp->uvdet_offs, fp->uvdet_slope);
	/* voltage = slope * det + offset */
	d->uv_cal = d->dfs_ext_cal * fp->uvdet_slope + fp->uvdet_offs;
	d->dfs_det_max = 0;

	nvkm_debug(subdev, "%s(): coeff=%u, ext_cal=%u, uv_cal=%u, det_max=%u\n",
			__func__, d->dfs_coeff, d->dfs_ext_cal, d->uv_cal,
			d->dfs_det_max);
}

/*
 * n_eff = n_int + 1/2 + SDM_DIN / 2^(SDM_DIN_RANGE + 1) +
 *         DVFS_COEFF * DVFS_DET_DELTA / 2^DFS_DET_RANGE
 */
static void
gm20b_clk_calc_dfs_ndiv(struct gm20b_clk *clk, struct
		gm20b_na_dvfs *d, int uv, int n_eff)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	int n, det_delta;
	u32 rem, rem_range;
	const struct gm20b_pllg_params *p = clk->params;
	struct gm20b_pllg_fused_params *fp = &clk->fused_params;

	det_delta = DIV_ROUND_CLOSEST(uv - fp->uvdet_offs, fp->uvdet_slope);
	det_delta -= d->dfs_ext_cal;
	det_delta = min(det_delta, d->dfs_det_max);
	det_delta = det_delta * d->dfs_coeff;

	n = (int)(n_eff << DFS_DET_RANGE) - det_delta;
	BUG_ON((n < 0) || (n > (p->max_n << DFS_DET_RANGE)));
	d->n_int = ((u32)n) >> DFS_DET_RANGE;

	rem = ((u32)n) & MASK(DFS_DET_RANGE);
	rem_range = SDM_DIN_RANGE + 1 - DFS_DET_RANGE;
	d->sdm_din = (rem << rem_range) - (1 << SDM_DIN_RANGE);
	d->sdm_din = (d->sdm_din >> 8) & MASK(GPCPLL_CFG2_SDM_DIN_WIDTH);

	nvkm_debug(subdev, "%s(): det_delta=%d, n_eff=%d, n_int=%u, sdm_din=%u\n",
			__func__, det_delta, n_eff, d->n_int, d->sdm_din);
}

static void
gm20b_clk_program_dfs_coeff(struct gm20b_clk *clk, u32 coeff)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	u32 mask = MASK(GPCPLL_DVFS0_DFS_COEFF_WIDTH) <<
		GPCPLL_DVFS0_DFS_COEFF_SHIFT;
	u32 val = (coeff << GPCPLL_DVFS0_DFS_COEFF_SHIFT) & mask;

	/* strobe to read external DFS coefficient */
	nvkm_mask(device, GPC_BCAST_GPCPLL_DVFS2,
			GPC_BCAST_GPCPLL_DVFS2_DFS_EXT_STROBE_BIT,
			GPC_BCAST_GPCPLL_DVFS2_DFS_EXT_STROBE_BIT);

	nvkm_mask(device, GPCPLL_DVFS0, mask, val);

	val = nvkm_rd32(device, GPC_BCAST_GPCPLL_DVFS2);
	udelay(1);
	val &= ~GPC_BCAST_GPCPLL_DVFS2_DFS_EXT_STROBE_BIT;
	nvkm_wr32(device, GPC_BCAST_GPCPLL_DVFS2, val);
}

static void
gm20b_clk_program_dfs_ext_cal(struct gm20b_clk *clk, u32 dfs_det_cal)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	u32 val;

	val = nvkm_rd32(device, GPC_BCAST_GPCPLL_DVFS2);
	val &= ~(BIT(DFS_DET_RANGE + 1) - 1);
	val |= dfs_det_cal;
	nvkm_wr32(device, GPC_BCAST_GPCPLL_DVFS2, val);

	val = nvkm_rd32(device, GPCPLL_DVFS1);
	val >>= GPCPLL_DVFS1_DFS_CTRL_SHIFT;
	val &= MASK(GPCPLL_DVFS1_DFS_CTRL_WIDTH);
	udelay(1);
	if (!(val & BIT(9))) {
		/* Use external value to overwide calibration value */
		val |= BIT(9);
		nvkm_wr32(device, GPCPLL_DVFS1, val << GPCPLL_DVFS1_DFS_CTRL_SHIFT);
	}
}

static void
gm20b_clk_program_dfs_detection(struct gm20b_clk *clk,
		struct gm20b_gpcpll *gpcpll)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	struct gm20b_na_dvfs *d = &gpcpll->dvfs;
	u32 val;

	/* strobe to read external DFS coefficient */
	nvkm_mask(device, GPC_BCAST_GPCPLL_DVFS2,
			GPC_BCAST_GPCPLL_DVFS2_DFS_EXT_STROBE_BIT,
			GPC_BCAST_GPCPLL_DVFS2_DFS_EXT_STROBE_BIT);

	val = nvkm_rd32(device, GPCPLL_DVFS0);
	val &= ~(MASK(GPCPLL_DVFS0_DFS_COEFF_WIDTH) <<
		GPCPLL_DVFS0_DFS_COEFF_SHIFT);
	val &= ~(MASK(GPCPLL_DVFS0_DFS_DET_MAX_WIDTH) <<
			GPCPLL_DVFS0_DFS_DET_MAX_SHIFT);
	val |= d->dfs_coeff << GPCPLL_DVFS0_DFS_COEFF_SHIFT;
	val |= d->dfs_det_max  << GPCPLL_DVFS0_DFS_DET_MAX_SHIFT;
	nvkm_wr32(device, GPCPLL_DVFS0, val);

	val = nvkm_rd32(device, GPC_BCAST_GPCPLL_DVFS2);
	udelay(1);
	val &= ~GPC_BCAST_GPCPLL_DVFS2_DFS_EXT_STROBE_BIT;
	nvkm_wr32(device, GPC_BCAST_GPCPLL_DVFS2, val);

	gm20b_clk_program_dfs_ext_cal(clk, d->dfs_ext_cal);
}

static int
gm20b_clk_setup_slide(struct gm20b_clk *clk, u32 rate)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	u32 step_a, step_b;

	/* setup */
	switch (rate) {
	case 12000:
	case 12800:
	case 13000:
		step_a = 0x2b;
		step_b = 0x0b;
		break;
	case 19200:
		step_a = 0x12;
		step_b = 0x08;
		break;
	case 38400:
		step_a = 0x04;
		step_b = 0x05;
		break;
	default:
		nvkm_error(subdev, "invalid updated clock rate %u KHz", rate);
		return -EINVAL;
	}
	nvkm_trace(subdev, "%s() updated clk rate=%u, step_a=%u, step_b=%u\n",
			__func__, rate, step_a, step_b);

	nvkm_mask(device, GPCPLL_CFG2, 0xff << GPCPLL_CFG2_PLL_STEPA_SHIFT,
		step_a << GPCPLL_CFG2_PLL_STEPA_SHIFT);
	nvkm_mask(device, GPCPLL_CFG3, 0xff << GPCPLL_CFG3_PLL_STEPB_SHIFT,
		step_b << GPCPLL_CFG3_PLL_STEPB_SHIFT);

	return 0;
}

static int
gm20b_pllg_slide(struct gm20b_clk *clk, struct gm20b_gpcpll *gpcpll)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	struct gm20b_pll pll = gpcpll->pll;
	u32 val;
	u32 nold, sdmold;
	int ramp_timeout;
	int ret;

	/* get old coefficients */
	val = nvkm_rd32(device, GPCPLL_COEFF);
	nold = (val >> GPCPLL_COEFF_N_SHIFT) & MASK(GPCPLL_COEFF_N_WIDTH);

	/* do nothing if NDIV is the same */
	if (clk->napll_enabled) {
		val = nvkm_rd32(device, GPCPLL_CFG2);
		sdmold = (val >>  GPCPLL_CFG2_SDM_DIN_SHIFT) &
			MASK(GPCPLL_CFG2_SDM_DIN_WIDTH);
		if (gpcpll->dvfs.n_int == nold &&
				gpcpll->dvfs.sdm_din == sdmold)
			return 0;
	} else {
		if (pll.n == nold)
			return 0;

		ret = gm20b_clk_setup_slide(clk,
				(clk->parent_rate / KHZ) / pll.m);
		if (ret)
			return ret;
	}

	/* pll slowdown mode */
	nvkm_mask(device, GPCPLL_NDIV_SLOWDOWN,
		BIT(GPCPLL_NDIV_SLOWDOWN_SLOWDOWN_USING_PLL_SHIFT),
		BIT(GPCPLL_NDIV_SLOWDOWN_SLOWDOWN_USING_PLL_SHIFT));

	/* new ndiv ready for ramp */
	val = nvkm_rd32(device, GPCPLL_COEFF);
	val &= ~(MASK(GPCPLL_COEFF_N_WIDTH) << GPCPLL_COEFF_N_SHIFT);
	val |= pll.n  << GPCPLL_COEFF_N_SHIFT;
	udelay(1);
	nvkm_wr32(device, GPCPLL_COEFF, val);

	/* dynamic ramp to new ndiv */
	val = nvkm_rd32(device, GPCPLL_NDIV_SLOWDOWN);
	val |= 0x1 << GPCPLL_NDIV_SLOWDOWN_EN_DYNRAMP_SHIFT;
	udelay(1);
	nvkm_wr32(device, GPCPLL_NDIV_SLOWDOWN, val);

	for (ramp_timeout = 500; ramp_timeout > 0; ramp_timeout--) {
		udelay(1);
		val = nvkm_rd32(device, GPC_BCAST_NDIV_SLOWDOWN_DEBUG);
		if (val & GPC_BCAST_NDIV_SLOWDOWN_DEBUG_PLL_DYNRAMP_DONE_SYNCED_MASK)
			break;
	}

	/* exit slowdown mode */
	nvkm_mask(device, GPCPLL_NDIV_SLOWDOWN,
		BIT(GPCPLL_NDIV_SLOWDOWN_SLOWDOWN_USING_PLL_SHIFT) |
		BIT(GPCPLL_NDIV_SLOWDOWN_EN_DYNRAMP_SHIFT), 0);
	nvkm_rd32(device, GPCPLL_NDIV_SLOWDOWN);

	if (ramp_timeout <= 0) {
		nvkm_error(subdev, "gpcpll dynamic ramp timeout\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static void
_gm20b_pllg_enable(struct gm20b_clk *clk)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;

	nvkm_mask(device, GPCPLL_CFG, GPCPLL_CFG_ENABLE, GPCPLL_CFG_ENABLE);
	nvkm_rd32(device, GPCPLL_CFG);
}

static void
_gm20b_pllg_disable(struct gm20b_clk *clk)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;

	nvkm_mask(device, GPCPLL_CFG, GPCPLL_CFG_ENABLE, 0);
	nvkm_rd32(device, GPCPLL_CFG);
}

static int
gm20b_clk_program_pdiv_under_bypass(struct gm20b_clk *clk,
		struct gm20b_gpcpll *gpcpll)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	u32 val;

	/* put PLL in bypass before programming it */
	val = nvkm_rd32(device, SEL_VCO);
	val &= ~(BIT(SEL_VCO_GPC2CLK_OUT_SHIFT));
	nvkm_wr32(device, SEL_VCO, val);

	/* change PDIV */
	val = nvkm_rd32(device, GPCPLL_COEFF);
	udelay(1);
	val &= ~(MASK(GPCPLL_COEFF_P_WIDTH) << GPCPLL_COEFF_P_SHIFT);
	val |= gpcpll->pll.pl << GPCPLL_COEFF_P_SHIFT;
	nvkm_wr32(device, GPCPLL_COEFF, val);

	/* switch to VCO mode */
	val = nvkm_rd32(device, SEL_VCO);
	udelay(1);
	val |= BIT(SEL_VCO_GPC2CLK_OUT_SHIFT);
	nvkm_wr32(device, SEL_VCO, val);

	nvkm_trace(subdev, "%s(): pdiv=%u\n", __func__, gpcpll->pll.pl);
	return 0;
}

static int
gm20b_lock_gpcpll_under_bypass(struct gm20b_clk *clk,
		struct gm20b_gpcpll *gpcpll)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	u32 val;

	/* put PLL in bypass before programming it */
	val = nvkm_rd32(device, SEL_VCO);
	val &= ~(BIT(SEL_VCO_GPC2CLK_OUT_SHIFT));
	nvkm_wr32(device, SEL_VCO, val);

	/* get out from IDDQ */
	val = nvkm_rd32(device, GPCPLL_CFG);
	if (val & GPCPLL_CFG_IDDQ) {
		val &= ~GPCPLL_CFG_IDDQ;
		nvkm_wr32(device, GPCPLL_CFG, val);
		nvkm_rd32(device, GPCPLL_CFG);
		udelay(5);
	} else {
		/* clear SYNC_MODE before disabling PLL */
		val &= ~(0x1 << GPCPLL_CFG_SYNC_MODE);
		nvkm_wr32(device, GPCPLL_CFG, val);
		nvkm_rd32(device, GPCPLL_CFG);

		/* disable running PLL before changing coefficients */
		_gm20b_pllg_disable(clk);
	}

	nvkm_trace(subdev, "%s(): m=%d n=%d pl=%d\n", __func__,
			gpcpll->pll.m, gpcpll->pll.n, gpcpll->pll.pl);

	/* change coefficients */
	if (clk->napll_enabled) {
		gm20b_clk_program_dfs_detection(clk, gpcpll);

		nvkm_mask(device, GPCPLL_CFG2,
				MASK(GPCPLL_CFG2_SDM_DIN_WIDTH) <<
				GPCPLL_CFG2_SDM_DIN_SHIFT,
				gpcpll->dvfs.sdm_din << GPCPLL_CFG2_SDM_DIN_SHIFT);

		val = gpcpll->pll.m << GPCPLL_COEFF_M_SHIFT;
		val |= gpcpll->dvfs.n_int << GPCPLL_COEFF_N_SHIFT;
		val |= gpcpll->pll.pl << GPCPLL_COEFF_P_SHIFT;
		nvkm_wr32(device, GPCPLL_COEFF, val);
	} else {
		val = gpcpll->pll.m << GPCPLL_COEFF_M_SHIFT;
		val |= gpcpll->pll.n << GPCPLL_COEFF_N_SHIFT;
		val |= gpcpll->pll.pl << GPCPLL_COEFF_P_SHIFT;
		nvkm_wr32(device, GPCPLL_COEFF, val);
	}

	_gm20b_pllg_enable(clk);

	if (clk->napll_enabled) {
		/* just delay in DVFS mode (lock cannot be used) */
		nvkm_rd32(device, GPCPLL_CFG);
		udelay(40);
		goto pll_locked;
	}

	/* lock pll */
	val = nvkm_rd32(device, GPCPLL_CFG);
	if (val & GPCPLL_CFG_LOCK_DET_OFF) {
		val &= ~GPCPLL_CFG_LOCK_DET_OFF;
		nvkm_wr32(device, GPCPLL_CFG, val);
	}

	if (!nvkm_wait_nsec(device, 300000, GPCPLL_CFG, GPCPLL_CFG_LOCK,
				GPCPLL_CFG_LOCK)) {
		nvkm_error(subdev, "%s: timeout waiting for pllg lock\n", __func__);
		return -ETIMEDOUT;
	}

pll_locked:
	/* set SYNC_MODE for glitchless switch out of bypass */
	val = nvkm_rd32(device, GPCPLL_CFG);
	val |= 0x1 << GPCPLL_CFG_SYNC_MODE;
	nvkm_wr32(device, GPCPLL_CFG, val);
	nvkm_rd32(device, GPCPLL_CFG);

	/* switch to VCO mode */
	nvkm_mask(device, SEL_VCO, 0, BIT(SEL_VCO_GPC2CLK_OUT_SHIFT));

	return 0;
}

static int
_gm20b_pllg_program_mnp(struct gm20b_clk *clk,
		struct gm20b_gpcpll *gpcpll, bool allow_slide)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	u32 val, cfg;
	struct gm20b_gpcpll gpll;
	bool pdiv_only = false;
	int ret;

	/* get old coefficients */
	gm20b_gpcpll_read_mnp(clk, &gpll.pll);

	gpll.dvfs = gpcpll->dvfs;

	/* do NDIV slide if there is no change in M and PL */
	cfg = nvkm_rd32(device, GPCPLL_CFG);
	if (allow_slide && (cfg & GPCPLL_CFG_ENABLE) &&
			gpcpll->pll.m == gpll.pll.m &&
			gpcpll->pll.pl == gpll.pll.pl) {
		return gm20b_pllg_slide(clk, gpcpll);
	}

	/* slide down to NDIV_LO */
	if (allow_slide && (cfg & GPCPLL_CFG_ENABLE)) {
		gpll.pll.n = DIV_ROUND_UP(gpll.pll.m * clk->params->min_vco,
				                              clk->parent_rate / KHZ);
		if (clk->napll_enabled)
			gm20b_clk_calc_dfs_ndiv(clk, &gpll.dvfs, gpll.dvfs.uv,
					gpll.pll.n);

		ret = gm20b_pllg_slide(clk, &gpll);
		if (ret)
			return ret;

		pdiv_only = gpll.pll.m == gpcpll->pll.m;
	}

	/* split FO-to-bypass jump in halfs by setting out divider 1:2 */
	nvkm_mask(device, GPC2CLK_OUT, GPC2CLK_OUT_VCODIV_MASK,
		0x2 << GPC2CLK_OUT_VCODIV_SHIFT);

	/*
	 * If the pldiv is glitchless and is the only coeff change compared
	 * with the current coeff after sliding down to min VCO, then we can
	 * ignore the bypass step.
	 */
	if (clk->pldiv_glitchless_supported && pdiv_only) {
		u32 interim_pl = gm20b_pllg_get_interim_pldiv(gpll.pll.pl,
				gpcpll->pll.pl);
		if (interim_pl)  {
			val = nvkm_rd32(device, GPCPLL_COEFF);
			val &= ~(MASK(GPCPLL_COEFF_P_WIDTH) << GPCPLL_COEFF_P_SHIFT);
			val |= interim_pl << GPCPLL_COEFF_P_SHIFT;
			nvkm_wr32(device, GPCPLL_COEFF, val);
			nvkm_rd32(device, GPCPLL_COEFF);
		}
	} else {
		gpll = *gpcpll;
		if (allow_slide) {
			gpll.pll.n = DIV_ROUND_UP(gpcpll->pll.m * clk->params->min_vco,
					                                 clk->parent_rate / KHZ);
			if (clk->napll_enabled)
				gm20b_clk_calc_dfs_ndiv(clk, &gpll.dvfs,
						gpll.dvfs.uv, gpll.pll.n);
		}

		if (pdiv_only)
			ret = gm20b_clk_program_pdiv_under_bypass(clk, &gpll);
		else
			ret = gm20b_lock_gpcpll_under_bypass(clk, &gpll);

		if (ret)
			return ret;
	}

	/* make sure we have the correct pdiv */
	val = nvkm_rd32(device, GPCPLL_COEFF);
	if (((val & MASK(GPCPLL_COEFF_P_WIDTH)) >> GPCPLL_COEFF_P_SHIFT) !=
			gpcpll->pll.pl) {
		val &= ~(MASK(GPCPLL_COEFF_P_WIDTH) << GPCPLL_COEFF_P_SHIFT);
		val |= gpcpll->pll.pl << GPCPLL_COEFF_P_SHIFT;
		nvkm_wr32(device, GPCPLL_COEFF, val);
	}

	/* restore out divider 1:1 */
	val = nvkm_rd32(device, GPC2CLK_OUT);
	if ((val & GPC2CLK_OUT_VCODIV_MASK) !=
			(GPC2CLK_OUT_VCODIV1 << GPC2CLK_OUT_VCODIV_SHIFT)) {
		val &= ~GPC2CLK_OUT_VCODIV_MASK;
		val |= GPC2CLK_OUT_VCODIV1 << GPC2CLK_OUT_VCODIV_SHIFT;
		udelay(2);
		nvkm_wr32(device, GPC2CLK_OUT, val);
		/* Intentional 2nd write to assure linear divider operation */
		nvkm_wr32(device, GPC2CLK_OUT, val);
		nvkm_rd32(device, GPC2CLK_OUT);
	}

	/* slide up to new NDIV */
	return allow_slide ? gm20b_pllg_slide(clk, gpcpll) : 0;
}

/*
 * Configure/calculate the DVFS coefficients and ndiv based on the desired
 * voltage level
 */
static void
gm20b_clk_config_dvfs(struct gm20b_clk *clk)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	struct nvkm_volt *volt = device->volt;
	int uv = nvkm_volt_get_voltage_by_id(volt, clk->vid);

	gm20b_clk_calc_dfs_det_coeff(clk, uv);
	gm20b_clk_calc_dfs_ndiv(clk, &clk->gpcpll.dvfs, uv,
			                         clk->gpcpll.pll.n);
	   clk->gpcpll.dvfs.uv = uv;
	nvkm_trace(subdev, "%s(): uv=%d\n", __func__, uv);
}

static void
gm20b_clk_calc_safe_dvfs(struct gm20b_clk *priv,
		struct gm20b_gpcpll *gpcpll)
{
	int nsafe, nmin;

	if (gpcpll->rate > priv->safe_fmax_vmin)
		/* margin is 10% */
		gpcpll->rate = gpcpll->rate * (100 - 10) / 100;

	nmin = DIV_ROUND_UP(gpcpll->pll.m * priv->params->min_vco,
			priv->parent_rate / KHZ);
	nsafe = gpcpll->pll.m * gpcpll->rate / (priv->parent_rate / KHZ);
	if (nsafe < nmin) {
		gpcpll->pll.pl = DIV_ROUND_UP(nmin * (priv->parent_rate / KHZ),
				gpcpll->pll.m * gpcpll->rate);
		nsafe = nmin;
	}
	gpcpll->pll.n = nsafe;
	gm20b_clk_calc_dfs_ndiv(priv, &gpcpll->dvfs, gpcpll->dvfs.uv,
			gpcpll->pll.n);
}

static int
_gm20b_pllg_program_na_mnp(struct gm20b_clk *clk,
		struct gm20b_gpcpll *gpcpll, bool allow_slide)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	struct nvkm_volt *volt = device->volt;
	int cur_uv = nvkm_volt_get(volt);
	int new_uv = nvkm_volt_get_voltage_by_id(volt, clk->vid);
	struct gm20b_gpcpll *last_gpcpll = &clk->last_gpcpll;
	u32 cur_rate = last_gpcpll->rate;

	gm20b_clk_config_dvfs(clk);

	/*
	 * We don't have to re-program the DVFS because the voltage keeps the
	 * same value (and we already have the same coeffients in hardware).
	 */
	if (!allow_slide || last_gpcpll->dvfs.uv == gpcpll->dvfs.uv)
		return _gm20b_pllg_program_mnp(clk, &clk->gpcpll, allow_slide);

	/* Before setting coefficient to 0, switch to safe frequency first */
	if (cur_rate > clk->safe_fmax_vmin) {
		struct gm20b_gpcpll safe_gpcpll;
		int ret;

		/* voltage is increasing */
		if (cur_uv < new_uv) {
			safe_gpcpll = clk->last_gpcpll;
			safe_gpcpll.dvfs.uv = clk->gpcpll.dvfs.uv;
		}
		/* voltage is decreasing */
		else {
			safe_gpcpll = clk->gpcpll;
			safe_gpcpll.dvfs = clk->last_gpcpll.dvfs;
		}

		gm20b_clk_calc_safe_dvfs(clk, &safe_gpcpll);
		ret = _gm20b_pllg_program_mnp(clk, &safe_gpcpll, true);
		if (ret) {
			nvkm_error(subdev, "failed to switch to Fsafe@Vmin\n");
			return ret;
		}
	}

	/*
	 * DVFS detection settings transition:
	 * - Set DVFS coefficient zero
	 * - Set calibration level to new voltage
	 * - Set DVFS coefficient to match new voltage
	 */
	gm20b_clk_program_dfs_coeff(clk, 0);
	gm20b_clk_program_dfs_ext_cal(clk, gpcpll->dvfs.dfs_ext_cal);
	gm20b_clk_program_dfs_coeff(clk, gpcpll->dvfs.dfs_coeff);

	return _gm20b_pllg_program_mnp(clk, gpcpll, true);
}

static int
gm20b_clk_program_gpcpll(struct gm20b_clk *clk)
{
	int err;

	err = _gm20b_pllg_program_mnp(clk, &clk->gpcpll, true);
	if (err)
		err = _gm20b_pllg_program_mnp(clk, &clk->gpcpll, false);

	return err;
}

static int
gm20b_clk_program_na_gpcpll(struct gm20b_clk *clk)
{
	int err;

	err = _gm20b_pllg_program_na_mnp(clk, &clk->gpcpll, true);
	if (err)
		err = _gm20b_pllg_program_na_mnp(clk, &clk->gpcpll, false);

	return err;

}

static int
gm20b_napll_setup(struct gm20b_clk *clk)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	const struct gm20b_pllg_params *p = clk->params;
	struct gm20b_pllg_fused_params *fp = &clk->fused_params;
	bool calibrated = fp->uvdet_slope && fp->uvdet_offs;
	u32 val;

	/* Enable NA DVFS */
	nvkm_mask(device, GPCPLL_DVFS1, GPCPLL_DVFS1_EN_DFS_BIT,
			GPCPLL_DVFS1_EN_DFS_BIT);

	/* Set VCO_CTRL */
	if (p->vco_ctrl)
		nvkm_mask(device, GPCPLL_CFG3, MASK(GPCPLL_CFG3_VCO_CTRL_WIDTH) <<
				GPCPLL_CFG3_VCO_CTRL_SHIFT,
				p->vco_ctrl << GPCPLL_CFG3_VCO_CTRL_SHIFT);

	if (calibrated)
		/* Start internal calibration, but ignore the result */
		nvkm_mask(device, GPCPLL_DVFS1, GPCPLL_DVFS1_EN_DFS_CAL_BIT,
				GPCPLL_DVFS1_EN_DFS_CAL_BIT);

	/* Exit IDDQ mode */
	nvkm_mask(device, GPCPLL_CFG, GPCPLL_CFG_IDDQ, 0);
	nvkm_rd32(device, GPCPLL_CFG);
	udelay(5);

	/*
	 * Dynamic ramp setup based on update rate, which in DVFS mode on
	 * GM20b is always 38.4 MHz, the same as reference clock rate.
	 */
	gm20b_clk_setup_slide(clk, clk->parent_rate / KHZ);

	if (calibrated)
		goto calibration_done;

	/*
	 * No fused calibration data available. Need to do internal
	 * calibration.
	 */
	if (!nvkm_wait_nsec(device, 5000, GPCPLL_DVFS1,
				GPCPLL_DVFS1_DFS_CAL_DONE_BIT,
				GPCPLL_DVFS1_DFS_CAL_DONE_BIT)) {
		nvkm_error(subdev, "%s: DVFS calibration timeout\n", __func__);
		//return -ETIMEDOUT;
	}

	val = nvkm_rd32(device, GPCPLL_CFG3);
	val >>= GPCPLL_CFG3_PLL_DFS_TESTOUT_SHIFT;
	val &= MASK(GPCPLL_CFG3_PLL_DFS_TESTOUT_WIDTH);
	/* default ADC detection slope 10mV */
	fp->uvdet_slope = 10000;
	/* gpu rail boot voltage 1.0V = 1000000uV */
	fp->uvdet_offs = 1000000 - val * fp->uvdet_slope;

calibration_done:
	nvkm_trace(subdev, "%s(): %s calibration slope=%d, intercept=%d\n",
			__func__, calibrated ? "external" : "internal",
			fp->uvdet_slope, fp->uvdet_offs);
	return 0;
}

static void
gm20b_pllg_disable(struct gm20b_clk *clk)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	u32 val;

	/* slide to VCO min */
	val = nvkm_rd32(device, GPCPLL_CFG);
	if (val & GPCPLL_CFG_ENABLE) {
		struct gm20b_gpcpll gpcpll = clk->gpcpll;

		gm20b_gpcpll_read_mnp(clk, &gpcpll.pll);
		gpcpll.pll.n = DIV_ROUND_UP(gpcpll.pll.m * clk->params->min_vco,
				                                clk->parent_rate / KHZ);
		if (clk->napll_enabled)
			gm20b_clk_calc_dfs_ndiv(clk, &gpcpll.dvfs, gpcpll.dvfs.uv,
					gpcpll.pll.n);
		gm20b_pllg_slide(clk, &gpcpll);
	}

	/* put PLL in bypass before disabling it */
	nvkm_mask(device, SEL_VCO, BIT(SEL_VCO_GPC2CLK_OUT_SHIFT), 0);

	/* clear SYNC_MODE before disabling PLL */
	nvkm_mask(device, GPCPLL_CFG, ~(0x1 << GPCPLL_CFG_SYNC_MODE), 0);

	_gm20b_pllg_disable(clk);
}

#define GM20B_CLK_GPC_MDIV 1000

static struct nvkm_pstate
gm20b_pstates[] = {
	{
		.base = {
			.domain[nv_clk_src_gpc] = 76800,
			.voltage = 0,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 153600,
			.voltage = 1,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 230400,
			.voltage = 2,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 307200,
			.voltage = 3,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 384000,
			.voltage = 4,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 460800,
			.voltage = 5,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 537600,
			.voltage = 6,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 614400,
			.voltage = 7,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 691200,
			.voltage = 8,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 768000,
			.voltage = 9,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 844800,
			.voltage = 10,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 921600,
			.voltage = 11,
		},
	},
	{
		.base = {
			.domain[nv_clk_src_gpc] = 998400,
			.voltage = 12,
		},
	},

};

static int
gm20b_clk_read(struct nvkm_clk *base, enum nv_clk_src src)
{
	struct gm20b_clk *clk = gm20b_clk(base);
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;

	switch (src) {
	case nv_clk_src_crystal:
		return device->crystal;
	case nv_clk_src_gpc:
		gm20b_pllg_read_mnp(clk);
		return gm20b_pllg_calc_rate(clk->parent_rate, &clk->gpcpll.pll) /
			GM20B_CLK_GPC_MDIV;
	default:
		nvkm_error(subdev, "invalid clock source %d\n", src);
		return -EINVAL;
	}
}

static int
gm20b_clk_calc(struct nvkm_clk *base, struct nvkm_cstate *cstate)
{
	struct gm20b_clk *clk = gm20b_clk(base);
	int ret;

	ret = gm20b_pllg_calc_mnp(clk, cstate->domain[nv_clk_src_gpc] *
					 GM20B_CLK_GPC_MDIV);
	if (!ret)
		clk->vid = cstate->voltage;

	return ret;
}

static int
gm20b_clk_prog(struct nvkm_clk *base)
{
	struct gm20b_clk *clk = gm20b_clk(base);
	int ret;

	if (clk->napll_enabled)
		ret = gm20b_clk_program_na_gpcpll(clk);
	else
		ret = gm20b_clk_program_gpcpll(clk);

	clk->last_gpcpll = clk->gpcpll;

	return ret;
}

static void
gm20b_clk_tidy(struct nvkm_clk *clk)
{
}

static void
gm20b_clk_fini(struct nvkm_clk *base)
{
	struct gm20b_clk *clk = gm20b_clk(base);
	gm20b_pllg_disable(clk);
}

static int
gm20b_clk_init(struct nvkm_clk *base)
{
	struct gm20b_clk *clk = gm20b_clk(base);
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	struct gm20b_gpcpll *gpcpll = &clk->gpcpll;
	struct gm20b_pll *pll = &gpcpll->pll;
	u32 val;
	int ret;

	/*
	 * Initial frequency, low enough to be safe at Vmin (default 1/3
	 * VCO min)
	 */
	pll->m = 1;
	pll->n = DIV_ROUND_UP(clk->params->min_vco, clk->parent_rate / KHZ);
	pll->pl = DIV_ROUND_UP(clk->params->min_vco, clk->safe_fmax_vmin);
	pll->pl = max(clk->gpcpll.pll.pl, 3U);
	gpcpll->rate = (clk->parent_rate / KHZ) * clk->gpcpll.pll.n;
	gpcpll->rate /= pl_to_div(clk->gpcpll.pll.pl);
	val = pll->m << GPCPLL_COEFF_M_SHIFT;
	val |= pll->n << GPCPLL_COEFF_N_SHIFT;
	val |= pll->pl << GPCPLL_COEFF_P_SHIFT;
	nvkm_wr32(device, GPCPLL_COEFF, val);
	nvkm_trace(subdev, "Initial freq=%uKHz(gpc2clk), m=%u, n=%u, pl=%u\n",
			gpcpll->rate, pll->m, pll->n, pll->pl);

	/* Set the global bypass control to VCO */
	nvkm_mask(device, BYPASSCTRL_SYS,
		MASK(BYPASSCTRL_SYS_GPCPLL_WIDTH) << BYPASSCTRL_SYS_GPCPLL_SHIFT,
		0);

	/* Disable idle slow down */
	nvkm_mask(device, 0x20160, 0x003f0000, 0x0);

	if (clk->napll_enabled) {
		ret = gm20b_napll_setup(clk);
		if (ret)
			return ret;
	}

	ret = gm20b_clk_prog(&clk->base);
	if (ret) {
		nvkm_error(subdev, "cannot initialize clock\n");
		return ret;
	}

	return 0;
}

static int
gm20b_clk_init_fused_params(struct gm20b_clk *priv)
{
	struct gm20b_pllg_fused_params *p = &priv->fused_params;
	u32 val;

	tegra_fuse_readl(FUSE_RESERVED_CALIB0, &val);
	if ((val >> FUSE_RESERVED_CALIB0_FUSE_REV_SHIFT) &
			MASK(FUSE_RESERVED_CALIB0_FUSE_REV_WIDTH)) {
		/* Integer part in mV  * 1000 + fractional part in uV */
		p->uvdet_slope =
			((val >> FUSE_RESERVED_CALIB0_SLOPE_INT_SHIFT) &
			MASK(FUSE_RESERVED_CALIB0_SLOPE_INT_WIDTH)) * 1000 +
			((val >> FUSE_RESERVED_CALIB0_SLOPE_FRAC_SHIFT) &
			MASK(FUSE_RESERVED_CALIB0_SLOPE_FRAC_WIDTH));
		/* Integer part in mV  * 1000 + fractional part in 100uV */
		p->uvdet_offs =
			((val >> FUSE_RESERVED_CALIB0_INTERCEPT_INT_SHIFT) &
			MASK(FUSE_RESERVED_CALIB0_INTERCEPT_INT_WIDTH)) * 1000 +
			((val >> FUSE_RESERVED_CALIB0_INTERCEPT_FRAC_SHIFT) &
			 MASK(FUSE_RESERVED_CALIB0_INTERCEPT_FRAC_WIDTH)) * 100;

		return 0;
	}

	/* If no fused parameters, we will try internal calibration later */
	return -EINVAL;
}

static int
gm20b_clk_init_safe_fmax(struct gm20b_clk *clk)
{
	struct nvkm_subdev *subdev = &clk->base.subdev;
	struct nvkm_device *device = subdev->device;
	struct nvkm_volt *volt = device->volt;
	int vmin, id = 0, fmax = 0;
	int i;

	vmin = volt->vid[0].uv;
	for (i = 1; i < volt->vid_nr; i++) {
		if (volt->vid[i].uv <= vmin) {
			vmin = volt->vid[i].uv;
			id =  volt->vid[i].vid;
		}
	}

	for (i = 0; i < ARRAY_SIZE(gm20b_pstates); i++) {
		if (gm20b_pstates[i].base.voltage == id)
			fmax = gm20b_pstates[i].base.domain[nv_clk_src_gpc];
	}

	if (!fmax) {
		nvkm_error(subdev, "failed to evaluate safe fmax\n");
		return -EINVAL;
	}

	/* margin is 10% */
	   clk->safe_fmax_vmin = fmax * (100 - 10) / 100;
	/* gpc2clk */
	   clk->safe_fmax_vmin *= 2;
	nvkm_trace(subdev, "safe famx @ vmin = %uKHz\n", clk->safe_fmax_vmin);

	return 0;
}

static const struct nvkm_clk_func
gm20b_clk = {
	.init = gm20b_clk_init,
	.fini = gm20b_clk_fini,
	.read = gm20b_clk_read,
	.calc = gm20b_clk_calc,
	.prog = gm20b_clk_prog,
	.tidy = gm20b_clk_tidy,
	.pstates = gm20b_pstates,
	.nr_pstates = ARRAY_SIZE(gm20b_pstates),
	.domains = {
		{ nv_clk_src_crystal, 0xff },
		{ nv_clk_src_gpc, 0xff, 0, "core", GM20B_CLK_GPC_MDIV },
		{ nv_clk_src_max },
	},
};

int
gm20b_clk_new(struct nvkm_device *device, int index, struct nvkm_clk **pclk)
{
	struct nvkm_device_tegra *tdev = device->func->tegra(device);
	struct gm20b_clk *clk;
	int ret, i;

	if (!(clk = kzalloc(sizeof(*clk), GFP_KERNEL)))
		return -ENOMEM;
	*pclk = &clk->base;

	/* Finish initializing the pstates */
	for (i = 0; i < ARRAY_SIZE(gm20b_pstates); i++) {
		INIT_LIST_HEAD(&gm20b_pstates[i].list);
		gm20b_pstates[i].pstate = i + 1;
	}

	clk->params = &gm20b_pllg_params;
	clk->parent_rate = clk_get_rate(tdev->clk);

	ret = nvkm_clk_ctor(&gm20b_clk, device, index, true, &clk->base);
	if (ret)
		return ret;
	nvkm_info(&clk->base.subdev, "parent clock rate: %d Khz\n",
		  clk->parent_rate / KHZ);


	ret = gm20b_clk_init_fused_params(clk);
	/* print error and use boot internal calibration later */
	if (ret)
		nvkm_error(&clk->base.subdev,
			 "missing fused ADC calibration parameters\n");

	ret = gm20b_clk_init_safe_fmax(clk);
	if (ret)
		return ret;

	clk->napll_enabled = tdev->gpu_speedo_id >= 1;
	clk->pldiv_glitchless_supported = true;

	return ret;
}