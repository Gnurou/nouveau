/*
 * Copyright (c) 2014-2015, NVIDIA CORPORATION. All rights reserved.
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
#include "gk20a.h"
#include "ctxgf100.h"

#include <nvif/class.h>
#include <subdev/timer.h>

static struct nvkm_oclass
gk20a_gr_sclass[] = {
	{ FERMI_TWOD_A, &nvkm_object_ofuncs },
	{ KEPLER_INLINE_TO_MEMORY_A, &nvkm_object_ofuncs },
	{ KEPLER_C, &gf100_fermi_ofuncs, gf100_gr_9097_omthds },
	{ KEPLER_COMPUTE_A, &nvkm_object_ofuncs, gf100_gr_90c0_omthds },
	{}
};

static void
gk20a_gr_init_dtor(struct gf100_gr_pack *pack)
{
	vfree(pack);
}

struct gk20a_fw_av
{
	u32 addr;
	u32 data;
};

static struct gf100_gr_pack *
gk20a_gr_av_to_init(struct gf100_gr_fuc *fuc)
{
	struct gf100_gr_init *init;
	struct gf100_gr_pack *pack;
	const int nent = (fuc->size / sizeof(struct gk20a_fw_av));
	int i;

	pack = vzalloc((sizeof(*pack) * 2) + (sizeof(*init) * (nent + 1)));
	if (!pack)
		return ERR_PTR(-ENOMEM);

	init = (void *)(pack + 2);

	pack[0].init = init;

	for (i = 0; i < nent; i++) {
		struct gf100_gr_init *ent = &init[i];
		struct gk20a_fw_av *av = &((struct gk20a_fw_av *)fuc->data)[i];

		ent->addr = av->addr;
		ent->data = av->data;
		ent->count = 1;
		ent->pitch = 1;
	}

	return pack;
}

struct gk20a_fw_aiv
{
	u32 addr;
	u32 index;
	u32 data;
};

static struct gf100_gr_pack *
gk20a_gr_aiv_to_init(struct gf100_gr_fuc *fuc)
{
	struct gf100_gr_init *init;
	struct gf100_gr_pack *pack;
	const int nent = (fuc->size / sizeof(struct gk20a_fw_aiv));
	int i;

	pack = vzalloc((sizeof(*pack) * 2) + (sizeof(*init) * (nent + 1)));
	if (!pack)
		return ERR_PTR(-ENOMEM);

	init = (void *)(pack + 2);

	pack[0].init = init;

	for (i = 0; i < nent; i++) {
		struct gf100_gr_init *ent = &init[i];
		struct gk20a_fw_aiv *av = &((struct gk20a_fw_aiv *)fuc->data)[i];

		ent->addr = av->addr;
		ent->data = av->data;
		ent->count = 1;
		ent->pitch = 1;
	}

	return pack;
}

static struct gf100_gr_pack *
gk20a_gr_av_to_method(struct gf100_gr_fuc *fuc)
{
	struct gf100_gr_init *init;
	struct gf100_gr_pack *pack;
	/* We don't suppose we will initialize more than 16 classes here... */
	static const unsigned int max_classes = 16;
	const int nent = (fuc->size / sizeof(struct gk20a_fw_av));
	int i, classidx = 0;
	u32 prevclass = 0;

	pack = vzalloc((sizeof(*pack) * max_classes) +
		       (sizeof(*init) * (nent + 1)));
	if (!pack)
		return ERR_PTR(-ENOMEM);

	init = (void *)(pack + max_classes);

	for (i = 0; i < nent; i++) {
		struct gf100_gr_init *ent = &init[i];
		struct gk20a_fw_av *av = &((struct gk20a_fw_av *)fuc->data)[i];
		u32 class = av->addr & 0xffff;
		u32 addr = (av->addr & 0xffff0000) >> 14;

		if (prevclass != class) {
			pack[classidx].init = ent;
			pack[classidx].type = class;
			prevclass = class;
			if (++classidx >= max_classes) {
				vfree(pack);
				return ERR_PTR(-ENOSPC);
			}
		}

		ent->addr = addr;
		ent->data = av->data;
		ent->count = 1;
		ent->pitch = 1;
	}

	return pack;
}

int
gk20a_gr_ctor(struct nvkm_object *parent, struct nvkm_object *engine,
	      struct nvkm_oclass *oclass, void *data, u32 size,
	      struct nvkm_object **pobject)
{
	int err;
	struct gf100_gr_priv *priv;
	struct gf100_gr_fuc fuc;

	err = gf100_gr_ctor(parent, engine, oclass, data, size, pobject);
	if (err)
		return err;

	priv = (void *)*pobject;

	err = gf100_gr_ctor_fw(priv, "sw_nonctx", &fuc);
	if (err)
		return err;
	priv->fuc_sw_nonctx = gk20a_gr_av_to_init(&fuc);
	gf100_gr_dtor_fw(&fuc);
	if (IS_ERR(priv->fuc_sw_nonctx))
		return PTR_ERR(priv->fuc_sw_nonctx);

	err = gf100_gr_ctor_fw(priv, "sw_ctx", &fuc);
	if (err)
		return err;
	priv->fuc_sw_ctx = gk20a_gr_aiv_to_init(&fuc);
	gf100_gr_dtor_fw(&fuc);
	if (IS_ERR(priv->fuc_sw_ctx))
		return PTR_ERR(priv->fuc_sw_ctx);

	err = gf100_gr_ctor_fw(priv, "bundle", &fuc);
	if (err)
		return err;
	priv->fuc_bundle = gk20a_gr_av_to_init(&fuc);
	gf100_gr_dtor_fw(&fuc);
	if (IS_ERR(priv->fuc_bundle))
		return PTR_ERR(priv->fuc_bundle);

	err = gf100_gr_ctor_fw(priv, "method", &fuc);
	if (err)
		return err;
	priv->fuc_method = gk20a_gr_av_to_method(&fuc);
	gf100_gr_dtor_fw(&fuc);
	if (IS_ERR(priv->fuc_method))
		return PTR_ERR(priv->fuc_method);

	return 0;
}

void
gk20a_gr_dtor(struct nvkm_object *object)
{
	struct gf100_gr_priv *priv = (void *)object;

	gk20a_gr_init_dtor(priv->fuc_method);
	gk20a_gr_init_dtor(priv->fuc_bundle);
	gk20a_gr_init_dtor(priv->fuc_sw_ctx);
	gk20a_gr_init_dtor(priv->fuc_sw_nonctx);

	gf100_gr_dtor(object);
}

static int
gk20a_gr_wait_mem_scrubbing(struct gf100_gr_priv *priv)
{
	if (!nv_wait(priv, 0x40910c, 0x6, 0x0)) {
		nv_error(priv, "FECS mem scrubbing timeout\n");
		return -ETIMEDOUT;
	}

	if (!nv_wait(priv, 0x41a10c, 0x6, 0x0)) {
		nv_error(priv, "GPCCS mem scrubbing timeout\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static void
gk20a_gr_set_hww_esr_report_mask(struct gf100_gr_priv *priv)
{
	nv_wr32(priv, 0x419e44, 0x1ffffe);
	nv_wr32(priv, 0x419e4c, 0x7f);
}

int
gk20a_gr_init(struct nvkm_object *object)
{
	struct gk20a_gr_oclass *oclass = (void *)object->oclass;
	struct gf100_gr_priv *priv = (void *)object;
	const u32 magicgpc918 = DIV_ROUND_UP(0x00800000, priv->tpc_total);
	u32 data[TPC_MAX / 8] = {};
	u8  tpcnr[GPC_MAX];
	int gpc, tpc;
	int ret, i;

	ret = nvkm_gr_init(&priv->base);
	if (ret)
		return ret;

	/* Clear SCC RAM */
	nv_wr32(priv, 0x40802c, 0x1);

	gf100_gr_mmio(priv, priv->fuc_sw_nonctx);

	ret = gk20a_gr_wait_mem_scrubbing(priv);
	if (ret)
		return ret;

	ret = gf100_gr_wait_idle(priv);
	if (ret)
		return ret;

	/* MMU debug buffer */
	nv_wr32(priv, 0x100cc8, priv->unk4188b4->addr >> 8);
	nv_wr32(priv, 0x100ccc, priv->unk4188b8->addr >> 8);

	if (oclass->init_gpc_mmu)
		oclass->init_gpc_mmu(priv);

	/* Set the PE as stream master */
	nv_mask(priv, 0x503018, 0x1, 0x1);

	/* Zcull init */
	memset(data, 0x00, sizeof(data));
	memcpy(tpcnr, priv->tpc_nr, sizeof(priv->tpc_nr));
	for (i = 0, gpc = -1; i < priv->tpc_total; i++) {
		do {
			gpc = (gpc + 1) % priv->gpc_nr;
		} while (!tpcnr[gpc]);
		tpc = priv->tpc_nr[gpc] - tpcnr[gpc]--;

		data[i / 8] |= tpc << ((i % 8) * 4);
	}

	nv_wr32(priv, GPC_BCAST(0x0980), data[0]);
	nv_wr32(priv, GPC_BCAST(0x0984), data[1]);
	nv_wr32(priv, GPC_BCAST(0x0988), data[2]);
	nv_wr32(priv, GPC_BCAST(0x098c), data[3]);

	for (gpc = 0; gpc < priv->gpc_nr; gpc++) {
		nv_wr32(priv, GPC_UNIT(gpc, 0x0914),
			priv->magic_not_rop_nr << 8 | priv->tpc_nr[gpc]);
		nv_wr32(priv, GPC_UNIT(gpc, 0x0910), 0x00040000 |
			priv->tpc_total);
		nv_wr32(priv, GPC_UNIT(gpc, 0x0918), magicgpc918);
	}

	nv_wr32(priv, GPC_BCAST(0x3fd4), magicgpc918);

	/* Enable FIFO access */
	nv_wr32(priv, 0x400500, 0x00010001);

	/* Enable interrupts */
	nv_wr32(priv, 0x400100, 0xffffffff);
	nv_wr32(priv, 0x40013c, 0xffffffff);

	/* Enable FECS error interrupts */
	nv_wr32(priv, 0x409c24, 0x000f0000);

	/* Enable hardware warning exceptions */
	nv_wr32(priv, 0x404000, 0xc0000000);
	nv_wr32(priv, 0x404600, 0xc0000000);

	if (oclass->set_hww_esr_report_mask)
		oclass->set_hww_esr_report_mask(priv);

	/* Enable TPC exceptions per GPC */
	nv_wr32(priv, 0x419d0c, 0x2);
	nv_wr32(priv, 0x41ac94, (((1 << priv->tpc_total) - 1) & 0xff) << 16);

	/* Reset and enable all exceptions */
	nv_wr32(priv, 0x400108, 0xffffffff);
	nv_wr32(priv, 0x400138, 0xffffffff);
	nv_wr32(priv, 0x400118, 0xffffffff);
	nv_wr32(priv, 0x400130, 0xffffffff);
	nv_wr32(priv, 0x40011c, 0xffffffff);
	nv_wr32(priv, 0x400134, 0xffffffff);

	gf100_gr_zbc_init(priv);

	/* Missing LTC CBC init? */

	return gf100_gr_init_ctxctl(priv);
}

struct nvkm_oclass *
gk20a_gr_oclass = &(struct gk20a_gr_oclass) {
	.gf100 = {
		.base.handle = NV_ENGINE(GR, 0xea),
		.base.ofuncs = &(struct nvkm_ofuncs) {
			.ctor = gk20a_gr_ctor,
			.dtor = gk20a_gr_dtor,
			.init = gk20a_gr_init,
			.fini = _nvkm_gr_fini,
		},
		.cclass = &gk20a_grctx_oclass,
		.sclass = gk20a_gr_sclass,
		.ppc_nr = 1,
	},
	.set_hww_esr_report_mask = gk20a_gr_set_hww_esr_report_mask,
}.gf100.base;
