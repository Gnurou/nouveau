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
#include "changk104.h"

#include <nvif/class.h>

static void
gm20b_fifo_gpfifo_fini(struct nvkm_fifo_chan *base)
{
	struct gk104_fifo_chan *chan = gk104_fifo_chan(base);
	struct gk104_fifo *fifo = chan->fifo;
	struct nvkm_device *device = fifo->base.engine.subdev.device;
	u32 coff = chan->base.chid * 8;

	if (!list_empty(&chan->head)) {
		list_del_init(&chan->head);
		nvkm_mask(device, 0x800004 + coff, 0x00000800, 0x00000800);
		gk104_fifo_runlist_commit(fifo, chan->engine);
	}

	gk104_fifo_gpfifo_kick(chan);
	nvkm_wr32(device, 0x800000 + coff, 0x00000000);
}

static const struct nvkm_fifo_chan_func
gm20b_fifo_gpfifo_func = {
	.dtor = gk104_fifo_gpfifo_dtor,
	.init = gk104_fifo_gpfifo_init,
	.fini = gm20b_fifo_gpfifo_fini,
	.ntfy = g84_fifo_chan_ntfy,
	.engine_ctor = gk104_fifo_gpfifo_engine_ctor,
	.engine_dtor = gk104_fifo_gpfifo_engine_dtor,
	.engine_init = gk104_fifo_gpfifo_engine_init,
	.engine_fini = gk104_fifo_gpfifo_engine_fini,
};

int
gm20b_fifo_gpfifo_new(struct nvkm_fifo *base, const struct nvkm_oclass *oclass,
		      void *data, u32 size, struct nvkm_object **pobject)
{
	return __gk104_fifo_gpfifo_new(base, oclass, &gm20b_fifo_gpfifo_func,
				       data, size, pobject);
}

const struct nvkm_fifo_chan_oclass
gm20b_fifo_gpfifo_oclass = {
	.base.oclass = MAXWELL_CHANNEL_GPFIFO_A,
	.base.minver = 0,
	.base.maxver = 0,
	.ctor = gm20b_fifo_gpfifo_new,
};
