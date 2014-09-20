/*
 * Copyright 2014 Red Hat Inc.
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
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Ben Skeggs <bskeggs@redhat.com>
 */

#include <subdev/bios.h>
#include <subdev/bios/image.h>
#include <subdev/bios/pcir.h>

static bool
nvbios_imagen(struct nouveau_bios *bios, struct nvbios_image *image)
{
	struct nvbios_pcirT pcir;
	u8  ver;
	u16 hdr;
	u32 data;

	switch ((data = nv_ro16(bios, image->base + 0x00))) {
	case 0xaa55:
		break;
	default:
		nv_debug(bios, "%08x: ROM signature (%04x) unknown\n",
			 image->base, data);
		return false;
	}

	if (!(data = nvbios_pcirTp(bios, image->base, &ver, &hdr, &pcir)))
		return false;
	image->size = pcir.image_size;
	image->type = pcir.image_type;
	image->last = pcir.last;
	return true;
}

bool
nvbios_image(struct nouveau_bios *bios, int idx, struct nvbios_image *image)
{
	memset(image, 0x00, sizeof(*image));
	do {
		image->base += image->size;
		if (image->last || !nvbios_imagen(bios, image))
			return false;
	} while(idx--);
	return true;
}