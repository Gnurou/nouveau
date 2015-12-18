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

/*
 * Secure boot is the process by which NVIDIA-signed firmware is loaded into
 * some of the falcons of a GPU. For production devices this is the only way
 * for the firmware to access useful (but sensitive) registers.
 *
 * A Falcon microprocessor supporting advanced security modes can run in one of
 * three modes:
 *
 * - Non-secure (NS). In this mode, functionality is similar to Falcon
 *   architectures before security modes were introduced (pre-Maxwell), but
 *   capability is restricted. In particular, certain registers may be
 *   inaccessible for reads and/or writes, and physical memory access may be
 *   disabled (on certain Falcon instances). This is the only possible mode that
 *   can be used if you don't have microcode cryptographically signed by NVIDIA.
 *
 * - Heavy Secure (HS). In this mode, the microprocessor is a black box - it's
 *   not possible to read or write any Falcon internal state or Falcon registers
 *   from outside the Falcon (for example, from the host system). The only way
 *   to enable this mode is by loading microcode that has been signed by NVIDIA.
 *   (The loading process involves tagging the IMEM block as secure, writing the
 *   signature into a Falcon register, and starting execution. The hardware will
 *   validate the signature, and if valid, grant HS privileges.)
 *
 * - Light Secure (LS). In this mode, the microprocessor has more privileges
 *   than NS but fewer than HS. Some of the microprocessor state is visible to
 *   host software to ease debugging. The only way to enable this mode is by HS
 *   microcode enabling LS mode. Some privileges available to HS mode are not
 *   available here. LS mode is introduced in GM20x.
 *
 * Secure boot consists in temporarily switchin a HS-capable falcon (typically
 * PMU) into HS mode in order to validate the LS firmware of managed falcons,
 * load it, and switch managed falcons into LS mode. Once secure boot completes,
 * no falcon remains in HS mode.
 *
 * Secure boot requires a write-protected memory region (WPR) which can only be
 * written by the secure falcon. On dGPU, the driver sets up the WPR region in
 * video memory. On Tegra, it is set up by the bootloader and its location and
 * size written into memory controller registers.
 *
 * The secure boot process takes place as follows:
 *
 * 1) A LS blob is constructed that contains all the LS firmwares we want to
 *    load, along with their signatures and bootloaders.
 *
 * 2) A HS blob (also called ACR) is created that contains the signed HS
 *    firmware in charge of loading the LS firmwares into their respective
 *    falcons.
 *
 * 3) The HS blob is loaded (via its own bootloader) and executed on the
 *    HS-capable falcon. It authenticates itself, switches the secure falcon to
 *    HS mode and copies the LS blob into the WPR region.
 *
 * 4) The LS blob now being secure from all external tampering. The HS falcon
 *    checks the signatures of the LS firmwares and, if valid, switches the
 *    managed falcons to LS mode and makes them ready to run the LS firmware.
 *
 * 5) The managed falcons remain in LS mode and can be started.
 *
 */

#include <core/secure_boot.h>
#include <core/gpuobj.h>
#include <subdev/mmu.h>
#include <subdev/timer.h>
#include <subdev/fb.h>

#include <linux/mutex.h>

enum {
	FALCON_DMAIDX_UCODE		= 0,
	FALCON_DMAIDX_VIRT		= 1,
	FALCON_DMAIDX_PHYS_VID		= 2,
	FALCON_DMAIDX_PHYS_SYS_COH	= 3,
	FALCON_DMAIDX_PHYS_SYS_NCOH	= 4,
};

/*
 *
 * LS blob structures
 *
 */

/**
 * struct lsf_ucode_desc - LS falcon signatures
 * @prd_keys:		signature to use when the GPU is in production mode
 * @dgb_keys:		signature to use when the GPU is in debug mode
 * @b_prd_present:	whether the production key is present
 * @b_dgb_present:	whether the debug key is present
 * @falcon_id:		ID of the falcon the ucode applies to
 *
 * Directly loaded from a signature file.
 */
struct lsf_ucode_desc {
	u8  prd_keys[2][16];
	u8  dbg_keys[2][16];
	u32 b_prd_present;
	u32 b_dbg_present;
	u32 falcon_id;
};

/**
 * struct lsf_lsb_header - LS firmware header
 * @signature:		signature to verify the firmware against
 * @ucode_off:		offset of the ucode blob in the WPR region. The ucode
 *                      blob contains the bootloader, code and data of the
 *                      LS falcon
 * @ucode_size:		size of the ucode blob, including bootloader
 * @data_size:		size of the ucode blob data
 * @bl_code_size:	size of the bootloader code
 * @bl_imem_off:	offset in imem of the bootloader
 * @bl_data_off:	offset of the bootloader data in WPR region
 * @bl_data_size:	size of the bootloader data
 * @app_code_off:	offset of the app code relative to ucode_off
 * @app_code_size:	size of the app code
 * @app_data_off:	offset of the app data relative to ucode_off
 * @app_data_size:	size of the app data
 * @flags:		flags for the secure bootloader
 *
 * This structure is written into the WPR region for each managed falcon. Each
 * instance is referenced by the lsb_offset member of the corresponding
 * lsf_wpr_header.
 */
struct lsf_lsb_header {
	struct lsf_ucode_desc signature;
	u32 ucode_off;
	u32 ucode_size;
	u32 data_size;
	u32 bl_code_size;
	u32 bl_imem_off;
	u32 bl_data_off;
	u32 bl_data_size;
	u32 app_code_off;
	u32 app_code_size;
	u32 app_data_off;
	u32 app_data_size;
	u32 flags;
#define NV_FLCN_ACR_LSF_FLAG_LOAD_CODE_AT_0_FALSE       0
#define NV_FLCN_ACR_LSF_FLAG_LOAD_CODE_AT_0_TRUE        1
#define NV_FLCN_ACR_LSF_FLAG_DMACTL_REQ_CTX_FALSE       0
#define NV_FLCN_ACR_LSF_FLAG_DMACTL_REQ_CTX_TRUE        4
#define NV_FLCN_ACR_LSF_FLAG_FORCE_PRIV_LOAD            8
};

/**
 * struct lsf_wpr_header - LS blob WPR Header
 * @falcon_id:		LS falcon ID
 * @lsb_offset:		offset of the lsb_lsf_header in the WPR region
 * @bootstrap_owner:	secure falcon reponsible for bootstrapping the LS falcon
 * @lazy_bootstrap:	skip bootstrapping by ACR
 * @status:		bootstrapping status
 *
 * An array of these is written at the beginning of the WPR region, one for
 * each managed falcon. The array is terminated by an instance which falcon_id
 * is LSF_FALCON_ID_INVALID.
 */
struct lsf_wpr_header {
	u32  falcon_id;
	u32  lsb_offset;
	u32  bootstrap_owner;
#define LSF_BOOTSTRAP_OWNER_DEFAULT	LSF_FALCON_ID_PMU
	u32  lazy_bootstrap;
	u32  status;
#define LSF_IMAGE_STATUS_NONE				0
#define LSF_IMAGE_STATUS_COPY				1
#define LSF_IMAGE_STATUS_VALIDATION_CODE_FAILED		2
#define LSF_IMAGE_STATUS_VALIDATION_DATA_FAILED		3
#define LSF_IMAGE_STATUS_VALIDATION_DONE		4
#define LSF_IMAGE_STATUS_VALIDATION_SKIPPED		5
#define LSF_IMAGE_STATUS_BOOTSTRAP_READY		6
};

struct flcn_u64 {
	u32 lo;
	u32 hi;
};

/**
 * struct flcn_bl_dmem_desc - DMEM bootloader descriptor
 * @signature:		16B signature for secure code. 0s if no secure code
 * @ctx_dma:		DMA context to be used by BL while loading code/data
 * @code_dma_base:	256B-aligned Physical FB Address where code is located
 *			(falcon's $xcbase register)
 * @non_sec_code_off:	offset from code_dma_base where the non-secure code is
 *                      located. The offset must be multiple of 256 to help perf
 * @non_sec_code_size:	the size of the nonSecure code part.
 * @sec_code_off:	offset from code_dma_base where the secure code is
 *                      located. The offset must be multiple of 256 to help perf
 * @sec_code_size:	offset from code_dma_base where the secure code is
 *                      located. The offset must be multiple of 256 to help perf
 * @code_entry_point:	code entry point which will be invoked by BL after
 *                      code is loaded.
 * @data_dma_base:	256B aligned Physical FB Address where data is located.
 *			(falcon's $xdbase register)
 * @data_size:		size of data block. Should be multiple of 256B
 *
 * Structure used by the bootloader to load the rest of the code. This has
 * to be filled by host and copied into DMEM at offset provided in the
 * hsflcn_bl_desc.bl_desc_dmem_load_off.
 */
struct flcn_bl_dmem_desc {
	u32 reserved[4];
	u32 signature[4];
	u32 ctx_dma;
	struct flcn_u64 code_dma_base;
	u32 non_sec_code_off;
	u32 non_sec_code_size;
	u32 sec_code_off;
	u32 sec_code_size;
	u32 code_entry_point;
	struct flcn_u64 data_dma_base;
	u32 data_size;
};

/**
 * struct ls_ucode_desc - descriptor of firmware image
 * @descriptor_size:		size of this descriptor
 * @image_size:			size of the whole image
 * @bootloader_start_offset:	start offset of the bootloader in ucode image
 * @bootloader_size:		size of the bootloader
 * @bootloader_imem_offset:	start off set of the bootloader in IMEM
 * @bootloader_entry_point:	entry point of the bootloader in IMEM
 * @app_start_offset:		start offset of the LS firmware
 * @app_size:			size of the LS firmware's code and data
 * @app_imem_offset:		offset of the app in IMEM
 * @app_imem_entry:		entry point of the app in IMEM
 * @app_dmem_offset:		offset of the data in DMEM
 * @app_resident_code_offset:	offset of app code from app_start_offset
 * @app_resident_code_size:	size of the code
 * @app_resident_data_offset:	offset of data from app_start_offset
 * @app_resident_data_size:	size of data
 *
 * A firmware image contains the code, data, and bootloader of a given LS
 * falcon in a single blob. This structure describes where everything is.
 *
 * This can be generated from a (bootloader, code, data) set if they have
 * been loaded separately, or come directly from a file. For the later case,
 * we need to keep the fields that are unused by the code.
 */
struct ls_ucode_desc {
	u32 descriptor_size;
	u32 image_size;
	u32 tools_version;
	u32 app_version;
	char date[64];
	u32 bootloader_start_offset;
	u32 bootloader_size;
	u32 bootloader_imem_offset;
	u32 bootloader_entry_point;
	u32 app_start_offset;
	u32 app_size;
	u32 app_imem_offset;
	u32 app_imem_entry;
	u32 app_dmem_offset;
	u32 app_resident_code_offset;
	u32 app_resident_code_size;
	u32 app_resident_data_offset;
	u32 app_resident_data_size;
	u32 nb_overlays;
	struct {u32 start; u32 size; } load_ovl[32];
	u32 compressed;
};

/**
 * struct lsf_ucode_img - temporary storage for loaded LS firmwares
 * @node:		to link within lsf_ucode_mgr
 * @falcon_id:		ID of the falcon this LS firmware is for
 * @ucode_desc:		loaded or generated map of ucode_data
 * @ucode_header:	header of the firmware
 * @ucode_data:		firmware payload (code and data)
 * @ucode_size:		size in bytes of data in ucode_data
 * @wpr_header:		WPR header to be written to the LS blob
 * @lsb_header:		LSB header to be written to the LS blob
 * @bl_dmem_desc:	DMEM bootloader descriptor to be written to the LS blob
 *
 * Preparing the WPR LS blob requires information about all the LS firmwares
 * (size, etc) to be known. This structure contains all the data of one LS
 * firmware.
 */
struct lsf_ucode_img {
	struct list_head node;
	u32 falcon_id;

	struct ls_ucode_desc ucode_desc;
	u32 *ucode_header;
	u8 *ucode_data;
	u32 ucode_size;

	/* All members below to be copied into the WPR blob */
	struct lsf_wpr_header wpr_header;
	struct lsf_lsb_header lsb_header;
	struct flcn_bl_dmem_desc bl_dmem_desc;
};

/**
 * struct lsf_ucode_mgr - manager for all LS falcon firmwares
 * @count:	number of managed LS falcons
 * @wpr_size:	size of the required WPR region in bytes
 * @img_list:	linked list of lsf_ucode_img
 */
struct lsf_ucode_mgr {
	u16 count;
	u32 wpr_size;
	struct list_head img_list;
};

/*
 *
 * HS blob structures
 *
 */

/**
 * struct hs_bin_hdr - header of HS firmware and bootloader files
 * @bin_magic:		always 0x10de
 * @bin_ver:		version of the bin format
 * @bin_size:		entire image size including this header
 * @header_offset:	offset of the firmware/bootloader header in the file
 * @data_offset:	offset of the firmware/bootloader payload in the file
 * @data_size:		size of the payload
 *
 * This header is located at the beginning of the HS firmware and HS bootloader
 * files, to describe where the headers and data can be found.
 */
struct hs_bin_hdr {
	u32 bin_magic;
	u32 bin_ver;
	u32 bin_size;
	u32 header_offset;
	u32 data_offset;
	u32 data_size;
};

/**
 * struct hsflcn_bl_desc - HS firmware bootloader descriptor
 * @bl_start_tag:		starting tag of bootloader
 * @bl_desc_dmem_load_off:	DMEM offset of flcn_bl_dmem_desc
 * @bl_code_off:		offset of code section
 * @bl_code_size:		size of code section
 * @bl_data_off:		offset of data section
 * @bl_data_size:		size of data section
 *
 * This structure is embedded in the HS bootloader firmware file at
 * hs_bin_hdr.header_offset to describe the IMEM and DMEM layout expected by the
 * HS bootloader.
 */
struct hsflcn_bl_desc {
	u32 bl_start_tag;
	u32 bl_desc_dmem_load_off;
	u32 bl_code_off;
	u32 bl_code_size;
	u32 bl_data_off;
	u32 bl_data_size;
};

/**
 * struct acr_fw_header - HS firmware descriptor
 * @sig_dbg_offset:	offset of the debug signature
 * @sig_dbg_size:	size of the debug signature
 * @sig_prod_offset:	offset of the production signature
 * @sig_prod_size:	size of the production signature
 * @patch_loc:		offset of the offset (sic) of where the signature is
 * @patch_sig:		offset of the offset (sic) to add to sig_*_offset
 * @hdr_offset:		offset of the load header (see struct hs_load_header)
 * @hdr_size:		size of above header
 *
 * This structure is embedded in the HS firmware image at
 * hs_bin_hdr.header_offset.
 */
struct acr_fw_header {
	u32 sig_dbg_offset;
	u32 sig_dbg_size;
	u32 sig_prod_offset;
	u32 sig_prod_size;
	u32 patch_loc;
	u32 patch_sig;
	u32 hdr_offset;
	u32 hdr_size;
};

/**
 * struct acr_load_header - HS firmware loading header
 *
 * Data to be copied as-is into the struct flcn_bl_dmem_desc for the HS firmware
 */
struct acr_load_header {
	u32 non_sec_code_off;
	u32 non_sec_code_size;
	u32 data_dma_base;
	u32 data_size;
	u32 reserved;
	u32 sec_code_off;
	u32 sec_code_size;
};

/**
 * Contains the whole secure boot state, allowing it to be performed as needed
 * @falcon_id:		falcon that will perform secure boot
 * @wpr_addr:		physical address of the WPR region
 * @wpr_size:		size in bytes of the WPR region
 * @ls_blob:		LS blob of all the LS firmwares, signatures, bootloaders
 * @ls_blob_size:	size of the LS blob
 * @ls_blob_nb_regions:	number of LS firmwares that will be loaded
 * @acr_blob:		HS blob
 * @acr_blob_vma:	mapping of the HS blob into the secure falcon's VM
 * @acr_bl_desc:	bootloader descriptor of the HS blob
 * @hsbl_blob:		HS blob bootloader
 * @inst:		instance block for HS falcon
 * @pgd:		page directory for the HS falcon
 * @vm:			address space used by the HS falcon
 */
struct secure_boot {
	u32 falcon_id;
	u64 wpr_addr;
	u32 wpr_size;
	u32 base;

	/* LS FWs, to be loaded by the HS ACR */
	struct nvkm_gpuobj *ls_blob;
	u32 ls_blob_size;
	u16 ls_blob_nb_regions;

	/* HS FW */
	struct nvkm_gpuobj *acr_blob;
	struct nvkm_vma acr_blob_vma;
	struct flcn_bl_dmem_desc acr_bl_desc;

	/* HS bootloader */
	void *hsbl_blob;

	/* Instance block & address space */
	struct nvkm_gpuobj *inst;
	struct nvkm_gpuobj *pgd;
	struct nvkm_vm *vm;

};

/* TODO move to global place? */
static void
nvkm_gpuobj_memcpy(struct nvkm_gpuobj *dest, u32 dstoffset, void *src,
		   u32 length)
{
	int i;

	for (i = 0; i < length; i += 4)
		nvkm_wo32(dest, dstoffset + i, *(u32 *)(src + i));
}

/* TODO share with the GR FW loading routine? */
static int
sb_get_firmware(struct nvkm_device *device, const char *fwname,
		const struct firmware **fw)
{
	char f[64];
	char cname[16];
	int i;

	/* Convert device name to lowercase */
	strncpy(cname, device->chip->name, sizeof(cname));
	cname[sizeof(cname) - 1] = '\0';
	i = strlen(cname);
	while (i) {
		--i;
		cname[i] = tolower(cname[i]);
	}

	snprintf(f, sizeof(f), "nvidia/%s/%s.bin", cname, fwname);
	return request_firmware(fw, f, device->dev);
}

/**
 * Convenience function to duplicate a firmware file in memory and check that
 * it has the required minimum size.
 */
static void *
sb_load_firmware(struct nvkm_device *device, const char *name,
		    size_t min_size)
{
	const struct firmware *fw;
	void *ret;
	int err;

	err = sb_get_firmware(device, name, &fw);
	if (err)
		return ERR_PTR(err);
	if (fw->size < min_size) {
		release_firmware(fw);
		return ERR_PTR(-EINVAL);
	}
	ret = kmemdup(fw->data, fw->size, GFP_KERNEL);
	release_firmware(fw);
	if (!ret)
		return ERR_PTR(-ENOMEM);

	return ret;
}

/*
 * Low-secure blob creation
 */

#define BL_DESC_BLK_SIZE 256
/**
 * Build a ucode image and descriptor from provided bootloader, code and data.
 *
 * @bl:		bootloader image, including 16-bytes descriptor
 * @code:	LS firmware code segment
 * @data:	LS firmware data segment
 * @desc:	ucode descriptor to be written
 *
 * Return: allocated ucode image with corresponding descriptor information. desc
 *         is also updated to contain the right offsets within returned image.
 */
static void *
lsf_ucode_img_build(const struct firmware *bl, const struct firmware *code,
		      const struct firmware *data, struct ls_ucode_desc *desc)
{
	struct {
		u32 start_offset;
		u32 size;
		u32 imem_offset;
		u32 entry_point;
	} *bl_desc;
	u32 *bl_image;
	u32 pos = 0;
	u8 *image;

	bl_desc = (void *)bl->data;
	bl_image = (void *)(bl_desc + 1);

	desc->bootloader_start_offset = pos;
	desc->bootloader_size = ALIGN(bl_desc->size, sizeof(u32));
	desc->bootloader_imem_offset = bl_desc->imem_offset;
	desc->bootloader_entry_point = bl_desc->entry_point;

	pos = ALIGN(pos + desc->bootloader_size, BL_DESC_BLK_SIZE);
	desc->app_start_offset = pos;
	desc->app_size = ALIGN(code->size, BL_DESC_BLK_SIZE) +
			 ALIGN(data->size, BL_DESC_BLK_SIZE);
	desc->app_imem_offset = 0;
	desc->app_imem_entry = 0;
	desc->app_dmem_offset = 0;
	desc->app_resident_code_offset = 0;
	desc->app_resident_code_size = ALIGN(code->size, BL_DESC_BLK_SIZE);

	pos = ALIGN(pos + desc->app_resident_code_size, BL_DESC_BLK_SIZE);
	desc->app_resident_data_offset = pos - desc->app_start_offset;
	desc->app_resident_data_size = ALIGN(data->size, BL_DESC_BLK_SIZE);

	desc->image_size = ALIGN(bl_desc->size, BL_DESC_BLK_SIZE) +
			   desc->app_size;

	image = kzalloc(desc->image_size, GFP_KERNEL);
	if (!image)
		return ERR_PTR(-ENOMEM);

	memcpy(image + desc->bootloader_start_offset, bl_image, bl_desc->size);
	memcpy(image + desc->app_start_offset, code->data, code->size);
	memcpy(image + desc->app_start_offset + desc->app_resident_data_offset,
	       data->data, data->size);

	return image;
}

/**
 * lsf_ucode_img_load_generic() - load and prepare a LS ucode image
 *
 * Load the LS microcode, bootloader and signature and pack them into a single
 * blob. Also generate the corresponding ucode descriptor.
 */
static int
lsf_ucode_img_load_generic(struct nvkm_device *device,
			   struct lsf_ucode_img *img, const char *falcon_name,
			   const u32 falcon_id)
{
	const struct firmware *bl, *code, *data;
	struct lsf_ucode_desc *lsf_desc;
	char f[64];
	int err;

	img->ucode_header = NULL;

	snprintf(f, sizeof(f), "%s_bl", falcon_name);
	err = sb_get_firmware(device, f, &bl);
	if (err)
		goto error;

	snprintf(f, sizeof(f), "%s_inst", falcon_name);
	err = sb_get_firmware(device, f, &code);
	if (err)
		goto free_bl;

	snprintf(f, sizeof(f), "%s_data", falcon_name);
	err = sb_get_firmware(device, f, &data);
	if (err)
		goto free_inst;

	img->ucode_data = lsf_ucode_img_build(bl, code, data,
					      &img->ucode_desc);
	if (IS_ERR(img->ucode_data)) {
		err = PTR_ERR(img->ucode_data);
		goto free_data;
	}
	img->ucode_size = img->ucode_desc.image_size;

	snprintf(f, sizeof(f), "%s_sig", falcon_name);
	lsf_desc = sb_load_firmware(device, f, sizeof(*lsf_desc));
	if (IS_ERR(lsf_desc)) {
		err = PTR_ERR(lsf_desc);
		goto free_image;
	}
	/* not needed? the signature should already have the right value */
	lsf_desc->falcon_id = falcon_id;
	memcpy(&img->lsb_header.signature, lsf_desc, sizeof(*lsf_desc));
	img->falcon_id = lsf_desc->falcon_id;
	kfree(lsf_desc);

	/* success path - only free requested firmware files */
	goto free_data;

free_image:
	kfree(img->ucode_data);
free_data:
	release_firmware(data);
free_inst:
	release_firmware(code);
free_bl:
	release_firmware(bl);
error:
	return err;
}

static int
lsf_ucode_img_load_fecs(struct nvkm_device *device, struct lsf_ucode_img *img)
{
	return lsf_ucode_img_load_generic(device, img, "fecs",
					  LSF_FALCON_ID_FECS);
}

static int
lsf_ucode_img_load_gpccs(struct nvkm_device *device, struct lsf_ucode_img *img)
{
	return lsf_ucode_img_load_generic(device, img, "gpccs",
					  LSF_FALCON_ID_GPCCS);
}

/**
 * lsf_ucode_img_populate_bl_desc() - populate a DMEM BL descriptor for LS image
 * @img:	ucode image to generate against
 * @desc:	descriptor to populate
 * @sb:		secure boot state to use for base addresses
 *
 * Populate the DMEM BL descriptor with the information contained in a
 * ls_ucode_desc.
 *
 */
static void
lsf_ucode_img_populate_bl_desc(struct lsf_ucode_img *img,
			       struct secure_boot *sb,
			       struct flcn_bl_dmem_desc *desc)
{
	struct ls_ucode_desc *pdesc = &img->ucode_desc;
	u64 addr_base;

	addr_base = sb->wpr_addr + img->lsb_header.ucode_off +
		pdesc->app_start_offset;

	memset(desc, 0, sizeof(*desc));
	desc->ctx_dma = FALCON_DMAIDX_UCODE;
	desc->code_dma_base.lo = lower_32_bits(
		(addr_base + pdesc->app_resident_code_offset));
	desc->code_dma_base.hi = upper_32_bits(
		(addr_base + pdesc->app_resident_code_offset));
	desc->non_sec_code_size = pdesc->app_resident_code_size;
	desc->data_dma_base.lo = lower_32_bits(
		(addr_base + pdesc->app_resident_data_offset));
	desc->data_dma_base.hi = upper_32_bits(
		(addr_base + pdesc->app_resident_data_offset));
	desc->data_size = pdesc->app_resident_data_size;
	desc->code_entry_point = pdesc->app_imem_entry;
}

typedef int (*lsf_load_func)(struct nvkm_device *, struct lsf_ucode_img *);

/**
 * lsf_ucode_img_load() - create a lsf_ucode_img and load it
 */
static struct lsf_ucode_img *
lsf_ucode_img_load(struct nvkm_device *device, lsf_load_func load_func)
{
	struct lsf_ucode_img *img;
	int err;

	img = kzalloc(sizeof(*img), GFP_KERNEL);
	if (!img)
		return ERR_PTR(-ENOMEM);

	err = load_func(device, img);
	if (err) {
		kfree(img);
		return ERR_PTR(err);
	}

	return img;
}

static const lsf_load_func lsf_load_funcs[] = {
	[LSF_FALCON_ID_END] = NULL, /* reserve enough space */
	[LSF_FALCON_ID_FECS] = lsf_ucode_img_load_fecs,
	[LSF_FALCON_ID_GPCCS] = lsf_ucode_img_load_gpccs,
};


#define LSF_LSB_HEADER_ALIGN 256
#define LSF_BL_DATA_ALIGN 256
#define LSF_BL_DATA_SIZE_ALIGN 256
#define LSF_BL_CODE_SIZE_ALIGN 256
#define LSF_UCODE_DATA_ALIGN 4096

/**
 * lsf_ucode_img_fill_headers - fill the WPR and LSB headers of an image
 * @img:	image to generate for
 * @offset:	offset in the WPR region where this image starts
 *
 * Allocate space in the WPR area from offset and write the WPR and LSB headers
 * accordingly.
 *
 * Return: offset at the end of this image.
 */
static u32
lsf_ucode_img_fill_headers(struct lsf_ucode_img *img, u32 offset, u32 falcon_id)
{
	struct lsf_wpr_header *whdr = &img->wpr_header;
	struct lsf_lsb_header *lhdr = &img->lsb_header;
	struct ls_ucode_desc *desc = &img->ucode_desc;

	/* Fill WPR header */
	whdr->falcon_id = img->falcon_id;
	whdr->bootstrap_owner = LSF_BOOTSTRAP_OWNER_DEFAULT;
	whdr->status = LSF_IMAGE_STATUS_COPY;

	/* Align, save off, and include an LSB header size */
	offset = ALIGN(offset, LSF_LSB_HEADER_ALIGN);
	whdr->lsb_offset = offset;
	offset += sizeof(struct lsf_lsb_header);

	/*
	 * Align, save off, and include the original (static) ucode
	 * image size
	 */
	offset = ALIGN(offset, LSF_UCODE_DATA_ALIGN);
	lhdr->ucode_off = offset;
	offset += img->ucode_size;

	/*
	 * For falcons that use a boot loader (BL), we append a loader
	 * desc structure on the end of the ucode image and consider
	 * this the boot loader data. The host will then copy the loader
	 * desc args to this space within the WPR region (before locking
	 * down) and the HS bin will then copy them to DMEM 0 for the
	 * loader.
	 */
	if (!img->ucode_header) {
		/* Use a loader */
		lhdr->bl_code_size = ALIGN(desc->bootloader_size,
					   LSF_BL_CODE_SIZE_ALIGN);
		lhdr->ucode_size = ALIGN(desc->app_resident_data_offset,
					 LSF_BL_CODE_SIZE_ALIGN) +
					lhdr->bl_code_size;
		lhdr->data_size = ALIGN(desc->app_size,
					LSF_BL_CODE_SIZE_ALIGN) +
					lhdr->bl_code_size -
					lhdr->ucode_size;
		/*
		 * Though the BL is located at 0th offset of the image, the VA
		 * is different to make sure that it doesn't collide the actual
		 * OS VA range
		 */
		lhdr->bl_imem_off = desc->bootloader_imem_offset;
		lhdr->app_code_off = desc->app_start_offset +
			desc->app_resident_code_offset;
		lhdr->app_code_size = desc->app_resident_code_size;
		lhdr->app_data_off = desc->app_start_offset +
					desc->app_resident_data_offset;
		lhdr->app_data_size = desc->app_resident_data_size;

		lhdr->flags = 0;
		if (img->falcon_id == falcon_id)
			lhdr->flags = NV_FLCN_ACR_LSF_FLAG_DMACTL_REQ_CTX_TRUE;

		if (img->falcon_id == LSF_FALCON_ID_GPCCS)
			lhdr->flags |= NV_FLCN_ACR_LSF_FLAG_FORCE_PRIV_LOAD;

		/* Align (size bloat) and save off BL descriptor size */
		lhdr->bl_data_size = ALIGN(sizeof(img->bl_dmem_desc),
					   LSF_BL_DATA_SIZE_ALIGN);
		/*
		 * Align, save off, and include the additional BL data
		 */
		offset = ALIGN(offset, LSF_BL_DATA_ALIGN);
		lhdr->bl_data_off = offset;
		offset += lhdr->bl_data_size;
	} else {
		/* Do not use a loader */
		lhdr->ucode_size = img->ucode_size;
		lhdr->data_size = 0;
		lhdr->bl_code_size = 0;
		lhdr->bl_data_off = 0;
		lhdr->bl_data_size = 0;

		lhdr->flags = NV_FLCN_ACR_LSF_FLAG_LOAD_CODE_AT_0_TRUE |
			NV_FLCN_ACR_LSF_FLAG_DMACTL_REQ_CTX_TRUE;

		/* TODO Complete for dGPU */

		/*
		 * bl_data_off is already assigned in static
		 * information. But that is from start of the image
		 */
		img->lsb_header.bl_data_off += (offset - img->ucode_size);
	}

	return offset;
}

static void
lsf_ucode_mgr_init(struct lsf_ucode_mgr *mgr)
{
	memset(mgr, 0, sizeof(*mgr));
	INIT_LIST_HEAD(&mgr->img_list);
}

static void
lsf_ucode_mgr_cleanup(struct lsf_ucode_mgr *mgr)
{
	struct lsf_ucode_img *img, *t;

	list_for_each_entry_safe(img, t, &mgr->img_list, node) {
		kfree(img->ucode_data);
		kfree(img->ucode_header);
		kfree(img);
	}
}

static void
lsf_ucode_mgr_add_img(struct lsf_ucode_mgr *mgr, struct lsf_ucode_img *img)
{
	mgr->count++;
	list_add_tail(&img->node, &mgr->img_list);
}

/**
 * lsf_mgr_fill_headers - fill the WPR and LSB headers of all managed images
 */
static void
lsf_ucode_mgr_fill_headers(struct secure_boot *sb, struct lsf_ucode_mgr *mgr)
{
	struct lsf_ucode_img *img;
	u32 offset;

	/*
	 * Start with an array of WPR headers at the base of the WPR.
	 * The expectation here is that the secure falcon will do a single DMA
	 * read of this array and cache it internally so it's ok to pack these.
	 * Also, we add 1 to the falcon count to indicate the end of the array.
	 */
	offset = sizeof(struct lsf_wpr_header) * (mgr->count + 1);

	/*
	 * Walk the managed falcons, accounting for the LSB structs
	 * as well as the ucode images.
	 */
	list_for_each_entry(img, &mgr->img_list, node) {
		offset = lsf_ucode_img_fill_headers(img, offset, sb->falcon_id);
	}

	mgr->wpr_size = offset;
}

/**
 * lsf_ucode_mgr_write_wpr - write the WPR blob contents
 */
static void
lsf_ucode_mgr_write_wpr(struct nvkm_device *device, struct lsf_ucode_mgr *mgr,
			struct nvkm_gpuobj *wpr_blob)
{
	struct secure_boot *sb = device->secure_boot_state;
	struct lsf_ucode_img *img;
	u32 pos = 0;

	nvkm_kmap(wpr_blob);

	list_for_each_entry(img, &mgr->img_list, node) {
		nvkm_gpuobj_memcpy(wpr_blob, pos, &img->wpr_header,
				   sizeof(img->wpr_header));

		nvkm_gpuobj_memcpy(wpr_blob, img->wpr_header.lsb_offset,
				   &img->lsb_header, sizeof(img->lsb_header));

		/* Generate and write BL descriptor */
		if (!img->ucode_header) {
			lsf_ucode_img_populate_bl_desc(img, sb,
						       &img->bl_dmem_desc);
			nvkm_gpuobj_memcpy(wpr_blob,
					   img->lsb_header.bl_data_off,
					   &img->bl_dmem_desc,
					   sizeof(img->bl_dmem_desc));
		}

		/* Copy ucode */
		nvkm_gpuobj_memcpy(wpr_blob, img->lsb_header.ucode_off,
				   img->ucode_data, img->ucode_size);

		pos += sizeof(img->wpr_header);
	}

	nvkm_wo32(wpr_blob, pos, LSF_FALCON_ID_INVALID);

	nvkm_done(wpr_blob);
}

/**
 * sb_prepare_ls_blob() - prepare the LS blob to be written in the WPR region
 *
 * For each securely managed falcon, load the FW, signatures and bootloaders and
 * prepare a ucode blob. Then, compute the offsets in the WPR region for each
 * blob, and finally write the headers and ucode blobs into a GPU object that
 * will be copied into the WPR region by the HS firmware.
 */
static int
sb_prepare_ls_blob(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	struct lsf_ucode_mgr mgr;
	int falcon_id;
	int err;

	lsf_ucode_mgr_init(&mgr);

	sb->falcon_id = device->chip->secure_boot.boot_falcon;

	/* Load all LS blobs */
	for_each_set_bit(falcon_id, &device->chip->secure_boot.managed_falcons,
			 LSF_FALCON_ID_END) {
		struct lsf_ucode_img *img;

		img = lsf_ucode_img_load(device, lsf_load_funcs[falcon_id]);

		if (IS_ERR(img)) {
			err = PTR_ERR(img);
			goto cleanup;
		}
		lsf_ucode_mgr_add_img(&mgr, img);
	}

	/*
	 * Fill the WPR and LSF headers with the right offsets and compute
	 * required WPR size
	 */
	lsf_ucode_mgr_fill_headers(sb, &mgr);

	if (device->type == NVKM_DEVICE_TEGRA && mgr.wpr_size > sb->wpr_size) {
		nvdev_error(device, "WPR region too small to host FW blob!\n");
		nvdev_error(device, "required: %d bytes\n", mgr.wpr_size);
		nvdev_error(device, "WPR size: %d bytes\n", sb->wpr_size);
		err = -ENOMEM;
		goto cleanup;
	}

	err = nvkm_gpuobj_new(device, 0x80000, 0x80000, false, NULL,
			      &sb->ls_blob);
	if (err)
		goto cleanup;

	nvdev_debug(device, "%d managed LS falcons, WPR size is %d bytes\n",
		    mgr.count, mgr.wpr_size);

	/* On non-Tegra devices the WPR will be programmed around the LS blob */
	if (device->type != NVKM_DEVICE_TEGRA) {
		sb->wpr_addr = sb->ls_blob->addr;
		sb->wpr_size = sb->ls_blob_size;
	}

	/* write LS blob */
	lsf_ucode_mgr_write_wpr(device, &mgr, sb->ls_blob);

	sb->ls_blob_size = mgr.wpr_size;
	sb->ls_blob_nb_regions = mgr.count;

cleanup:
	lsf_ucode_mgr_cleanup(&mgr);

	return err;
}

static void
sb_cleanup_ls_blob(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;

	nvkm_gpuobj_del(&sb->ls_blob);
}

/*
 * High-secure blob creation
 */

/**
 * hsf_img_patch_signature() - patch the HS blob with the correct signature
 */
static void
hsf_img_patch_signature(struct nvkm_device *device, void *acr_image)
{
	struct secure_boot *sb = device->secure_boot_state;
	struct hs_bin_hdr *hsbin_hdr = acr_image;
	struct acr_fw_header *fw_hdr = acr_image + hsbin_hdr->header_offset;
	void *hs_data = acr_image + hsbin_hdr->data_offset;
	u32 patch_loc;
	u32 patch_sig;
	void *sig;
	u32 sig_size;

	patch_loc = *(u32 *)(acr_image + fw_hdr->patch_loc);
	patch_sig = *(u32 *)(acr_image + fw_hdr->patch_sig);

	/* Falcon in debug or production mode? */
	if ((nvkm_rd32(device, sb->base + 0xc08) >> 20) & 0x1) {
		sig = acr_image + fw_hdr->sig_dbg_offset;
		sig_size = fw_hdr->sig_dbg_size;
	} else {
		sig = acr_image + fw_hdr->sig_prod_offset;
		sig_size = fw_hdr->sig_prod_size;
	}

	/* Patch signature */
	memcpy(hs_data + patch_loc, sig + patch_sig, sig_size);
}

/**
 * struct hsflcn_acr_desc - data section of the HS firmware
 *
 * This header is to be copied at the beginning of DMEM by the HS bootloader.
 *
 * @signature:		signature of ACR ucode
 * @wpr_region_id:	region ID holding the WPR header and its details
 * @wpr_offset:		offset from the WPR region holding the wpr header
 * @regions:		region descriptors
 * @nonwpr_ucode_blob_size:	size of LS blob
 * @nonwpr_ucode_blob_start:	FB location of LS blob is
 */
struct hsflcn_acr_desc {
	union {
		u8 reserved_dmem[0x200];
		u32 signatures[4];
	} ucode_reserved_space;
	u32 wpr_region_id;
	u32 wpr_offset;
	u32 mmu_mem_range;
#define FLCN_ACR_MAX_REGIONS 2
	struct {
		u32 no_regions;
		struct {
			u32 start_addr;
			u32 end_addr;
			u32 region_id;
			u32 read_mask;
			u32 write_mask;
			u32 client_mask;
		} region_props[FLCN_ACR_MAX_REGIONS];
	} regions;
	u32 nonwpr_ucode_blob_size;
	u64 nonwpr_ucode_blob_start __attribute__ ((aligned (8)));
	struct {
		u32 vpr_enabled;
		u32 vpr_start;
		u32 vpr_end;
		u32 hdcp_policies;
	} vpr_desc;
};

/**
 * hsf_img_patch_desc() - patch the HS firmware with location of the LS blob
 */
static void
hsf_img_patch_desc(struct nvkm_device *device, void *acr_image)
{
	struct secure_boot *sb = device->secure_boot_state;
	struct hs_bin_hdr *hsbin_hdr = acr_image;
	struct acr_fw_header *fw_hdr = acr_image + hsbin_hdr->header_offset;
	struct acr_load_header *load_hdr = acr_image + fw_hdr->hdr_offset;
	void *hs_data = acr_image + hsbin_hdr->data_offset;
	struct hsflcn_acr_desc *desc = hs_data + load_hdr->data_dma_base;

	desc->nonwpr_ucode_blob_start = sb->ls_blob->addr;
	desc->nonwpr_ucode_blob_size = sb->ls_blob_size;

	/* Only set WPR regions on non-Tegra devices */
	if (device->type != NVKM_DEVICE_TEGRA) {
		desc->wpr_region_id = 1;
		desc->regions.no_regions = 1;
		desc->regions.region_props[0].region_id = 1;
		desc->regions.region_props[0].start_addr = sb->ls_blob->addr >> 8;
		desc->regions.region_props[0].end_addr = (sb->ls_blob->addr + 0x80000 - 0x1000) >> 8;
	}

	desc->wpr_offset = 0;
}

/**
 * hsf_img_populate_bl_desc() - populate a DMEM BL descriptor for HS image
 */
static void
hsf_img_populate_bl_desc(void *acr_image, struct flcn_bl_dmem_desc *bl_desc)
{
	struct hs_bin_hdr *hsbin_hdr = acr_image;
	struct acr_fw_header *fw_hdr = acr_image + hsbin_hdr->header_offset;
	struct acr_load_header *load_hdr = acr_image + fw_hdr->hdr_offset;

	/*
	 * Descriptor for the bootloader that will load the ACR image into
	 * IMEM/DMEM memory.
	 */
	fw_hdr = acr_image + hsbin_hdr->header_offset;
	load_hdr = acr_image + fw_hdr->hdr_offset;
	memset(bl_desc, 0, sizeof(*bl_desc));
	bl_desc->ctx_dma = FALCON_DMAIDX_VIRT;
	bl_desc->non_sec_code_off = load_hdr->non_sec_code_off;
	bl_desc->non_sec_code_size = load_hdr->non_sec_code_size;
	bl_desc->sec_code_off = load_hdr->sec_code_off;
	bl_desc->sec_code_size = load_hdr->sec_code_size;
	bl_desc->code_entry_point = 0;
	/*
	 * We need to set code_dma_base to the virtual address of the acr_blob,
	 * and add this address to data_dma_base before writing it into DMEM
	 */
	bl_desc->code_dma_base.lo = 0;
	bl_desc->data_dma_base.lo = load_hdr->data_dma_base;
	bl_desc->data_size = load_hdr->data_size;
}

static int
sb_prepare_hs_blob(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	void *acr_image;
	struct hs_bin_hdr *hsbin_hdr;
	u32 img_size;
	int err;

	acr_image = sb_load_firmware(device, "acr_ucode_load", 0);
	if (IS_ERR(acr_image))
		return PTR_ERR(acr_image);

	/* Patch image */
	hsf_img_patch_signature(device, acr_image);
	hsf_img_patch_desc(device, acr_image);

	/* Generate HS BL descriptor */
	hsf_img_populate_bl_desc(acr_image, &sb->acr_bl_desc);

	/* Create ACR blob and copy HS data to it */
	hsbin_hdr = acr_image;
	img_size = ALIGN(hsbin_hdr->data_size, 256);
	err = nvkm_gpuobj_new(device, img_size, 0x1000, false, NULL,
			      &sb->acr_blob);
	if (err)
		goto cleanup;

	nvkm_kmap(sb->acr_blob);
	nvkm_gpuobj_memcpy(sb->acr_blob, 0, acr_image + hsbin_hdr->data_offset,
			   img_size);
	nvkm_done(sb->acr_blob);

cleanup:
	kfree(acr_image);

	return err;
}

static void
sb_cleanup_hs_blob(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;

	nvkm_gpuobj_del(&sb->acr_blob);
}

/*
 * High-secure bootloader blob creation
 */

static int
sb_prepare_hsbl_blob(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;

	if (!sb->hsbl_blob) {
		sb->hsbl_blob = sb_load_firmware(device, "acr_bl", 0);
		if (IS_ERR(sb->hsbl_blob)) {
			int err = PTR_ERR(sb->hsbl_blob);

			sb->hsbl_blob = NULL;
			return err;
		}
	}

	return 0;
}

static void
sb_cleanup_hsbl_blob(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;

	kfree(sb->hsbl_blob);
	sb->hsbl_blob = NULL;
}

/*
 * Falcon/PMU utility functions
 */

static int
falcon_wait_clear_halt_interrupt(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	int err;

	nvkm_mask(device, sb->base + 0x004, 0x10, 0x10);
	err = nvkm_wait_usec(device, 10000, sb->base + 0x008, 0x10, 0x0);
	if (err < 0)
		return err;

	return 0;
}

static int
falcon_wait_for_halt(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	u32 data;
	int err;

	err = nvkm_wait_msec(device, 100, sb->base + 0x100, 0x10, 0x10);
	if (err < 0)
		return err;

	data = nvkm_rd32(device, sb->base + 0x040);
	if (data) {
		nvdev_error(device, "ACR boot failed, err %x", data);
		return -EAGAIN;
	}

	return 0;
}

static int
falcon_wait_idle(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	int err;

	err = nvkm_wait_msec(device, 10, sb->base + 0x04c, 0xffff, 0x0);
	if (err < 0)
		return err;

	return 0;
}

/* TODO these functions are still PMU-specific... */

static void
pmu_enable_irq(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;

	nvkm_wr32(device, sb->base + 0x010, 0xff);
	nvkm_mask(device, 0x640, 0x1000000, 0x1000000);
	nvkm_mask(device, 0x644, 0x1000000, 0x1000000);
}

static void
pmu_disable_irq(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;

	nvkm_mask(device, 0x644, 0x1000000, 0x0);
	nvkm_mask(device, 0x640, 0x1000000, 0x0);
	nvkm_wr32(device, sb->base + 0x014, 0xff);
}


static int
pmu_enable(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	int err;

	nvkm_mask(device, 0x200, 0x2000, 0x2000);
	nvkm_rd32(device, 0x200);
	err = nvkm_wait_msec(device, 10, sb->base + 0x10c, 0x6, 0x0);
	if (err < 0) {
		nvkm_mask(device, 0x200, 0x2000, 0x0);
		nvdev_error(device, "Falcon mem scrubbing timeout\n");
		return err;
	}

	err = falcon_wait_idle(device);
	if (err)
		return err;

	pmu_enable_irq(device);

	return 0;
}

static void
pmu_disable(struct nvkm_device *device)
{
	if ((nvkm_rd32(device, 0x200) & 0x2000) != 0) {
		pmu_disable_irq(device);
		nvkm_mask(device, 0x200, 0x2000, 0x0);
	}
}

static int
pmu_reset(struct nvkm_device *device)
{
	int err;

	err = falcon_wait_idle(device);
	if (err)
		return err;

	pmu_disable(device);

	return pmu_enable(device);
}

#define FALCON_DMEM_ADDR_MASK	0xfffc
static int
falcon_copy_to_dmem(struct nvkm_device *device, const u32 base, u32 dst,
		    void *src, u32 size, u8 port)
{
	/* Number of full words */
	u32 w_size = size / sizeof(u32);
	/* Number of extra bytes */
	u32 b_size = size % sizeof(u32);
	int i;

	if (size == 0)
		return 0;

	if (dst & 0x3) {
		nvdev_error(device, "destination offset not aligned\n");
		return -EINVAL;
	}

	dst &= FALCON_DMEM_ADDR_MASK;

	mutex_lock(&device->mutex);

	nvkm_wr32(device, base + (0x1c0 + (port * 8)), (dst | (0x1 << 24)));

	for (i = 0; i < w_size; i++)
		nvkm_wr32(device, base + (0x1c4 + (port * 8)), ((u32 *)src)[i]);

	if (b_size != 0) {
		u32 data = 0;

		memcpy(&data, ((u32 *)src) + w_size, b_size);
		nvkm_wr32(device, base + (0x1c4 + (port * 8)), data);
	}

	mutex_unlock(&device->mutex);

	return 0;
}

/*
 * Hardware setup functions
 */

/**
 * sb_setup_falcon() - set up the secure falcon for secure boot
 */
static int
sb_setup_falcon(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	const u32 reg_base = sb->base + 0xe00;
	u32 inst_loc;
	int err;

	err = falcon_wait_clear_halt_interrupt(device);
	if (err)
		return err;

	err = pmu_reset(device);
	if (err)
		return err;
	/* disable irqs for hs falcon booting as we will poll for halt */
	pmu_disable_irq(device);

	/* setup apertures - virtual */
	nvkm_wr32(device, reg_base + 4 * (FALCON_DMAIDX_UCODE), 0x4);
	nvkm_wr32(device, reg_base + 4 * (FALCON_DMAIDX_VIRT), 0x0);
	/* setup apertures - physical */
	nvkm_wr32(device, reg_base + 4 * (FALCON_DMAIDX_PHYS_VID), 0x4);
	nvkm_wr32(device, reg_base + 4 * (FALCON_DMAIDX_PHYS_SYS_COH),
		  0x4 | 0x1);
	nvkm_wr32(device, reg_base + 4 * (FALCON_DMAIDX_PHYS_SYS_NCOH),
		  0x4 | 0x2);

	/* Set context */
	if (device->fb->ram)
		inst_loc = 0x0; /* FB */
	else
		inst_loc = 0x3; /* Non-coherent sysmem */

	nvkm_mask(device, sb->base + 0x048, 0x1, 0x1);
	nvkm_wr32(device, sb->base + 0x480, ((sb->inst->addr >> 12) & 0xfffffff)
					    | (inst_loc << 28) | (1 << 30));

	return 0;
}

/**
 * sb_load_hs_bl() - load HS bootloader into DMEM and IMEM
 */
static void
sb_load_hs_bl(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	struct hs_bin_hdr *hdr = sb->hsbl_blob;
	struct hsflcn_bl_desc *hsbl_desc = sb->hsbl_blob + hdr->header_offset;
	u32 acr_blob_vma_base = lower_32_bits(sb->acr_blob_vma.offset);
	void *hsbl_code = sb->hsbl_blob + hdr->data_offset;
	u32 code_size = ALIGN(hsbl_desc->bl_code_size, 256);
	u32 dst_blk;
	u32 tag;
	int i;

	/*
	 * Copy HS bootloader interface structure where the HS descriptor
	 * expects it to be, after updating virtual address of DMA bases
	 */
	sb->acr_bl_desc.code_dma_base.lo += acr_blob_vma_base;
	sb->acr_bl_desc.data_dma_base.lo += acr_blob_vma_base;
	falcon_copy_to_dmem(device, sb->base, hsbl_desc->bl_desc_dmem_load_off,
			    &sb->acr_bl_desc, sizeof(sb->acr_bl_desc), 0);
	sb->acr_bl_desc.code_dma_base.lo -= acr_blob_vma_base;
	sb->acr_bl_desc.data_dma_base.lo -= acr_blob_vma_base;

	/* Copy HS bootloader code to IMEM */
	dst_blk = (nvkm_rd32(device, sb->base + 0x108) & 0x1ff) -
		  (code_size >> 8);
	tag = hsbl_desc->bl_start_tag;
	nvkm_wr32(device, sb->base + 0x180,
		  ((dst_blk & 0xff) << 8) | (0x1 << 24));
	for (i = 0; i < code_size; i += 4) {
		/* write new tag every 256B */
		if ((i % 0x100) == 0) {
			nvkm_wr32(device, sb->base + 0x188, tag & 0xffff);
			tag++;
		}
		nvkm_wr32(device, sb->base + 0x184, *(u32 *)(hsbl_code + i));
	}
	nvkm_wr32(device, sb->base + 0x188, 0);
}

/**
 * sb_start() - start the falcon to perform secure boot
 */
static int
sb_start(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	struct hs_bin_hdr *hdr = sb->hsbl_blob;
	struct hsflcn_bl_desc *hsbl_desc = sb->hsbl_blob + hdr->header_offset;
	/* virtual start address for boot vector */
	u32 virt_addr = hsbl_desc->bl_start_tag << 8;

	/* Set boot vector to code's starting virtual address */
	nvkm_wr32(device, sb->base + 0x104, virt_addr);
	/* Start falcon */
	nvkm_wr32(device, sb->base + 0x100, 0x2);

	return 0;
}

/*
 * sb_execute() - execute secure boot from the prepared state
 *
 * Load the HS bootloader and ask the falcon to run it. This will in turn
 * load the HS firmware and run it, so once the falcon stops all the managed
 * falcons should have their LS firmware loaded and be ready to run.
 */
static int
sb_execute(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	int err;

	/* Map the HS firmware so the HS bootloader can see it */
	err = nvkm_gpuobj_map(sb->acr_blob, sb->vm, NV_MEM_ACCESS_RW,
			      &sb->acr_blob_vma);
	if (err)
		return err;

	/* Reset the falcon and make it ready to run the HS bootloader */
	err = sb_setup_falcon(device);
	if (err)
		goto done;

	/* Load the HS bootloader into the falcon's IMEM/DMEM */
	sb_load_hs_bl(device);

	/* Start the HS bootloader */
	err = sb_start(device);
	if (err)
		goto done;

	/* Wait until secure boot completes */
	err = falcon_wait_for_halt(device);
	if (err)
		goto done;

	err = falcon_wait_clear_halt_interrupt(device);

done:
	/* We don't need the ACR firmware anymore */
	nvkm_gpuobj_unmap(&sb->acr_blob_vma);

	return err;
}

const char *managed_falcons_names[] = {
	[LSF_FALCON_ID_PMU] = "PMU",
	[LSF_FALCON_ID_RESERVED] = "<invalid>",
	[LSF_FALCON_ID_FECS] = "FECS",
	[LSF_FALCON_ID_GPCCS] = "GPCCS",
	[LSF_FALCON_ID_END] = "<invalid>",
};

/**
 * nvkm_secure_boot() - perform secure boot
 *
 * Perform secure boot after loading all the required firmwares and preparing
 * the WPR blob. After this function returns, all the managed falcons should
 * have their LS firmware loaded and be ready to run.
 *
 * The various firmware blobs are kept in memory, so subsequent calls to this
 * function will directly run the cached state instead of rebuilding it every
 * time.
 */
int
nvkm_secure_boot(struct nvkm_device *device)
{
	struct secure_boot *sb;
	unsigned long falcon_id;
	int err;

	sb = device->secure_boot_state;

	nvdev_debug(device, "performing secure boot of:\n");
	for_each_set_bit(falcon_id, &device->chip->secure_boot.managed_falcons,
			 LSF_FALCON_ID_END)
		nvdev_debug(device, "- %s\n", managed_falcons_names[falcon_id]);

	/* Load all the LS firmwares and prepare the blob */
	if (!sb->ls_blob) {
		err = sb_prepare_ls_blob(device);
		if (err)
			return err;
	}

	/* Load the HS firmware for the performing falcon */
	if (!sb->acr_blob) {
		err = sb_prepare_hs_blob(device);
		if (err)
			return err;
	}

	/* Load the HS firmware bootloader */
	if (!sb->hsbl_blob) {
		err = sb_prepare_hsbl_blob(device);
		if (err)
			return err;
	}

	/*
	 * Run the HS bootloader. It will load the HS firmware and then run it.
	 * Once this returns, the LS firmwares will be loaded into the managed
	 * falcons.
	 */
	err = sb_execute(device);

	return err;
}

/**
 * sb_init_vm() - prepare the VM required for doing secure boot.
 */
static int
sb_init_vm(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	struct nvkm_vm *vm;
	int err;

	const u64 vm_area_len = 600 * 1024;

	err = nvkm_gpuobj_new(device, 0x1000, 0, true, NULL, &sb->inst);
	if (err)
		return err;

	err = nvkm_gpuobj_new(device, 0x8000, 0, true, NULL, &sb->pgd);
	if (err)
		return err;

	err = nvkm_vm_new(device, 0, vm_area_len, 0, NULL, &vm);
	if (err)
		return err;

	atomic_inc(&vm->engref[NVKM_SUBDEV_PMU]);

	err = nvkm_vm_ref(vm, &sb->vm, sb->pgd);
	nvkm_vm_ref(NULL, &vm, NULL);
	if (err)
		return err;

	nvkm_kmap(sb->inst);
	nvkm_wo32(sb->inst, 0x200, lower_32_bits(sb->pgd->addr));
	nvkm_wo32(sb->inst, 0x204, upper_32_bits(sb->pgd->addr));
	nvkm_wo32(sb->inst, 0x208, lower_32_bits(vm_area_len - 1));
	nvkm_wo32(sb->inst, 0x20c, upper_32_bits(vm_area_len - 1));
	nvkm_done(sb->inst);

	return 0;
}

static void
sb_cleanup_vm(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;

	nvkm_vm_ref(NULL, &sb->vm, sb->pgd);
	nvkm_gpuobj_del(&sb->pgd);
	nvkm_gpuobj_del(&sb->inst);
}

#ifdef CONFIG_ARCH_TEGRA
/* TODO Should this be handled by the Tegra MC driver? */
#define TEGRA_MC_BASE				0x70019000
#define MC_SECURITY_CARVEOUT2_CFG0		0xc58
#define MC_SECURITY_CARVEOUT2_BOM_0		0xc5c
#define MC_SECURITY_CARVEOUT2_BOM_HI_0		0xc60
#define MC_SECURITY_CARVEOUT2_SIZE_128K		0xc64
#define TEGRA_MC_SECURITY_CARVEOUT_CFG_LOCKED	(1 << 1)
/**
 * sb_tegra_read_wpr() - read the WPR registers on Tegra
 *
 * On dGPU, we can manage the WPR region ourselves, but on Tegra the WPR region
 * is reserved from system memory by the bootloader and irreversibly locked.
 * This function reads the address and size of the pre-configured WPR region.
 */
static int
sb_tegra_read_wpr(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;
	void __iomem *mc;
	u32 cfg;

	mc = ioremap(TEGRA_MC_BASE, 0xd00);
	if (!mc) {
		nvdev_error(device, "Cannot map Tegra MC registers\n");
		return PTR_ERR(mc);
	}
	sb->wpr_addr = ioread32_native(mc + MC_SECURITY_CARVEOUT2_BOM_0) |
	      ((u64)ioread32_native(mc + MC_SECURITY_CARVEOUT2_BOM_HI_0) << 32);
	sb->wpr_size = ioread32_native(mc + MC_SECURITY_CARVEOUT2_SIZE_128K)
		<< 17;
	cfg = ioread32_native(mc + MC_SECURITY_CARVEOUT2_CFG0);
	iounmap(mc);

	/* Check that WPR settings are valid */
	if (sb->wpr_size == 0) {
		nvdev_error(device, "WPR region is empty\n");
		return -EINVAL;
	}

	if (!(cfg & TEGRA_MC_SECURITY_CARVEOUT_CFG_LOCKED)) {
		nvdev_error(device, "WPR region not locked\n");
		return -EINVAL;
	}

	return 0;
}
#else
static int
sb_tegra_read_wpr(struct nvkm_device *device)
{
	nvdev_error(device, "Tegra support not compiled in\n");
	return -EINVAL;
}
#endif

/**
 * nvkm_secure_boot_init() - initialize secure boot for a device
 *
 * Prepare secure boot for a device. This will not load the firmwares yet,
 * firmwares are loaded and cached upon the first call to nvkm_secure_boot().
 */
int
nvkm_secure_boot_init(struct nvkm_device *device)
{
	struct secure_boot *sb;
	int err;

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	if (!sb) {
		err = -ENOMEM;
		goto error;
	}
	device->secure_boot_state = sb;

	switch (device->type) {
	case NVKM_DEVICE_TEGRA:
		err = sb_tegra_read_wpr(device);
		if (err)
			goto error_free;
		break;
	case NVKM_DEVICE_PCI:
	case NVKM_DEVICE_AGP:
	case NVKM_DEVICE_PCIE:
		break;
	default:
		nvdev_error(device, "device not supported for Secure Boot!\n");
		err = -EINVAL;
		goto error_free;
	}

	switch (device->chip->secure_boot.boot_falcon) {
	case LSF_FALCON_ID_PMU:
		sb->base = 0x10a000;
		break;
	default:
		nvdev_error(device, "invalid secure boot falcon\n");
		err = -EINVAL;
		goto error_free;
	};

	err = sb_init_vm(device);
	if (err) {
		goto error_free;
	}

	return 0;

error_free:
	kfree(sb);
	device->secure_boot_state = NULL;
error:
	nvdev_error(device, "Secure Boot initialization failed: %d\n", err);
	return err;
}

/**
 * nvkm_secure_boot_fini() - cleanup secure boot state for a device
 *
 * Frees all the memory used by secure boot.
 */
void
nvkm_secure_boot_fini(struct nvkm_device *device)
{
	struct secure_boot *sb = device->secure_boot_state;

	if (!sb)
		return;

	if (sb->hsbl_blob)
		sb_cleanup_hsbl_blob(device);

	if (sb->acr_blob)
		sb_cleanup_hs_blob(device);

	if (sb->ls_blob)
		sb_cleanup_ls_blob(device);

	   sb_cleanup_vm(device);

	kfree(sb);
	device->secure_boot_state = NULL;
}
