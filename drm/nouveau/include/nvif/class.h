#ifndef __NVIF_CLASS_H__
#define __NVIF_CLASS_H__

/* these class numbers are made up by us, and not nvidia-assigned */
#define NVIF_CLASS_CONTROL                                    /* if0001.h */ -1
#define NVIF_CLASS_PERFMON                                    /* if0002.h */ -2
#define NVIF_CLASS_PERFDOM                                    /* if0003.h */ -3
#define NVIF_CLASS_SW_NV04                                    /* if0004.h */ -4
#define NVIF_CLASS_SW_NV10                                    /* if0005.h */ -5
#define NVIF_CLASS_SW_NV50                                    /* if0005.h */ -6
#define NVIF_CLASS_SW_GF100                                   /* if0005.h */ -7

/* the below match nvidia-assigned (either in hw, or sw) class numbers */
#define NV_DEVICE                                                    0x00000080

#define NV_DMA_FROM_MEMORY                                           0x00000002
#define NV_DMA_TO_MEMORY                                             0x00000003
#define NV_DMA_IN_MEMORY                                             0x0000003d

#define FERMI_TWOD_A                                                 0x0000902d

#define FERMI_MEMORY_TO_MEMORY_FORMAT_A                              0x00009039

#define KEPLER_INLINE_TO_MEMORY_A                                    0x0000a040
#define KEPLER_INLINE_TO_MEMORY_B                                    0x0000a140

#define NV04_DISP                                     /* cl0046.h */ 0x00000046

#define NV03_CHANNEL_DMA                              /* cl506b.h */ 0x0000006b
#define NV10_CHANNEL_DMA                              /* cl506b.h */ 0x0000006e
#define NV17_CHANNEL_DMA                              /* cl506b.h */ 0x0000176e
#define NV40_CHANNEL_DMA                              /* cl506b.h */ 0x0000406e
#define NV50_CHANNEL_DMA                              /* cl506e.h */ 0x0000506e
#define G82_CHANNEL_DMA                               /* cl826e.h */ 0x0000826e

#define NV50_CHANNEL_GPFIFO                           /* cl506f.h */ 0x0000506f
#define G82_CHANNEL_GPFIFO                            /* cl826f.h */ 0x0000826f
#define FERMI_CHANNEL_GPFIFO                          /* cl906f.h */ 0x0000906f
#define KEPLER_CHANNEL_GPFIFO_A                       /* cla06f.h */ 0x0000a06f
#define MAXWELL_CHANNEL_GPFIFO_A                      /* cla06f.h */ 0x0000b06f

#define NV50_DISP                                     /* cl5070.h */ 0x00005070
#define G82_DISP                                      /* cl5070.h */ 0x00008270
#define GT200_DISP                                    /* cl5070.h */ 0x00008370
#define GT214_DISP                                    /* cl5070.h */ 0x00008570
#define GT206_DISP                                    /* cl5070.h */ 0x00008870
#define GF110_DISP                                    /* cl5070.h */ 0x00009070
#define GK104_DISP                                    /* cl5070.h */ 0x00009170
#define GK110_DISP                                    /* cl5070.h */ 0x00009270
#define GM107_DISP                                    /* cl5070.h */ 0x00009470
#define GM204_DISP                                    /* cl5070.h */ 0x00009570

#define NV31_MPEG                                                    0x00003174
#define G82_MPEG                                                     0x00008274

#define NV74_VP2                                                     0x00007476

#define NV50_DISP_CURSOR                              /* cl507a.h */ 0x0000507a
#define G82_DISP_CURSOR                               /* cl507a.h */ 0x0000827a
#define GT214_DISP_CURSOR                             /* cl507a.h */ 0x0000857a
#define GF110_DISP_CURSOR                             /* cl507a.h */ 0x0000907a
#define GK104_DISP_CURSOR                             /* cl507a.h */ 0x0000917a

#define NV50_DISP_OVERLAY                             /* cl507b.h */ 0x0000507b
#define G82_DISP_OVERLAY                              /* cl507b.h */ 0x0000827b
#define GT214_DISP_OVERLAY                            /* cl507b.h */ 0x0000857b
#define GF110_DISP_OVERLAY                            /* cl507b.h */ 0x0000907b
#define GK104_DISP_OVERLAY                            /* cl507b.h */ 0x0000917b

#define NV50_DISP_BASE_CHANNEL_DMA                    /* cl507c.h */ 0x0000507c
#define G82_DISP_BASE_CHANNEL_DMA                     /* cl507c.h */ 0x0000827c
#define GT200_DISP_BASE_CHANNEL_DMA                   /* cl507c.h */ 0x0000837c
#define GT214_DISP_BASE_CHANNEL_DMA                   /* cl507c.h */ 0x0000857c
#define GF110_DISP_BASE_CHANNEL_DMA                   /* cl507c.h */ 0x0000907c
#define GK104_DISP_BASE_CHANNEL_DMA                   /* cl507c.h */ 0x0000917c
#define GK110_DISP_BASE_CHANNEL_DMA                   /* cl507c.h */ 0x0000927c

#define NV50_DISP_CORE_CHANNEL_DMA                    /* cl507d.h */ 0x0000507d
#define G82_DISP_CORE_CHANNEL_DMA                     /* cl507d.h */ 0x0000827d
#define GT200_DISP_CORE_CHANNEL_DMA                   /* cl507d.h */ 0x0000837d
#define GT214_DISP_CORE_CHANNEL_DMA                   /* cl507d.h */ 0x0000857d
#define GT206_DISP_CORE_CHANNEL_DMA                   /* cl507d.h */ 0x0000887d
#define GF110_DISP_CORE_CHANNEL_DMA                   /* cl507d.h */ 0x0000907d
#define GK104_DISP_CORE_CHANNEL_DMA                   /* cl507d.h */ 0x0000917d
#define GK110_DISP_CORE_CHANNEL_DMA                   /* cl507d.h */ 0x0000927d
#define GM107_DISP_CORE_CHANNEL_DMA                   /* cl507d.h */ 0x0000947d
#define GM204_DISP_CORE_CHANNEL_DMA                   /* cl507d.h */ 0x0000957d

#define NV50_DISP_OVERLAY_CHANNEL_DMA                 /* cl507e.h */ 0x0000507e
#define G82_DISP_OVERLAY_CHANNEL_DMA                  /* cl507e.h */ 0x0000827e
#define GT200_DISP_OVERLAY_CHANNEL_DMA                /* cl507e.h */ 0x0000837e
#define GT214_DISP_OVERLAY_CHANNEL_DMA                /* cl507e.h */ 0x0000857e
#define GF110_DISP_OVERLAY_CONTROL_DMA                /* cl507e.h */ 0x0000907e
#define GK104_DISP_OVERLAY_CONTROL_DMA                /* cl507e.h */ 0x0000917e

#define FERMI_A                                       /* cl9097.h */ 0x00009097
#define FERMI_B                                       /* cl9097.h */ 0x00009197
#define FERMI_C                                       /* cl9097.h */ 0x00009297

#define KEPLER_A                                      /* cl9097.h */ 0x0000a097
#define KEPLER_B                                      /* cl9097.h */ 0x0000a197
#define KEPLER_C                                      /* cl9097.h */ 0x0000a297

#define MAXWELL_A                                     /* cl9097.h */ 0x0000b097
#define MAXWELL_B                                     /* cl9097.h */ 0x0000b197

#define NV74_BSP                                                     0x000074b0

#define GT212_MSVLD                                                  0x000085b1
#define IGT21A_MSVLD                                                 0x000086b1
#define G98_MSVLD                                                    0x000088b1
#define GF100_MSVLD                                                  0x000090b1
#define GK104_MSVLD                                                  0x000095b1

#define GT212_MSPDEC                                                 0x000085b2
#define G98_MSPDEC                                                   0x000088b2
#define GF100_MSPDEC                                                 0x000090b2
#define GK104_MSPDEC                                                 0x000095b2

#define GT212_MSPPP                                                  0x000085b3
#define G98_MSPPP                                                    0x000088b3
#define GF100_MSPPP                                                  0x000090b3

#define G98_SEC                                                      0x000088b4

#define GT212_DMA                                                    0x000085b5
#define FERMI_DMA                                                    0x000090b5
#define KEPLER_DMA_COPY_A                                            0x0000a0b5
#define MAXWELL_DMA_COPY_A                                           0x0000b0b5

#define FERMI_DECOMPRESS                                             0x000090b8

#define FERMI_COMPUTE_A                                              0x000090c0
#define FERMI_COMPUTE_B                                              0x000091c0
#define KEPLER_COMPUTE_A                                             0x0000a0c0
#define KEPLER_COMPUTE_B                                             0x0000a1c0
#define MAXWELL_COMPUTE_A                                            0x0000b0c0
#define MAXWELL_COMPUTE_B                                            0x0000b1c0

#define NV74_CIPHER                                                  0x000074c1

/*******************************************************************************
 * client
 ******************************************************************************/

#define NV_CLIENT_DEVLIST                                                  0x00

struct nv_client_devlist_v0 {
	__u8  version;
	__u8  count;
	__u8  pad02[6];
	__u64 device[];
};


/*******************************************************************************
 * device
 ******************************************************************************/

struct nv_device_v0 {
	__u8  version;
	__u8  pad01[7];
	__u64 device;	/* device identifier, ~0 for client default */
};

#define NV_DEVICE_V0_INFO                                                  0x00
#define NV_DEVICE_V0_TIME                                                  0x01

struct nv_device_info_v0 {
	__u8  version;
#define NV_DEVICE_INFO_V0_IGP                                              0x00
#define NV_DEVICE_INFO_V0_PCI                                              0x01
#define NV_DEVICE_INFO_V0_AGP                                              0x02
#define NV_DEVICE_INFO_V0_PCIE                                             0x03
#define NV_DEVICE_INFO_V0_SOC                                              0x04
	__u8  platform;
	__u16 chipset;	/* from NV_PMC_BOOT_0 */
	__u8  revision;	/* from NV_PMC_BOOT_0 */
#define NV_DEVICE_INFO_V0_TNT                                              0x01
#define NV_DEVICE_INFO_V0_CELSIUS                                          0x02
#define NV_DEVICE_INFO_V0_KELVIN                                           0x03
#define NV_DEVICE_INFO_V0_RANKINE                                          0x04
#define NV_DEVICE_INFO_V0_CURIE                                            0x05
#define NV_DEVICE_INFO_V0_TESLA                                            0x06
#define NV_DEVICE_INFO_V0_FERMI                                            0x07
#define NV_DEVICE_INFO_V0_KEPLER                                           0x08
#define NV_DEVICE_INFO_V0_MAXWELL                                          0x09
	__u8  family;
	__u8  pad06[2];
	__u64 ram_size;
	__u64 ram_user;
	char  chip[16];
	char  name[64];
};

struct nv_device_time_v0 {
	__u8  version;
	__u8  pad01[7];
	__u64 time;
};


/*******************************************************************************
 * context dma
 ******************************************************************************/

struct nv_dma_v0 {
	__u8  version;
#define NV_DMA_V0_TARGET_VM                                                0x00
#define NV_DMA_V0_TARGET_VRAM                                              0x01
#define NV_DMA_V0_TARGET_PCI                                               0x02
#define NV_DMA_V0_TARGET_PCI_US                                            0x03
#define NV_DMA_V0_TARGET_AGP                                               0x04
	__u8  target;
#define NV_DMA_V0_ACCESS_VM                                                0x00
#define NV_DMA_V0_ACCESS_RD                                                0x01
#define NV_DMA_V0_ACCESS_WR                                                0x02
#define NV_DMA_V0_ACCESS_RDWR                 (NV_DMA_V0_ACCESS_RD | NV_DMA_V0_ACCESS_WR)
	__u8  access;
	__u8  pad03[5];
	__u64 start;
	__u64 limit;
	/* ... chipset-specific class data */
};

struct nv50_dma_v0 {
	__u8  version;
#define NV50_DMA_V0_PRIV_VM                                                0x00
#define NV50_DMA_V0_PRIV_US                                                0x01
#define NV50_DMA_V0_PRIV__S                                                0x02
	__u8  priv;
#define NV50_DMA_V0_PART_VM                                                0x00
#define NV50_DMA_V0_PART_256                                               0x01
#define NV50_DMA_V0_PART_1KB                                               0x02
	__u8  part;
#define NV50_DMA_V0_COMP_NONE                                              0x00
#define NV50_DMA_V0_COMP_1                                                 0x01
#define NV50_DMA_V0_COMP_2                                                 0x02
#define NV50_DMA_V0_COMP_VM                                                0x03
	__u8  comp;
#define NV50_DMA_V0_KIND_PITCH                                             0x00
#define NV50_DMA_V0_KIND_VM                                                0x7f
	__u8  kind;
	__u8  pad05[3];
};

struct gf100_dma_v0 {
	__u8  version;
#define GF100_DMA_V0_PRIV_VM                                               0x00
#define GF100_DMA_V0_PRIV_US                                               0x01
#define GF100_DMA_V0_PRIV__S                                               0x02
	__u8  priv;
#define GF100_DMA_V0_KIND_PITCH                                            0x00
#define GF100_DMA_V0_KIND_VM                                               0xff
	__u8  kind;
	__u8  pad03[5];
};

struct gf119_dma_v0 {
	__u8  version;
#define GF119_DMA_V0_PAGE_LP                                               0x00
#define GF119_DMA_V0_PAGE_SP                                               0x01
	__u8  page;
#define GF119_DMA_V0_KIND_PITCH                                            0x00
#define GF119_DMA_V0_KIND_VM                                               0xff
	__u8  kind;
	__u8  pad03[5];
};
#endif
