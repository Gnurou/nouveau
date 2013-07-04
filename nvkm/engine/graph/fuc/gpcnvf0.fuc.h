uint32_t nvf0_grgpc_data[] = {
/* 0x0000: gpc_mmio_list_head */
	0x0000006c,
/* 0x0004: gpc_mmio_list_tail */
/* 0x0004: tpc_mmio_list_head */
	0x0000006c,
/* 0x0008: tpc_mmio_list_tail */
/* 0x0008: unk_mmio_list_head */
	0x0000006c,
/* 0x000c: unk_mmio_list_tail */
	0x0000006c,
/* 0x0010: gpc_id */
	0x00000000,
/* 0x0014: tpc_count */
	0x00000000,
/* 0x0018: tpc_mask */
	0x00000000,
/* 0x001c: unk_count */
	0x00000000,
/* 0x0020: unk_mask */
	0x00000000,
/* 0x0024: cmd_queue */
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};

uint32_t nvf0_grgpc_code[] = {
	0x03060ef5,
/* 0x0004: queue_put */
	0x9800d898,
	0x86f001d9,
	0x0489b808,
	0xf00c1bf4,
	0x21f502f7,
	0x00f802ec,
/* 0x001c: queue_put_next */
	0xb60798c4,
	0x8dbb0384,
	0x0880b600,
	0x80008e80,
	0x90b6018f,
	0x0f94f001,
	0xf801d980,
/* 0x0039: queue_get */
	0x0131f400,
	0x9800d898,
	0x89b801d9,
	0x210bf404,
	0xb60789c4,
	0x9dbb0394,
	0x0890b600,
	0x98009e98,
	0x80b6019f,
	0x0f84f001,
	0xf400d880,
/* 0x0066: queue_get_done */
	0x00f80132,
/* 0x0068: nv_rd32 */
	0x0728b7f1,
	0xb906b4b6,
	0xc9f002ec,
	0x00bcd01f,
/* 0x0078: nv_rd32_wait */
	0xc800bccf,
	0x1bf41fcc,
	0x06a7f0fa,
	0x010321f5,
	0xf840bfcf,
/* 0x008d: nv_wr32 */
	0x28b7f100,
	0x06b4b607,
	0xb980bfd0,
	0xc9f002ec,
	0x1ec9f01f,
/* 0x00a3: nv_wr32_wait */
	0xcf00bcd0,
	0xccc800bc,
	0xfa1bf41f,
/* 0x00ae: watchdog_reset */
	0x87f100f8,
	0x84b60430,
	0x1ff9f006,
	0xf8008fd0,
/* 0x00bd: watchdog_clear */
	0x3087f100,
	0x0684b604,
	0xf80080d0,
/* 0x00c9: wait_donez */
	0x3c87f100,
	0x0684b608,
	0x99f094bd,
	0x0089d000,
	0x081887f1,
	0xd00684b6,
/* 0x00e2: wait_donez_ne */
	0x87f1008a,
	0x84b60400,
	0x0088cf06,
	0xf4888aff,
	0x87f1f31b,
	0x84b6085c,
	0xf094bd06,
	0x89d00099,
/* 0x0103: wait_doneo */
	0xf100f800,
	0xb6083c87,
	0x94bd0684,
	0xd00099f0,
	0x87f10089,
	0x84b60818,
	0x008ad006,
/* 0x011c: wait_doneo_e */
	0x040087f1,
	0xcf0684b6,
	0x8aff0088,
	0xf30bf488,
	0x085c87f1,
	0xbd0684b6,
	0x0099f094,
	0xf80089d0,
/* 0x013d: mmctx_size */
/* 0x013f: nv_mmctx_size_loop */
	0x9894bd00,
	0x85b600e8,
	0x0180b61a,
	0xbb0284b6,
	0xe0b60098,
	0x04efb804,
	0xb9eb1bf4,
	0x00f8029f,
/* 0x015c: mmctx_xfer */
	0x083c87f1,
	0xbd0684b6,
	0x0199f094,
	0xf10089d0,
	0xb6071087,
	0x94bd0684,
	0xf405bbfd,
	0x8bd0090b,
	0x0099f000,
/* 0x0180: mmctx_base_disabled */
	0xf405eefd,
	0x8ed00c0b,
	0xc08fd080,
/* 0x018f: mmctx_multi_disabled */
	0xb70199f0,
	0xc8010080,
	0xb4b600ab,
	0x0cb9f010,
	0xb601aec8,
	0xbefd11e4,
	0x008bd005,
/* 0x01a8: mmctx_exec_loop */
/* 0x01a8: mmctx_wait_free */
	0xf0008ecf,
	0x0bf41fe4,
	0x00ce98fa,
	0xd005e9fd,
	0xc0b6c08e,
	0x04cdb804,
	0xc8e81bf4,
	0x1bf402ab,
/* 0x01c9: mmctx_fini_wait */
	0x008bcf18,
	0xb01fb4f0,
	0x1bf410b4,
	0x02a7f0f7,
	0xf4c921f4,
/* 0x01de: mmctx_stop */
	0xabc81b0e,
	0x10b4b600,
	0xf00cb9f0,
	0x8bd012b9,
/* 0x01ed: mmctx_stop_wait */
	0x008bcf00,
	0xf412bbc8,
/* 0x01f6: mmctx_done */
	0x87f1fa1b,
	0x84b6085c,
	0xf094bd06,
	0x89d00199,
/* 0x0207: strand_wait */
	0xf900f800,
	0x02a7f0a0,
	0xfcc921f4,
/* 0x0213: strand_pre */
	0xf100f8a0,
	0xf04afc87,
	0x97f00283,
	0x0089d00c,
	0x020721f5,
/* 0x0226: strand_post */
	0x87f100f8,
	0x83f04afc,
	0x0d97f002,
	0xf50089d0,
	0xf8020721,
/* 0x0239: strand_set */
	0xfca7f100,
	0x02a3f04f,
	0x0500aba2,
	0xd00fc7f0,
	0xc7f000ac,
	0x00bcd00b,
	0x020721f5,
	0xf000aed0,
	0xbcd00ac7,
	0x0721f500,
/* 0x0263: strand_ctx_init */
	0xf100f802,
	0xb6083c87,
	0x94bd0684,
	0xd00399f0,
	0x21f50089,
	0xe7f00213,
	0x3921f503,
	0xfca7f102,
	0x02a3f046,
	0x0400aba0,
	0xf040a0d0,
	0xbcd001c7,
	0x0721f500,
	0x010c9202,
	0xf000acd0,
	0xbcd002c7,
	0x0721f500,
	0x2621f502,
	0x8087f102,
	0x0684b608,
	0xb70089cf,
	0x95220080,
/* 0x02ba: ctx_init_strand_loop */
	0x8ed008fe,
	0x408ed000,
	0xb6808acf,
	0xa0b606a5,
	0x00eabb01,
	0xb60480b6,
	0x1bf40192,
	0x08e4b6e8,
	0xf1f2efbc,
	0xb6085c87,
	0x94bd0684,
	0xd00399f0,
	0x00f80089,
/* 0x02ec: error */
	0xe7f1e0f9,
	0xe3f09814,
	0x8d21f440,
	0x041ce0b7,
	0xf401f7f0,
	0xe0fc8d21,
/* 0x0306: init */
	0x04bd00f8,
	0xf10004fe,
	0xf0120017,
	0x12d00227,
	0x5717f100,
	0x0010fe04,
	0x040017f1,
	0xf0c010d0,
	0x12d00427,
	0x1031f400,
	0x060817f1,
	0xcf0614b6,
	0x37f00012,
	0x1f24f001,
	0xb60432bb,
	0x02800132,
	0x06038005,
	0x040010b7,
	0x800012cf,
	0xe7f10402,
	0xe3f00c30,
	0xbd24bd50,
/* 0x035f: init_unk_loop */
	0xf444bd34,
	0xf6b06821,
	0x0f0bf400,
	0xbb01f7f0,
	0x4ffd04f2,
	0x0130b605,
/* 0x0374: init_unk_next */
	0xb60120b6,
	0x26b004e0,
	0xe21bf402,
/* 0x0380: init_unk_done */
	0x80070380,
	0x27f10804,
	0x24b60800,
	0x4022cf06,
	0x47f134bd,
	0x44b60700,
	0x08259506,
	0xd00045d0,
	0x0e984045,
	0x010f9800,
	0x013d21f5,
	0xbb002fbb,
	0x0e98003f,
	0x020f9801,
	0x013d21f5,
	0xfd050e98,
	0x2ebb00ef,
	0x003ebb00,
	0x98020e98,
	0x21f5030f,
	0x0e98013d,
	0x00effd07,
	0xbb002ebb,
	0x40b7003e,
	0x35b61300,
	0x0043d002,
	0xb60825b6,
	0x20b60635,
	0x0130b601,
	0xb60824b6,
	0x2fb90834,
	0x6321f502,
	0x003fbb02,
	0x080017f1,
	0xd00614b6,
	0x10b74013,
	0x24bd0800,
	0xd01f29f0,
/* 0x041a: main */
	0x31f40012,
	0x0028f400,
	0xf424d7f0,
	0x01f43921,
	0x04e4b0f4,
	0xfe1e18f4,
	0x27f00181,
	0xfd20bd06,
	0xe4b60412,
	0x051efd01,
	0xf50018fe,
	0xf404dc21,
/* 0x044a: main_not_ctx_xfer */
	0xef94d30e,
	0x01f5f010,
	0x02ec21f5,
/* 0x0457: ih */
	0xf9c60ef4,
	0x0188fe80,
	0x90f980f9,
	0xb0f9a0f9,
	0xe0f9d0f9,
	0x0acff0f9,
	0x04abc480,
	0xf11d0bf4,
	0xf01900b7,
	0xbecf24d7,
	0x00bfcf40,
	0xb70421f4,
	0xf00400b0,
	0xbed001e7,
/* 0x048d: ih_no_fifo */
	0x400ad000,
	0xe0fcf0fc,
	0xb0fcd0fc,
	0x90fca0fc,
	0x88fe80fc,
	0xf480fc00,
	0x01f80032,
/* 0x04a8: hub_barrier_done */
	0x9801f7f0,
	0xfebb040e,
	0x18e7f104,
	0x40e3f094,
	0xf88d21f4,
/* 0x04bd: ctx_redswitch */
	0x14e7f100,
	0x06e4b606,
	0xd020f7f0,
	0xf7f000ef,
/* 0x04cd: ctx_redswitch_delay */
	0x01f2b608,
	0xf1fd1bf4,
	0xd00a20f7,
	0x00f800ef,
/* 0x04dc: ctx_xfer */
	0x0a0417f1,
	0xd00614b6,
	0x11f4001f,
	0xbd21f507,
/* 0x04ed: ctx_xfer_not_load */
	0xfc17f104,
	0x0213f04a,
	0xd00c27f0,
	0x21f50012,
	0x27f10207,
	0x23f047fc,
	0x0020d002,
	0xb6012cf0,
	0x12d00320,
	0x01acf000,
	0xf002a5f0,
	0xb3f000b7,
	0x040c9850,
	0xbb0fc4b6,
	0x0c9800bc,
	0x010d9800,
	0xf500e7f0,
	0xf0015c21,
	0xb7f101ac,
	0xb3f04000,
	0x040c9850,
	0xbb0fc4b6,
	0x0c9800bc,
	0x020d9801,
	0xf1060f98,
	0xf50800e7,
	0xf0015c21,
	0xa5f001ac,
	0x00b7f104,
	0x50b3f030,
	0xb6040c98,
	0xbcbb0fc4,
	0x020c9800,
	0x98030d98,
	0xe7f1080f,
	0x21f50200,
	0x21f5015c,
	0x01f40207,
	0x1412f406,
/* 0x0588: ctx_xfer_post */
	0x4afc17f1,
	0xf00213f0,
	0x12d00d27,
	0x0721f500,
/* 0x0599: ctx_xfer_done */
	0xa821f502,
	0x0000f804,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
	0x00000000,
};
