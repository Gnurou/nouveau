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
#ifndef __hwref_gm20b_flush_h__
#define __hwref_gm20b_flush_h__

#define NV_UFLUSH_L2_SYSMEM_INVALIDATE                     0x70004
#define NV_UFLUSH_L2_SYSMEM_INVALIDATE_PENDING                 0:0
#define NV_UFLUSH_L2_SYSMEM_INVALIDATE_PENDING_BUSY              1
#define NV_UFLUSH_L2_SYSMEM_INVALIDATE_OUTSTANDING             1:1
#define NV_UFLUSH_L2_FLUSH_DIRTY                           0x70010
#define NV_UFLUSH_L2_FLUSH_DIRTY_PENDING                       0:0
#define NV_UFLUSH_L2_FLUSH_DIRTY_PENDING_EMPTY                   0
#define NV_UFLUSH_L2_FLUSH_DIRTY_PENDING_BUSY                    1
#define NV_UFLUSH_L2_FLUSH_DIRTY_OUTSTANDING                   1:1
#define NV_UFLUSH_FB_FLUSH                                 0x70000
#define NV_UFLUSH_FB_FLUSH_PENDING                             0:0
#define NV_UFLUSH_FB_FLUSH_PENDING_BUSY                          1
#define NV_UFLUSH_FB_FLUSH_OUTSTANDING                         1:1

#endif /* __hwref_gm20b_flush_h__ */
