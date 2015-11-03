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
#ifndef __hwref_gk208b_timer_h__
#define __hwref_gk208b_timer_h__

#define NV_PTIMER_PRI_TIMEOUT                               0x9080
#define NV_PTIMER_PRI_TIMEOUT_PERIOD                          23:0
#define NV_PTIMER_PRI_TIMEOUT_EN                             31:31
#define NV_PTIMER_PRI_TIMEOUT_SAVE_0                        0x9084
#define NV_PTIMER_PRI_TIMEOUT_SAVE_1                        0x9088
#define NV_PTIMER_PRI_TIMEOUT_FECS_ERRCODE                  0x908c

#endif /* __hwref_gk208b_timer_h__ */
