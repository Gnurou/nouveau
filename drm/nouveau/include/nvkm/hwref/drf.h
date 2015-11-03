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

#ifndef __hwref_drf_h__
#define __hwref_drf_h__
/*
 * See drf.txt in this directory for explanation/illustrations.
 * Note: that discussion isn't necessarily implemented 1:1 here.
 */

/*
 * The following inlines bind the drf macros following to specific integral types.
 * They can also be used as gathering points for "is-using" and "can-reach" analysis breadcrumbs.
 */
static inline u32 _drf_lo(u32 b)
{
	return b;
}
static inline u32 _drf_hi(u32 b)
{
	return b;
}
static inline u32 _drf_val(u32 v)
{
	return v;
}
static inline u32 _dr_offset(u32 o)
{
	return o;
}
static inline u32 _dr_offset_i(u32 o)
{
	return o;
}

/* return the hi/lo bit numbers for a field */
#define drf_lo(d,r,f) _drf_lo(0 ? NV_##d##_##r##_##f)
#define drf_hi(d,r,f) _drf_hi(1 ? NV_##d##_##r##_##f)

/* return the bit width and offsets for a field */
#define drf_width(d,r,f) (1 + drf_hi(d,r,f) - drf_lo(d,r,f))
#define drf_shift(d,r,f) drf_lo(d,r,f)

/* return masks for a field */
#define drf_mask(d,r,f)   ((1 << drf_width(d,r,f)) - 1)
#define drf_mask_p(d,r,f) (drf_mask(d,r,f) << drf_shift(d,r,f))

/* return defined values for a field */
#define drf_val(d,r,f,v)   _drf_val(NV_##d##_##r##_##f##_##v)
#define drf_val_p(d,r,f,v) (drf_val(d,r,f,v) << drf_shift(d,r,f))

/* mask off a number for use in a field */
#define drf_num(d,r,f,n)   ((n) & drf_mask(d,r,f))
#define drf_num_p(d,r,f,n) (drf_num(d,r,f,n) << drf_shift(d,r,f))

/* return the value of a field within a given */
#define drf_get(g,d,r,f)   (((g) >> drf_shift(d,r,f)) & drf_mask(d,r,f) )
#define drf_get_p(g,d,r,f) ((g) & drf_mask_placed(d,r,f))

/* utils to clear and set fields within a given */
#define drf_clear(g,d,r,f)   ((g) & ~drf_mask_p(d,r,f))
#define drf_set_v(g,d,r,f,v) (drf_clear(g,d,r,f) | drf_val_p(d,r,f,v))
#define drf_set_n(g,d,r,f,n) (drf_clear(g,d,r,f) | drf_num_p(d,r,f,n))

/* return register offset */
#define dr_offset(d,r)     _dr_offset(NV_##d##_##r)
#define dr_offset_i(d,r,i) _dr_offset_i(NV_##d##_##r(i))

/* register read32 coupled with field ops.  note: p == priv given to nv_rd32 */
#define dr_rd32(p,d,r)      nv_rd32(p, dr_offset(d,r))
#define dr_rd32_i(p,d,r,i)  nv_rd32(p, dr_offset_i(d,r,i))
#define drf_rd32(p,d,r,f)   drf_get(dr_rd32(p,d,r), d,r,f)
#define drf_rd32_p(p,d,r,f) drf_get_p(dr_rd32(p,d,r), d,r,f)

#define dr_rd32_i(p,d,r,i)  nv_rd32(p, dr_offset_i(d,r,i))


/*
 * These are here to help when porting nvgpu code.
 */
static inline u32 u64_hi32(u64 n)
{
	return (u32)((n >> 32) & ~(u32)0);
}
static inline u32 u64_lo32(u64 n)
{
	return (u32)(n & ~(u32)0);
}
static inline u32 set_field(u32 val, u32 mask, u32 field)
{
	return ((val & ~mask) | field);
}


#endif /* __hwref_drf_h__ */
