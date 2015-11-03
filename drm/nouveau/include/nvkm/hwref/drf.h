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

#ifndef __nv_drf_h__
#define __nv_drf_h__
/*
 * See nv_drf.txt in this directory for explanation/illustrations.
 * Note: that discussion isn't necessarily implemented 1:1 here.
 */

/*
 * The following inlines bind the drf macros following to specific integral types.
 * They also help provide "is-using" and "can-reach" breadcrumbs for analysis.
 */
static inline u32 _nv_drf_fld_lo_bit(const char *D, const char *R, const char *F, u32 b)
{
	return b;
}
static inline u32 _nv_drf_fld_hi_bit(const char *D, const char *R, const char *F, u32 b)
{
	return b;
}
static inline u32 _nv_drf_fld_val(const char *D, const char *R, const char *F, const char *V, u32 v)
{
	return v;
}
static inline u32 _nv_drf_reg_offset(const char *D, const char *R, u32 o)
{
	return o;
}

/* return the hi/lo bit numbers for a field */
#define drf_fld_lo_bit(d,r,f) _nv_drf_fld_lo_bit(#d,#r,#f, 0 ? NV_##d##_##r##_##f)
#define drf_fld_hi_bit(d,r,f) _nv_drf_fld_hi_bit(#d,#r,#f, 1 ? NV_##d##_##r##_##f)

/* return the bit width and offsets for a field */
#define drf_fld_width_bits(d,r,f) (1 + drf_fld_hi_bit(d,r,f) - drf_fld_lo_bit(d,r,f))
#define drf_fld_shift_bits(d,r,f) drf_fld_lo_bit(d,r,f)

/* return masks for a field */
#define drf_fld_mask(d,r,f)        ((1 << drf_fld_width_bits(d,r,f)) - 1)
#define drf_fld_mask_placed(d,r,f) (drf_fld_mask(d,r,f) << drf_fld_shift_bits(d,r,f))

/* return defined values for a field */
#define drf_fld_val(d,r,f,v)        _nv_drf_fld_val(#d,#r,#f,#v, NV_##d##_##r##_##f##_##v)
#define drf_fld_val_placed(d,r,f,v) (drf_fld_val(d,r,f,v) << drf_fld_shift_bits(d,r,f))

/* mask off a number for use in a field */
#define drf_fld_num(d,r,f,n)        ((n) & drf_fld_mask(d,r,f))
#define drf_fld_num_placed(d,r,f,n) (drf_fld_num(d,r,f,n) << drf_fld_shift_bits(d,r,f))

/* return the value of a field within a given */
#define drf_get_fld(g, d,r,f)        (((g) >> drf_fld_shift_bits(d,r,f)) & drf_fld_mask(d,r,f) )
#define drf_get_fld_placed(g, d,r,f) ((g) & drf_fld_mask_placed(d,r,f))

/* utils to clear and set fields within a given */
#define drf_clear_fld(g, d,r,f)      ((g) & ~drf_fld_mask_placed(d,r,f))
#define drf_set_fld_val(g, d,r,f,v)  (drf_clear_fld(g, d,r,f) | drf_fld_val_placed(d,r,f,v))
#define drf_set_fld_num(g, d,r,f,n)  (drf_clear_fld(g, d,r,f) | drf_fld_num_placed(d,r,f,n))

/* return register offset */
#define drf_reg_offset(d,r) _nv_drf_reg_offset(#d,#r,NV_##d##_##r)

/* register read32 coupled with field ops.  note: p == priv given to nv_rd32 */
#define drf_rd32(p, d,r)              nv_rd32(p, drf_reg_offset(d,r))
#define drf_rd32_fld(p, d,r,f)        drf_get_fld(drf_rd32(p, d,r), d,r,f)
#define drf_rd32_fld_placed(p, d,r,f) drf_get_fld_placed(drf_rd32(p, d,r), d,r,f)

#endif /* __nv_drf_h__ */
