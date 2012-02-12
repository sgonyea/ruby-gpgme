/* gpgme_n.c -- low level interface to GPGME
   Copyright (C) 2003,2006,2007,2008,2009 Daiki Ueno

   This file is a part of Ruby-GPGME.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA */

/* While this file was written by hand, it is (semi) automatically
   generated.  High-level functions are written in Ruby instead of C
   (See "lib/gpgme.rb").  If you are about to edit this file, you may
   want to check out the translation rules:

1. Each symbol defined in this file is either a class, a module
   function, or a constant.  _No instance methods are defined here_.

2. Each symbol defined in this file follows the same naming convention
   as the GPGME API.  That is, symbol names are followed by `gpgme_'
   for functions, and `GPGME_' or `GPG_' for constants.

3. Output arguments are wrapped in arrays.  For example, the first
   argument of `gpgme_data_new' has the type `gpgme_data_t *', and to
   be used to hold a newly created gpgme_data_t object.  The
   corresponding Ruby interface expects an array (empty for typical
   cases) for that.  */

#include "ruby.h"
#include "gpgme.h"
#include <errno.h>

/* Define this if you use GPGME 1.1.2 and earlier.
   https://bugs.g10code.com/gnupg/issue715 */
#ifdef RUBY_GPGME_NEED_WORKAROUND_KEYLIST_NEXT
#define CHECK_KEYLIST_IN_PROGRESS(vctx)					\
  if (rb_iv_get (vctx, "ruby_gpgme_keylist_in_progress") != Qtrue)	\
    return LONG2NUM(gpgme_error (GPG_ERR_INV_STATE))
#define CHECK_KEYLIST_NOT_IN_PROGRESS(vctx)				\
  if (rb_iv_get (vctx, "ruby_gpgme_keylist_in_progress") == Qtrue)	\
    return LONG2NUM(gpgme_error (GPG_ERR_INV_STATE))
#define SET_KEYLIST_IN_PROGRESS(vctx)				\
  rb_iv_set (vctx, "ruby_gpgme_keylist_in_progress", Qtrue)
#define RESET_KEYLIST_IN_PROGRESS(vctx)				\
  rb_iv_set (vctx, "ruby_gpgme_keylist_in_progress", Qfalse)
#else
#define CHECK_KEYLIST_IN_PROGRESS(vctx)
#define CHECK_KEYLIST_NOT_IN_PROGRESS(vctx)
#define SET_KEYLIST_IN_PROGRESS(vctx)
#define RESET_KEYLIST_IN_PROGRESS(vctx)
#endif

/* StringValuePtr is not available in 1.6. */
#ifndef StringValuePtr
#define StringValuePtr(str) RSTRING(str)->ptr
#endif

/* STR2CSTR is obsoleted in 1.8. */
#ifndef StringValueCStr
#define StringValueCStr STR2CSTR
#endif

/* RARRAY_LEN is not available in 1.8. */
#ifndef RARRAY_LEN
#define RARRAY_LEN(a) RARRAY(a)->len
#endif

/* RARRAY_PTR is not available in 1.8. */
#ifndef RARRAY_PTR
#define RARRAY_PTR(a) RARRAY(a)->ptr
#endif

/* RSTRING_LEN is not available in 1.8.5. */
#ifndef RSTRING_LEN
#define RSTRING_LEN(a) RSTRING(a)->len
#endif

#define WRAP_GPGME_DATA(dh)					\
  Data_Wrap_Struct(cData, 0, gpgme_data_release, dh)
/* `gpgme_data_t' is typedef'ed as `struct gpgme_data *'. */
#define UNWRAP_GPGME_DATA(vdh, dh)				\
  Data_Get_Struct(vdh, struct gpgme_data, dh);

#define WRAP_GPGME_CTX(ctx)					\
  Data_Wrap_Struct(cCtx, 0, gpgme_release, ctx)
/* `gpgme_ctx_t' is typedef'ed as `struct gpgme_context *'. */
#define UNWRAP_GPGME_CTX(vctx, ctx)				\
  Data_Get_Struct(vctx, struct gpgme_context, ctx)

#define WRAP_GPGME_KEY(key)					\
  Data_Wrap_Struct(cKey, 0, gpgme_key_unref, key)
/* `gpgme_key_t' is typedef'ed as `struct _gpgme_key *'. */
#define UNWRAP_GPGME_KEY(vkey, key)				\
  Data_Get_Struct(vkey, struct _gpgme_key, key)

#define WRAP_GPGME_TRUST_ITEM(item)					  \
  Data_Wrap_Struct(cTrustItem, 0, gpgme_trust_item_unref, item)
/* `gpgme_trust_item_t' is typedef'ed as `struct _gpgme_trust_item *'. */
#define UNWRAP_GPGME_TRUST_ITEM(vitem, item)			\
  Data_Get_Struct(vitem, struct _gpgme_trust_item, item)

static VALUE cEngineInfo,
  cCtx,
  cData,
  cKey,
  cSubKey,
  cUserID,
  cKeySig,
  cInvalidKey,
  cNewSignature,
  cSignature,
  cSigNotation,
  cTrustItem,
  cDecryptResult,
  cVerifyResult,
  cSignResult,
  cEncryptResult,
  cImportStatus,
  cImportResult;

// @TODO: Remove. This is only in place so the rest of the tests pass.
static VALUE
rb_s_gpgme_check_version (VALUE dummy, VALUE vreq)
{
  const char *result = gpgme_check_version (NIL_P(vreq) ? NULL :
             StringValueCStr(vreq));
  return result ? rb_str_new2 (result) : Qnil;
}

static VALUE
rb_s_gpgme_hash_algo_name (VALUE dummy, VALUE valgo)
{
  const char *name = gpgme_hash_algo_name (NUM2INT(valgo));
  if (name)
    return rb_str_new2 (name);
  return Qnil;
}

static VALUE
rb_s_gpgme_err_code (VALUE dummy, VALUE verr)
{
  return INT2FIX(gpgme_err_code (NUM2LONG(verr)));
}

static VALUE
rb_s_gpgme_err_source (VALUE dummy, VALUE verr)
{
  return INT2FIX(gpgme_err_source (NUM2LONG(verr)));
}

static VALUE
rb_s_gpgme_strerror (VALUE dummy, VALUE verr)
{
  return rb_str_new2 (gpgme_strerror (NUM2LONG(verr)));
}

static VALUE
rb_s_gpgme_data_new (VALUE dummy, VALUE rdh)
{
  gpgme_data_t dh;
  gpgme_error_t err = gpgme_data_new (&dh);

  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    rb_ary_store (rdh, 0, WRAP_GPGME_DATA(dh));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_new_from_mem (VALUE dummy, VALUE rdh, VALUE vbuffer,
			      VALUE vsize)
{
  gpgme_data_t dh;
  VALUE vdh;
  size_t size = NUM2UINT(vsize);
  gpgme_error_t err;

  if (RSTRING_LEN(vbuffer) < size)
    rb_raise (rb_eArgError, "argument out of range");

  err = gpgme_data_new_from_mem (&dh, StringValuePtr(vbuffer), size, 1);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      vdh = WRAP_GPGME_DATA(dh);
      rb_ary_store (rdh, 0, vdh);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_new_from_fd (VALUE dummy, VALUE rdh, VALUE vfd)
{
  gpgme_data_t dh;
  gpgme_error_t err = gpgme_data_new_from_fd (&dh, NUM2INT(vfd));
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    rb_ary_store (rdh, 0, WRAP_GPGME_DATA(dh));
  return LONG2NUM(err);
}

static ssize_t
read_cb (void *handle, void *buffer, size_t size)
{
  VALUE vcb = (VALUE)handle, vcbs, vhook_value, vbuffer;

  vcbs = RARRAY_PTR(vcb)[0];
  vhook_value = RARRAY_PTR(vcb)[1];

  vbuffer = rb_funcall (vcbs, rb_intern ("read"), 2, vhook_value,
			LONG2NUM(size));
  if (NIL_P(vbuffer))
    return 0;
  memcpy (buffer, StringValuePtr(vbuffer), RSTRING_LEN(vbuffer));
  return RSTRING_LEN(vbuffer);
}

static ssize_t
write_cb (void *handle, const void *buffer, size_t size)
{
  VALUE vcb = (VALUE)handle, vcbs, vhook_value, vbuffer, vnwrite;

  vcbs = RARRAY_PTR(vcb)[0];
  vhook_value = RARRAY_PTR(vcb)[1];
  vbuffer = rb_str_new (buffer, size);

  vnwrite = rb_funcall (vcbs, rb_intern ("write"), 3,
			vhook_value, vbuffer, LONG2NUM(size));
  return NUM2LONG(vnwrite);
}

static off_t
seek_cb (void *handle, off_t offset, int whence)
{
  VALUE vcb = (VALUE)handle, vcbs, vhook_value, vpos;
  ID id_seek = rb_intern ("seek");

  vcbs = RARRAY_PTR(vcb)[0];
  vhook_value = RARRAY_PTR(vcb)[1];

  if (rb_respond_to (vcbs, id_seek))
    {
      vpos = rb_funcall (vcbs, id_seek, 3,
			 vhook_value, LONG2NUM(offset), INT2FIX(whence));
      return NUM2LONG(vpos);
    }
  errno = ENOSYS;
  return -1;
}

static struct gpgme_data_cbs cbs =
  {
    .read = read_cb,
    .write = write_cb,
    .seek = seek_cb,
    .release = NULL
  };

static VALUE
rb_s_gpgme_data_new_from_cbs (VALUE dummy, VALUE rdh, VALUE vcbs,
			      VALUE vhandle)
{
  gpgme_data_t dh;
  gpgme_error_t err;
  VALUE vcbs_handle = rb_ary_new ();

  rb_ary_push (vcbs_handle, vcbs);
  rb_ary_push (vcbs_handle, vhandle);

  err = gpgme_data_new_from_cbs (&dh, &cbs, (void*)vcbs_handle);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      VALUE vdh = WRAP_GPGME_DATA(dh);
      /* Keep a reference to avoid GC. */
      rb_iv_set (vdh, "@cbs_handle", vcbs_handle);
      rb_ary_store (rdh, 0, vdh);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_read (VALUE dummy, VALUE vdh, VALUE vlength)
{
  gpgme_data_t dh;
  ssize_t length = NUM2LONG(vlength), nread;
  void *buffer;
  VALUE vbuffer = Qnil;

  UNWRAP_GPGME_DATA(vdh, dh);

  buffer = ALLOC_N (char, length);
  nread = gpgme_data_read (dh, buffer, length);
  if (nread > 0)
    vbuffer = rb_str_new (buffer, nread);
  xfree (buffer);
  if (nread < 0)
    rb_sys_fail ("rb_s_gpgme_data_read");
  return vbuffer;
}

static VALUE
rb_s_gpgme_data_seek (VALUE dummy, VALUE vdh, VALUE voffset, VALUE vwhence)
{
  gpgme_data_t dh;
  off_t pos;

  UNWRAP_GPGME_DATA(vdh, dh);
  pos = gpgme_data_seek (dh, NUM2LONG(voffset), NUM2INT(vwhence));
  if (pos < 0)
    rb_sys_fail ("rb_s_gpgme_data_seek");
  return LONG2NUM(pos);
}

static VALUE
rb_s_gpgme_data_write (VALUE dummy, VALUE vdh, VALUE vbuf, VALUE vlen)
{
  gpgme_data_t dh;
  ssize_t nwrite;

  UNWRAP_GPGME_DATA(vdh, dh);
  nwrite = gpgme_data_write (dh, StringValuePtr(vbuf), NUM2UINT(vlen));
  if (nwrite < 0)
    rb_sys_fail ("rb_s_gpgme_data_write");
  return LONG2NUM(nwrite);
}

static VALUE
rb_s_gpgme_data_get_encoding (VALUE dummy, VALUE vdh)
{
  gpgme_data_t dh;
  gpgme_error_t err;

  UNWRAP_GPGME_DATA(vdh, dh);
  err = gpgme_data_get_encoding (dh);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_data_set_encoding (VALUE dummy, VALUE vdh, VALUE venc)
{
  gpgme_data_t dh;
  gpgme_error_t err;

  UNWRAP_GPGME_DATA(vdh, dh);
  err = gpgme_data_set_encoding (dh, NUM2INT(venc));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_new (VALUE dummy, VALUE rctx)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err = gpgme_new (&ctx);

  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    rb_ary_store (rctx, 0, WRAP_GPGME_CTX(ctx));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_release (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_release (ctx);
  DATA_PTR(vctx) = NULL;
  return Qnil;
}

static VALUE
rb_s_gpgme_set_protocol (VALUE dummy, VALUE vctx, VALUE vproto)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  err = gpgme_set_protocol (ctx, NUM2INT(vproto));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_protocol (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_protocol_t proto;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  proto = gpgme_get_protocol (ctx);
  return INT2FIX(proto);
}

static VALUE
rb_s_gpgme_set_armor (VALUE dummy, VALUE vctx, VALUE vyes)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_set_armor (ctx, NUM2INT(vyes));

  return Qnil;
}

static VALUE
rb_s_gpgme_get_armor (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  int yes;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  yes = gpgme_get_armor (ctx);
  return INT2FIX(yes);
}

static VALUE
rb_s_gpgme_set_textmode (VALUE dummy, VALUE vctx, VALUE vyes)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_set_textmode (ctx, NUM2INT(vyes));
  return Qnil;
}

static VALUE
rb_s_gpgme_get_textmode (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  int yes;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  yes = gpgme_get_textmode (ctx);
  return INT2FIX(yes);
}

static VALUE
rb_s_gpgme_set_include_certs (VALUE dummy, VALUE vctx, VALUE vnr_of_certs)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_set_include_certs (ctx, NUM2INT(vnr_of_certs));
  return Qnil;
}

static VALUE
rb_s_gpgme_get_include_certs (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  err = gpgme_get_include_certs (ctx);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_set_keylist_mode (VALUE dummy, VALUE vctx, VALUE vmode)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  err = gpgme_set_keylist_mode (ctx, NUM2INT(vmode));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_keylist_mode (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  int mode;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  mode = gpgme_get_keylist_mode (ctx);
  return INT2FIX(mode);
}

static gpgme_error_t
passphrase_cb (void *hook, const char *uid_hint, const char *passphrase_info,
	       int prev_was_bad, int fd)
{
  VALUE vcb = (VALUE)hook, vpassfunc, vhook_value;

  vpassfunc = RARRAY_PTR(vcb)[0];
  vhook_value = RARRAY_PTR(vcb)[1];

  rb_funcall (vpassfunc, rb_intern ("call"), 5,
	      vhook_value,
	      uid_hint ? rb_str_new2 (uid_hint) : Qnil,
	      passphrase_info ? rb_str_new2 (passphrase_info) : Qnil,
	      INT2FIX(prev_was_bad),
	      INT2NUM(fd));
  return gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR);
}

static VALUE
rb_s_gpgme_set_passphrase_cb (VALUE dummy, VALUE vctx, VALUE vpassfunc,
			      VALUE vhook_value)
{
  gpgme_ctx_t ctx;
  VALUE vcb = rb_ary_new ();

  rb_ary_push (vcb, vpassfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@passphrase_cb", vcb);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_set_passphrase_cb (ctx, passphrase_cb, (void*)vcb);
  return Qnil;
}

static VALUE
rb_s_gpgme_get_passphrase_cb (VALUE dummy, VALUE vctx, VALUE rpassfunc,
			      VALUE rhook_value)
{
  VALUE vcb = rb_iv_get (vctx, "@passphrase_cb");

  /* No need to call gpgme_get_passphrase_cb. */
  rb_ary_store (rpassfunc, 0, RARRAY_PTR(vcb)[0]);
  rb_ary_store (rhook_value, 0, RARRAY_PTR(vcb)[1]);
  return Qnil;
}

static void
progress_cb (void *hook, const char *what, int type, int current, int total)
{
  VALUE vcb = (VALUE)hook, vprogfunc, vhook_value;

  vprogfunc = RARRAY_PTR(vcb)[0];
  vhook_value = RARRAY_PTR(vcb)[1];

  rb_funcall (vprogfunc, rb_intern ("call"), 5, vhook_value,
	      rb_str_new2 (what), INT2NUM(type), INT2NUM(current),
	      INT2NUM(total));
}

static VALUE
rb_s_gpgme_set_progress_cb (VALUE dummy, VALUE vctx, VALUE vprogfunc,
			    VALUE vhook_value)
{
  gpgme_ctx_t ctx;
  VALUE vcb = rb_ary_new ();

  rb_ary_push (vcb, vprogfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@progress_cb", vcb);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_set_progress_cb (ctx, progress_cb, (void*)vcb);

  return Qnil;
}

static VALUE
rb_s_gpgme_get_progress_cb (VALUE dummy, VALUE vctx, VALUE rprogfunc,
			    VALUE rhook_value)
{
  VALUE vcb = rb_iv_get (vctx, "@progress_cb");
  rb_ary_store (rprogfunc, 0, RARRAY_PTR(vcb)[0]);
  rb_ary_store (rhook_value, 0, RARRAY_PTR(vcb)[1]);
  return Qnil;
}

static VALUE
rb_s_gpgme_set_locale (VALUE dummy, VALUE vctx, VALUE vcategory, VALUE vvalue)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_set_locale (ctx, NUM2INT(vcategory), StringValueCStr(vvalue));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_keylist_start (VALUE dummy, VALUE vctx, VALUE vpattern,
			     VALUE vsecret_only)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_op_keylist_start (ctx, NIL_P(vpattern) ? NULL :
				StringValueCStr(vpattern),
				NUM2INT(vsecret_only));
  if (gpgme_err_code (err) == GPG_ERR_NO_ERROR)
    SET_KEYLIST_IN_PROGRESS(vctx);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_keylist_ext_start (VALUE dummy, VALUE vctx, VALUE vpattern,
				 VALUE vsecret_only)
{
  gpgme_ctx_t ctx;
  const char **pattern = NULL;
  int i, err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  if (!NIL_P(vpattern))
    {
      /* Convert RARRAY into `const char *' array. */
      pattern = ALLOC_N(const char *, RARRAY_LEN(vpattern) + 1);
      for (i = 0; i<RARRAY_LEN(vpattern); i++)
	pattern[i] = StringValueCStr(RARRAY_PTR(vpattern)[i]);
      pattern[RARRAY_LEN(vpattern)] = NULL;
    }

  err = gpgme_op_keylist_ext_start (ctx, pattern, NUM2INT(vsecret_only), 0);
  if (gpgme_err_code (err) == GPG_ERR_NO_ERROR)
    SET_KEYLIST_IN_PROGRESS(vctx);
  if (pattern)
    xfree (pattern);
  return LONG2NUM(err);
}

static VALUE
save_gpgme_key_attrs (VALUE vkey, gpgme_key_t key)
{
  VALUE vsubkeys, vuids;
  gpgme_subkey_t subkey;
  gpgme_user_id_t user_id;

  rb_iv_set (vkey, "@keylist_mode", INT2FIX(key->keylist_mode));
  rb_iv_set (vkey, "@revoked", INT2FIX(key->revoked));
  rb_iv_set (vkey, "@expired", INT2FIX(key->expired));
  rb_iv_set (vkey, "@disabled", INT2FIX(key->disabled));
  rb_iv_set (vkey, "@invalid", INT2FIX(key->invalid));
  rb_iv_set (vkey, "@can_encrypt", INT2FIX(key->can_encrypt));
  rb_iv_set (vkey, "@can_sign", INT2FIX(key->can_sign));
  rb_iv_set (vkey, "@can_certify", INT2FIX(key->can_certify));
  rb_iv_set (vkey, "@can_authenticate", INT2FIX(key->can_authenticate));
  rb_iv_set (vkey, "@secret", INT2FIX(key->secret));
  rb_iv_set (vkey, "@protocol", INT2FIX(key->protocol));
  if (key->issuer_serial)
    rb_iv_set (vkey, "@issuer_serial", rb_str_new2 (key->issuer_serial));
  if (key->issuer_name)
    rb_iv_set (vkey, "@issuer_name", rb_str_new2 (key->issuer_name));
  if (key->chain_id)
    rb_iv_set (vkey, "@chain_id", rb_str_new2 (key->chain_id));
  rb_iv_set (vkey, "@owner_trust", INT2FIX(key->owner_trust));
  vsubkeys = rb_ary_new ();
  rb_iv_set (vkey, "@subkeys", vsubkeys);
  for (subkey = key->subkeys; subkey; subkey = subkey->next)
    {
      VALUE vsubkey = rb_class_new_instance(0, NULL, cSubKey);
      rb_iv_set (vsubkey, "@revoked", INT2FIX(subkey->revoked));
      rb_iv_set (vsubkey, "@expired", INT2FIX(subkey->expired));
      rb_iv_set (vsubkey, "@disabled", INT2FIX(subkey->disabled));
      rb_iv_set (vsubkey, "@invalid", INT2FIX(subkey->invalid));
      rb_iv_set (vsubkey, "@can_encrypt", INT2FIX(subkey->can_encrypt));
      rb_iv_set (vsubkey, "@can_sign", INT2FIX(subkey->can_sign));
      rb_iv_set (vsubkey, "@can_certify", INT2FIX(subkey->can_certify));
      rb_iv_set (vsubkey, "@can_authenticate",
		 INT2FIX(subkey->can_authenticate));
      rb_iv_set (vsubkey, "@secret", INT2FIX(subkey->secret));
      rb_iv_set (vsubkey, "@pubkey_algo", INT2FIX(subkey->pubkey_algo));
      rb_iv_set (vsubkey, "@length", UINT2NUM(subkey->length));
      rb_iv_set (vsubkey, "@keyid", rb_str_new2 (subkey->keyid));
      if (subkey->fpr)
        rb_iv_set (vsubkey, "@fpr", rb_str_new2 (subkey->fpr));
      rb_iv_set (vsubkey, "@timestamp", LONG2NUM(subkey->timestamp));
      rb_iv_set (vsubkey, "@expires", LONG2NUM(subkey->expires));
      rb_ary_push (vsubkeys, vsubkey);
    }
  vuids = rb_ary_new ();
  rb_iv_set (vkey, "@uids", vuids);
  for (user_id = key->uids; user_id; user_id = user_id->next)
    {
      VALUE vuser_id = rb_class_new_instance(0, NULL, cUserID), vsignatures;
      rb_iv_set (vuser_id, "@revoked", INT2FIX(user_id->revoked));
      rb_iv_set (vuser_id, "@invalid", INT2FIX(user_id->invalid));
      rb_iv_set (vuser_id, "@validity", INT2FIX(user_id->validity));
      rb_iv_set (vuser_id, "@uid", rb_str_new2 (user_id->uid));
      rb_iv_set (vuser_id, "@name", rb_str_new2 (user_id->name));
      rb_iv_set (vuser_id, "@comment", rb_str_new2 (user_id->comment));
      rb_iv_set (vuser_id, "@email", rb_str_new2 (user_id->email));

      vsignatures = rb_ary_new ();
      rb_iv_set (vuser_id, "@signatures", vsignatures);
      gpgme_key_sig_t key_sig;
      for (key_sig = user_id->signatures; key_sig; key_sig = key_sig->next)
	{
	  VALUE vkey_sig = rb_class_new_instance(0, NULL, cKeySig);
	  rb_iv_set (vkey_sig, "@revoked", INT2FIX(key_sig->revoked));
	  rb_iv_set (vkey_sig, "@expired", INT2FIX(key_sig->expired));
	  rb_iv_set (vkey_sig, "@invalid", INT2FIX(key_sig->invalid));
	  rb_iv_set (vkey_sig, "@exportable", INT2FIX(key_sig->exportable));
	  rb_iv_set (vkey_sig, "@pubkey_algo", INT2FIX(key_sig->pubkey_algo));
	  rb_iv_set (vkey_sig, "@keyid", rb_str_new2 (key_sig->keyid));
	  rb_iv_set (vkey_sig, "@timestamp", LONG2NUM(key_sig->timestamp));
	  rb_iv_set (vkey_sig, "@expires", LONG2NUM(key_sig->expires));
	  rb_ary_push (vsignatures, vkey_sig);
	}
      rb_ary_push (vuids, vuser_id);
    }
  return vkey;
}

static VALUE
rb_s_gpgme_op_keylist_next (VALUE dummy, VALUE vctx, VALUE rkey)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_error_t err;

  CHECK_KEYLIST_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_op_keylist_next (ctx, &key);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      VALUE vkey = WRAP_GPGME_KEY(key);
      save_gpgme_key_attrs (vkey, key);
      rb_ary_store (rkey, 0, vkey);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_keylist_end (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  CHECK_KEYLIST_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_op_keylist_end (ctx);
  RESET_KEYLIST_IN_PROGRESS(vctx);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_get_key (VALUE dummy, VALUE vctx, VALUE vfpr, VALUE rkey,
		    VALUE vsecret)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_key_t key;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  err = gpgme_get_key (ctx, StringValueCStr(vfpr), &key, NUM2INT(vsecret));

  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      VALUE vkey = WRAP_GPGME_KEY(key);
      save_gpgme_key_attrs (vkey, key);
      rb_ary_store (rkey, 0, vkey);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_genkey (VALUE dummy, VALUE vctx, VALUE vparms, VALUE vpubkey,
		      VALUE vseckey)
{
  gpgme_ctx_t ctx;
  gpgme_data_t pubkey = NULL, seckey = NULL;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  if (!NIL_P(vpubkey))
    UNWRAP_GPGME_DATA(vpubkey, pubkey);
  if (!NIL_P(vseckey))
    UNWRAP_GPGME_DATA(vseckey, seckey);

  err = gpgme_op_genkey (ctx, StringValueCStr(vparms), pubkey, seckey);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_genkey_start (VALUE dummy, VALUE vctx, VALUE vparms,
			    VALUE vpubkey, VALUE vseckey)
{
  gpgme_ctx_t ctx;
  gpgme_data_t pubkey = NULL, seckey = NULL;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  if (!NIL_P(vpubkey))
    UNWRAP_GPGME_DATA(vpubkey, pubkey);
  if (!NIL_P(vseckey))
    UNWRAP_GPGME_DATA(vseckey, seckey);

  err = gpgme_op_genkey_start (ctx, StringValueCStr(vparms), pubkey, seckey);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export (VALUE dummy, VALUE vctx, VALUE vpattern, VALUE vmode,
		      VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  err = gpgme_op_export (ctx, StringValueCStr(vpattern), NUM2UINT(vmode),
			 keydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export_start (VALUE dummy, VALUE vctx, VALUE vpattern,
			    VALUE vmode, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  err = gpgme_op_export_start (ctx, StringValueCStr(vpattern),
			       NUM2UINT(vmode), keydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export_ext (VALUE dummy, VALUE vctx, VALUE vpattern, VALUE vmode,
			  VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  const char **pattern;
  int i;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  pattern = ALLOC_N(const char *, RARRAY_LEN(vpattern));
  for (i = 0; i < RARRAY_LEN(vpattern); i++)
    pattern[i] = StringValueCStr(RARRAY_PTR(vpattern)[i]);
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  err = gpgme_op_export_ext (ctx, pattern, NUM2UINT(vmode), keydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export_ext_start (VALUE dummy, VALUE vctx, VALUE vpattern,
			    VALUE vmode, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;
  const char **pattern;
  int i;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  pattern = ALLOC_N(const char *, RARRAY_LEN(vpattern));
  for (i = 0; i < RARRAY_LEN(vpattern); i++)
    pattern[i] = StringValueCStr(RARRAY_PTR(vpattern)[i]);
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  err = gpgme_op_export_ext_start (ctx, pattern, NUM2UINT(vmode), keydata);
  return LONG2NUM(err);
}

#ifdef HAVE_GPGME_OP_EXPORT_KEYS
static VALUE
rb_s_gpgme_op_export_keys (VALUE dummy, VALUE vctx, VALUE vkeys,
			   VALUE vmode, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_key_t *keys;
  gpgme_data_t keydata;
  gpgme_error_t err;
  int i;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  keys = ALLOC_N(gpgme_key_t, RARRAY_LEN(vkeys) + 1);
  for (i = 0; i < RARRAY_LEN(vkeys); i++)
    UNWRAP_GPGME_KEY(RARRAY_PTR(vkeys)[i], keys[i]);

  UNWRAP_GPGME_DATA(vkeydata, keydata);

  err = gpgme_op_export_keys (ctx, keys, NUM2UINT(vmode), keydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_export_keys_start (VALUE dummy, VALUE vctx, VALUE vkeys,
				 VALUE vmode, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_key_t *keys;
  gpgme_data_t keydata;
  gpgme_error_t err;
  int i;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  keys = ALLOC_N(gpgme_key_t, RARRAY_LEN(vkeys) + 1);
  for (i = 0; i < RARRAY_LEN(vkeys); i++)
    UNWRAP_GPGME_KEY(RARRAY_PTR(vkeys)[i], keys[i]);

  UNWRAP_GPGME_DATA(vkeydata, keydata);

  err = gpgme_op_export_keys_start (ctx, keys, NUM2UINT(vmode), keydata);
  return LONG2NUM(err);
}
#endif	/*HAVE_GPGME_OP_EXPORT_KEYS*/

static VALUE
rb_s_gpgme_op_import (VALUE dummy, VALUE vctx, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  err = gpgme_op_import (ctx, keydata);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_import_start (VALUE dummy, VALUE vctx, VALUE vkeydata)
{
  gpgme_ctx_t ctx;
  gpgme_data_t keydata;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vkeydata, keydata);

  err = gpgme_op_import_start (ctx, keydata);
  return LONG2NUM(err);
}

#ifdef HAVE_GPGME_OP_EXPORT_KEYS
static VALUE
rb_s_gpgme_op_import_keys (VALUE dummy, VALUE vctx, VALUE vkeys)
{
  gpgme_ctx_t ctx;
  gpgme_key_t *keys;
  gpgme_error_t err;
  int i;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  keys = ALLOC_N(gpgme_key_t, RARRAY_LEN(vkeys) + 1);
  for (i = 0; i < RARRAY_LEN(vkeys); i++)
    UNWRAP_GPGME_KEY(RARRAY_PTR(vkeys)[i], keys[i]);
  keys[i] = NULL;

  err = gpgme_op_import_keys (ctx, keys);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_import_keys_start (VALUE dummy, VALUE vctx, VALUE vkeys)
{
  gpgme_ctx_t ctx;
  gpgme_key_t *keys;
  gpgme_error_t err;
  int i;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  keys = ALLOC_N(gpgme_key_t, RARRAY_LEN(vkeys) + 1);
  for (i = 0; i < RARRAY_LEN(vkeys); i++)
    UNWRAP_GPGME_KEY(RARRAY_PTR(vkeys)[i], keys[i]);
  keys[i] = NULL;

  err = gpgme_op_import_keys_start (ctx, keys);
  return LONG2NUM(err);
}
#endif	/*HAVE_GPGME_OP_EXPORT_KEYS*/

static VALUE
rb_s_gpgme_op_import_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_import_result_t result;
  gpgme_import_status_t status;
  VALUE vresult, vimports;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  result = gpgme_op_import_result (ctx);
  vresult = rb_class_new_instance (0, NULL, cImportResult);
  rb_iv_set (vresult, "@considered", INT2NUM(result->considered));
  rb_iv_set (vresult, "@no_user_id", INT2NUM(result->no_user_id));
  rb_iv_set (vresult, "@imported", INT2NUM(result->imported));
  rb_iv_set (vresult, "@imported_rsa", INT2NUM(result->imported_rsa));
  rb_iv_set (vresult, "@unchanged", INT2NUM(result->unchanged));
  rb_iv_set (vresult, "@new_user_ids", INT2NUM(result->new_user_ids));
  rb_iv_set (vresult, "@new_sub_keys", INT2NUM(result->new_sub_keys));
  rb_iv_set (vresult, "@new_signatures", INT2NUM(result->new_signatures));
  rb_iv_set (vresult, "@new_revocations", INT2NUM(result->new_revocations));
  rb_iv_set (vresult, "@secret_read", INT2NUM(result->secret_read));
  rb_iv_set (vresult, "@secret_imported", INT2NUM(result->secret_imported));
  rb_iv_set (vresult, "@secret_unchanged", INT2NUM(result->secret_unchanged));
  rb_iv_set (vresult, "@not_imported", INT2NUM(result->not_imported));
  vimports = rb_ary_new ();
  rb_iv_set (vresult, "@imports", vimports);
  for (status = result->imports; status;
       status = status->next)
    {
      VALUE vstatus =
	rb_class_new_instance (0, NULL, cImportStatus);
      rb_iv_set (vstatus, "@fpr", rb_str_new2 (status->fpr));
      rb_iv_set (vstatus, "@result", LONG2NUM(status->result));
      rb_iv_set (vstatus, "@status", UINT2NUM(status->status));
      rb_ary_push (vimports, vstatus);
    }
  return vresult;
}

static VALUE
rb_s_gpgme_op_delete (VALUE dummy, VALUE vctx, VALUE vkey, VALUE vallow_secret)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_KEY(vkey, key);

  err = gpgme_op_delete (ctx, key, NUM2INT(vallow_secret));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_delete_start (VALUE dummy, VALUE vctx, VALUE vkey,
			    VALUE vallow_secret)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_KEY(vkey, key);

  err = gpgme_op_delete_start (ctx, key, NUM2INT(vallow_secret));
  return LONG2NUM(err);
}

static gpgme_error_t
edit_cb (void *hook, gpgme_status_code_t status, const char *args, int fd)
{
  VALUE vcb = (VALUE)hook, veditfunc, vhook_value;


  veditfunc = RARRAY_PTR(vcb)[0];
  vhook_value = RARRAY_PTR(vcb)[1];

  rb_funcall (veditfunc, rb_intern ("call"), 4, vhook_value, INT2FIX(status),
	      rb_str_new2 (args), INT2NUM(fd));
  return gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_NO_ERROR);
}

static VALUE
rb_s_gpgme_op_edit (VALUE dummy, VALUE vctx, VALUE vkey,
		    VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_KEY(vkey, key);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@edit_cb", vcb);

  err = gpgme_op_edit (ctx, key, edit_cb, (void *)vcb, out);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_edit_start (VALUE dummy, VALUE vctx, VALUE vkey,
			  VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_KEY(vkey, key);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@edit_cb", vcb);

  err = gpgme_op_edit_start (ctx, key, edit_cb, (void *)vcb, out);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_card_edit (VALUE dummy, VALUE vctx, VALUE vkey,
		    VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_KEY(vkey, key);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@card_edit_cb", vcb);

  err = gpgme_op_card_edit (ctx, key, edit_cb, (void *)vcb, out);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_card_edit_start (VALUE dummy, VALUE vctx, VALUE vkey,
			       VALUE veditfunc, VALUE vhook_value, VALUE vout)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_data_t out = NULL;
  VALUE vcb;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_KEY(vkey, key);
  if (!NIL_P(vout))
    UNWRAP_GPGME_DATA(vout, out);

  vcb = rb_ary_new ();
  rb_ary_push (vcb, veditfunc);
  rb_ary_push (vcb, vhook_value);
  /* Keep a reference to avoid GC. */
  rb_iv_set (vctx, "@card_edit_cb", vcb);

  err = gpgme_op_card_edit_start (ctx, key, edit_cb, (void *)vcb, out);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_trustlist_start (VALUE dummy, VALUE vctx, VALUE vpattern,
			       VALUE vmax_level)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  err = gpgme_op_trustlist_start (ctx, StringValueCStr(vpattern),
				  NUM2INT(vmax_level));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_trustlist_next (VALUE dummy, VALUE vctx, VALUE ritem)
{
  gpgme_ctx_t ctx;
  gpgme_trust_item_t item;
  gpgme_error_t err;
  VALUE vitem;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_op_trustlist_next (ctx, &item);
  if (gpgme_err_code(err) == GPG_ERR_NO_ERROR)
    {
      vitem = WRAP_GPGME_TRUST_ITEM(item);
      rb_iv_set (vitem, "@keyid", rb_str_new2 (item->keyid));
      rb_iv_set (vitem, "@type", INT2FIX(item->type));
      rb_iv_set (vitem, "@level", INT2FIX(item->level));
      if (item->owner_trust)
	rb_iv_set (vitem, "@owner_trust", rb_str_new2 (item->owner_trust));
      rb_iv_set (vitem, "@validity", rb_str_new2 (item->validity));
      if (item->name)
	rb_iv_set (vitem, "@name", rb_str_new2 (item->name));
      rb_ary_store (ritem, 0, vitem);
    }
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_trustlist_end (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  err = gpgme_op_trustlist_end (ctx);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_decrypt (VALUE dummy, VALUE vctx, VALUE vcipher, VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t cipher, plain;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vcipher, cipher);
  UNWRAP_GPGME_DATA(vplain, plain);

  err = gpgme_op_decrypt (ctx, cipher, plain);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_decrypt_start (VALUE dummy, VALUE vctx, VALUE vcipher,
			     VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t cipher, plain;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vcipher, cipher);
  UNWRAP_GPGME_DATA(vplain, plain);

  err = gpgme_op_decrypt_start (ctx, cipher, plain);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_decrypt_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_decrypt_result_t result;
  VALUE vresult;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  result = gpgme_op_decrypt_result (ctx);
  vresult = rb_class_new_instance (0, NULL, cDecryptResult);
  if (result->unsupported_algorithm)
    rb_iv_set (vresult, "@unsupported_algorithm",
	       rb_str_new2 (result->unsupported_algorithm));
  rb_iv_set (vresult, "@wrong_key_usage", INT2FIX(result->wrong_key_usage));
  return vresult;
}

static VALUE
rb_s_gpgme_op_verify (VALUE dummy, VALUE vctx, VALUE vsig, VALUE vsigned_text,
		      VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t sig, signed_text = NULL, plain = NULL;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vsig, sig);
  if (!NIL_P(vsigned_text))
    UNWRAP_GPGME_DATA(vsigned_text, signed_text);
  if (!NIL_P(vplain))
    UNWRAP_GPGME_DATA(vplain, plain);

  err = gpgme_op_verify (ctx, sig, signed_text, plain);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_verify_start (VALUE dummy, VALUE vctx, VALUE vsig,
			    VALUE vsigned_text, VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t sig, signed_text = NULL, plain = NULL;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vsig, sig);
  if (!NIL_P(vsigned_text))
    UNWRAP_GPGME_DATA(vsigned_text, signed_text);
  if (!NIL_P(vplain))
    UNWRAP_GPGME_DATA(vplain, plain);

  err = gpgme_op_verify_start (ctx, sig, signed_text, plain);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_verify_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_verify_result_t verify_result;
  gpgme_signature_t signature;
  VALUE vverify_result, vsignatures = rb_ary_new ();

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  verify_result = gpgme_op_verify_result (ctx);
  vverify_result = rb_class_new_instance(0, NULL, cVerifyResult);
  rb_iv_set (vverify_result, "@signatures", vsignatures);
  for (signature = verify_result->signatures; signature;
       signature = signature->next)
    {
      VALUE vsignature = rb_class_new_instance(0, NULL, cSignature),
	vnotations = rb_ary_new ();
      gpgme_sig_notation_t notation;
      rb_iv_set (vsignature, "@summary", INT2FIX(signature->summary));
      rb_iv_set (vsignature, "@fpr", rb_str_new2 (signature->fpr));
      rb_iv_set (vsignature, "@status", LONG2NUM(signature->status));
      rb_iv_set (vsignature, "@notations", vnotations);
      for (notation = signature->notations; notation;
	   notation = notation->next)
	{
	  VALUE vnotation = rb_class_new_instance(0, NULL, cSigNotation);
	  rb_iv_set (vnotation, "@name", rb_str_new2 (notation->name));
	  rb_iv_set (vnotation, "@value", rb_str_new2 (notation->value));
	  rb_ary_push (vnotations, vnotation);
	}
      rb_iv_set (vsignature, "@timestamp", ULONG2NUM(signature->timestamp));
      rb_iv_set (vsignature, "@exp_timestamp",
		 ULONG2NUM(signature->exp_timestamp));
      rb_iv_set (vsignature, "@wrong_key_usage",
		 INT2FIX(signature->wrong_key_usage));
      rb_iv_set (vsignature, "@validity", INT2FIX(signature->validity));
      rb_iv_set (vsignature, "@validity_reason",
		 LONG2NUM(signature->validity_reason));
      /* PKA related fields were added in 1.1.1. */
#ifdef GPGME_STATUS_PKA_TRUST_BAD
      rb_iv_set (vsignature, "@pka_trust", INT2FIX(signature->pka_trust));
      rb_iv_set (vsignature, "@pka_address",
		 rb_str_new2 (signature->pka_address));
#endif
      rb_ary_push (vsignatures, vsignature);
    }
  return vverify_result;
}

static VALUE
rb_s_gpgme_op_decrypt_verify (VALUE dummy, VALUE vctx, VALUE vcipher,
			      VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t cipher, plain;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vcipher, cipher);
  UNWRAP_GPGME_DATA(vplain, plain);

  err = gpgme_op_decrypt_verify (ctx, cipher, plain);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_decrypt_verify_start (VALUE dummy, VALUE vctx, VALUE vcipher,
				    VALUE vplain)
{
  gpgme_ctx_t ctx;
  gpgme_data_t cipher, plain;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vcipher, cipher);
  UNWRAP_GPGME_DATA(vplain, plain);

  err = gpgme_op_decrypt_verify_start (ctx, cipher, plain);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_signers_clear (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  gpgme_signers_clear (ctx);
  return Qnil;
}

static VALUE
rb_s_gpgme_signers_add (VALUE dummy, VALUE vctx, VALUE vkey)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_error_t err;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_KEY(vkey, key);

  err = gpgme_signers_add (ctx, key);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_signers_enum (VALUE dummy, VALUE vctx, VALUE vseq)
{
  gpgme_ctx_t ctx;
  gpgme_key_t key;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  key = gpgme_signers_enum (ctx, NUM2INT(vseq));
  if (!key)
    return Qnil;
  return WRAP_GPGME_KEY(key);
}

static VALUE
rb_s_gpgme_op_sign (VALUE dummy, VALUE vctx, VALUE vplain, VALUE vsig,
		    VALUE vmode)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, sig;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vsig, sig);

  err = gpgme_op_sign (ctx, plain, sig, NUM2INT(vmode));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_sign_start (VALUE dummy, VALUE vctx, VALUE vplain, VALUE vsig,
			  VALUE vmode)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, sig;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vsig, sig);

  err = gpgme_op_sign_start (ctx, plain, sig, NUM2INT(vmode));
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_sign_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_sign_result_t result;
  gpgme_invalid_key_t invalid_key;
  gpgme_new_signature_t new_signature;
  VALUE vresult, vinvalid_signers, vsignatures;

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  result = gpgme_op_sign_result (ctx);
  vresult = rb_class_new_instance (0, NULL, cSignResult);
  vinvalid_signers = rb_ary_new ();
  rb_iv_set (vresult, "@invalid_signers", vinvalid_signers);
  for (invalid_key = result->invalid_signers; invalid_key;
       invalid_key = invalid_key->next)
    {
      VALUE vinvalid_key =
	rb_class_new_instance (0, NULL, cInvalidKey);
      rb_iv_set (vinvalid_key, "@fpr", rb_str_new2 (invalid_key->fpr));
      rb_iv_set (vinvalid_key, "@reason", LONG2NUM(invalid_key->reason));
      rb_ary_push (vinvalid_signers, vinvalid_key);
    }
  vsignatures = rb_ary_new ();
  rb_iv_set (vresult, "@signatures", vsignatures);
  for (new_signature = result->signatures; new_signature;
       new_signature = new_signature->next)
    {
      VALUE vnew_signature =
	rb_class_new_instance (0, NULL, cNewSignature);
      rb_iv_set (vnew_signature, "@type", INT2FIX(new_signature->type));
      rb_iv_set (vnew_signature, "@pubkey_algo",
		 INT2FIX(new_signature->pubkey_algo));
      rb_iv_set (vnew_signature, "@hash_algo",
		 INT2FIX(new_signature->hash_algo));
      rb_iv_set (vnew_signature, "@sig_class",
		 UINT2NUM(new_signature->sig_class));
      rb_iv_set (vnew_signature, "@timestamp",
		 LONG2NUM(new_signature->timestamp));
      rb_iv_set (vnew_signature, "@fpr", rb_str_new2 (new_signature->fpr));
      rb_ary_push (vsignatures, vnew_signature);
    }
  return vresult;
}

static VALUE
rb_s_gpgme_op_encrypt (VALUE dummy, VALUE vctx, VALUE vrecp, VALUE vflags,
		       VALUE vplain, VALUE vcipher)
{
  gpgme_ctx_t ctx;
  gpgme_key_t *recp = NULL;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  /* If RECP is `NULL', symmetric rather than public key encryption is
     performed. */
  if (!NIL_P(vrecp))
    {
      int i;
      recp = ALLOC_N(gpgme_key_t, RARRAY_LEN(vrecp) + 1);
      for (i = 0; i < RARRAY_LEN(vrecp); i++)
	UNWRAP_GPGME_KEY(RARRAY_PTR(vrecp)[i], recp[i]);
      recp[i] = NULL;
    }
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vcipher, cipher);

  err = gpgme_op_encrypt (ctx, recp, NUM2INT(vflags), plain, cipher);
  if (recp)
    xfree (recp);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_encrypt_start (VALUE dummy, VALUE vctx, VALUE vrecp,
			     VALUE vflags, VALUE vplain, VALUE vcipher)
{
  gpgme_ctx_t ctx;
  gpgme_key_t *recp = NULL;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  /* If RECP is `NULL', symmetric rather than public key encryption is
     performed. */
  if (!NIL_P(vrecp))
    {
      int i;
      recp = ALLOC_N(gpgme_key_t, RARRAY_LEN(vrecp) + 1);
      for (i = 0; i < RARRAY_LEN(vrecp); i++)
	UNWRAP_GPGME_KEY(RARRAY_PTR(vrecp)[i], recp[i]);
      recp[i] = NULL;
    }
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vcipher, cipher);

  err = gpgme_op_encrypt_start (ctx, recp, NUM2INT(vflags), plain, cipher);
  if (recp)
    xfree (recp);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_encrypt_result (VALUE dummy, VALUE vctx)
{
  gpgme_ctx_t ctx;
  gpgme_encrypt_result_t result;
  gpgme_invalid_key_t invalid_key;
  VALUE vresult, vinvalid_recipients;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");

  result = gpgme_op_encrypt_result (ctx);
  vresult = rb_class_new_instance (0, NULL, cEncryptResult);
  vinvalid_recipients = rb_ary_new ();
  rb_iv_set (vresult, "@invalid_recipients", vinvalid_recipients);
  for (invalid_key = result->invalid_recipients; invalid_key;
       invalid_key = invalid_key->next)
    {
      VALUE vinvalid_key =
	rb_class_new_instance (0, NULL, cInvalidKey);
      rb_iv_set (vinvalid_key, "@fpr", rb_str_new2 (invalid_key->fpr));
      rb_iv_set (vinvalid_key, "@reason", LONG2NUM(invalid_key->reason));
      rb_ary_push (vinvalid_recipients, vinvalid_key);
    }
  return vresult;
}

static VALUE
rb_s_gpgme_op_encrypt_sign (VALUE dummy, VALUE vctx, VALUE vrecp, VALUE vflags,
			    VALUE vplain, VALUE vcipher)
{
  gpgme_ctx_t ctx;
  gpgme_key_t *recp = NULL;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  /* If RECP is `NULL', symmetric rather than public key encryption is
     performed. */
  if (!NIL_P(vrecp))
    {
      int i;
      recp = ALLOC_N(gpgme_key_t, RARRAY_LEN(vrecp) + 1);
      for (i = 0; i < RARRAY_LEN(vrecp); i++)
	UNWRAP_GPGME_KEY(RARRAY_PTR(vrecp)[i], recp[i]);
      recp[i] = NULL;
    }
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vcipher, cipher);

  err = gpgme_op_encrypt_sign (ctx, recp, NUM2INT(vflags), plain, cipher);
  if (recp)
    xfree (recp);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_op_encrypt_sign_start (VALUE dummy, VALUE vctx, VALUE vrecp,
				  VALUE vflags, VALUE vplain, VALUE vcipher)
{
  gpgme_ctx_t ctx;
  gpgme_key_t *recp = NULL;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;

  CHECK_KEYLIST_NOT_IN_PROGRESS(vctx);

  UNWRAP_GPGME_CTX(vctx, ctx);
  if (!ctx)
    rb_raise (rb_eArgError, "released ctx");
  /* If RECP is `NULL', symmetric rather than public key encryption is
     performed. */
  if (!NIL_P(vrecp))
    {
      int i;
      recp = ALLOC_N(gpgme_key_t, RARRAY_LEN(vrecp) + 1);
      for (i = 0; i < RARRAY_LEN(vrecp); i++)
	UNWRAP_GPGME_KEY(RARRAY_PTR(vrecp)[i], recp[i]);
      recp[i] = NULL;
    }
  UNWRAP_GPGME_DATA(vplain, plain);
  UNWRAP_GPGME_DATA(vcipher, cipher);

  err = gpgme_op_encrypt_sign_start (ctx, recp, NUM2INT(vflags), plain,
				     cipher);
  if (recp)
    xfree (recp);
  return LONG2NUM(err);
}

static VALUE
rb_s_gpgme_wait (VALUE dummy, VALUE vctx, VALUE rstatus, VALUE vhang)
{
  gpgme_ctx_t ctx = NULL, ret;
  gpgme_error_t status;

  /* The CTX argument can be `NULL'.  In that case, `gpgme_wait' waits
     for any context to complete its operation. */
  if (!NIL_P(vctx))
    {
      UNWRAP_GPGME_CTX(vctx, ctx);
      if (!ctx)
	rb_raise (rb_eArgError, "released ctx");
    }

  ret = gpgme_wait (ctx, &status, NUM2INT(vhang));
  if (ret)
    {
      rb_ary_store (rstatus, 0, INT2NUM(status));
      if (ret != ctx)
	vctx = WRAP_GPGME_CTX(ret);
      return vctx;
    }
  return Qnil;
}

void
Init_gpgme_n (void)
{
  VALUE mGPGME;

  mGPGME = rb_define_module ("GPGME");

  rb_define_module_function (mGPGME, "gpgme_check_version_x",       rb_s_gpgme_check_version, 1);

  rb_define_module_function (mGPGME, "gpgme_hash_algo_name",        rb_s_gpgme_hash_algo_name, 1);

  rb_define_module_function (mGPGME, "gpgme_err_code",              rb_s_gpgme_err_code, 1);
  rb_define_module_function (mGPGME, "gpgme_err_source",            rb_s_gpgme_err_source, 1);
  rb_define_module_function (mGPGME, "gpgme_strerror",              rb_s_gpgme_strerror, 1);

  cEngineInfo     = rb_define_class_under (mGPGME, "EngineInfo", rb_cObject);
  cCtx            = rb_define_class_under (mGPGME, "Ctx", rb_cObject);
  cData           = rb_define_class_under (mGPGME, "Data", rb_cObject);
  cKey            = rb_define_class_under (mGPGME, "Key", rb_cObject);
  cSubKey         = rb_define_class_under (mGPGME, "SubKey", rb_cObject);
  cUserID         = rb_define_class_under (mGPGME, "UserID", rb_cObject);
  cKeySig         = rb_define_class_under (mGPGME, "KeySig", rb_cObject);
  cDecryptResult  = rb_define_class_under (mGPGME, "DecryptResult", rb_cObject);
  cVerifyResult   = rb_define_class_under (mGPGME, "VerifyResult", rb_cObject);
  cSignResult     = rb_define_class_under (mGPGME, "SignResult", rb_cObject);
  cEncryptResult  = rb_define_class_under (mGPGME, "EncryptResult", rb_cObject);
  cSignature      = rb_define_class_under (mGPGME, "Signature", rb_cObject);
  cSigNotation    = rb_define_class_under (mGPGME, "SigNotation", rb_cObject);
  cTrustItem      = rb_define_class_under (mGPGME, "TrustItem", rb_cObject);
  cInvalidKey     = rb_define_class_under (mGPGME, "InvalidKey", rb_cObject);
  cNewSignature   = rb_define_class_under (mGPGME, "NewSignature", rb_cObject);
  cImportResult   = rb_define_class_under (mGPGME, "ImportResult", rb_cObject);
  cImportStatus   = rb_define_class_under (mGPGME, "ImportStatus", rb_cObject);

  /* Creating Data Buffers
   *
   * gpgme_data_new_from_filepart is not currently supported.
   */
  rb_define_module_function (mGPGME, "gpgme_data_new",          rb_s_gpgme_data_new, 1);
  rb_define_module_function (mGPGME, "gpgme_data_new_from_mem", rb_s_gpgme_data_new_from_mem, 3);
  rb_define_module_function (mGPGME, "gpgme_data_new_from_fd",  rb_s_gpgme_data_new_from_fd, 2);
  rb_define_module_function (mGPGME, "gpgme_data_new_from_cbs", rb_s_gpgme_data_new_from_cbs, 3);

  /* Manipulating Data Buffers */
  rb_define_module_function (mGPGME, "gpgme_data_read",         rb_s_gpgme_data_read, 2);
  rb_define_module_function (mGPGME, "gpgme_data_seek",         rb_s_gpgme_data_seek, 3);
  rb_define_module_function (mGPGME, "gpgme_data_write",        rb_s_gpgme_data_write, 3);
  rb_define_module_function (mGPGME, "gpgme_data_get_encoding", rb_s_gpgme_data_get_encoding, 1);
  rb_define_module_function (mGPGME, "gpgme_data_set_encoding", rb_s_gpgme_data_set_encoding, 2);

  /* Creating Contexts */
  rb_define_module_function (mGPGME, "gpgme_new",     rb_s_gpgme_new, 1);
  rb_define_module_function (mGPGME, "gpgme_release", rb_s_gpgme_release, 1);

  /* Context Attributes */
  rb_define_module_function (mGPGME, "gpgme_set_protocol",      rb_s_gpgme_set_protocol, 2);
  rb_define_module_function (mGPGME, "gpgme_get_protocol",      rb_s_gpgme_get_protocol, 1);
  rb_define_module_function (mGPGME, "gpgme_set_armor",         rb_s_gpgme_set_armor, 2);
  rb_define_module_function (mGPGME, "gpgme_get_armor",         rb_s_gpgme_get_armor, 1);
  rb_define_module_function (mGPGME, "gpgme_set_textmode",      rb_s_gpgme_set_textmode, 2);
  rb_define_module_function (mGPGME, "gpgme_get_textmode",      rb_s_gpgme_get_textmode, 1);
  rb_define_module_function (mGPGME, "gpgme_set_include_certs", rb_s_gpgme_set_include_certs, 2);
  rb_define_module_function (mGPGME, "gpgme_get_include_certs", rb_s_gpgme_get_include_certs, 1);
  rb_define_module_function (mGPGME, "gpgme_set_keylist_mode",  rb_s_gpgme_set_keylist_mode, 2);
  rb_define_module_function (mGPGME, "gpgme_get_keylist_mode",  rb_s_gpgme_get_keylist_mode, 1);
  rb_define_module_function (mGPGME, "gpgme_set_passphrase_cb", rb_s_gpgme_set_passphrase_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_get_passphrase_cb", rb_s_gpgme_get_passphrase_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_set_progress_cb",   rb_s_gpgme_set_progress_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_get_progress_cb",   rb_s_gpgme_get_progress_cb, 3);
  rb_define_module_function (mGPGME, "gpgme_set_locale",        rb_s_gpgme_set_locale, 3);

  /* Key Management */
  rb_define_module_function (mGPGME, "gpgme_op_keylist_start",      rb_s_gpgme_op_keylist_start, 3);
  rb_define_module_function (mGPGME, "gpgme_op_keylist_ext_start",  rb_s_gpgme_op_keylist_ext_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_keylist_next",       rb_s_gpgme_op_keylist_next, 2);
  rb_define_module_function (mGPGME, "gpgme_op_keylist_end",        rb_s_gpgme_op_keylist_end, 1);
  rb_define_module_function (mGPGME, "gpgme_get_key",               rb_s_gpgme_get_key, 4);
  rb_define_module_function (mGPGME, "gpgme_op_genkey",             rb_s_gpgme_op_genkey, 4);
  rb_define_module_function (mGPGME, "gpgme_op_genkey_start",       rb_s_gpgme_op_genkey_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export",             rb_s_gpgme_op_export, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export_start",       rb_s_gpgme_op_export_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export_ext",         rb_s_gpgme_op_export_ext, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export_ext_start",   rb_s_gpgme_op_export_ext_start, 4);

#ifdef HAVE_GPGME_OP_EXPORT_KEYS
  rb_define_module_function (mGPGME, "gpgme_op_export_keys",        rb_s_gpgme_op_export_keys, 4);
  rb_define_module_function (mGPGME, "gpgme_op_export_keys_start",  rb_s_gpgme_op_export_keys_start, 4);
#endif
  rb_define_module_function (mGPGME, "gpgme_op_import",       rb_s_gpgme_op_import, 2);
  rb_define_module_function (mGPGME, "gpgme_op_import_start", rb_s_gpgme_op_import_start, 2);
#ifdef HAVE_GPGME_OP_EXPORT_KEYS
  rb_define_module_function (mGPGME, "gpgme_op_import_keys",        rb_s_gpgme_op_import_keys, 2);
  rb_define_module_function (mGPGME, "gpgme_op_import_keys_start",  rb_s_gpgme_op_import_keys_start, 2);
#endif
  rb_define_module_function (mGPGME, "gpgme_op_import_result",    rb_s_gpgme_op_import_result, 1);
  rb_define_module_function (mGPGME, "gpgme_op_delete",           rb_s_gpgme_op_delete, 3);
  rb_define_module_function (mGPGME, "gpgme_op_delete_start",     rb_s_gpgme_op_delete_start, 3);
  rb_define_module_function (mGPGME, "gpgme_op_edit",             rb_s_gpgme_op_edit, 5);
  rb_define_module_function (mGPGME, "gpgme_op_edit_start",       rb_s_gpgme_op_edit_start, 5);
  rb_define_module_function (mGPGME, "gpgme_op_card_edit",        rb_s_gpgme_op_card_edit, 5);
  rb_define_module_function (mGPGME, "gpgme_op_card_edit_start",  rb_s_gpgme_op_card_edit_start, 5);

  /* Trust Item Management */
  rb_define_module_function (mGPGME, "gpgme_op_trustlist_start",  rb_s_gpgme_op_trustlist_start, 3);
  rb_define_module_function (mGPGME, "gpgme_op_trustlist_next",   rb_s_gpgme_op_trustlist_next, 2);
  rb_define_module_function (mGPGME, "gpgme_op_trustlist_end",    rb_s_gpgme_op_trustlist_end, 1);

  /* Decrypt */
  rb_define_module_function (mGPGME, "gpgme_op_decrypt",        rb_s_gpgme_op_decrypt, 3);
  rb_define_module_function (mGPGME, "gpgme_op_decrypt_start",  rb_s_gpgme_op_decrypt_start, 3);
  rb_define_module_function (mGPGME, "gpgme_op_decrypt_result", rb_s_gpgme_op_decrypt_result, 1);

  /* Verify */
  rb_define_module_function (mGPGME, "gpgme_op_verify",         rb_s_gpgme_op_verify, 4);
  rb_define_module_function (mGPGME, "gpgme_op_verify_start",   rb_s_gpgme_op_verify_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_verify_result",  rb_s_gpgme_op_verify_result, 1);

  /* Decrypt and Verify */
  rb_define_module_function (mGPGME, "gpgme_op_decrypt_verify",       rb_s_gpgme_op_decrypt_verify, 3);
  rb_define_module_function (mGPGME, "gpgme_op_decrypt_verify_start", rb_s_gpgme_op_decrypt_verify_start, 3);

  /* Sign */
  rb_define_module_function (mGPGME, "gpgme_signers_clear",   rb_s_gpgme_signers_clear, 1);
  rb_define_module_function (mGPGME, "gpgme_signers_add",     rb_s_gpgme_signers_add, 2);
  rb_define_module_function (mGPGME, "gpgme_signers_enum",    rb_s_gpgme_signers_enum, 2);
  rb_define_module_function (mGPGME, "gpgme_op_sign",         rb_s_gpgme_op_sign, 4);
  rb_define_module_function (mGPGME, "gpgme_op_sign_start",   rb_s_gpgme_op_sign_start, 4);
  rb_define_module_function (mGPGME, "gpgme_op_sign_result",  rb_s_gpgme_op_sign_result, 1);

  /* Encrypt */
  rb_define_module_function (mGPGME, "gpgme_op_encrypt",            rb_s_gpgme_op_encrypt, 5);
  rb_define_module_function (mGPGME, "gpgme_op_encrypt_start",      rb_s_gpgme_op_encrypt_start, 5);
  rb_define_module_function (mGPGME, "gpgme_op_encrypt_result",     rb_s_gpgme_op_encrypt_result, 1);
  rb_define_module_function (mGPGME, "gpgme_op_encrypt_sign",       rb_s_gpgme_op_encrypt_sign, 5);
  rb_define_module_function (mGPGME, "gpgme_op_encrypt_sign_start", rb_s_gpgme_op_encrypt_sign_start, 5);

  /* Run Control */
  rb_define_module_function (mGPGME, "gpgme_wait", rb_s_gpgme_wait, 3);
}
