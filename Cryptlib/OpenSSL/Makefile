ifneq ($(CCACHE_DISABLE),)
export CCACHE_DISABLE
endif

CRYPTDIR	= $(TOPDIR)/Cryptlib
OSSLDIR		= $(TOPDIR)/Cryptlib/OpenSSL

DEFINES		= -DL_ENDIAN \
		  -D_CRT_SECURE_NO_DEPRECATE \
		  -D_CRT_NONSTDC_NO_DEPRECATE \
		  -DOPENSSL_SMALL_FOOTPRINT \
		  -DPEDANTIC

INCLUDES	= -I$(OSSLDIR) -I$(CRYPTDIR) -I$(OSSLDIR)/Include/ \
		  -I$(OSSLDIR)/crypto -I$(CRYPTDIR)/Include $(EFI_INCLUDES) \
		  -I$(OSSLDIR)/crypto/asn1 -I$(OSSLDIR)/crypto/evp \
		  -I$(OSSLDIR)/crypto/modes -I$(OSSLDIR)/crypto/include \
		  -isystem $(TOPDIR)/include/system \
		  -isystem $(shell $(CC) -print-file-name=include)

FEATUREFLAGS	+= -nostdinc

WARNFLAGS	+= -Wno-empty-body \
		   -Wno-implicit-fallthrough \
		   $(if $(findstring gcc,$(CC)),-Wno-old-style-declaration) \
		   -Wno-unused-but-set-variable \
		   -Wno-unused-parameter

WERRFLAGS	+= -Wno-error=unused-but-set-variable \
		   -Wno-error=unused-parameter

CFLAGS		= $(FEATUREFLAGS) \
		  $(OPTIMIZATIONS) \
		  $(WARNFLAGS) \
		  $(WERRFLAGS) \
		  $(INCLUDES) \
		  $(DEFINES)

CLANG_BUGS	= $(if $(findstring gcc,$(CC)),-maccumulate-outgoing-args,)

ifeq ($(ARCH),x86_64)
FEATUREFLAGS	+= -m64 -mno-mmx -mno-sse -mno-red-zone $(CLANG_BUGS)
DEFINES		+= -DMDE_CPU_X64
endif
ifeq ($(ARCH),ia32)
FEATUREFLAGS	+= -m32 -mno-mmx -mno-sse -mno-red-zone -nostdinc $(CLANG_BUGS)
DEFINES		+= -DMDE_CPU_IA32
endif
ifeq ($(ARCH),aarch64)
DEFINES		+= -DMDE_CPU_AARCH64
endif
ifeq ($(ARCH),arm)
DEFINES		+= -DMDE_CPU_ARM
endif

LDFLAGS		= -nostdlib -znocombreloc

TARGET		= libopenssl.a
OBJS		= crypto/cryptlib.o \
		  crypto/mem.o \
		  crypto/mem_clr.o \
		  crypto/mem_dbg.o \
		  crypto/cversion.o \
		  crypto/ex_data.o \
		  crypto/cpt_err.o \
		  crypto/ebcdic.o \
		  crypto/uid.o \
		  crypto/o_time.o \
		  crypto/o_str.o \
		  crypto/o_dir.o \
		  crypto/o_fips.o \
		  crypto/o_init.o \
		  crypto/fips_ers.o \
		  crypto/md5/md5_dgst.o \
		  crypto/md5/md5_one.o \
		  crypto/sha/sha_dgst.o \
		  crypto/sha/sha1dgst.o \
		  crypto/sha/sha_one.o \
		  crypto/sha/sha1_one.o \
		  crypto/sha/sha256.o \
		  crypto/sha/sha512.o \
		  crypto/hmac/hmac.o \
		  crypto/hmac/hm_ameth.o \
		  crypto/hmac/hm_pmeth.o \
		  crypto/rc4/rc4_enc.o \
		  crypto/rc4/rc4_skey.o \
		  crypto/rc4/rc4_utl.o \
		  crypto/aes/aes_misc.o \
		  crypto/aes/aes_ecb.o \
		  crypto/aes/aes_cfb.o \
		  crypto/aes/aes_ofb.o \
		  crypto/aes/aes_ctr.o \
		  crypto/aes/aes_ige.o \
		  crypto/aes/aes_wrap.o \
		  crypto/aes/aes_core.o \
		  crypto/aes/aes_cbc.o \
		  crypto/modes/cbc128.o \
		  crypto/modes/ctr128.o \
		  crypto/modes/cts128.o \
		  crypto/modes/cfb128.o \
		  crypto/modes/ofb128.o \
		  crypto/modes/gcm128.o \
		  crypto/modes/ccm128.o \
		  crypto/modes/xts128.o \
		  crypto/modes/wrap128.o \
		  crypto/bn/bn_add.o \
		  crypto/bn/bn_div.o \
		  crypto/bn/bn_exp.o \
		  crypto/bn/bn_lib.o \
		  crypto/bn/bn_ctx.o \
		  crypto/bn/bn_mul.o \
		  crypto/bn/bn_mod.o \
		  crypto/bn/bn_print.o \
		  crypto/bn/bn_rand.o \
		  crypto/bn/bn_shift.o \
		  crypto/bn/bn_word.o \
		  crypto/bn/bn_blind.o \
		  crypto/bn/bn_kron.o \
		  crypto/bn/bn_sqrt.o \
		  crypto/bn/bn_gcd.o \
		  crypto/bn/bn_prime.o \
		  crypto/bn/bn_err.o \
		  crypto/bn/bn_sqr.o \
		  crypto/bn/bn_asm.o \
		  crypto/bn/bn_recp.o \
		  crypto/bn/bn_mont.o \
		  crypto/bn/bn_mpi.o \
		  crypto/bn/bn_exp2.o \
		  crypto/bn/bn_gf2m.o \
		  crypto/bn/bn_nist.o \
		  crypto/bn/bn_depr.o \
		  crypto/bn/bn_x931p.o \
		  crypto/bn/bn_const.o \
		  crypto/rsa/rsa_eay.o \
		  crypto/rsa/rsa_gen.o \
		  crypto/rsa/rsa_lib.o \
		  crypto/rsa/rsa_sign.o \
		  crypto/rsa/rsa_saos.o \
		  crypto/rsa/rsa_err.o \
		  crypto/rsa/rsa_pk1.o \
		  crypto/rsa/rsa_ssl.o \
		  crypto/rsa/rsa_none.o \
		  crypto/rsa/rsa_oaep.o \
		  crypto/rsa/rsa_chk.o \
		  crypto/rsa/rsa_null.o \
		  crypto/rsa/rsa_pss.o \
		  crypto/rsa/rsa_x931.o \
		  crypto/rsa/rsa_asn1.o \
		  crypto/rsa/rsa_depr.o \
		  crypto/rsa/rsa_ameth.o \
		  crypto/rsa/rsa_prn.o \
		  crypto/rsa/rsa_pmeth.o \
		  crypto/rsa/rsa_crpt.o \
		  crypto/dso/dso_dl.o \
		  crypto/dso/dso_dlfcn.o \
		  crypto/dso/dso_err.o \
		  crypto/dso/dso_lib.o \
		  crypto/dso/dso_null.o \
		  crypto/dso/dso_openssl.o \
		  crypto/dso/dso_win32.o \
		  crypto/dso/dso_vms.o \
		  crypto/dso/dso_beos.o \
		  crypto/dh/dh_asn1.o \
		  crypto/dh/dh_gen.o \
		  crypto/dh/dh_key.o \
		  crypto/dh/dh_lib.o \
		  crypto/dh/dh_check.o \
		  crypto/dh/dh_err.o \
		  crypto/dh/dh_depr.o \
		  crypto/dh/dh_ameth.o \
		  crypto/dh/dh_pmeth.o \
		  crypto/dh/dh_prn.o \
		  crypto/dh/dh_rfc5114.o \
		  crypto/buffer/buffer.o \
		  crypto/buffer/buf_str.o \
		  crypto/buffer/buf_err.o \
		  crypto/bio/bio_lib.o \
		  crypto/bio/bio_cb.o \
		  crypto/bio/bio_err.o \
		  crypto/bio/bss_mem.o \
		  crypto/bio/bss_null.o \
		  crypto/bio/bss_fd.o \
		  crypto/bio/bss_file.o \
		  crypto/bio/bss_sock.o \
		  crypto/bio/bss_conn.o \
		  crypto/bio/bf_null.o \
		  crypto/bio/bf_buff.o \
		  crypto/bio/b_dump.o \
		  crypto/bio/b_print.o \
		  crypto/bio/b_sock.o \
		  crypto/bio/bss_acpt.o \
		  crypto/bio/bf_nbio.o \
		  crypto/bio/bss_log.o \
		  crypto/bio/bss_bio.o \
		  crypto/bio/bss_dgram.o \
		  crypto/stack/stack.o \
		  crypto/lhash/lhash.o \
		  crypto/lhash/lh_stats.o \
		  crypto/rand/md_rand.o \
		  crypto/rand/randfile.o \
		  crypto/rand/rand_lib.o \
		  crypto/rand/rand_err.o \
		  crypto/rand/rand_unix.o \
		  crypto/err/err.o \
		  crypto/err/err_all.o \
		  crypto/err/err_prn.o \
		  crypto/objects/o_names.o \
		  crypto/objects/obj_dat.o \
		  crypto/objects/obj_lib.o \
		  crypto/objects/obj_err.o \
		  crypto/objects/obj_xref.o \
		  crypto/evp/encode.o \
		  crypto/evp/digest.o \
		  crypto/evp/evp_enc.o \
		  crypto/evp/evp_key.o \
		  crypto/evp/evp_acnf.o \
		  crypto/evp/evp_cnf.o \
		  crypto/evp/e_des.o \
		  crypto/evp/e_bf.o \
		  crypto/evp/e_idea.o \
		  crypto/evp/e_des3.o \
		  crypto/evp/e_camellia.o \
		  crypto/evp/e_rc4.o \
		  crypto/evp/e_aes.o \
		  crypto/evp/names.o \
		  crypto/evp/e_seed.o \
		  crypto/evp/e_xcbc_d.o \
		  crypto/evp/e_rc2.o \
		  crypto/evp/e_cast.o \
		  crypto/evp/e_rc5.o \
		  crypto/evp/m_null.o \
		  crypto/evp/m_md2.o \
		  crypto/evp/m_md4.o \
		  crypto/evp/m_md5.o \
		  crypto/evp/m_sha.o \
		  crypto/evp/m_sha1.o \
		  crypto/evp/m_wp.o \
		  crypto/evp/m_dss.o \
		  crypto/evp/m_dss1.o \
		  crypto/evp/m_mdc2.o \
		  crypto/evp/m_ripemd.o \
		  crypto/evp/m_ecdsa.o \
		  crypto/evp/p_open.o \
		  crypto/evp/p_seal.o \
		  crypto/evp/p_sign.o \
		  crypto/evp/p_verify.o \
		  crypto/evp/p_lib.o \
		  crypto/evp/p_enc.o \
		  crypto/evp/p_dec.o \
		  crypto/evp/bio_md.o \
		  crypto/evp/bio_b64.o \
		  crypto/evp/bio_enc.o \
		  crypto/evp/evp_err.o \
		  crypto/evp/e_null.o \
		  crypto/evp/c_all.o \
		  crypto/evp/c_allc.o \
		  crypto/evp/c_alld.o \
		  crypto/evp/evp_lib.o \
		  crypto/evp/bio_ok.o \
		  crypto/evp/evp_pkey.o \
		  crypto/evp/evp_pbe.o \
		  crypto/evp/p5_crpt.o \
		  crypto/evp/p5_crpt2.o \
		  crypto/evp/e_old.o \
		  crypto/evp/pmeth_lib.o \
		  crypto/evp/pmeth_fn.o \
		  crypto/evp/pmeth_gn.o \
		  crypto/evp/m_sigver.o \
		  crypto/evp/e_aes_cbc_hmac_sha1.o \
		  crypto/evp/e_aes_cbc_hmac_sha256.o \
		  crypto/evp/e_rc4_hmac_md5.o \
		  crypto/asn1/a_object.o \
		  crypto/asn1/a_bitstr.o \
		  crypto/asn1/a_utctm.o \
		  crypto/asn1/a_gentm.o \
		  crypto/asn1/a_time.o \
		  crypto/asn1/a_int.o \
		  crypto/asn1/a_octet.o \
		  crypto/asn1/a_print.o \
		  crypto/asn1/a_type.o \
		  crypto/asn1/a_set.o \
		  crypto/asn1/a_dup.o \
		  crypto/asn1/a_d2i_fp.o \
		  crypto/asn1/a_i2d_fp.o \
		  crypto/asn1/a_enum.o \
		  crypto/asn1/a_utf8.o \
		  crypto/asn1/a_sign.o \
		  crypto/asn1/a_digest.o \
		  crypto/asn1/a_verify.o \
		  crypto/asn1/a_mbstr.o \
		  crypto/asn1/a_strex.o \
		  crypto/asn1/x_algor.o \
		  crypto/asn1/x_val.o \
		  crypto/asn1/x_pubkey.o \
		  crypto/asn1/x_sig.o \
		  crypto/asn1/x_req.o \
		  crypto/asn1/x_attrib.o \
		  crypto/asn1/x_bignum.o \
		  crypto/asn1/x_long.o \
		  crypto/asn1/x_name.o \
		  crypto/asn1/x_x509.o \
		  crypto/asn1/x_x509a.o \
		  crypto/asn1/x_crl.o \
		  crypto/asn1/x_info.o \
		  crypto/asn1/x_spki.o \
		  crypto/asn1/nsseq.o \
		  crypto/asn1/x_nx509.o \
		  crypto/asn1/d2i_pu.o \
		  crypto/asn1/d2i_pr.o \
		  crypto/asn1/i2d_pu.o \
		  crypto/asn1/i2d_pr.o \
		  crypto/asn1/t_req.o \
		  crypto/asn1/t_x509.o \
		  crypto/asn1/t_x509a.o \
		  crypto/asn1/t_crl.o \
		  crypto/asn1/t_pkey.o \
		  crypto/asn1/t_spki.o \
		  crypto/asn1/t_bitst.o \
		  crypto/asn1/tasn_new.o \
		  crypto/asn1/tasn_fre.o \
		  crypto/asn1/tasn_enc.o \
		  crypto/asn1/tasn_dec.o \
		  crypto/asn1/tasn_utl.o \
		  crypto/asn1/tasn_typ.o \
		  crypto/asn1/tasn_prn.o \
		  crypto/asn1/ameth_lib.o \
		  crypto/asn1/f_int.o \
		  crypto/asn1/f_string.o \
		  crypto/asn1/n_pkey.o \
		  crypto/asn1/f_enum.o \
		  crypto/asn1/x_pkey.o \
		  crypto/asn1/a_bool.o \
		  crypto/asn1/x_exten.o \
		  crypto/asn1/bio_asn1.o \
		  crypto/asn1/bio_ndef.o \
		  crypto/asn1/asn_mime.o \
		  crypto/asn1/asn1_gen.o \
		  crypto/asn1/asn1_par.o \
		  crypto/asn1/asn1_lib.o \
		  crypto/asn1/asn1_err.o \
		  crypto/asn1/a_bytes.o \
		  crypto/asn1/a_strnid.o \
		  crypto/asn1/evp_asn1.o \
		  crypto/asn1/asn_pack.o \
		  crypto/asn1/p5_pbe.o \
		  crypto/asn1/p5_pbev2.o \
		  crypto/asn1/p8_pkey.o \
		  crypto/asn1/asn_moid.o \
		  crypto/pem/pem_sign.o \
		  crypto/pem/pem_seal.o \
		  crypto/pem/pem_info.o \
		  crypto/pem/pem_lib.o \
		  crypto/pem/pem_all.o \
		  crypto/pem/pem_err.o \
		  crypto/pem/pem_x509.o \
		  crypto/pem/pem_xaux.o \
		  crypto/pem/pem_oth.o \
		  crypto/pem/pem_pk8.o \
		  crypto/pem/pem_pkey.o \
		  crypto/pem/pvkfmt.o \
		  crypto/x509/x509_def.o \
		  crypto/x509/x509_d2.o \
		  crypto/x509/x509_r2x.o \
		  crypto/x509/x509_cmp.o \
		  crypto/x509/x509_obj.o \
		  crypto/x509/x509_req.o \
		  crypto/x509/x509spki.o \
		  crypto/x509/x509_vfy.o \
		  crypto/x509/x509_set.o \
		  crypto/x509/x509cset.o \
		  crypto/x509/x509rset.o \
		  crypto/x509/x509_err.o \
		  crypto/x509/x509name.o \
		  crypto/x509/x509_v3.o \
		  crypto/x509/x509_ext.o \
		  crypto/x509/x509_att.o \
		  crypto/x509/x509type.o \
		  crypto/x509/x509_lu.o \
		  crypto/x509/x_all.o \
		  crypto/x509/x509_txt.o \
		  crypto/x509/x509_trs.o \
		  crypto/x509/x509_vpm.o \
		  crypto/x509v3/v3_bcons.o \
		  crypto/x509v3/v3_bitst.o \
		  crypto/x509v3/v3_conf.o \
		  crypto/x509v3/v3_extku.o \
		  crypto/x509v3/v3_ia5.o \
		  crypto/x509v3/v3_lib.o \
		  crypto/x509v3/v3_prn.o \
		  crypto/x509v3/v3_utl.o \
		  crypto/x509v3/v3err.o \
		  crypto/x509v3/v3_genn.o \
		  crypto/x509v3/v3_alt.o \
		  crypto/x509v3/v3_skey.o \
		  crypto/x509v3/v3_akey.o \
		  crypto/x509v3/v3_pku.o \
		  crypto/x509v3/v3_int.o \
		  crypto/x509v3/v3_enum.o \
		  crypto/x509v3/v3_sxnet.o \
		  crypto/x509v3/v3_cpols.o \
		  crypto/x509v3/v3_crld.o \
		  crypto/x509v3/v3_purp.o \
		  crypto/x509v3/v3_info.o \
		  crypto/x509v3/v3_ocsp.o \
		  crypto/x509v3/v3_akeya.o \
		  crypto/x509v3/v3_pmaps.o \
		  crypto/x509v3/v3_pcons.o \
		  crypto/x509v3/v3_ncons.o \
		  crypto/x509v3/v3_pcia.o \
		  crypto/x509v3/v3_pci.o \
		  crypto/x509v3/pcy_cache.o \
		  crypto/x509v3/pcy_node.o \
		  crypto/x509v3/pcy_data.o \
		  crypto/x509v3/pcy_map.o \
		  crypto/x509v3/pcy_tree.o \
		  crypto/x509v3/pcy_lib.o \
		  crypto/x509v3/v3_asid.o \
		  crypto/x509v3/v3_addr.o \
		  crypto/conf/conf_err.o \
		  crypto/conf/conf_lib.o \
		  crypto/conf/conf_api.o \
		  crypto/conf/conf_def.o \
		  crypto/conf/conf_mod.o \
		  crypto/conf/conf_mall.o \
		  crypto/conf/conf_sap.o \
		  crypto/txt_db/txt_db.o \
		  crypto/pkcs7/pk7_asn1.o \
		  crypto/pkcs7/pk7_lib.o \
		  crypto/pkcs7/pkcs7err.o \
		  crypto/pkcs7/pk7_doit.o \
		  crypto/pkcs7/pk7_smime.o \
		  crypto/pkcs7/pk7_attr.o \
		  crypto/pkcs7/pk7_mime.o \
		  crypto/pkcs7/bio_pk7.o \
		  crypto/pkcs12/p12_add.o \
		  crypto/pkcs12/p12_asn.o \
		  crypto/pkcs12/p12_attr.o \
		  crypto/pkcs12/p12_crpt.o \
		  crypto/pkcs12/p12_crt.o \
		  crypto/pkcs12/p12_decr.o \
		  crypto/pkcs12/p12_init.o \
		  crypto/pkcs12/p12_key.o \
		  crypto/pkcs12/p12_kiss.o \
		  crypto/pkcs12/p12_mutl.o \
		  crypto/pkcs12/p12_utl.o \
		  crypto/pkcs12/p12_npas.o \
		  crypto/pkcs12/pk12err.o \
		  crypto/pkcs12/p12_p8d.o \
		  crypto/pkcs12/p12_p8e.o \
		  crypto/comp/comp_lib.o \
		  crypto/comp/comp_err.o \
		  crypto/comp/c_rle.o \
		  crypto/comp/c_zlib.o \
		  crypto/ocsp/ocsp_asn.o \
		  crypto/ocsp/ocsp_ext.o \
		  crypto/ocsp/ocsp_ht.o \
		  crypto/ocsp/ocsp_lib.o \
		  crypto/ocsp/ocsp_cl.o \
		  crypto/ocsp/ocsp_srv.o \
		  crypto/ocsp/ocsp_prn.o \
		  crypto/ocsp/ocsp_vfy.o \
		  crypto/ocsp/ocsp_err.o \
		  crypto/cmac/cmac.o \
		  crypto/cmac/cm_ameth.o \
		  crypto/cmac/cm_pmeth.o \

all: $(TARGET)

libopenssl.a: $(OBJS)
	ar rcs libopenssl.a $(OBJS)

clean:
	rm -f $(TARGET) $(OBJS)
