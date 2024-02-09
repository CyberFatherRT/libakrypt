/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_oid.с                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*                           функции для доступа к именам криптоалгоритмов                         */
/* ----------------------------------------------------------------------------------------------- */
 static const char *libakrypt_engine_names[] = {
    "identifier",
    "block cipher",
    "stream cipher",
    "hybrid cipher",
    "hash function",
    "hmac function",
    "cmac function",
    "mgm function",
    "mac function",
    "sign function",
    "verify function",
    "random generator",
    "oid engine",
    "master key",
    "subscriber's key",
    "pairwise key",
    "undefined engine",
};

/* ----------------------------------------------------------------------------------------------- */
 static const char *libakrypt_mode_names[] = {
    "algorithm",
    "parameter",
    "wcurve params",
    "ecurve params",
    "kbox params",
    "encrypt mode",
    "encrypt2k mode",
    "acpkm mode",
    "mac mode",
    "aead mode",
    "xcrypt mode",
    "descriptor",
    "undefined mode"
};

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения имен идентификаторов */
 static const char *asn1_lcg_n[] =         { "lcg", NULL };
 static const char *asn1_lcg_i[] =         { "1.2.643.2.52.1.1.1", NULL };
#if defined(__unix__) || defined(__APPLE__)
 static const char *asn1_dev_random_n[] =  { "dev-random", "/dev/random", NULL };
 static const char *asn1_dev_random_i[] =  { "1.2.643.2.52.1.1.2", NULL };
 static const char *asn1_dev_urandom_n[] = { "dev-urandom", "/dev/urandom", NULL };
 static const char *asn1_dev_urandom_i[] = { "1.2.643.2.52.1.1.3", NULL };
#endif
#ifdef _WIN32
 static const char *asn1_winrtl_n[] =       { "winrtl", NULL };
 static const char *asn1_winrtl_i[] =       { "1.2.643.2.52.1.1.4", NULL };
#endif
/* генератор, использующий функцию хеширования согласно Р 1323565.1.006-2017 */
 static const char *asn1_hrng_n[] =     { "hrng", NULL };
 static const char *asn1_hrng_i[] =     { "1.2.643.2.52.1.1.5", NULL };
 static const char *asn1_nlfsr_n[] =     { "nlfsr", NULL };
 static const char *asn1_nlfsr_i[] =     { "1.2.643.2.52.1.1.6", NULL };

 static const char *asn1_streebog256_n[] = { "streebog256", "md_gost12_256", NULL };
 static const char *asn1_streebog256_i[] = { "1.2.643.7.1.1.2.2", NULL };
 static const char *asn1_streebog512_n[] = { "streebog512", "md_gost12_512", NULL };
 static const char *asn1_streebog512_i[] = { "1.2.643.7.1.1.2.3", NULL };
 static const char *asn1_hmac_streebog256_n[] = { "hmac-streebog256", "HMAC-md_gost12_256", NULL };
 static const char *asn1_hmac_streebog256_i[] = { "1.2.643.7.1.1.4.1", NULL };
 static const char *asn1_hmac_streebog512_n[] = { "hmac-streebog512", "HMAC-md_gost12_512", NULL };
 static const char *asn1_hmac_streebog512_i[] = { "1.2.643.7.1.1.4.2", NULL };
 static const char *asn1_nmac_streebog_n[] =    { "nmac-streebog", NULL };
 static const char *asn1_nmac_streebog_i[] =    { "1.2.643.2.52.1.8.1", NULL };
 static const char *asn1_magma_n[] =       { "magma", NULL };
 static const char *asn1_magma_i[] =       { "1.2.643.7.1.1.5.1", NULL };
 static const char *asn1_kuznechik_n[] =   { "kuznechik", "kuznyechik", "grasshopper", NULL };
 static const char *asn1_kuznechik_i[] =   { "1.2.643.7.1.1.5.2", NULL };

 static const char *asn1_ctr_magma_n[] =   { "ctr-magma", NULL };
 static const char *asn1_ctr_magma_i[] =   { "1.2.643.2.52.1.5.1.1", NULL };
 static const char *asn1_ctr_kuznechik_n[] =
                                           { "ctr-kuznechik", "ctr-kuznyechik", NULL };
 static const char *asn1_ctr_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.1.2", NULL };
 static const char *asn1_ofb_magma_n[] =   { "ofb-magma", NULL };
 static const char *asn1_ofb_magma_i[] =   { "1.2.643.2.52.1.5.2.1", NULL };
 static const char *asn1_ofb_kuznechik_n[] =
                                           { "ofb-kuznechik", "ofb-kuznyechik", NULL };
 static const char *asn1_ofb_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.2.2", NULL };
 static const char *asn1_cfb_magma_n[] =   { "cfb-magma", NULL };
 static const char *asn1_cfb_magma_i[] =   { "1.2.643.2.52.1.5.3.1", NULL };
 static const char *asn1_cfb_kuznechik_n[] =
                                           { "cfb-kuznechik", "cfb-kuznyechik", NULL };
 static const char *asn1_cfb_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.3.2", NULL };
 static const char *asn1_cbc_magma_n[] =   { "cbc-magma", NULL };
 static const char *asn1_cbc_magma_i[] =   { "1.2.643.2.52.1.5.4.1", NULL };
 static const char *asn1_cbc_kuznechik_n[] =
                                           { "cbc-kuznechik", "cbc-kuznyechik", NULL };
 static const char *asn1_cbc_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.4.2", NULL };

 static const char *asn1_xts_magma_n[] =   { "xts-magma", NULL };
 static const char *asn1_xts_magma_i[] =   { "1.2.643.2.52.1.5.5.1", NULL };
 static const char *asn1_xts_kuznechik_n[] =
                                           { "xts-kuznechik", NULL };
 static const char *asn1_xts_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.5.2", NULL };

 /*   id-gostr3412-2015-magma-ctracpkm OBJECT IDENTIFIER ::= { 1.2.643.7.1.1.5.1.1 }
      id-gostr3412-2015-kuznechik-ctracpkm OBJECT IDENTIFIER ::= { 1.2.643.7.1.1.5.2.1 } */

 static const char *asn1_acpkm_magma_n[] = { "acpkm-magma",
                                             "id-gostr3412-2015-magma-ctracpkm", NULL };
 static const char *asn1_acpkm_magma_i[] = { "1.2.643.7.1.1.5.1.1", NULL };
 static const char *asn1_acpkm_kuznechik_n[] =
                                           { "acpkm-kuznechik", "acpkm-kuznyechik",
                                             "id-gostr3412-2015-kuznechik-ctracpkm", NULL };
 static const char *asn1_acpkm_kuznechik_i[] =
                                           { "1.2.643.7.1.1.5.2.1", NULL };

 static const char *asn1_cmac_magma_n[] =  { "cmac-magma", NULL };
 static const char *asn1_cmac_magma_i[] =  { "1.2.643.2.52.1.7.1.1", NULL };
 static const char *asn1_cmac_kuznechik_n[] =
                                           { "cmac-kuznechik", "cmac-kuznyechik", NULL };
 static const char *asn1_cmac_kuznechik_i[] =
                                           { "1.2.643.2.52.1.7.1.2", NULL };

 static const char *asn1_mgm_magma_n[] =   { "mgm-magma",
                                             "id-tc26-cipher-gostr3412-2015-magma-mgm", NULL };
 static const char *asn1_mgm_magma_i[] =   { "1.2.643.7.1.1.5.1.3", NULL };
 static const char *asn1_mgm_kuznechik_n[] =
                                           { "mgm-kuznechik", "mgm-kuznyechik",
                                             "id-tc26-cipher-gostr3412-2015-kuznechik-mgm",
                                             "id-tc26-cipher-gostr3412-2015-kuznyechik-mgm", NULL };
 static const char *asn1_mgm_kuznechik_i[] =
                                           { "1.2.643.7.1.1.5.2.3", NULL };
 static const char *asn1_ctr_cmac_magma_n[] =
                                           { "ctr-cmac-magma", NULL };
 static const char *asn1_ctr_cmac_magma_i[] =
                                           { "1.2.643.2.52.1.6.1.1", NULL };
 static const char *asn1_ctr_cmac_kuznechik_n[] =
                                           { "ctr-cmac-kuznechik",
                                             "ctr-cmac-kuznyechik", NULL };
 static const char *asn1_ctr_cmac_kuznechik_i[] =
                                           { "1.2.643.2.52.1.6.1.2", NULL };
 static const char *asn1_ctr_hmac_magma_streebog256_n[] =
                                           { "ctr-hmac-magma-streebog256", NULL };
 static const char *asn1_ctr_hmac_magma_streebog256_i[] =
                                           { "1.2.643.2.52.1.6.2.1.1", NULL };
 static const char *asn1_ctr_hmac_magma_streebog512_n[] =
                                           { "ctr-hmac-magma-streebog512", NULL };
 static const char *asn1_ctr_hmac_magma_streebog512_i[] =
                                           { "1.2.643.2.52.1.6.2.1.2", NULL };
 static const char *asn1_ctr_nmac_magma_n[] =
                                           { "ctr-nmac-magma", NULL };
 static const char *asn1_ctr_nmac_magma_i[] =
                                           { "1.2.643.2.52.1.6.2.1.3", NULL };
 static const char *asn1_ctr_hmac_kuznechik_streebog256_n[] =
                                           { "ctr-hmac-kuznechik-streebog256",
                                             "ctr-hmac-kuznyechik-streebog256", NULL };
 static const char *asn1_ctr_hmac_kuznechik_streebog256_i[] =
                                           { "1.2.643.2.52.1.6.2.2.1", NULL };
 static const char *asn1_ctr_hmac_kuznechik_streebog512_n[] =
                                           { "ctr-hmac-kuznechik-streebog512",
                                             "ctr-hmac-kuznyechik-streebog512", NULL };
 static const char *asn1_ctr_hmac_kuznechik_streebog512_i[] =
                                           { "1.2.643.2.52.1.6.2.2.2", NULL };
 static const char *asn1_ctr_nmac_kuznechik_n[] =
                                           { "ctr-nmac-kuznechik",
                                             "ctr-nmac-kuznyechik", NULL };
 static const char *asn1_ctr_nmac_kuznechik_i[] =
                                           { "1.2.643.2.52.1.6.2.2.3", NULL };
/*
 static const char *asn1_xtsmac_magma_n[] =
                                           { "xtsmac-magma", NULL };
 static const char *asn1_xtsmac_magma_i[] =
                                           { "1.2.643.2.52.1.6.3.1", NULL };
 static const char *asn1_xtsmac_kuznechik_n[] =
                                           { "xtsmac-kuznechik", "xtsmac-kuznyechik", NULL };
 static const char *asn1_xtsmac_kuznechik_i[] =
                                           { "1.2.643.2.52.1.6.3.2", NULL }; */

 static const char *asn1_sign256_n[] =     { "id-tc26-signwithdigest-gost3410-12-256",
                                             "sign256", NULL };
 static const char *asn1_sign256_i[] =     { "1.2.643.7.1.1.3.2", NULL };
 static const char *asn1_sign512_n[] =     { "id-tc26-signwithdigest-gost3410-12-512",
                                             "sign512", NULL };
 static const char *asn1_sign512_i[] =     { "1.2.643.7.1.1.3.3", NULL };
 static const char *asn1_verify256_n[] =   { "id-tc26-gost3410-12-256", "verify256", NULL };
 static const char *asn1_verify256_i[] =   { "1.2.643.7.1.1.1.1", NULL };
 static const char *asn1_verify512_n[] =   { "id-tc26-gost3410-12-512", "verify512", NULL };
 static const char *asn1_verify512_i[] =   { "1.2.643.7.1.1.1.2", NULL };

 static const char *asn1_w256_pst_n[] =    { "id-tc26-gost-3410-2012-256-paramSetTest", NULL };
 static const char *asn1_w256_pst_i[] =    { "1.2.643.7.1.2.1.1.0",
                                             "1.2.643.2.2.35.0", NULL };
 static const char *asn1_w256_psa_n[] =    { "id-tc26-gost-3410-2012-256-paramSetA", 
                                             "tc26a", NULL };
 static const char *asn1_w256_psa_i[] =    { "1.2.643.7.1.2.1.1.1", NULL };
 static const char *asn1_w256_psb_n[] =    { "id-tc26-gost-3410-2012-256-paramSetB",
                                             "id-rfc4357-gost-3410-2001-paramSetA",
                                             "id-rfc4357-2001dh-paramSet",
                                             "cspdh",
                                             "cspa", "tc26b", NULL };
 static const char *asn1_w256_psb_i[] =    { "1.2.643.7.1.2.1.1.2",
                                             "1.2.643.2.2.35.1",
                                             "1.2.643.2.2.36.0", NULL };
 static const char *asn1_w256_psc_n[] =    { "id-tc26-gost-3410-2012-256-paramSetC",
                                             "id-rfc4357-gost-3410-2001-paramSetB",
                                             "cspb", "tc26c", NULL };
 static const char *asn1_w256_psc_i[] =    { "1.2.643.7.1.2.1.1.3",
                                             "1.2.643.2.2.35.2", NULL };
 static const char *asn1_w256_psd_n[] =    { "id-tc26-gost-3410-2012-256-paramSetD",
                                             "id-rfc4357-gost-3410-2001-paramSetC",
                                             "cspc", "tc26d", NULL };
 static const char *asn1_w256_psd_i[] =    { "1.2.643.7.1.2.1.1.4",
                                             "1.2.643.2.2.35.3", NULL };
 static const char *asn1_w256_axel_n[] =   { "id-axel-gost-3410-2012-256-paramSetN0",
                                             "axeln0", NULL };
 static const char *asn1_w256_axel_i[] =   { "1.2.643.2.52.1.12.1.1", NULL };

/* теперь кривые длиной 512 бит */
 static const char *asn1_w512_pst_n[] =    { "id-tc26-gost-3410-2012-512-paramSetTest", NULL };
 static const char *asn1_w512_pst_i[] =    { "1.2.643.7.1.2.1.2.0", NULL };
 static const char *asn1_w512_psa_n[] =    { "id-tc26-gost-3410-2012-512-paramSetA",
                                             "ec512a", NULL };
 static const char *asn1_w512_psa_i[] =    { "1.2.643.7.1.2.1.2.1", NULL };
 static const char *asn1_w512_psb_n[] =    { "id-tc26-gost-3410-2012-512-paramSetB",
                                             "ec512b", NULL };
 static const char *asn1_w512_psb_i[] =    { "1.2.643.7.1.2.1.2.2", NULL };
 static const char *asn1_w512_psc_n[] =    { "id-tc26-gost-3410-2012-512-paramSetC",
                                             "ec512c", NULL };
 static const char *asn1_w512_psc_i[] =    { "1.2.643.7.1.2.1.2.3", NULL };

 static const char *asn1_blom_m_n[] =      { "blom-master", "blom-matrix", NULL };
 static const char *asn1_blom_m_i[] =      { "1.2.643.2.52.1.181.1", NULL };
 static const char *asn1_blom_a_n[] =      { "blom-user", "blom-subscriber", "blom-abonent", NULL };
 static const char *asn1_blom_a_i[] =      { "1.2.643.2.52.1.181.2", NULL };
 static const char *asn1_blom_p_n[] =      { "blom-pairwise", NULL };
 static const char *asn1_blom_p_i[] =      { "1.2.643.2.52.1.181.3", NULL };

 static const char *asn1_akcont_n[] =      { "libakrypt-container", NULL };
 static const char *asn1_akcont_i[] =      { "1.2.643.2.52.1.127.1.1", NULL };

 static const char *asn1_nokey_n[] =       { "no-basic-key", NULL };
 static const char *asn1_nokey_i[] =       { "1.2.643.2.52.1.127.2.0", NULL };
 static const char *asn1_pbkdf2key_n[] =   { "pbkdf2-basic-key", NULL };
 static const char *asn1_pbkdf2key_i[] =   { "1.2.643.2.52.1.127.2.1", NULL };
 static const char *asn1_sdhkey_n[] =      { "static-dh-basic-key", NULL };
 static const char *asn1_sdhkey_i[] =      { "1.2.643.2.52.1.127.2.2", NULL };
 static const char *asn1_extkey_n[] =      { "external-basic-key", NULL };
 static const char *asn1_extkey_i[] =      { "1.2.643.2.52.1.127.2.3", NULL };
 static const char *asn1_ecieskey_n[] =    { "ecies-scheme-key", NULL };
 static const char *asn1_ecieskey_i[] =    { "1.2.643.2.52.1.127.2.4", NULL };

 static const char *asn1_symkmd_n[] =      { "symmetric-key-content", NULL };
 static const char *asn1_symkmd_i[] =      { "1.2.643.2.52.1.127.3.1", NULL };
 static const char *asn1_skmd_n[] =        { "secret-key-content", NULL };
 static const char *asn1_skmd_i[] =        { "1.2.643.2.52.1.127.3.2", NULL };
 static const char *asn1_pkmd_n[] =        { "public-key-certificate-content", NULL };
 static const char *asn1_pkmd_i[] =        { "1.2.643.2.52.1.127.3.3", NULL };
 static const char *asn1_pkmdr_n[] =       { "public-key-request-content", NULL };
 static const char *asn1_pkmdr_i[] =       { "1.2.643.2.52.1.127.3.4", NULL };
 static const char *asn1_ecmd_n[] =        { "encrypted-content", NULL };
 static const char *asn1_ecmd_i[] =        { "1.2.643.2.52.1.127.3.5", NULL };
 static const char *asn1_pcmd_n[] =        { "plain-content", NULL };
 static const char *asn1_pcmd_i[] =        { "1.2.643.2.52.1.127.3.6", NULL };

/* добавляем аттрибуты типов (X.500) и расширенные аттрибуты */
 static const char *asn1_email_n[] =       { "email-address", "em", "Почта", NULL };
 static const char *asn1_email_i[] =       { "1.2.840.113549.1.9.1", NULL };
 static const char *asn1_cn_n[] =          { "common-name", "cn", "Имя", NULL };
 static const char *asn1_cn_i[] =          { "2.5.4.3", NULL };
 static const char *asn1_s_n[] =           { "surname", "su", "Фамилия", NULL };
 static const char *asn1_s_i[] =           { "2.5.4.4", NULL };
 static const char *asn1_sn_n[] =          { "serial-number", "sn", "Серийный номер", NULL };
 static const char *asn1_sn_i[] =          { "2.5.4.5", NULL };
 static const char *asn1_c_n[] =           { "country-name", "ct", "Страна", NULL };
 static const char *asn1_c_i[] =           { "2.5.4.6", NULL };
 static const char *asn1_l_n[] =           { "locality-name", "ln", "Населенный пункт", NULL };
 static const char *asn1_l_i[] =           { "2.5.4.7", NULL };
 static const char *asn1_st_n[] =          { "state-or-province-name", "st", "Область", NULL };
 static const char *asn1_st_i[] =          { "2.5.4.8", NULL };
 static const char *asn1_sa_n[] =          { "street-address", "sa", "Адрес", NULL };
 static const char *asn1_sa_i[] =          { "2.5.4.9", NULL };
 static const char *asn1_o_n[] =           { "organization", "or", "Организация", NULL };
 static const char *asn1_o_i[] =           { "2.5.4.10", NULL };
 static const char *asn1_ou_n[] =          { "organization-unit", "ou", "Подразделение", NULL };
 static const char *asn1_ou_i[] =          { "2.5.4.11", NULL };
 static const char *asn1_title_n[] =       { "title", "tl", "Название", NULL };
 static const char *asn1_title_i[] =       { "2.5.4.12", NULL };
 static const char *asn1_gn_n[] =          { "given-name", "gn", "Имя, данное при рождении", NULL };
 static const char *asn1_gn_i[] =          { "2.5.4.42", NULL };
 static const char *asn1_ps_n[] =          { "pseudonym", "ps", "Псевдоним", NULL };
 static const char *asn1_ps_i[] =          { "2.5.4.65", NULL };

 static const char *asn1_ski_n[] =         { "subject-key-identifier", NULL };
 static const char *asn1_ski_i[] =         { "2.5.29.14", NULL };
 static const char *asn1_ku_n[] =          { "key-usage", NULL };
 static const char *asn1_ku_i[] =          { "2.5.29.15", NULL };
 static const char *asn1_san_n[] =         { "subject-alternative-name", NULL };
 static const char *asn1_san_i[] =         { "2.5.29.17", NULL };
 static const char *asn1_ian_n[] =         { "issuer-alternative-name", NULL };
 static const char *asn1_ian_i[] =         { "2.5.29.18", NULL };
 static const char *asn1_bc_n[] =          { "basic-constraints", NULL };
 static const char *asn1_bc_i[] =          { "2.5.29.19", NULL };
 static const char *asn1_crldp_n[] =       { "crl-distribution-points", NULL };
 static const char *asn1_crldp_i[] =       { "2.5.29.31", NULL };
 static const char *asn1_cp_n[] =          { "certificate-policies", NULL };
 static const char *asn1_cp_i[] =          { "2.5.29.32", NULL };
 static const char *asn1_wcp_n[] =         { "wildcard-certificate-policy", NULL };
 static const char *asn1_wcp_i[] =         { "2.5.29.32.0", NULL };
 static const char *asn1_aki_n[] =         { "authority-key-identifier", NULL };
 static const char *asn1_aki_i[] =         { "2.5.29.35", NULL };
 static const char *asn1_eku_n[] =         { "extended-key-usage", NULL };
 static const char *asn1_eku_i[] =         { "2.5.29.37", NULL };

/* значения для extended key usage */
 static const char *asn1_kpsa_n[] =        { "tls-server-authentication", NULL };
 static const char *asn1_kpsa_i[] =        { "1.3.6.1.5.5.7.3.1", NULL };
 static const char *asn1_kpca_n[] =        { "tls-client-authentication", NULL };
 static const char *asn1_kpca_i[] =        { "1.3.6.1.5.5.7.3.2", NULL };
 static const char *asn1_kpcs_n[] =        { "executable-code-signing", NULL };
 static const char *asn1_kpcs_i[] =        { "1.3.6.1.5.5.7.3.3", NULL };
 static const char *asn1_kpep_n[] =        { "email-protection", NULL };
 static const char *asn1_kpep_i[] =        { "1.3.6.1.5.5.7.3.4", NULL };

/* дополнительные расширения из RFC 2459 */
 static const char *asn1_pkix_exaIA_n[] =  { "pkix-authority-info-access", NULL };
 static const char *asn1_pkix_exaIA_i[] =  { "1.3.6.1.5.5.7.1.1", NULL };

 static const char *asn1_pkix_exAD_n[] =   { "pkix-access-descriptor-caIssuers", NULL };
 static const char *asn1_pkix_exAD_i[] =   { "1.3.6.1.5.5.7.48.2", NULL };

/* следующее добро из Приказа ФСБ N 795 */
 static const char *asn1_ogrn_n[] =        { "ogrn", "og", "ОГРН", NULL };
 static const char *asn1_ogrn_i[] =        { "1.2.643.100.1", NULL };
 static const char *asn1_snils_n[] =       { "snils", "si", "СНИЛС", NULL };
 static const char *asn1_snils_i[] =       { "1.2.643.100.3", NULL };
 static const char *asn1_ogrnip_n[] =      { "ogrnip", "oi", "ОГРНИП", NULL };
 static const char *asn1_ogrnip_i[] =      { "1.2.643.100.5", NULL };
 static const char *asn1_owner_mod_n[] =   { "subject-crypto-module", NULL };
 static const char *asn1_owner_mod_i[] =   { "1.2.643.100.111", NULL };
 static const char *asn1_issuer_mod_n[] =  { "issuer-crypto-module", NULL };
 static const char *asn1_issuer_mod_i[] =  { "1.2.643.100.112", NULL };
 static const char *asn1_inn_n[] =         { "inn", "in", "ИНН физлица", NULL }; /* ИНН физлица */
 static const char *asn1_inn_i[] =         { "1.2.643.3.131.1.1", NULL };
 static const char *asn1_innle_n[] =       { "inn-legal-entity", "le", "ИНН юрлица", NULL }; /* ИНН юрлица, начиная с 2021 г. */
 static const char *asn1_innle_i[] =       { "1.2.643.100.4", NULL };
 static const char *asn1_class_kc1_n[] =   { "digital-signature-module, class kc1", "kc1", NULL };
 static const char *asn1_class_kc1_i[] =   { "1.2.643.100.113.1", NULL };
 static const char *asn1_class_kc2_n[] =   { "digital-signature-module, class kc2", "kc2", NULL };
 static const char *asn1_class_kc2_i[] =   { "1.2.643.100.113.2", NULL };
 static const char *asn1_class_kc3_n[] =   { "digital-signature-module, class kc3", "kc3", NULL };
 static const char *asn1_class_kc3_i[] =   { "1.2.643.100.113.3", NULL };
 static const char *asn1_class_kb1_n[] =   { "digital-signature-module, class kb1", "kb", NULL };
 static const char *asn1_class_kb1_i[] =   { "1.2.643.100.113.4", NULL };
 static const char *asn1_class_kb2_n[] =   { "digital-signature-module, class kb2", NULL };
 static const char *asn1_class_kb2_i[] =   { "1.2.643.100.113.5", NULL };
 static const char *asn1_class_ka1_n[] =   { "digital-signature-module, class ka", "ka", NULL };
 static const char *asn1_class_ka1_i[] =   { "1.2.643.100.113.6", NULL };
 static const char *asn1_identkind_n[] =   { "identification-kind", "ik", NULL };
 static const char *asn1_identkind_i[] =   { "1.2.643.100.114", NULL };

/* расширения PKIX, определяемые библиотекой libakrypt */
 static const char *asn1_akskn_n[] =       { "secret-key-number", NULL };
 static const char *asn1_akskn_i[] =       { "1.2.643.2.52.1.98.1", NULL };

/* ----------------------------------------------------------------------------------------------- */
/* идентификаторы из RFC 5652 (про CMS) */
/* ----------------------------------------------------------------------------------------------- */
 static const char *asn1_cms_data_n[] =    { "cms-data-content-type", NULL };
 static const char *asn1_cms_data_i[] =    { "1.2.840.113549.1.7.1", NULL };
 static const char *asn1_cms_signed_n[] =  { "cms-signed-data-content-type", NULL };
 static const char *asn1_cms_signed_i[] =  { "1.2.840.113549.1.7.2", NULL };
 static const char *asn1_cms_envelop_n[] = { "cms-enveloped-data-content-type", NULL };
 static const char *asn1_cms_envelop_i[] = { "1.2.840.113549.1.7.3", NULL };
 static const char *asn1_cms_digest_n[] =  { "cms-digest-data-content-type", NULL };
 static const char *asn1_cms_digest_i[] =  { "1.2.840.113549.1.7.5", NULL };
 static const char *asn1_cms_enc_n[] =     { "cms-encrypted-data-content-type", NULL };
 static const char *asn1_cms_enc_i[] =     { "1.2.840.113549.1.7.6", NULL };

/* ----------------------------------------------------------------------------------------------- */
/* внутренности openssl */
/* ----------------------------------------------------------------------------------------------- */
 static const char *asn1_netsmsg_n[] =     { "netscape-certificate-comment", NULL };
 static const char *asn1_netsmsg_i[] =     { "2.16.840.1.113730.1.13", NULL };

/* ----------------------------------------------------------------------------------------------- */
/* вот что приходится разбирать в сертификатах от КриптоПро */
/*   Microsoft OID...................................1.3.6.1.4.1.311  */
/*   см. также https://www.dogtagpki.org/wiki/Certificate_Extensions  */
/* ----------------------------------------------------------------------------------------------- */
 static const char *asn1_mscav_n[] =       { "microsoft-ca-version", NULL };
 static const char *asn1_mscav_i[] =       { "1.3.6.1.4.1.311.21.1", NULL };
 static const char *asn1_msct_n[] =        { "microsoft-certificate-template", NULL };
 static const char *asn1_msct_i[] =        { "1.3.6.1.4.1.311.21.7", NULL };
 static const char *asn1_mspsh_n[] =       { "microsoft-previous-certificate-hash", NULL };
 static const char *asn1_mspsh_i[] =       { "1.3.6.1.4.1.311.21.2", NULL };
 static const char *asn1_mstndc_n[] =      { "microsoft-enrollment-certificate-type", NULL };
 static const char *asn1_mstndc_i[] =      { "1.3.6.1.4.1.311.20.2", NULL };

/* ----------------------------------------------------------------------------------------------- */
/* неподдерживаемые алгоритмы подписи, сертификаты которых могут разбираться на части */
 static const char *asn1_sign94_n[] =      { "id-gost3411-94-with-gost3410-2001", NULL };
 static const char *asn1_sign94_i[] =      { "1.2.643.2.2.3", NULL };
 static const char *asn1_sign01_n[] =      { "id-gost3410-2001", NULL };
 static const char *asn1_sign01_i[] =      { "1.2.643.2.2.19", NULL };
 static const char *asn1_sha1sign_n[] =    { "sha1-with-rsa-signature", NULL };
 static const char *asn1_sha1sign_i[] =    { "1.2.840.113549.1.1.5", NULL };
 static const char *asn1_sha256sign_n[] =  { "sha256-with-rsa-encryption", NULL };
 static const char *asn1_sha256sign_i[] =  { "1.2.840.113549.1.1.11", NULL };
 static const char *asn1_sha384sign_n[] =  { "sha384-with-rsa-encryption", NULL };
 static const char *asn1_sha384sign_i[] =  { "1.2.840.113549.1.1.12", NULL };
 static const char *asn1_sha512sign_n[] =  { "sha512-with-rsa-encryption", NULL };
 static const char *asn1_sha512sign_i[] =  { "1.2.840.113549.1.1.13", NULL };
 static const char *asn1_sha224sign_n[] =  { "sha224-with-rsa-encryption", NULL };
 static const char *asn1_sha224sign_i[] =  { "1.2.840.113549.1.1.14", NULL };
 static const char *asn1_ecdsasha1_n[] =   { "ecdsa-with-sha1", NULL };
 static const char *asn1_ecdsasha1_i[] =   { "1.2.840.10045.4.1", NULL };
 static const char *asn1_ecdsasha224_n[] = { "ecdsa-with-sha224", NULL };
 static const char *asn1_ecdsasha224_i[] = { "1.2.840.10045.4.3.1", NULL };
 static const char *asn1_ecdsasha256_n[] = { "ecdsa-with-sha256", NULL };
 static const char *asn1_ecdsasha256_i[] = { "1.2.840.10045.4.3.2", NULL };
 static const char *asn1_ecdsasha384_n[] = { "ecdsa-with-sha384", NULL };
 static const char *asn1_ecdsasha384_i[] = { "1.2.840.10045.4.3.3", NULL };
 static const char *asn1_ecdsasha512_n[] = { "ecdsa-with-sha512", NULL };
 static const char *asn1_ecdsasha512_i[] = { "1.2.840.10045.4.3.4", NULL };

/* Сертикомовские параметры тоже могут быть определены,
   но пока примеры их применения не находятся в анамнезе

    2.23.42.9.11.4.1.0  - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm generic curve ecdsaWithSHA-1
    2.23.42.9.11.4.1.10 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec131a01
    2.23.42.9.11.4.1.11 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec163a01
    2.23.42.9.11.4.1.12 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec239a01
    2.23.42.9.11.4.1.13 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec131b01
    2.23.42.9.11.4.1.14 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec155b01
    2.23.42.9.11.4.1.15 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec163b01
    2.23.42.9.11.4.1.16 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec191b01
    2.23.42.9.11.4.1.17 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec210b01
    2.23.42.9.11.4.1.18 - Certicom ECDSA, Elliptic Curve Digital Signature Algorithm curve sigECDSAec239b01
*/


/* ----------------------------------------------------------------------------------------------- */
 #define ak_object_bckey_magma { sizeof( struct bckey ), \
                           ( ak_function_create_object *) ak_bckey_create_magma, \
                           ( ak_function_destroy_object *) ak_bckey_destroy, \
                           ( ak_function_set_key_object *)ak_bckey_set_key, \
                           ( ak_function_set_key_random_object *)ak_bckey_set_key_random, \
                      ( ak_function_set_key_from_password_object *)ak_bckey_set_key_from_password }

 #define ak_object_bckey_kuznechik { sizeof( struct bckey ), \
                           ( ak_function_create_object *) ak_bckey_create_kuznechik, \
                           ( ak_function_destroy_object *) ak_bckey_destroy, \
                           ( ak_function_set_key_object *)ak_bckey_set_key, \
                           ( ak_function_set_key_random_object *)ak_bckey_set_key_random, \
                      ( ak_function_set_key_from_password_object *)ak_bckey_set_key_from_password }

 #define ak_object_hmac_streebog256 { sizeof( struct hmac ), \
                           ( ak_function_create_object *) ak_hmac_create_streebog256, \
                           ( ak_function_destroy_object *) ak_hmac_destroy, \
                           ( ak_function_set_key_object *)ak_hmac_set_key, \
                           ( ak_function_set_key_random_object *)ak_hmac_set_key_random, \
                       ( ak_function_set_key_from_password_object *)ak_hmac_set_key_from_password }

 #define ak_object_hmac_streebog512 { sizeof( struct hmac ), \
                           ( ak_function_create_object *) ak_hmac_create_streebog512, \
                           ( ak_function_destroy_object *) ak_hmac_destroy, \
                           ( ak_function_set_key_object *)ak_hmac_set_key, \
                           ( ak_function_set_key_random_object *)ak_hmac_set_key_random, \
                       ( ak_function_set_key_from_password_object *)ak_hmac_set_key_from_password }

 #define ak_object_nmac_streebog { sizeof( struct hmac ), \
                           ( ak_function_create_object *) ak_hmac_create_nmac, \
                           ( ak_function_destroy_object *) ak_hmac_destroy, \
                           ( ak_function_set_key_object *)ak_hmac_set_key, \
                           ( ak_function_set_key_random_object *)ak_hmac_set_key_random, \
                       ( ak_function_set_key_from_password_object *)ak_hmac_set_key_from_password }

 #define ak_object_signkey256 { sizeof( struct signkey ), \
                          ( ak_function_create_object *) ak_signkey_create_streebog256, \
                          ( ak_function_destroy_object *) ak_signkey_destroy, \
                          ( ak_function_set_key_object *) ak_signkey_set_key, \
                          ( ak_function_set_key_random_object *) ak_signkey_set_key_random, NULL }

 #define ak_object_signkey512 { sizeof( struct signkey ), \
                          ( ak_function_create_object *) ak_signkey_create_streebog512, \
                          ( ak_function_destroy_object *) ak_signkey_destroy, \
                          ( ak_function_set_key_object *) ak_signkey_set_key, \
                          ( ak_function_set_key_random_object *) ak_signkey_set_key_random, NULL }

 #define ak_object_verifykey256 { sizeof( struct signkey ), \
                          ( ak_function_create_object *) ak_verifykey_create_streebog256, \
                          ( ak_function_destroy_object *) ak_verifykey_destroy, \
                                                                                NULL, NULL, NULL }

 #define ak_object_verifykey512 { sizeof( struct signkey ), \
                          ( ak_function_create_object *) ak_verifykey_create_streebog512, \
                          ( ak_function_destroy_object *) ak_verifykey_destroy, \
                                                                                NULL, NULL, NULL }

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения OID библиотеки */
static struct oid libakrypt_oids[] =
{
 /* идентификаторы  */
 { random_generator, algorithm, asn1_lcg_i, asn1_lcg_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_lcg,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},
#if defined(__unix__) || defined(__APPLE__)
 { random_generator, algorithm, asn1_dev_random_i, asn1_dev_random_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_random,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},
 { random_generator, algorithm, asn1_dev_urandom_i, asn1_dev_urandom_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_urandom,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},
#endif
#ifdef _WIN32
 { random_generator, algorithm,asn1_winrtl_i, asn1_winrtl_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_winrtl,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},
#endif

 { random_generator, algorithm, asn1_hrng_i, asn1_hrng_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_hrng,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},

 { random_generator, algorithm, asn1_nlfsr_i, asn1_nlfsr_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_nlfsr,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},

/* добавляем идентификаторы алгоритмов */
 { hash_function, algorithm, asn1_streebog256_i, asn1_streebog256_n, NULL,
  {{ sizeof( struct hash ), ( ak_function_create_object *) ak_hash_create_streebog256,
                              ( ak_function_destroy_object *) ak_hash_destroy, NULL, NULL, NULL },
                              ak_object_undefined, (ak_function_run_object *) ak_hash_ptr, NULL }},

 { hash_function, algorithm, asn1_streebog512_i, asn1_streebog512_n, NULL,
  {{ sizeof( struct hash ), ( ak_function_create_object *) ak_hash_create_streebog512,
                              ( ak_function_destroy_object *) ak_hash_destroy, NULL, NULL, NULL },
                              ak_object_undefined, (ak_function_run_object *) ak_hash_ptr, NULL }},

 { hmac_function, algorithm, asn1_hmac_streebog256_i, asn1_hmac_streebog256_n, NULL,
                            { ak_object_hmac_streebog256,
                              ak_object_undefined, (ak_function_run_object *) ak_hmac_ptr, NULL }},

 { hmac_function, algorithm, asn1_hmac_streebog512_i, asn1_hmac_streebog512_n, NULL,
                            { ak_object_hmac_streebog512,
                              ak_object_undefined, (ak_function_run_object *) ak_hmac_ptr, NULL }},

 { hmac_function, algorithm, asn1_nmac_streebog_i, asn1_nmac_streebog_n, NULL,
                            { ak_object_nmac_streebog,
                              ak_object_undefined, (ak_function_run_object *) ak_hmac_ptr, NULL }},

 { block_cipher, algorithm, asn1_magma_i, asn1_magma_n, NULL,
                                       { ak_object_bckey_magma, ak_object_undefined, NULL, NULL }},

 { block_cipher, algorithm, asn1_kuznechik_i, asn1_kuznechik_n, NULL,
                                   { ak_object_bckey_kuznechik, ak_object_undefined, NULL, NULL }},

/* базовые режимы блочного шифрования */
 { block_cipher, encrypt_mode, asn1_ctr_magma_i, asn1_ctr_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ctr,
                                                       ( ak_function_run_object *) ak_bckey_ctr }},

 { block_cipher, encrypt_mode, asn1_ctr_kuznechik_i, asn1_ctr_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ctr,
                                                       ( ak_function_run_object *) ak_bckey_ctr }},

 { block_cipher, encrypt_mode, asn1_ofb_magma_i, asn1_ofb_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ofb,
                                                       ( ak_function_run_object *) ak_bckey_ofb }},

 { block_cipher, encrypt_mode, asn1_ofb_kuznechik_i, asn1_ofb_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ofb,
                                                       ( ak_function_run_object *) ak_bckey_ofb }},

 { block_cipher, encrypt_mode, asn1_cfb_magma_i, asn1_cfb_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_encrypt_cfb,
                                               ( ak_function_run_object *) ak_bckey_decrypt_cfb }},

 { block_cipher, encrypt_mode, asn1_cfb_kuznechik_i, asn1_cfb_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined,
                                                ( ak_function_run_object *) ak_bckey_encrypt_cfb,
                                               ( ak_function_run_object *) ak_bckey_decrypt_cfb }},

 { block_cipher, encrypt_mode, asn1_cbc_magma_i, asn1_cbc_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_encrypt_cbc,
                                               ( ak_function_run_object *) ak_bckey_decrypt_cbc }},

 { block_cipher, encrypt_mode, asn1_cbc_kuznechik_i, asn1_cbc_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined,
                                                ( ak_function_run_object *) ak_bckey_encrypt_cbc,
                                               ( ak_function_run_object *) ak_bckey_decrypt_cbc }},

 { block_cipher, encrypt2k_mode, asn1_xts_magma_i, asn1_xts_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_bckey_magma,
                                                ( ak_function_run_object *) ak_bckey_encrypt_xts,
                                               ( ak_function_run_object *) ak_bckey_decrypt_xts }},

 { block_cipher, encrypt2k_mode, asn1_xts_kuznechik_i, asn1_xts_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_bckey_kuznechik,
                                                 ( ak_function_run_object *) ak_bckey_encrypt_xts,
                                               ( ak_function_run_object *) ak_bckey_decrypt_xts }},

 { block_cipher, acpkm, asn1_acpkm_magma_i, asn1_acpkm_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ctr_acpkm,
                                                 ( ak_function_run_object *) ak_bckey_ctr_acpkm }},

 { block_cipher, acpkm, asn1_acpkm_kuznechik_i, asn1_acpkm_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined,
                                                  ( ak_function_run_object *) ak_bckey_ctr_acpkm,
                                                 ( ak_function_run_object *) ak_bckey_ctr_acpkm }},

 { block_cipher, mac, asn1_cmac_magma_i, asn1_cmac_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_cmac, NULL }},

 { block_cipher, mac, asn1_cmac_kuznechik_i, asn1_cmac_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined,
                                                ( ak_function_run_object *) ak_bckey_cmac, NULL }},

/* расширенные режимы блочного шифрования */
 { block_cipher, aead, asn1_mgm_magma_i, asn1_mgm_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_bckey_magma,
                                               ( ak_function_run_object *) ak_bckey_encrypt_mgm,
                                               ( ak_function_run_object *) ak_bckey_decrypt_mgm }},

 { block_cipher, aead, asn1_mgm_kuznechik_i, asn1_mgm_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_bckey_kuznechik,
                                               ( ak_function_run_object *) ak_bckey_encrypt_mgm,
                                               ( ak_function_run_object *) ak_bckey_decrypt_mgm }},

 { block_cipher, aead, asn1_ctr_cmac_magma_i, asn1_ctr_cmac_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_bckey_magma,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_cmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_cmac }},

 { block_cipher, aead, asn1_ctr_cmac_kuznechik_i, asn1_ctr_cmac_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_bckey_kuznechik,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_cmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_cmac }},

 { block_cipher, aead, asn1_ctr_hmac_magma_streebog256_i, asn1_ctr_hmac_magma_streebog256_n, NULL,
  { ak_object_bckey_magma, ak_object_hmac_streebog256,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead, asn1_ctr_hmac_magma_streebog512_i, asn1_ctr_hmac_magma_streebog512_n, NULL,
  { ak_object_bckey_magma, ak_object_hmac_streebog512,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead,
             asn1_ctr_hmac_kuznechik_streebog256_i, asn1_ctr_hmac_kuznechik_streebog256_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_hmac_streebog256,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead,
             asn1_ctr_hmac_kuznechik_streebog512_i, asn1_ctr_hmac_kuznechik_streebog512_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_hmac_streebog512,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead, asn1_ctr_nmac_magma_i, asn1_ctr_nmac_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_nmac_streebog,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead, asn1_ctr_nmac_kuznechik_i, asn1_ctr_nmac_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_nmac_streebog,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

/*
 { block_cipher, aead, asn1_xtsmac_magma_i, asn1_xtsmac_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_bckey_magma,
                                            ( ak_function_run_object *) ak_bckey_encrypt_xtsmac,
                                            ( ak_function_run_object *) ak_bckey_decrypt_xtsmac }},
 { block_cipher, aead, asn1_xtsmac_kuznechik_i, asn1_xtsmac_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_bckey_kuznechik,
                                            ( ak_function_run_object *) ak_bckey_encrypt_xtsmac,
                                            ( ak_function_run_object *) ak_bckey_decrypt_xtsmac }},*/

 { sign_function, algorithm, asn1_sign256_i, asn1_sign256_n, NULL,
  { ak_object_signkey256, ak_object_undefined,
                                          ( ak_function_run_object *) ak_signkey_sign_ptr, NULL }},

 { sign_function, algorithm, asn1_sign512_i, asn1_sign512_n, NULL,
  { ak_object_signkey512, ak_object_undefined,
                                          ( ak_function_run_object *) ak_signkey_sign_ptr, NULL }},

 { verify_function, algorithm, asn1_verify256_i, asn1_verify256_n, NULL,
  { ak_object_verifykey256, ak_object_undefined,
                                      ( ak_function_run_object *) ak_verifykey_verify_ptr, NULL }},

 { verify_function, algorithm, asn1_verify512_i, asn1_verify512_n, NULL,
  { ak_object_verifykey256, ak_object_undefined,
                                      ( ak_function_run_object *) ak_verifykey_verify_ptr, NULL }},

 { identifier, wcurve_params, asn1_w256_pst_i, asn1_w256_pst_n,
          (ak_pointer) &id_tc26_gost_3410_2012_256_paramSetTest, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_psa_i, asn1_w256_psa_n,
             (ak_pointer) &id_tc26_gost_3410_2012_256_paramSetA, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_psb_i, asn1_w256_psb_n,
              (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetA, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_psc_i, asn1_w256_psc_n,
              (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetB, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_psd_i, asn1_w256_psd_n,
              (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetC, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_axel_i, asn1_w256_axel_n,
           (ak_pointer) &id_axel_gost_3410_2012_256_paramSet_N0, ak_functional_objects_undefined },

 { identifier, wcurve_params, asn1_w512_pst_i, asn1_w512_pst_n,
          (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetTest, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w512_psa_i, asn1_w512_psa_n,
             (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetA, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w512_psb_i, asn1_w512_psb_n,
             (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetB, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w512_psc_i, asn1_w512_psc_n,
             (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetC, ak_functional_objects_undefined },

/* идентификаторы, используемые при реализации схемы Блома */
 { blom_master, algorithm, asn1_blom_m_i, asn1_blom_m_n, NULL, ak_functional_objects_undefined },
 { blom_subscriber, algorithm, asn1_blom_a_i, asn1_blom_a_n, NULL,
                                                                 ak_functional_objects_undefined },
 { blom_pairwise, algorithm, asn1_blom_p_i, asn1_blom_p_n, NULL, ak_functional_objects_undefined },

/* идентификаторы, используемые при разборе сертификатов и ключевых контейнеров */
 { identifier, descriptor, asn1_akcont_i, asn1_akcont_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_nokey_i, asn1_nokey_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_pbkdf2key_i, asn1_pbkdf2key_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_sdhkey_i, asn1_sdhkey_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_extkey_i, asn1_extkey_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ecieskey_i, asn1_ecieskey_n, NULL,
                                                                 ak_functional_objects_undefined },
 { identifier, parameter, asn1_symkmd_i, asn1_symkmd_n,
                             (ak_pointer) symmetric_key_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_skmd_i, asn1_skmd_n,
                                (ak_pointer) secret_key_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_pkmd_i, asn1_pkmd_n,
                    (ak_pointer) public_key_certificate_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_pkmdr_i, asn1_pkmdr_n,
                        (ak_pointer) public_key_request_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_ecmd_i, asn1_ecmd_n,
                                 (ak_pointer) encrypted_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_pcmd_i, asn1_pcmd_n,
                                     (ak_pointer) plain_content, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_email_i, asn1_email_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cn_i, asn1_cn_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_s_i, asn1_s_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_sn_i, asn1_sn_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_c_i, asn1_c_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_l_i, asn1_l_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_st_i, asn1_st_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_sa_i, asn1_sa_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_o_i, asn1_o_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ou_i, asn1_ou_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_title_i, asn1_title_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_gn_i, asn1_gn_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ps_i, asn1_ps_n, NULL, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_ski_i, asn1_ski_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ku_i, asn1_ku_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ian_i, asn1_ian_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_san_i, asn1_san_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_bc_i, asn1_bc_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_crldp_i, asn1_crldp_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cp_i, asn1_cp_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_wcp_i, asn1_wcp_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_aki_i, asn1_aki_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_eku_i, asn1_eku_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_kpsa_i, asn1_kpsa_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_kpca_i, asn1_kpca_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_kpcs_i, asn1_kpcs_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_kpep_i, asn1_kpep_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_pkix_exaIA_i, asn1_pkix_exaIA_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_pkix_exAD_i, asn1_pkix_exAD_n,
                                                           NULL, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_ogrn_i, asn1_ogrn_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_snils_i, asn1_snils_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ogrnip_i, asn1_ogrnip_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_owner_mod_i, asn1_owner_mod_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_issuer_mod_i, asn1_issuer_mod_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_inn_i, asn1_inn_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_innle_i, asn1_innle_n, NULL, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_class_kc1_i, asn1_class_kc1_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_kc2_i, asn1_class_kc2_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_kc3_i, asn1_class_kc3_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_kb1_i, asn1_class_kb1_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_kb2_i, asn1_class_kb2_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_ka1_i, asn1_class_ka1_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_identkind_i, asn1_identkind_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cms_data_i, asn1_cms_data_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cms_signed_i, asn1_cms_signed_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cms_envelop_i, asn1_cms_envelop_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cms_digest_i, asn1_cms_digest_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cms_enc_i, asn1_cms_enc_n, NULL, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_netsmsg_i, asn1_netsmsg_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_mscav_i, asn1_mscav_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_msct_i, asn1_msct_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_mspsh_i, asn1_mspsh_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_mstndc_i, asn1_mstndc_n, NULL, ak_functional_objects_undefined },

/* PKIX расширения библиотеки libakrypt */
 { identifier, descriptor, asn1_akskn_i, asn1_akskn_n, NULL, ak_functional_objects_undefined },

 /* неподдерживаемые алгоритмы подписи */
 { identifier, algorithm, asn1_sign94_i, asn1_sign94_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_sign01_i, asn1_sign01_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_sha1sign_i,
                                          asn1_sha1sign_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_sha256sign_i,
                                        asn1_sha256sign_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_sha384sign_i,
                                        asn1_sha384sign_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_sha512sign_i,
                                        asn1_sha512sign_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_sha224sign_i,
                                        asn1_sha224sign_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_ecdsasha1_i,
                                         asn1_ecdsasha1_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_ecdsasha224_i,
                                       asn1_ecdsasha224_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_ecdsasha256_i,
                                       asn1_ecdsasha256_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_ecdsasha384_i,
                                       asn1_ecdsasha384_n, NULL, ak_functional_objects_undefined },
 { identifier, algorithm, asn1_ecdsasha512_i,
                                       asn1_ecdsasha512_n, NULL, ak_functional_objects_undefined },

 /* завершающая константа, должна всегда принимать неопределенные и нулевые значения */
  ak_oid_undefined
};

/* ----------------------------------------------------------------------------------------------- */
/*! \param engine Тип криптографического механизма.
    \return Функция возвращает указатель на константную строку.                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_engine_name( const oid_engines_t engine )
{
  if( engine > undefined_engine ) {
    ak_error_message_fmt( ak_error_oid_engine, __func__, "incorrect value of engine: %d", engine );
    return ak_null_string;
  }
 return libakrypt_engine_names[engine];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param mode Режим криптографического механизма.
    \return Функция возвращает указатель на константную строку.                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_mode_name( const oid_modes_t mode )
{
  if( mode > undefined_mode ) {
    ak_error_message_fmt( ak_error_oid_mode, __func__, "incorrect value of engine mode: %d", mode );
    return ak_null_string;
  }
 return libakrypt_mode_names[mode];
}

/* ----------------------------------------------------------------------------------------------- */
/*                           функции для создания объектов по oid                                  */
/* ----------------------------------------------------------------------------------------------- */
/*! \param oid Идентификатор создаваемого объекта
    \return Функция возвращает указатель на контекст созданного объекта. В случае возникновения
    ошибки возвращается NULL. */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_new_object( ak_oid oid )
{
  ak_pointer ctx = NULL;
  int error = ak_error_ok;

  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to object identifer" );
    return NULL;
  }
  if( oid->func.first.create == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                           "create an object that does not support this feature" );
    return NULL;
  }
  if( oid->func.first.destroy == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                        "create an object that does not support destroy feature" );
    return NULL;
  }

  if(( ctx = malloc( oid->func.first.size )) != NULL ) {
    if(( error = ((ak_function_create_object*)oid->func.first.create )( ctx )) != ak_error_ok ) {
      ak_error_message_fmt( error, __func__, "creation of the %s object failed",
                                                      ak_libakrypt_get_engine_name( oid->engine ));
      if( ctx != NULL ) {
        free( ctx );
        ctx = NULL;
      }
    }
  } else
    ak_error_message( ak_error_out_of_memory, __func__, "memory allocation error" );

 return ctx;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param oid Идентификатор создаваемого объекта
    \return Функция возвращает указатель на контекст созданного объекта. В случае возникновения
    ошибки возвращается NULL. */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_new_second_object( ak_oid oid )
{
  ak_pointer ctx = NULL;
  int error = ak_error_ok;

  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to object identifer" );
    return NULL;
  }
  if( oid->func.second.create == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                           "create an object that does not support this feature" );
    return NULL;
  }
  if( oid->func.second.destroy == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                        "create an object that does not support destroy feature" );
    return NULL;
  }

  if(( ctx = malloc( oid->func.second.size )) != NULL ) {
    if(( error = ((ak_function_create_object*)oid->func.second.create )( ctx )) != ak_error_ok ) {
      ak_error_message_fmt( error, __func__, "creation of the %s object failed",
                                                      ak_libakrypt_get_engine_name( oid->engine ));
      if( ctx != NULL ) {
        free( ctx );
        ctx = NULL;
      }
    }
  } else
    ak_error_message( ak_error_out_of_memory, __func__, "memory allocation error" );

 return ctx;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param oid Идентификатор удаляемого объекта
    \param ctx Контекст удаляемого объекта
    \return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_delete_object( ak_oid oid, ak_pointer ctx )
{
  int error = ak_error_ok;

  if( ctx == NULL ) return ctx;
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to object identifer" );
    return NULL;
  }
  if( oid->func.first.destroy == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                          "destroy an object that does not support this feature" );
  } else {
     if(( error = ((ak_function_destroy_object*)oid->func.first.destroy )( ctx )) != ak_error_ok )
       ak_error_message_fmt( error, __func__, "the destroing of %s object failed",
                                                      ak_libakrypt_get_engine_name( oid->engine ));
     }
  if( ctx != NULL ) free( ctx );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param oid Идентификатор удаляемого объекта
    \param ctx Контекст удаляемого объекта
    \return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_delete_second_object( ak_oid oid, ak_pointer ctx )
{
  int error = ak_error_ok;

  if( ctx == NULL ) return ctx;
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to object identifer" );
    return NULL;
  }
  if( oid->func.second.destroy == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                          "destroy an object that does not support this feature" );
  } else {
     if(( error = ((ak_function_destroy_object*)oid->func.second.destroy )( ctx )) != ak_error_ok )
       ak_error_message_fmt( error, __func__, "the destroing of %s object failed",
                                                      ak_libakrypt_get_engine_name( oid->engine ));
     }
  if( ctx != NULL ) free( ctx );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          поиск OID - функции внутреннего интерфейса                             */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_libakrypt_oids_count( void )
{
 return ( sizeof( libakrypt_oids )/( sizeof( struct oid )) - 1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param index индекс oid, данное значение не должно превышать величины,
    возвращаемой функцией ak_libakrypt_oids_count().
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL и устанавливается код ошибки.  */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_index( const size_t index )
{
  if( index < ak_libakrypt_oids_count()) return &libakrypt_oids[index];
  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param name строка, содержащая символьное (человекочитаемое) имя криптографического механизма
    или параметра.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL и устанавливается код ошибки.  */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_name( const char *name )
{
  size_t idx = 0;

 /* надо ли стартовать */
  if( name == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }
 /* перебор по всем возможным значениям */
  do{
     const char *str = NULL;
     size_t len = 0, jdx = 0;
     while(( str = libakrypt_oids[idx].name[jdx] ) != NULL ) {
        len = strlen( str );
        if(( strlen( name ) == len ) && ak_ptr_is_equal( name, str, len ))
          return  &libakrypt_oids[idx];
        jdx++;
     }
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param id строка, содержащая символьную запись идентификатора - последовательность чисел,
    разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_id( const char *id )
{
  size_t idx = 0;
  if( id == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid identifier" );
    return NULL;
  }
 /* перебор по всем возможным значениям */
  do{
     const char *str = NULL;
     size_t len = 0, jdx = 0;
     while(( str = libakrypt_oids[idx].id[jdx] ) != NULL ) {
        len = strlen( str );
        if(( strlen( id ) == len ) && ak_ptr_is_equal( id, str, len ))
          return  &libakrypt_oids[idx];
        jdx++;
     }
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ni строка, содержащая символьную запись имени или идентификатора - последовательности
    чисел, разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_ni( const char *ni )
{
  size_t idx = 0;
  if( ni == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
              "using null pointer to oid name or identifier" );
    return NULL;
  }

  /* перебор по всем возможным значениям имен */
  do{
    const char *str = NULL;
    size_t len = 0, jdx = 0;
    while(( str = libakrypt_oids[idx].name[jdx] ) != NULL ) {
      len = strlen( str );
      if(( strlen( ni ) == len ) && ak_ptr_is_equal( ni, str, len ))
        return  &libakrypt_oids[idx];
      jdx++;
    }
  } while( ++idx < ak_libakrypt_oids_count( ));

  /* перебор по всем возможным значениям идентификаторов */
  idx = 0;
  do{
    const char *str = NULL;
    size_t len = 0, jdx = 0;
    while(( str = libakrypt_oids[idx].id[jdx] ) != NULL ) {
      len = strlen( str );
      if(( strlen( ni ) == len ) && ak_ptr_is_equal( ni, str, len ))
        return  &libakrypt_oids[idx];
      jdx++;
    }
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr указатель на область памяти, по которой ищется oid
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_data( ak_const_pointer ptr )
{
  size_t idx = 0;

 /* надо ли стартовать */
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }

 /* перебор по всем возможным значениям */
  do{
     if( libakrypt_oids[idx].data == ptr ) return  &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографического механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_engine( const oid_engines_t engine )
{
  size_t idx = 0;
  do{
     if( libakrypt_oids[idx].engine == engine ) return &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_engine, __func__, "searching oid with wrong engine" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mode режим работы криптографического механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_mode( const oid_modes_t mode )
{
  size_t idx = 0;
  do{
     if( libakrypt_oids[idx].mode == mode ) return &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_mode, __func__, "searching oid with wrong mode" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param startoid предыдущий найденный oid.
    @param engine тип криптографическиого механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_findnext_by_engine( const ak_oid startoid, const oid_engines_t engine )
{
 ak_oid oid = ( ak_oid )startoid;

 if( oid == NULL) {
   ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid" );
   return NULL;
 }

 /* сдвигаемся по массиву OID вперед */
  while( (++oid)->engine != undefined_engine ) {
    if( oid->engine == engine ) return oid;
  }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param startoid предыдущий найденный oid.
    @param mode режим использования криптографического механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_findnext_by_mode( const ak_oid startoid, const oid_modes_t mode )
{
 ak_oid oid = ( ak_oid )startoid;

 if( oid == NULL) {
   ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid" );
   return NULL;
 }

 /* сдвигаемся по массиву OID вперед */
  while( (++oid)->mode != undefined_mode ) {
    if( oid->mode == mode ) return oid;
  }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid Тестируемый на корректность адрес
    @return Функция возвращает истину, если заданный адрес `oid` дествительно содержится
    среди предопределенных oid библиотеки (является корректно определенным адресом).               */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_oid_check( const ak_pointer ptr )
{
  size_t i;
  bool_t result = ak_false;

  for( i = 0; i < ak_libakrypt_oids_count(); i++ )
     if( ptr == &libakrypt_oids[i] ) result = ak_true;

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
