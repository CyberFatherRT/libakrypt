/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 - 2022 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_aead.c                                                                                 */
/*  - содержит функции, реализующие аутентифицированное шифрование                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст aead алгоритма
    \param crf флаг необходимости создания ключа шифрования
    \param name идентификатор aead алгоритма
    \return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_keys( ak_aead ctx, bool_t crf, char *name )
{
   if(( ctx->oid = ak_oid_find_by_name( name )) == NULL )
     return ak_error_message_fmt( ak_error_oid_name, __func__, "invalid oid name \"%s\"", name );
   if( ctx->oid->mode != aead ) return ak_error_message_fmt( ak_error_oid_mode, __func__,
                                                             "oid mode must be an \"aead mode\"" );
  /* создаем ключи (значения не присваиваем) */
   if(( ctx->authenticationKey = ak_oid_new_second_object( ctx->oid )) == NULL )
     return ak_error_message( ak_error_get_value(), __func__,
                                            "incorrect memory allocation for authentication key" );
   ctx->encryptionKey = NULL;
   if( crf ) { /* по запросу пользователя создаем ключ шифрования */
     if(( ctx->encryptionKey = ak_oid_new_object( ctx->oid )) == NULL ) {
       ak_oid_delete_second_object( ctx->authenticationKey, ctx->oid );
       return ak_error_message( ak_error_get_value(), __func__,
                                                "incorrect memory allocation for encryption key" );
     }
   }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_oid( ak_aead ctx, bool_t crf, ak_oid oid )
{
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                     "using null pointer to oid" );
  if( oid->mode != aead ) return ak_error_message( ak_error_oid_mode, __func__,
                                                                  "using oid with non aead mode" );
  if( strncmp( oid->name[0], "mgm-magma", 9 ) == 0 )
    return ak_aead_create_mgm_magma( ctx, crf );
  if( strncmp( oid->name[0], "mgm-kuznechik", 13 ) == 0 )
    return ak_aead_create_mgm_kuznechik( ctx, crf );
  if( strncmp( oid->name[0], "xtsmac-magma", 12 ) == 0 )
    return ak_aead_create_xtsmac_magma( ctx, crf );
/* if( strncmp( oid->name[0], "xtsmac-kuznechik", 16 ) == 0 )
    return ak_aead_create_xtsmac_kuznechik( ctx, crf ); */
  if( strncmp( oid->name[0], "ctr-cmac-magma", 14 ) == 0 )
    return ak_aead_create_ctr_cmac_magma( ctx, crf );
  if( strncmp( oid->name[0], "ctr-cmac-kuznechik", 18 ) == 0 )
    return ak_aead_create_ctr_cmac_kuznechik( ctx, crf );

  if( strncmp( oid->name[0], "ctr-hmac-magma-streebog256", 26 ) == 0 )
    return ak_aead_create_ctr_hmac_magma_streebog256( ctx, crf );
  if( strncmp( oid->name[0], "ctr-hmac-magma-streebog512", 26 ) == 0 )
    return ak_aead_create_ctr_hmac_magma_streebog512( ctx, crf );
  if( strncmp( oid->name[0], "ctr-hmac-kuznechik-streebog256", 30 ) == 0 )
    return ak_aead_create_ctr_hmac_kuznechik_streebog256( ctx, crf );
  if( strncmp( oid->name[0], "ctr-hmac-kuznechik-streebog512", 30 ) == 0 )
    return ak_aead_create_ctr_hmac_kuznechik_streebog512( ctx, crf );
  if( strncmp( oid->name[0], "ctr-nmac-magma", 14 ) == 0 )
    return ak_aead_create_ctr_nmac_magma( ctx, crf );
  if( strncmp( oid->name[0], "ctr-nmac-kuznechik", 18 ) == 0 )
    return ak_aead_create_ctr_nmac_kuznechik( ctx, crf );

 return ak_error_message( ak_error_wrong_oid, __func__, "using unsupported oid" );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_destroy( ak_aead ctx )
{
   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   if( ctx->oid == NULL ) return ak_error_message( ak_error_wrong_oid, __func__,
                                                         "destroying context with undefined oid" );
   if( ctx->authenticationKey != NULL )
     ak_oid_delete_second_object( ctx->oid, ctx->authenticationKey );
   if( ctx->encryptionKey != NULL ) ak_oid_delete_object( ctx->oid, ctx->encryptionKey );
   if( ctx->ictx != NULL ) free( ctx->ictx );

   ctx->oid = NULL;
   ctx->tag_size = 0;
   ctx->auth_clean = NULL;
   ctx->auth_update = NULL;
   ctx->auth_finalize = NULL;
   ctx->enc_clean = NULL;
   ctx->enc_update = NULL;
   ctx->dec_update = NULL;

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param iv синхропосылка
    \param iv_size размер синхропосылки (в октетах)
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_clean( ak_aead ctx, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->auth_clean == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to auth_clean function" );
  if( ctx->enc_clean == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to enc_clean function" );
  if(( error = ctx->auth_clean( ctx->ictx, ctx->authenticationKey, iv, iv_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of aead authentication context" );
  if(( error = ctx->enc_clean( ctx->ictx, ctx->encryptionKey, iv, iv_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of aead encryption context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param iv синхропосылка
    \param iv_size размер синхропосылки (в октетах)
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_auth_clean( ak_aead ctx, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->auth_clean == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to auth_clean function" );
  if(( error = ctx->auth_clean( ctx->ictx, ctx->authenticationKey, iv, iv_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of aead authentication context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param iv синхропосылка
    \param iv_size размер синхропосылки (в октетах)
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_encrypt_clean( ak_aead ctx, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->enc_clean == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to enc_clean function" );
  if(( error = ctx->enc_clean( ctx->ictx, ctx->encryptionKey, iv, iv_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of aead encryption context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param adata аутентфицируемые данные
    \param adata_size размер аутентифицируемых данных (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_auth_update( ak_aead ctx, const ak_pointer adata, const size_t adata_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->auth_update == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to auth_update function" );
  if(( error = ctx->auth_update( ctx->ictx,
                                     ctx->authenticationKey, adata, adata_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong updating of aead authentication context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param out область памяти, куда помещается код аутентификации (имитовставка)
    \param out_size размер код аутентификации (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_finalize( ak_aead ctx, ak_pointer out, const size_t out_size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->auth_finalize == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to auth_finalize function" );
  if(( error = ctx->auth_finalize( ctx->ictx,
                                         ctx->authenticationKey, out, out_size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong finalizing of aead authentication context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param in область памяти, в которой хранятся открытые данные
    \param out область памяти, куда помещаются зашифрованые данные
    \param size размер данных (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_encrypt_update( ak_aead ctx, const ak_pointer in, ak_pointer out, const size_t size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->enc_update == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to enc_update function" );
  if(( error = ctx->enc_update( ctx->ictx, ctx->encryptionKey,
                                         ctx->authenticationKey, in, out, size )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect data encryption" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param in область памяти, в которой хранятся зашифровыванные данные
    \param out область памяти, куда помещаются расшифровываемые данные
    \param size размер данных (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_decrypt_update( ak_aead ctx, const ak_pointer in, ak_pointer out, const size_t size )
{
  int error = ak_error_ok;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->dec_update == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to enc_update function" );
  if(( error = ctx->dec_update( ctx->ictx, ctx->encryptionKey,
                                         ctx->authenticationKey, in, out, size )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect data decryption" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param key область памяти, в которой хранится значение ключа шифрования
    \param size размер ключа (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_set_encrypt_key( ak_aead ctx, const ak_pointer key, const size_t size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to encryption key" );
  if( ak_oid_check( ctx->oid ) != ak_true ) return ak_error_message( ak_error_wrong_oid, __func__,
                                                              "pointer is not object identifier" );
  return ctx->oid->func.first.set_key( ctx->encryptionKey, key, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param key область памяти, в которой хранится значение ключа аутентификации (имитозащиты)
    \param size размер ключа (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_set_auth_key( ak_aead ctx, const ak_pointer key, const size_t size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to authentication key" );
  if( ak_oid_check( ctx->oid ) != ak_true ) return ak_error_message( ak_error_wrong_oid, __func__,
                                                              "pointer is not object identifier" );
  return ctx->oid->func.second.set_key( ctx->authenticationKey, key, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст алгоритма аутентифицированного шифрования
     (должен быть предварительно инициализирован, ключам должны быть присвоены значения)
    \param ekey область памяти, в которой хранится значение ключа шифрования
    \param esize размер ключа шифрования (в октетах).
    \param akey область памяти, в которой хранится значение ключа аутентификации (имитозащиты)
    \param asize размер ключа аутентификации (в октетах).
    \return В случае успеха функция возвращает  ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_set_keys( ak_aead ctx, const ak_pointer ekey, const size_t esize,
                                                        const ak_pointer akey, const size_t asize )
{
  int error = ak_error_ok;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ak_oid_check( ctx->oid ) != ak_true ) return ak_error_message( ak_error_wrong_oid, __func__,
                                                              "pointer is not object identifier" );
  if( ctx->encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to encryption key" );
  if( ctx->authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to authentication key" );

  if(( error = ctx->oid->func.first.set_key( ctx->encryptionKey, ekey, esize )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect assigning of ecryption key value" );
  if(( error = ctx->oid->func.second.set_key( ctx->authenticationKey, akey, asize )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect assigning of ecryption key value" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_aead_get_tag_size( ak_aead ctx )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
 return ctx->tag_size;
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_aead_get_block_size( ak_aead ctx )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
 return ctx->block_size;
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_aead_get_iv_size( ak_aead ctx )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
 return ctx->iv_size;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует режим шифрования с одновременным вычислением имитовставки.
    На вход функции подаются как данные, подлежащие зашифрованию,
    так и ассоциированные данные, которые не зашифровываются. При этом имитовставка вычисляется
    для всех переданных на вход функции данных.

    Перед вызовом функции контекст алгоритма аутентифицированного шифрования должен быть создан
    и содержать оба ключевых значения, как значение секретного ключа, так и значение ключа имитозащиты.
    Если указатель на ключ шифрования равен `NULL`, то возбуждается ошибка.

    @param ctx контекст алгоритма аутентифицированного шифрования
    @param adata указатель на ассоциированные (незашифровываемые) данные
    @param adata_size длина ассоциированных данных в октетах
    @param in указатель на зашифровываеме данные
    @param out указатель на зашифрованные данные
    @param size размер зашифровываемых данных в октетах
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в октетах
    @param icode указатель на область памяти, куда будет помещено значение имитовставки
           память должна быть выделена заранее
    @param icode_size ожидаемый размер имитовставки в байтах

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_encrypt( ak_aead ctx,  const ak_pointer adata, const size_t adata_size,
                    const ak_pointer in, ak_pointer out, const size_t size, const ak_pointer iv,
                                 const size_t iv_size, ak_pointer icode, const size_t icode_size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                    "encryption key must be created before use of this function" );
 return ctx->oid->func.direct(
                    ctx->encryptionKey,
                    ctx->authenticationKey,
                    adata,
                    adata_size,
                    in,
                    out,
                    size,
                    iv,
                    iv_size,
                    icode,
                    icode_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования данных с одновременной проверкой имитовставки.
    На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные (незашифрованные) данные.

    Перед вызовом функции контекст алгоритма аутентифицированного шифрования должен быть создан
    и содержать оба ключевых значения, как значение секретного ключа, так и значение ключа имитозащиты.
    Если указатель на ключ шифрования равен `NULL`, то возбуждается ошибка.

    @param ctx контекст алгоритма аутентифицированного шифрования
    @param adata указатель на ассоциированные (незашифровываемые) данные
    @param adata_size длина ассоциированных данных в байтах
    @param in указатель на зашифрованные данные
    @param out указатель на расшифровываемые данные
    @param size размер зашифровыванных данных в байтах
    @param iv указатель на синхропосылку
    @param iv_size длина синхропосылки в октетах
    @param icode указатель на область памяти, где находится проверяемое значение имитовставки
    @param icode_size размер имитовставки в октетах

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_decrypt( ak_aead ctx,  const ak_pointer adata, const size_t adata_size,
                    const ak_pointer in, ak_pointer out, const size_t size, const ak_pointer iv,
                                 const size_t iv_size, ak_pointer icode, const size_t icode_size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                    "encryption key must be created before use of this function" );
 return ctx->oid->func.invert(
                    ctx->encryptionKey,
                    ctx->authenticationKey,
                    adata,
                    adata_size,
                    in,
                    out,
                    size,
                    iv,
                    iv_size,
                    icode,
                    icode_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Перед вызовом функции контекст алгоритма аутентифицированного шифрования должен быть создан
    и содержать значение ключа имитозащиты.

    @param ctx контекст алгоритма аутентифицированного шифрования
    @param adata указатель на ассоциированные (незашифровываемые) данные
    @param adata_size длина ассоциированных данных в байтах
    @param iv указатель на синхропосылку (в режимах, где синхропосылка не используется
    целесообразно использовать значение NULL)
    @param iv_size длина синхропосылки в октетах (в режимах, где синхропосылка не используется
    целесообразно использовать значение 0)
    @param icode указатель на область памяти, куда помещается значение имитовставки
    @param icode_size размер имитовставки в октетах

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_mac( ak_aead ctx,  const ak_pointer adata, const size_t adata_size,
             const ak_pointer iv, const size_t iv_size, ak_pointer icode, const size_t icode_size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
  if( ctx->authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                "authentication key must be created before use of this function" );
 return ctx->oid->func.direct(
                    ctx->encryptionKey,
                    ctx->authenticationKey,
                    adata,
                    adata_size,
                    NULL,
                    NULL,
                    0,
                    iv,
                    iv_size,
                    icode,
                    icode_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_aead.c  */
/* ----------------------------------------------------------------------------------------------- */
