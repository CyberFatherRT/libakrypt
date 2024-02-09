/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mgm.c                                                                                  */
/*  - содержит функции, реализующие аутентифицированное шифрование
      и различные режимы его применения.                                                           */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, содержащая текущее состояние внутренних переменных режима `mgm`
   аутентифицированного шифрования. */
 typedef struct mgm_ctx {
  /*! \brief Текущее значение имитовставки. */
   ak_uint128 sum;
  /*! \brief Счетчик, значения которого используются при шифровании информации. */
   ak_uint128 ycount;
  /*! \brief Счетчик, значения которого используются при выработке имитовставки. */
   ak_uint128 zcount;
  /*! \brief Размер обработанных зашифровываемых/расшифровываемых данных в битах. */
   ssize_t pbitlen;
  /*! \brief Размер обработанных дополнительных данных в битах. */
   ssize_t abitlen;
  /*! \brief Флаги состояния контекста. */
   ak_uint32 flags;
} *ak_mgm_ctx;

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует значение счетчика, отвечающего за вычисление значений (множителей),
    используемых для вычисления имитовставки (счетчик H).

    В ходе выполнения функции выполняются проверки корректности переданных данных.

    @param ctx Контекст внутреннего состояния алгоритма
    @param authenticationKey Ключ блочного алгоритма шифрования, используемый для шифрования
    текущего значения счетчика
    @param iv Синхропосылка.
    \note Для работы используются только \f$ n-1 \f$ младший бит. Старший бит принудительно
    получает значение, равное 1.

    @param iv_size Длина синхропосылки в байтах. Длина должна быть отлична от нуля и может быть
    меньше, чем длина блока (в этом случае синхропосылка дополняется нулями в старших байтах).

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_mgm_authentication_clean( ak_pointer actx,
                                        ak_pointer akey, const ak_pointer iv, const size_t iv_size )
{
  ak_mgm_ctx ctx = actx;
  ak_bckey authenticationKey = akey;
  ak_uint8 ivector[16]; /* временное значение синхропосылки */

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to internal mgm context");
  if( authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");
  if( authenticationKey->bsize > 16 ) return ak_error_message( ak_error_wrong_length,
                                                 __func__, "using key with very large block size" );
 /* инициализация значением и ресурс */
  if(( authenticationKey->key.flags&key_flag_set_key ) == 0 )
    return ak_error_message( ak_error_key_value, __func__,
                                         "using block cipher key context with undefined key value");
  if( authenticationKey->key.resource.value.counter <= 0 )
    return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");

  if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
  if( !iv_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using initial vector of zero length" );
 /* обнуляем необходимое */
  ctx->abitlen = 0;
  ctx->flags = 0;
  ctx->pbitlen = 0;
  memset( ctx->sum.b, 0, 16 );
  memset( ctx->zcount.b, 0, 16 );

  memcpy( ivector, iv, ak_min( iv_size, authenticationKey->bsize )); /* копируем нужное количество байт */
 /* принудительно устанавливаем старший бит в 1 */
  ivector[authenticationKey->bsize-1] = ( ivector[authenticationKey->bsize-1]&0x7F ) ^ 0x80;

 /* зашифровываем необходимое и удаляемся */
  authenticationKey->encrypt( &authenticationKey->key, ivector, &ctx->zcount );
  authenticationKey->key.resource.value.counter--;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_LITTLE_ENDIAN
 #define astep64(DATA)  authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &h ); \
                        ak_gf64_mul( &h, &h, (DATA) ); \
                        ctx->sum.q[0] ^= h.q[0]; \
                        ctx->zcount.w[1]++;

 #define astep128(DATA) authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &h ); \
                        ak_gf128_mul( &h, &h, (DATA) ); \
                        ctx->sum.q[0] ^= h.q[0]; \
                        ctx->sum.q[1] ^= h.q[1]; \
                        ctx->zcount.q[1]++;

#else
 #define astep64(DATA)  authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &h ); \
                        ak_gf64_mul( &h, &h, (DATA) ); \
                        ctx->sum.q[0] ^= h.q[0]; \
                        ctx->zcount.w[1] = bswap_32( ctx->zcount.w[1] ); \
                        ctx->zcount.w[1]++; \
                        ctx->zcount.w[1] = bswap_32( ctx->zcount.w[1] );
 #define astep128(DATA) authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &h ); \
                        ak_gf128_mul( &h, &h, (DATA) ); \
                        ctx->sum.q[0] ^= h.q[0]; \
                        ctx->sum.q[1] ^= h.q[1]; \
                        ctx->zcount.q[1] = bswap_64( ctx->zcount.q[1] ); \
                        ctx->zcount.q[1]++; \
                        ctx->zcount.q[1] = bswap_64( ctx->zcount.q[1] );

#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция обрабатывает очередной блок дополнительных данных и
    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    выработки имитовставки. Если длина входных данных не кратна длине блока алгоритма шифрования,
    то это воспринимается как конец процесса обновления (после этого вызов функции блокируется).

    Если данные кратны длине блока, то блокировки не происходит --
    блокировка происходит в момент вызова функций обработки зашифровываемых данных.

    @param ctx Контекст внутреннего состояния алгоритма
    @param authenticationKey Ключ блочного алгоритма шифрования, используемый для
    шифрования текущего значения счетчика
    @param adata
    @param adata_size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_mgm_authentication_update( ak_pointer actx,
                                  ak_pointer akey, const ak_pointer adata, const size_t adata_size )
{
  ak_uint128 h;
  ak_mgm_ctx ctx = actx;
  ak_bckey authenticationKey = akey;
  ak_uint8 temp[16], *aptr = (ak_uint8 *)adata;
  ssize_t absize = ( ssize_t ) authenticationKey->bsize;
  ssize_t resource = 0,
          tail = ( ssize_t ) adata_size%absize,
          blocks = ( ssize_t ) adata_size/absize;

 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_assosiated_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                                  "attemp to update previously closed mgm context");
 /* ни чего не задано => ни чего не обрабатываем */
  if(( adata == NULL ) || ( adata_size == 0 )) return ak_error_ok;

 /* проверка ресурса ключа */
  if( authenticationKey->key.resource.value.counter <= (resource = blocks + (tail > 0)))
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else authenticationKey->key.resource.value.counter -= resource;

 /* теперь основной цикл */
 if( absize == 16 ) { /* обработка 128-битным шифром */

   ctx->abitlen += ( blocks  << 7 );
   for( ; blocks > 0; blocks--, aptr += 16 ) { astep128( aptr ); }
   if( tail ) {
    memset( temp, 0, 16 );
    memcpy( temp+absize-tail, aptr, (size_t)tail );
    astep128( temp );

  /* закрываем добавление ассоциированных данных */
    ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
    ctx->abitlen += ( tail << 3 );
  }
 } else { /* обработка 64-битным шифром */

   ctx->abitlen += ( blocks << 6 );
   for( ; blocks > 0; blocks--, aptr += 8 ) { astep64( aptr ); }
   if( tail ) {
    memset( temp, 0, 8 );
    memcpy( temp+absize-tail, aptr, (size_t)tail );
    astep64( temp );
   /* закрываем добавление ассоциированных данных */
    ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
    ctx->abitlen += ( tail << 3 );
  }
 }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция завершает вычисления и возвращает значение имитовставки.

   @param ctx
   @param authenticationKey
   @param out
   @param out_size

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_mgm_authentication_finalize( ak_pointer actx,
                                  ak_pointer akey, ak_pointer out, const size_t out_size )
{
  ak_uint128 temp, h;
  ak_mgm_ctx ctx = actx;
  ak_bckey authenticationKey = akey;
  size_t absize = authenticationKey->bsize;

  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to output buffer" );
 /* проверка запрашиваемой длины iv */
  if( out_size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                      "unexpected zero length of integrity code" );
 /* проверка длины блока */
  if( absize > 16 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                               "using key with large block size" );
 /* традиционная проверка ресурса */
  if( authenticationKey->key.resource.value.counter <= 0 )
    return ak_error_message( ak_error_low_key_resource, __func__,
                                                                "using key with low key resource");
   else authenticationKey->key.resource.value.counter--;

 /* закрываем добавление шифруемых данных */
   ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );

 /* формируем последний вектор из длин */
  if(  absize&0x10 ) {
#ifdef AK_LITTLE_ENDIAN
    temp.q[0] = ( ak_uint64 )ctx->pbitlen;
    temp.q[1] = ( ak_uint64 )ctx->abitlen;
#else
    temp.q[0] = bswap_64(( ak_uint64 )ctx->pbitlen );
    temp.q[1] = bswap_64(( ak_uint64 )ctx->abitlen );
#endif
    astep128( temp.b );
  } else { /* теперь тоже самое, но для 64-битного шифра */

     if(( ctx->abitlen > 0xFFFFFFFF ) || ( ctx->pbitlen > 0xFFFFFFFF ))
       return ak_error_message( ak_error_overflow, __func__,
                                                        "using an algorithm with very long data" );

#ifdef AK_LITTLE_ENDIAN
     temp.w[0] = (ak_uint32) ctx->pbitlen;
     temp.w[1] = (ak_uint32) ctx->abitlen;
#else
     temp.w[0] = bswap_32((ak_uint32) ctx->pbitlen );
     temp.w[1] = bswap_32((ak_uint32) ctx->abitlen );
#endif
     astep64( temp.b );
  }

 /* последнее шифрование и завершение работы */
  authenticationKey->encrypt( &authenticationKey->key, &ctx->sum, &ctx->sum );
 /* если памяти много (out_size >= absize), то копируем все, */
      /* в противном случае - только ту часть, что вмещается */
  memcpy( out, ctx->sum.b+(out_size >= absize ? 0 : absize - out_size), ak_min( out_size, absize ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует значение внутренних переменных алгоритма MGM, участвующих в процессе
    шифрования.

    @param ctx
    @param encryptionKey
    @param iv
    @param iv_size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_mgm_encryption_clean( ak_pointer ectx,
                                        ak_pointer ekey, const ak_pointer iv, const size_t iv_size )
{
  ak_mgm_ctx ctx = ectx;
  ak_bckey encryptionKey = ekey;
  ak_uint8 ivector[16]; /* временное значение синхропосылки */

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to internal mgm context");
  if( encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");
  if( encryptionKey->bsize > 16 ) return ak_error_message( ak_error_wrong_length,
                                                      __func__, "using key with large block size" );
 /* инициализация значением и ресурс */
  if(( encryptionKey->key.flags&key_flag_set_key ) == 0 )
    return ak_error_message( ak_error_key_value, __func__,
                                               "using secret key context with undefined key value");
  if( encryptionKey->key.resource.value.counter <= 0 )
    return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");

  if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
  if( !iv_size ) return ak_error_message( ak_error_zero_length,
                                                 __func__, "using initial vector with zero length");
 /* обнуляем необходимое */
  ctx->flags &= ak_aead_assosiated_data_bit;
  ctx->pbitlen = 0;
  memset( &ctx->ycount, 0, 16 );
  memset( ivector, 0, 16 );
  memcpy( ivector, iv, ak_min( iv_size, encryptionKey->bsize )); /* копируем нужное количество байт */
 /* принудительно устанавливаем старший бит в 0 */
  ivector[encryptionKey->bsize-1] = ( ivector[encryptionKey->bsize-1]&0x7F );

 /* зашифровываем необходимое и удаляемся */
  encryptionKey->encrypt( &encryptionKey->key, ivector, &ctx->ycount );
  encryptionKey->key.resource.value.counter--;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_LITTLE_ENDIAN
 #define estep64  encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e ); \
                  outp[0] = inp[0] ^ e.q[0]; \
                  ctx->ycount.w[0]++;

 #define estep128 encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e ); \
                  outp[0] = inp[0] ^ e.q[0]; \
                  outp[1] = inp[1] ^ e.q[1]; \
                  ctx->ycount.q[0]++;

#else
 #define estep64  encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e ); \
                  outp[0] = inp[0] ^ e.q[0]; \
                  ctx->ycount.w[0] = bswap_32( ctx->ycount.w[0] ); \
                  ctx->ycount.w[0]++; \
                  ctx->ycount.w[0] = bswap_32( ctx->ycount.w[0] );

 #define estep128 encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e ); \
                  outp[0] = inp[0] ^ e.q[0]; \
                  outp[1] = inp[1] ^ e.q[1]; \
                  ctx->ycount.q[0] = bswap_64( ctx->ycount.q[0] ); \
                  ctx->ycount.q[0]++; \
                  ctx->ycount.q[0] = bswap_64( ctx->ycount.q[0] );
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция зашифровывает очередной фрагмент данных и
    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    шифрования с одновременной выработкой имитовставки. Если длина входных данных не кратна длине
    блока алгоритма шифрования, то это воспринимается как конец процесса шифрования/обновления
    (после этого вызов функции блокируется).

    @param ctx
    @param encryptionKey
    @param authenticationKey
    @param in
    @param out
    @param size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_mgm_encryption_update( ak_pointer ectx, ak_pointer ekey,
                           ak_pointer akey, const ak_pointer in, ak_pointer out, const size_t size )
{
  ak_uint128 e, h;
  ak_uint8 temp[16];
  ak_mgm_ctx ctx = ectx;
  size_t i = 0, absize = 0;
  ak_bckey encryptionKey = ekey;
  ak_bckey authenticationKey = akey;
  size_t resource = 0, tail, blocks;
  ak_uint64 *inp = (ak_uint64 *)in, *outp = (ak_uint64 *)out;

 /* проверяем возможность обновления */
  if( ctx->flags&ak_aead_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                        "using this function with previously closed aead context");
 /* проверка того, что хотя бы один ключ определен */
  if(( authenticationKey == NULL ) && ( encryptionKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointers to both secret keys");
 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;

 /* проверяем, что ключ шифрования определен,
    если нет, то используем входные данные как ассоциированные
    отметим, что если ассоциированные данные были ранее обработаны
    и их длина была не кратна длине блока, то здесь появится ошибка */
  if( encryptionKey == NULL ) {
    return ak_mgm_authentication_update( ectx, authenticationKey, in, size );
  }

 /* вычисляем длины блоков */
  absize = encryptionKey->bsize;
  tail = size%absize,
  blocks = size/absize;

 /* проверка ресурса ключа выработки имитовставки */
  if( authenticationKey != NULL ) {
    if( authenticationKey->key.resource.value.counter <= ( ssize_t )(resource = blocks + (tail > 0)))
      return ak_error_message( ak_error_low_key_resource, __func__,
                                                "using authentication key with low key resource");
    else authenticationKey->key.resource.value.counter -= resource;
  }

 /* проверка ресурса ключа шифрования */
  if( encryptionKey->key.resource.value.counter <= ( ssize_t )(resource = blocks + (tail > 0)) )
    return ak_error_message( ak_error_low_key_resource, __func__,
                                                   "using encryption key with low key resource");
   else encryptionKey->key.resource.value.counter -= resource;

 /* теперь обработка данных */
  memset( &e, 0, 16 );
  ctx->pbitlen += ( absize*blocks << 3 );

 /* ----------------------------------------------------------- */
 /* рассматриваем все возможные случаи отдельно,
    начинаем со случая, в котором реализуется только шифрование */
  if(( authenticationKey == NULL ) && ( encryptionKey != NULL )) {

    if( absize&0x10 ) { /* режим работы для 128-битного шифра */
     /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         estep128;
      }
      /* хвост */
      if( tail ) {
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[16-tail+i];
       /* закрываем добавление шифруемых данных */
        ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
       /* основная часть */
        for( ; blocks > 0; blocks--, inp++, outp++ ) {
           estep64;
        }
       /* хвост */
        if( tail ) {
          encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
          for( i = 0; i < tail; i++ )
             ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[8-tail+i];
         /* закрываем добавление шифруемых данных */
          ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
          ctx->pbitlen += ( tail << 3 );
        }
      } /* конец шифрования без аутентификации для 64-битного шифра */

   return ak_error_ok;
  }

 /* -------------------------------------- */
 /* в завершение, реализуется общий случай */

  if( absize&0x10 ) { /* режим работы для 128-битного шифра */
   /* основная часть */
    for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
      estep128;
      astep128( outp );
    }
   /* хвост */
    if( tail ) {
      memset( temp, 0, 16 );
      encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
      for( i = 0; i < tail; i++ )
         ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[16-tail+i];
      memcpy( temp+16-tail, outp, (size_t)tail );
      astep128( temp );

    /* закрываем добавление шифруемых данных */
      ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
      ctx->pbitlen += ( tail << 3 );
    }
  } else { /* режим работы для 64-битного шифра */

    /* основная часть */
     for( ; blocks > 0; blocks--, inp++, outp++ ) {
        estep64;
        astep64( outp );
     }
    /* хвост */
     if( tail ) {
       memset( temp, 0, 8 );
       encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
       for( i = 0; i < tail; i++ )
          ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[8-tail+i];
       memcpy( temp+8-tail, outp, (size_t)tail );
       astep64( temp );

      /* закрываем добавление шифруемых данных */
       ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
       ctx->pbitlen += ( tail << 3 );
     }
  } /* конец 64-битного шифра */

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция расшифровывает очередной фрагмент данных и
    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    расшифрования с проверкой имитовставки. Если длина входных данных не кратна длине
    блока алгоритма шифрования, то это воспринимается как конец процесса расшифрования/обновления
    (после этого вызов функции блокируется).

    @param ctx
    @param encryptionKey
    @param authenticationKey
    @param in
    @param out
    @param size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_mgm_decryption_update( ak_pointer ectx, ak_pointer ekey,
                           ak_pointer akey, const ak_pointer in, ak_pointer out, const size_t size )
{
  ak_mgm_ctx ctx = ectx;
  ak_bckey encryptionKey = ekey;
  ak_bckey authenticationKey = akey;
  ak_uint8 temp[16];
  ak_uint128 e, h;
  size_t i = 0, absize = encryptionKey->bsize;
  ak_uint64 *inp = (ak_uint64 *)in, *outp = (ak_uint64 *)out;
  size_t resource = 0,
         tail = size%absize,
         blocks = size/absize;

 /* принудительно закрываем обновление ассоциированных данных */
  ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
 /* проверяем возможность обновления */
  if( ctx->flags&ak_aead_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                        "using this function with previously closed aead context");

 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;

 /* проверка ресурса ключа выработки имитовставки */
  if( authenticationKey != NULL ) {
    if( authenticationKey->key.resource.value.counter <= ( ssize_t )(resource = blocks + (tail > 0)))
      return ak_error_message( ak_error_low_key_resource, __func__,
                                                "using authentication key with low key resource");
    else authenticationKey->key.resource.value.counter -= resource;
  }

 /* проверка ресурса ключа шифрования */
  if( encryptionKey->key.resource.value.counter <= ( ssize_t )resource )
   return ak_error_message( ak_error_low_key_resource, __func__,
                                                   "using encryption key with low key resource");
  else encryptionKey->key.resource.value.counter -= resource;

 /* теперь обработка данных */
  memset( &e, 0, 16 );
  ctx->pbitlen += ( absize*blocks << 3 );
  if( authenticationKey == NULL ) { /* только шифрование (без вычисления имитовставки) */
                                    /* это полная копия кода, содержащегося в функции .. _encryption_ ... */
    if( absize&0x10 ) { /* режим работы для 128-битного шифра */
     /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         estep128;
      }
      /* хвост */
      if( tail ) {
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[16-tail+i];
       /* закрываем добавление шифруемых данных */
        ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
       /* основная часть */
        for( ; blocks > 0; blocks--, inp++, outp++ ) {
           estep64;
        }
       /* хвост */
        if( tail ) {
          encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
          for( i = 0; i < tail; i++ )
             ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[8-tail+i];
         /* закрываем добавление шифруемых данных */
          ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
          ctx->pbitlen += ( tail << 3 );
        }
      } /* конец шифрования без аутентификации для 64-битного шифра */

  } else { /* основной режим работы => шифрование с одновременной выработкой имитовставки */

     if( absize&0x10 ) { /* режим работы для 128-битного шифра */
      /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         astep128( inp );
         estep128;
      }
      /* хвост */
      if( tail ) {
        memset( temp, 0, 16 );
        memcpy( temp+16-tail, inp, (size_t)tail );
        astep128( temp );
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[16-tail+i];

       /* закрываем добавление шифруемых данных */
        ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
      /* основная часть */
       for( ; blocks > 0; blocks--, inp++, outp++ ) {
          astep64( inp );
          estep64;
       }
       /* хвост */
       if( tail ) {
         memset( temp, 0, 8 );
         memcpy( temp+8-tail, inp, (size_t)tail );
         astep64( temp );
         encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &e );
         for( i = 0; i < tail; i++ )
            ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ e.b[8-tail+i];

        /* закрываем добавление шифруемых данных */
         ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
         ctx->pbitlen += ( tail << 3 );
       }
     } /* конец 64-битного шифра */
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_bckey_check_mgm_length( const size_t asize,
                                                           const size_t psize, const size_t bsize )
{
 /* требования к размерам:
    - длина ассоциированных данных (в битах) не более 2^n/2
    - длина шифруемых данных (в битах) не более 2^n/2
    - суммарная длина длина данных (в битах) не более 2^n/2  */

  size_t temp, aval = asize << 3, pval = psize << 3;

   if( aval < asize ) return ak_error_message( ak_error_wrong_length, __func__,
                                                        "length of assosiated data is very huge");
   if( pval < psize ) return ak_error_message( ak_error_wrong_length, __func__,
                                                       "total length of plain data is very huge");
   if(( temp = ( aval + pval )) < pval )
     return ak_error_message( ak_error_wrong_length, __func__,
                                        "total length of assosiated and plain data is very huge");

  /* на 32-х битной архитектуре size_t не превосходит 32 бита =>
     длины корректны для Магмы и для Кузнечика

     на 64-х битной архитектуре много может быть только для Магмы => проверяем */
   if(( sizeof ( ak_pointer ) > 4 ) && ( bsize != 16 )) {
     if( aval > 0x0000000100000000LL ) return ak_error_message( ak_error_wrong_length, __func__,
                                                       "length of assosiated data is very large");
     if( pval > 0x0000000100000000LL ) return ak_error_message( ak_error_wrong_length, __func__,
                                                            "length of plain data is very large");
     if( temp > 0x0000000100000000LL ) return ak_error_message( ak_error_wrong_length, __func__,
                                       "total length of assosiated and plain data is very large");
   }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует режим `mgm` - режим шифрования для блочного шифра с одновременным вычислением
    имитовставки. На вход функции подаются как данные, подлежащие зашифрованию,
    так и ассоциированные данные, которые не зашифровываются. При этом имитовставка вычисляется
    для всех переданных на вход функции данных.

    Режим `mgm` может использовать для шифрования и выработки имитовставки два различных ключа -
    в этом случае длины блоков обрабатываемых данных для ключей должны совпадать (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если указатель на ключ шифрования равен `NULL`, то шифрование данных не производится и указатель на
    зашифровываемые (plain data) и зашифрованные (cipher data) данные \b должен быть равен `NULL`;
    длина данных (size) также \b должна принимать нулевое значение.

    Если указатель на ключ выработки имитовставки равен `NULL`, то аутентификация данных не производится.
    В этом случае указатель на ассоциированные данные (associated data) \b должен быть равен `NULL`,
    указатель на имитовставку (icode) \b должен быть равен `NULL`, длина дополнительных данных \b должна
    равняться нулю.

    Ситуация, при которой оба указателя на ключ принимают значение `NULL` воспринимается как ошибка.

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
           может принимать значение NULL;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на зашифровываеме данные;
    @param out указатель на зашифрованные данные;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, куда будет помещено значение имитовставки;
           память должна быть выделена заранее; указатель может принимать значение NULL.
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;
           если значение icode_size меньше, чем длина блока, то возвращается запрашиваемое количество
           старших байт результата вычислений.

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_mgm( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  size_t bs = 0;
  int error = ak_error_ok;
  struct mgm_ctx mgm; /* контекст структуры, в которой хранятся промежуточные данные */

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                               "using null pointers both to encryption and authentication keys" );
  if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
      return ak_error_message( ak_error_not_equal_data, __func__,
                                                   "different block sizes for given secret keys");
  }
  if( encryptionKey != NULL ) bs = ((ak_bckey)encryptionKey)->bsize;
    else bs = ((ak_bckey)authenticationKey)->bsize;

 /* проверяем размер входных данных */
  if(( error = ak_bckey_check_mgm_length( adata_size, size, bs )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect length of input data");

 /* подготавливаем память */
  memset( &mgm, 0, sizeof( struct mgm_ctx ));

 /* в начале обрабатываем ассоциированные данные */
  if( authenticationKey != NULL ) {
    if(( error = ak_mgm_authentication_clean( &mgm, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)authenticationKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
    }
    if(( error = ak_mgm_authentication_update( &mgm, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)authenticationKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect hashing of associated data" );
    }
  }

 /* потом зашифровываем данные */
  if( encryptionKey != NULL ) {
    if(( error = ak_mgm_encryption_clean( &mgm, encryptionKey, iv, iv_size )) != ak_error_ok ) {
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)encryptionKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
    }
    if(( error = ak_mgm_encryption_update( &mgm, encryptionKey, authenticationKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)encryptionKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect encryption of plain data" );
    }
  }

 /* в конце - вырабатываем имитовставку */
  if( authenticationKey != NULL ) {
    if(( error = ak_mgm_authentication_finalize( &mgm,
                                         authenticationKey, icode, icode_size )) != ak_error_ok ) {
      ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)authenticationKey)->key.generator );
      return ak_error_message( error, __func__, "incorrect finanlize of integrity code" );
    }
    ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)authenticationKey)->key.generator );
  } else /* выше проверка того, что два ключа одновременно не равну NULL =>
                                                              один из двух ключей очистит контекст */
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)encryptionKey)->key.generator );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных. Требования к передаваемым параметрам
    аналогичны требованиям, предъявляемым к параметрам функции ak_bckey_encrypt_mgm().

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
           может принимать значение `NULL`;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на расшифровываемые данные;
    @param out указатель на область памяти, куда будут помещены расшифрованные данные;
           данный указатель может совпадать с указателем in;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, в которой хранится значение имитовставки;
    @param icode_size размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;

    @return Функция возвращает \ref ak_error_ok, если значение имитовтсавки совпало с
            вычисленным в ходе выполнения функции значением; если значения не совпадают,
            или в ходе выполнения функции возникла ошибка, то возвращается код ошибки.             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_mgm( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  size_t bs = 0;
  struct mgm_ctx mgm; /* контекст структуры, в которой хранятся промежуточные данные */
  int error = ak_error_ok;

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                               "using null pointers both to encryption and authentication keys" );

  if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
      return ak_error_message( ak_error_wrong_length, __func__, "different block sizes for given keys");
  }
   if( encryptionKey != NULL ) bs = ((ak_bckey)encryptionKey)->bsize;
     else bs = ((ak_bckey)authenticationKey)->bsize;

 /* проверяем размер входных данных */
  if(( error = ak_bckey_check_mgm_length( adata_size, size, bs )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect length of input data");

 /* подготавливаем память */
  memset( &mgm, 0, sizeof( struct mgm_ctx ));

 /* в начале обрабатываем ассоциированные данные */
  if( authenticationKey != NULL ) {
    if(( error = ak_mgm_authentication_clean( &mgm, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)authenticationKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
    }
    if(( error = ak_mgm_authentication_update( &mgm, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)authenticationKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect hashing of associated data" );
    }
  }

 /* потом расшифровываем данные */
  if( encryptionKey != NULL ) {
    if(( error = ak_mgm_encryption_clean( &mgm, encryptionKey, iv, iv_size )) != ak_error_ok ) {
      ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)encryptionKey)->key.generator );
      return ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
    }
    if(( error = ak_mgm_decryption_update( &mgm, encryptionKey, authenticationKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)encryptionKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect encryption of plain data" );
    }
  }

 /* в конце - вырабатываем имитовставку */
  if( authenticationKey != NULL ) {
    ak_uint8 icode2[16];
    memset( icode2, 0, 16 );

    if(( error = ak_mgm_authentication_finalize( &mgm,
                                          authenticationKey, icode2, icode_size )) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect finalize of integrity code" );
     else {
        if( ak_ptr_is_equal( icode, icode2, icode_size )) error = ak_error_ok;
          else error = ak_error_not_equal_data;
     }
    ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)authenticationKey)->key.generator );

  } else { /* выше была проверка того, что два ключа одновременно не равну NULL =>
                                                              один из двух ключей очистит контекст */
         error = ak_error_ok; /* мы ни чего не проверяли => все хорошо */
         ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &((ak_bckey)encryptionKey)->key.generator );
        }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                           создание структур управления контекстом                               */
/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст aead алгоритма
    \param crf флаг необходимости создания ключа шифрования
    \return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_mgm_magma( ak_aead ctx, bool_t crf )
{
   int error = ak_error_ok;

   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   memset( ctx, 0, sizeof( struct aead ));
   if(( ctx->ictx = malloc( sizeof( struct mgm_ctx ))) == NULL )
     return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   if(( error = ak_aead_create_keys( ctx, crf, "mgm-magma" )) != ak_error_ok ) {
     if( ctx->ictx != NULL ) free( ctx->ictx );
     return ak_error_message( error, __func__, "incorrect secret keys context creation" );
   }

   ctx->tag_size = ctx->iv_size = ctx->block_size = 8; /* длина блока алгоритма Магма */
   ctx->auth_clean = ak_mgm_authentication_clean;
   ctx->auth_update = ak_mgm_authentication_update;
   ctx->auth_finalize = ak_mgm_authentication_finalize;
   ctx->enc_clean = ak_mgm_encryption_clean;
   ctx->enc_update = ak_mgm_encryption_update;
   ctx->dec_update = ak_mgm_decryption_update;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx контекст aead алгоритма
    \param crf флаг необходимости создания ключа шифрования
    \return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_mgm_kuznechik( ak_aead ctx, bool_t crf )
{
   int error = ak_error_ok;

   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   memset( ctx, 0, sizeof( struct aead ));
   if(( ctx->ictx = malloc( sizeof( struct mgm_ctx ))) == NULL )
     return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   if(( error = ak_aead_create_keys( ctx, crf, "mgm-kuznechik" )) != ak_error_ok ) {
     if( ctx->ictx != NULL ) free( ctx->ictx );
     return ak_error_message( error, __func__, "incorrect secret keys context creation" );
   }

   ctx->tag_size = ctx->iv_size = ctx->block_size = 16; /* длина блока алгоритма Кузнечик */
   ctx->auth_clean = ak_mgm_authentication_clean;
   ctx->auth_update = ak_mgm_authentication_update;
   ctx->auth_finalize = ak_mgm_authentication_finalize;
   ctx->enc_clean = ak_mgm_encryption_clean;
   ctx->enc_update = ak_mgm_encryption_update;
   ctx->dec_update = ak_mgm_decryption_update;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                               тестирование корректной реализации                                */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_mgm( void )
{
  bool_t result = ak_false;
  int error = ak_error_ok, audit = ak_log_get_level();

 /* константные значения ключей из ГОСТ Р 34.13-2015 */
  ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 keyAnnexB[32] = {
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

 /* открытый текст, подлежащий зашифрованию (модификация ГОСТ Р 34.13-2015, приложение А.1) */
  ak_uint8 out[67];
  ak_uint8 plain[67] = {
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0xCC, 0xBB, 0xAA };

 /* несколько вариантов шифртекстов */
  ak_uint8 cipherOne[67] = {
     0xFC, 0x42, 0x9F, 0xE8, 0x3D, 0xA3, 0xB8, 0x55, 0x90, 0x6E, 0x95, 0x47, 0x81, 0x7B, 0x75, 0xA9,
     0x39, 0x6B, 0xC1, 0xAD, 0x9A, 0x06, 0xF7, 0xD3, 0x5B, 0xFD, 0xF9, 0x2B, 0x21, 0xD2, 0x75, 0x80,
     0x1C, 0x85, 0xF6, 0xA9, 0x0E, 0x5D, 0x6B, 0x93, 0x85, 0xBA, 0xA6, 0x15, 0x59, 0xB1, 0x7A, 0x49,
     0xEB, 0x6D, 0xC7, 0x95, 0x06, 0x42, 0x94, 0xAB, 0xD0, 0x83, 0xF8, 0xD3, 0xD4, 0x14, 0x0C, 0xC6,
     0x52, 0x75, 0x2C };

  ak_uint8 cipherThree[67] = {
     0x3B, 0xA0, 0x9E, 0x5F, 0x6C, 0x06, 0x95, 0xC7, 0xAE, 0x85, 0x91, 0x45, 0x42, 0x33, 0x11, 0x85,
     0x5D, 0x78, 0x2B, 0xBF, 0xD6, 0x00, 0x2E, 0x1F, 0x7D, 0x8E, 0x9C, 0xBB, 0xB8, 0x70, 0x04, 0x94,
     0x70, 0xDC, 0x7D, 0x1F, 0x73, 0xD3, 0x5D, 0x9A, 0x76, 0xA5, 0x6F, 0xCE, 0x0A, 0xCB, 0x27, 0xEC,
     0xD5, 0x75, 0xBB, 0x6A, 0x64, 0x5C, 0xF6, 0x70, 0x4E, 0xC3, 0xB5, 0xBC, 0xC3, 0x37, 0xAA, 0x47,
     0x9C, 0xBB, 0x03 };

 /* асссоциированные данные */
  ak_uint8 associated[41] = {
     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA };

 /* синхропосылки */
  ak_uint8 iv128[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
  ak_uint8 iv64[8] = {
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92 };

 /* значения для проверки вычисленного значения */
  ak_uint8 icode[16];
  ak_uint8 icodeOne[16] = {
    0x4C, 0xDB, 0xFC, 0x29, 0x0E, 0xBB, 0xE8, 0x46, 0x5C, 0x4F, 0xC3, 0x40, 0x6F, 0x65, 0x5D, 0xCF };
  ak_uint8 icodeTwo[16] = {
    0x57, 0x4E, 0x52, 0x01, 0xA8, 0x07, 0x26, 0x60, 0x66, 0xC6, 0xE9, 0x22, 0x57, 0x6B, 0x1B, 0x89 };
  ak_uint8 icodeThree[8] = { 0x10, 0xFD, 0x10, 0xAA, 0x69, 0x80, 0x92, 0xA7 };
  ak_uint8 icodeFour[8] = { 0xC5, 0x43, 0xDE, 0xF2, 0x4C, 0xB0, 0xC3, 0xF7 };

 /* ключи для проверки */
  struct bckey kuznechikKeyA, kuznechikKeyB, magmaKeyA, magmaKeyB;

 /* инициализация ключей */
 /* - 1 - */
  if(( error = ak_bckey_create_kuznechik( &kuznechikKeyA )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of first secret key");
    return ak_false;
  }
  if(( error = ak_bckey_set_key( &kuznechikKeyA, keyAnnexA, 32 )) != ak_error_ok ) {
    ak_bckey_destroy( &kuznechikKeyA );
    ak_error_message( error, __func__, "incorrect assigning a first constant value to kuznechik key");
    return ak_false;
  }
 /* - 2 - */
  if(( error = ak_bckey_create_kuznechik( &kuznechikKeyB )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of second secret key");
    ak_bckey_destroy( &kuznechikKeyA );
    return ak_false;
  }
  if(( error = ak_bckey_set_key( &kuznechikKeyB, keyAnnexB, 32 )) != ak_error_ok ) {
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    ak_error_message( error, __func__, "incorrect assigning a second constant value to kuznechik key");
    return ak_false;
  }
 /* - 3 - */
  if(( error = ak_bckey_create_magma( &magmaKeyA )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of third secret key");
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    return ak_false;
  }
  if(( error = ak_bckey_set_key( &magmaKeyA, keyAnnexA, 32 )) != ak_error_ok ) {
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    ak_bckey_destroy( &magmaKeyA );
    ak_error_message( error, __func__, "incorrect assigning a third constant value to magma key");
    return ak_false;
  }
 /* - 4 - */
  if(( error = ak_bckey_create_magma( &magmaKeyB )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of fourth secret key");
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    ak_bckey_destroy( &magmaKeyA );
    return ak_false;
  }
  if(( error = ak_bckey_set_key( &magmaKeyB, keyAnnexB, 32 )) != ak_error_ok ) {
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    ak_bckey_destroy( &magmaKeyA );
    ak_bckey_destroy( &magmaKeyB );
    ak_error_message( error, __func__, "incorrect assigning a fourth constant value to magma key");
    return ak_false;
  }

 /* первый тест - шифрование и имитовставка, алгоритм Кузнечик, один ключ */
  memset( icode, 0, 16 );
  if(( error = ak_bckey_encrypt_mgm( &kuznechikKeyA, &kuznechikKeyA, associated,
                  sizeof( associated ), plain, out, sizeof( plain ), iv128, sizeof( iv128 ),
                                                                    icode, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for first example");
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( icode, icodeOne, sizeof( icodeOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                    "the value of integrity code for one kuznechik key is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( out, cipherOne, sizeof( cipherOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the encryption test for one kuznechik key is wrong" );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if(( error = ak_bckey_decrypt_mgm( &kuznechikKeyA, &kuznechikKeyA,
            associated, sizeof( associated ), cipherOne, out, sizeof( cipherOne ),
                                        iv128, sizeof( iv128 ), icodeOne, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,
                                    "checking the integrity code for one kuznechik key is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the decryption test for one kuznechik key is wrong" );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
             "the 1st full encryption, decryption & integrity test with one kuznechik key is Ok" );

 /* второй тест - шифрование и имитовставка, алгоритм Кузнечик, два ключа */
  memset( icode, 0, 16 );
  if(( error = ak_bckey_encrypt_mgm( &kuznechikKeyA, &kuznechikKeyB, associated,
                       sizeof( associated ), plain, out, sizeof( plain ), iv128,
                                                   sizeof( iv128 ), icode, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for second example");
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( icode, icodeTwo, sizeof( icodeTwo ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the integrity code for two kuznechik keys is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( out, cipherOne, sizeof( cipherOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                           "the encryption test for two kuznechik keys is wrong" );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if(( error = ak_bckey_decrypt_mgm( &kuznechikKeyA, &kuznechikKeyB,
            associated, sizeof( associated ), cipherOne, out, sizeof( cipherOne ),
                                         iv128, sizeof( iv128 ), icodeTwo, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,
                                   "checking the integrity code for two kuznechik keys is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                           "the decryption test for two kuznechik keys is wrong" );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
            "the 2nd full encryption, decryption & integrity test with two kuznechik keys is Ok" );

 /* третий тест - шифрование и имитовставка, алгоритм Магма, один ключ */
  memset( icode, 0, 16 );
  if(( error = ak_bckey_encrypt_mgm( &magmaKeyB, &magmaKeyB, associated, sizeof( associated ),
                  plain, out, sizeof( plain ), iv64, sizeof( iv64 ), icode, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for third example");
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( icode, icodeThree, sizeof( icodeThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "the integrity code for one magma key is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( out, cipherThree, sizeof( cipherThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the encryption test for one magma key is wrong" );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if(( error = ak_bckey_decrypt_mgm( &magmaKeyB, &magmaKeyB,
            associated, sizeof( associated ), cipherThree, out, sizeof( cipherThree ),
                                         iv64, sizeof( iv64 ), icodeThree, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "checking the integrity code for one magma key is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the decryption test for one magma key is wrong" );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                 "the 3rd full encryption, decryption & integrity test with one magma key is Ok" );

 /* четвертый тест - шифрование и имитовставка, алгоритм Магма, два ключа */
  memset( icode, 0, 16 );
  if(( error = ak_bckey_encrypt_mgm( &magmaKeyB, &magmaKeyA, associated, sizeof( associated ),
                  plain, out, sizeof( plain ), iv64, sizeof( iv64 ), icode, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for fourth example");
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( icode, icodeFour, sizeof( icodeFour ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the integrity code for two magma keys is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( out, cipherThree, sizeof( cipherThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                              "the encryption test for two magma keys is wrong" );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if(( error = ak_bckey_decrypt_mgm( &magmaKeyB, &magmaKeyA,
            associated, sizeof( associated ), cipherThree, out, sizeof( cipherThree ),
                                           iv64, sizeof( iv64 ), icodeFour, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "checking the integrity code for two magma keys is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                              "the decryption test for two magma keys is wrong" );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
               "the 4th full encryption, decryption & integrity test with two magma keys is Ok" );

 /* только здесь все хорошо */
  result = ak_true;

 /* освобождение памяти */
  exit:
  ak_bckey_destroy( &magmaKeyB );
  ak_bckey_destroy( &magmaKeyA );
  ak_bckey_destroy( &kuznechikKeyB );
  ak_bckey_destroy( &kuznechikKeyA );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-mgm01.c                                                                          */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mgm.c  */
/* ----------------------------------------------------------------------------------------------- */
