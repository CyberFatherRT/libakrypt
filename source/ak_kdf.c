/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 - 2023 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_kdf.с                                                                                  */
/*  - содержит реализацию функций выработки производных ключей                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
             /* Реализация функций генерации ключей согласно Р 50.1.113-2016 */
/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации ключа используется алгоритм, названный в рекомендациях KDF_GOSTR3411_2012_256.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

    \code
      K = KDF256( Kin, label, seed ) = HMAC256( Kin, 0x01 || label || 0x00 || seed || 0x01 || 0x00 )
    \endcode

    \note Особенность реализации данной функции состоит в том, что исходный ключ передается
          в аргументах функции в открытом виде.

    \param master_key Указатель на область памяти.
    \param master_key_size Размер памяти в байтах.
    \param label Используемая в алгоритме метка производного ключа
    \param label_size Длина метки (в октетах)
    \param seed Используемое в алгоритме инициализирующее значение
    \param seed_size Длина инициализирующего значения (в октетах)
    \param out Указатель на область памяти, в которую помещается выработанное значение
     (память в размере 32 октета должна быть выделена заранее)
    \param size Размер выделенной памяти

    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
    возвращается \ref ak_error_ok (ноль).                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_derive_kdf256( ak_uint8 *master_key, const size_t master_key_size,
               ak_uint8 *label, const size_t label_size, ak_uint8 *seed, const size_t seed_size,
                                                                 ak_uint8 *out, const size_t size )
{
    struct hmac pctx;
    int error = ak_error_ok;
    ak_uint8 cv[2] = { 0x01, 0x00 };

   /* создаем контекст алгоритма hmac */
    if(( error = ak_hmac_create_streebog256( &pctx )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect creation of hmac context" );
    if(( error = ak_hmac_set_key( &pctx, master_key, master_key_size )) != ak_error_ok ) {
      ak_hmac_destroy( &pctx );
      return ak_error_message( error, __func__, "incorrect creation of hmac secret key" );
    }

   /* только теперь приступаем к выработке нового ключевого значения */
    ak_hmac_clean( &pctx );
    ak_hmac_update( &pctx, cv, 1 );
    if(( label != NULL ) && ( label_size != 0 )) ak_hmac_update( &pctx, label, label_size );
    ak_hmac_update( &pctx, cv+1, 1 );
    if(( seed != NULL ) && ( seed_size != 0 )) ak_hmac_update( &pctx, seed, seed_size );
    if(( error = ak_hmac_finalize( &pctx, cv, 2, out, size )) != ak_error_ok )
      ak_error_message( error, __func__, "wrong creation of a derivative value of a secret key" );
    ak_hmac_destroy( &pctx );
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации ключа используется алгоритм, названный в рекомендациях KDF_GOSTR3411_2012_256.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

    \code
      K = KDF256( Kin, label, seed ) = HMAC256( Kin, 0x01 || label || 0x00 || seed || 0x01 || 0x00 )
    \endcode

    \note Особенность реализации данной функции состоит в том, что исходный ключ передается
          в составе указателя на структуру skey или ее насленики, что обеспечивает контроль
          целостности ключевой информации.

    \param master_key Указатель на корректно созданный ранее контекст секретного ключа `Kin`.
    В качестве типов криптографических механизмов для данного ключа допускаются блочные шифры и
    ключи выработки hmac. Использование ключей с другим установленным значением типа
    криптографического механизма приводит к ошибке.
    \param label Используемая в алгоритме метка производного ключа
    \param label_size Длина метки (в октетах)
    \param seed Используемое в алгоритме инициализирующее значение
    \param seed_size Длина инициализирующего значения (в октетах)
    \param out Указатель на область памяти, в которую помещается выработанное значение
     (память в размере 32 октета должна быть выделена заранее)
    \param size Размер выделенной памяти

    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
    возвращается \ref ak_error_ok (ноль).                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_derive_kdf256_from_skey( ak_pointer master_key, ak_uint8 *label,
                               const size_t label_size, ak_uint8 *seed, const size_t seed_size,
                                                                 ak_uint8 *out, const size_t size )
{
    int error = ak_error_ok;
    ak_skey master = ( ak_skey ) master_key;

   /* проверяем указатели */
    if( master_key == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to master key" );
    if(( label == NULL ) && ( seed == NULL ))
      return ak_error_message( ak_error_null_pointer, __func__,
                                                "using null pointer to both input data pointers" );
    if(( label_size == 0 ) && ( seed_size == 0 ))
      return ak_error_message( ak_error_null_pointer, __func__,
                                                "using zero length for both input data pointers" );
   /* проверяем, что мастер-ключ установлен */
    if( master->oid->mode != algorithm )
      return ak_error_message( ak_error_oid_mode, __func__,
                                   "using the master key which is not a cryptographic algorithm" );
    switch( master->oid->engine ) {
      case block_cipher:
      case hmac_function:
        break;
      default: return ak_error_message_fmt( ak_error_oid_engine, __func__,
                                            "using the master key with unsupported engine (%s)",
                                              ak_libakrypt_get_engine_name( master->oid->engine ));
    }

    if(( master->flags&key_flag_set_key ) == 0 )
      return ak_error_message( ak_error_key_value, __func__,
                                                     "using the master key with undefined value" );
   /* целостность ключа */
    if( master->check_icode( master ) != ak_true )
      return ak_error_message( ak_error_wrong_key_icode,
                                              __func__, "incorrect integrity code of master key" );

  /* только теперь вызываем функцию генерации производного ключа */
    master->unmask( master );
    error = ak_skey_derive_kdf256( master->key, master->key_size, label, label_size,
                                                                     seed, seed_size, out, size );
    master->set_mask( master );
    if( error != ak_error_ok )
       ak_error_message( error, __func__, "incorrect creation of derivative secret key value" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации ключа используется алгоритм, названный в рекомендациях KDF_GOSTR3411_2012_256.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

    \code
      K = KDF256( Kin, label, seed ) = HMAC256( Kin, 0x01 || label || 0x00 || seed || 0x01 || 0x00 )
    \endcode

    \note Особенность реализации данной функции состоит в том, что в процессе выполнения функция
    выделяет в памяти область для нового ключа, инициализирует его и присваивает выработанное
    значение, а также устанавливает ресурс ключа.

    \param oid Идентификатор создаваемого ключа
    \param master_key Указатель на корректно созданный ранее контекст секретного ключа `Kin`.
    В качестве типов криптографических механизмов для данного ключа допускаются блочные шифры и
    ключи выработки hmac. Использование ключей с другим установленным значением типа
    криптографического механизма приводит к ошибке.
    \param label Используемая в алгоритме метка производного ключа
    \param label_size Длина метки (в октетах)
    \param seed Используемое в алгоритме инициализирующее значение
    \param seed_size Длина инициализирующего значения (в октетах)

    \return В случае возникновения ошибки функция возвращает NULL, а код ошибки может быть
    получен с помощью функции ak_error_get_value(). В случае успеха
    возвращает указатель на созданый контекст секретного ключа.                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_new_derive_kdf256_from_skey( ak_oid oid, ak_pointer master_key,
                ak_uint8* label, const size_t label_size, ak_uint8* seed, const size_t seed_size )
{
  ak_uint8 out[32]; /* размер 32 определяется используемым алгоритмом kdf256 */
  int error = ak_error_ok;
  ak_pointer handle = NULL;

 /* выполняем проверки */
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid context" );
    return NULL;
  }
  if( oid->func.first.set_key == NULL ) {
    ak_error_message_fmt( ak_error_undefined_function, __func__,
                         "using oid (%s) with unsupported key assigning mechanism", oid->name[0] );
    return NULL;
  }

 /* создаем производный ключ */
  if(( error = ak_skey_derive_kdf256_from_skey( master_key,
                                 label, label_size, seed, seed_size, out, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of derivative secret key value" );
    goto labex;
  }

 /* погружаем данные в контекст */
  if(( handle = ak_oid_new_object( oid )) == NULL ) {
    ak_error_message( error = ak_error_get_value(), __func__,
                                                  "incorrect creation of new secret key context" );
    goto labex;
  }
  if(( error = oid->func.first.set_key( handle, out, 32 )) != ak_error_ok ) {
   ak_error_message( error, __func__, "incorrect assigning a derivative key value" );
   goto labex;
  }

 /* очищаем память */
  labex:
    if( error != ak_error_ok ) handle = ak_oid_delete_object( oid, handle );
    ak_ptr_wipe( out, sizeof( out ), &((ak_skey)master_key)->generator );

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return В случае успеха, функция возвращает истину. В случае возникновения ошибки,
 *  возвращается ложь. Код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_kdf256( void )
{
   /* входной ключ */
    ak_uint8 static_input_key[32] = {
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
   /* выходной ключ */
    ak_uint8 static_output_key[32] = {
     0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
     0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
    };

    ak_uint8 out[32];
    int error = ak_error_ok;
    ak_uint8 static_label[4] = { 0x26, 0xbd, 0xb8, 0x78 };
    ak_uint8 static_seed[8] = { 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78 };

   /* структура временного ключа */
    struct bckey sk;

   /* инициализируем контекст секретного ключа для блочного шифра */
    if(( error = ak_bckey_create_magma( &sk )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect creation of block cipher context");
      return ak_false;
    }
    if(( error = ak_bckey_set_key( &sk, static_input_key,
                                                     sizeof( static_input_key ))) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect assignin' of new secret key value");
      goto exlab;
    }

   /* вычисляем производный ключ и сравниваем результат */
    memset( out, 0, 32 );
    if(( error = ak_skey_derive_kdf256_from_skey( &sk,
                                  static_label,
                                  sizeof( static_label ),
                                  static_seed,
                                  sizeof( static_seed ),
                                  out, /* сюда помещаем результат вычислений */
                                  sizeof( out ))) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect generation of a new secret key value");
      goto exlab;
    }

   /* сравниваем вычисленный вектор с изначально заданным */
    if( !ak_ptr_is_equal_with_log( out, static_output_key, sizeof( static_output_key ))) {
      ak_error_message( error = ak_error_not_equal_data, __func__,
                                         "the value of kdf_gostr3411_2012_256 function is wrong ");
    }
     else {
        if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                       "the test for kdf-gostr3411-2012-256 function from R 50.1.113-2016 is Ok" );
     }

    exlab:
      ak_ptr_wipe( out, 32, &sk.key.generator );
      ak_bckey_destroy( &sk );

 return ( error == ak_error_ok ) ? ak_true : ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
          /* Реализация функций генерации ключей согласно Р 1323565.1.030-2019 (TLS 1.3) */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Предопределенные массивы констант из Р 1323565.1.030-2019,
 *  используемые в алгоритме tlstree выработки производного
 *  ключа и индексируемые значениями типа tlstree_t.
 *
 *  \details В большинстве приложений библиотеки используется пред последний случай, а именно,
 *  создание множества из \f$ 2^{16} = 65536\f$ производных ключей, определяемых равенством
 *  `K(i) = TLSTREE( k1, k2, k3 )`, где
 *    -  ключ k3 меняется каждого ключа
 *    -  ключ k2 меняется каждые \f$ 2^8 = 256 \f$ значений индекса i,
 *    -  ключ k2 меняется каждые \f$ 2^{12} = 4096\f$ значений индекса i. */
 const static struct tlstree_constant_values {
   ak_uint64 c1, c2, c3;
 } tlstree_constant_values[] = {
    { 0xf800000000000000, 0xfffffff000000000, 0xffffffffffffe000 },
    { 0xffe0000000000000, 0xffffffffc0000000, 0xffffffffffffff80 },
    { 0xffffffffe0000000, 0xffffffffffff0000, 0xfffffffffffffff8 },
    { 0xfffffffffc000000, 0xffffffffffffe000, 0xffffffffffffffff },
    { 0xfffffffffffff000, 0xffffffffffffff00, 0xffffffffffffffff },
    { 0xffffffffffffff00, 0xfffffffffffffff0, 0xffffffffffffffff },
 };

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации производного ключа используется алгоритм, названный в рекомендациях TLSTREE.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

    \code
      K = KDF256( Kin, index ) =
           Divers3( Divers2( Divers1( Kin, Str8( index &C1 )), Str8( index &C2 )), Str8( index &C3))

      Divers1( Ki, S ) = KDF256( Ki, "level1", S )
      Divers2( K,  S ) = KDF256( K,  "level2", S )
      Divers3( K,  S ) = KDF256( K,  "level3", S )
    \endcode

    а `Str8` -- запись целого беззнакового числа в виде последовательности 8 байт в big-endian формате

    \note Особенность реализации данной функции состоит в том, что исходный ключ передается
          в аргументах функции в открытом виде, а результат работы помещается внуть пременной ctx.
          Для того, чтобы получить значение производного ключа в явном виде
          желательно использовать функцию int ak_skey_derive_tlstree().

    \param ctx Контекст алгоритма TLSTREE.
    \param master_key Указатель на область памяти.
    \param master_key_size Размер памяти в байтах.
    \param index Порядковый номер вырабатываемого ключа
    \param tlstree Набор константан, являющийся параметром алгоритма
    \param out Указатель на область памяти, в которую помещается выработанное значение
     (память в размере 32 октета должна быть выделена заранее)
    \param size Размер выделенной памяти

    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
    возвращается \ref ak_error_ok (ноль).                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlstree_state_create( ak_tlstree_state ctx, ak_uint8 *master_key,
                                const size_t master_key_size, ak_uint64 index, tlstree_t tlstree )
{
    ak_uint64 seed;
    int error = ak_error_ok;

   /* проверки */
    if( ctx == NULL )
      return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null-pointer to tlstree state" );
   /* размещаем исходный ключ */
    memset( ctx, 0, sizeof( struct tlstree_state ));
    memcpy( ctx->key, master_key, ak_min( 32, master_key_size ));
    ctx->key_number = index;
    ctx->state = tlstree;

   /* первая итерация */
  #ifdef AK_LITTLE_ENDIAN
    seed = bswap_64( ctx->ind1 = ( index&tlstree_constant_values[tlstree].c1 ));
  #else
    seed = ctx->ind1 = ( index&tlstree_constant_values[tlstree].c1 );
  #endif
    if(( error = ak_skey_derive_kdf256( ctx->key,
                                        32,
                                        (ak_uint8 *) "level1",
                                        6,
                                        (ak_uint8 *) &seed,
                                        8,
                                        ctx->key +32,
                                        32 )) != ak_error_ok ) {
      ak_tlstree_state_destroy( ctx );
      return ak_error_message( error, __func__, "incorrect creation of temporary K1 value" );
    }

   /* вторая итерация */
  #ifdef AK_LITTLE_ENDIAN
    seed = bswap_64( ctx->ind2 = ( index&tlstree_constant_values[tlstree].c2 ));
  #else
    seed = ctx->ind2 = ( index&tlstree_constant_values[tlstree].c2 );
  #endif
    if(( error = ak_skey_derive_kdf256( ctx->key +32,
                                        32,
                                        (ak_uint8 *) "level2",
                                        6,
                                        (ak_uint8 *) &seed,
                                        8,
                                        ctx->key +64,
                                        32 )) != ak_error_ok ) {
      ak_tlstree_state_destroy( ctx );
      return ak_error_message( error, __func__, "incorrect creation of temporary K2 value" );
    }

   /* третья итерация */
  #ifdef AK_LITTLE_ENDIAN
    seed = bswap_64( ctx->ind3 = ( index&tlstree_constant_values[tlstree].c3 ));
  #else
    seed = ctx->ind3 = ( index&tlstree_constant_values[tlstree].c3 );
  #endif
    if(( error = ak_skey_derive_kdf256( ctx->key +64,
                                        32,
                                        (ak_uint8 *) "level3",
                                        6,
                                        (ak_uint8 *) &seed,
                                        8,
                                        ctx->key +96,
                                        32 )) != ak_error_ok ) {
      ak_tlstree_state_destroy( ctx );
      return ak_error_message( error, __func__, "incorrect creation of temporary K3 value" );
    }

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция увеличивает на единицу текущее значение номера ключа, после чего, при необходимости,
 *  пересчитывает значения промежуточных ключей.
 *
 *  \param ctx Контекст алгоритма TLSTREE.
 *  \return В случае возникновения ошибки, функция возвращает ее код. В случае успешного завершения
 *  возвращается ноль. */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlstree_state_next( ak_tlstree_state ctx )
{
    ak_uint64 seed = 0;
    int error = ak_error_ok;

    if( ctx == NULL )
      return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null-pointer to the tlstree context");

   /* следующий номер ключа */
    ++ctx->key_number;

   /* первая итерация */
    if(( seed = ( ctx->key_number&tlstree_constant_values[ctx->state].c1 )) != ctx->ind1 )
   {
     #ifdef AK_LITTLE_ENDIAN
       seed = bswap_64( ctx->ind1 = seed );
     #else
       ctx->ind1 = seed;
     #endif
       if(( error = ak_skey_derive_kdf256( ctx->key,
                                           32,
                                           (ak_uint8 *) "level1",
                                           6,
                                           (ak_uint8 *) &seed,
                                           8,
                                           ctx->key +32,
                                           32 )) != ak_error_ok ) {
         ak_tlstree_state_destroy( ctx );
         return ak_error_message( error, __func__, "incorrect creation of temporary K1 value" );
       }
   }

   /* вторая итерация */
    if(( seed = ( ctx->key_number&tlstree_constant_values[ctx->state].c2 )) != ctx->ind2 )
   {
     #ifdef AK_LITTLE_ENDIAN
       seed = bswap_64( ctx->ind2 = seed );
     #else
       ctx->ind2 = seed;
     #endif
       if(( error = ak_skey_derive_kdf256( ctx->key +32,
                                           32,
                                           (ak_uint8 *) "level2",
                                           6,
                                           (ak_uint8 *) &seed,
                                           8,
                                           ctx->key +64,
                                           32 )) != ak_error_ok ) {
         ak_tlstree_state_destroy( ctx );
         return ak_error_message( error, __func__, "incorrect creation of temporary K2 value" );
       }
   }

   /* третья итерация */
    if(( seed = ( ctx->key_number&tlstree_constant_values[ctx->state].c3 )) != ctx->ind3 )
   {
     #ifdef AK_LITTLE_ENDIAN
       seed = bswap_64( ctx->ind3 = seed );
     #else
       ctx->ind3 = seed;
     #endif
       if(( error = ak_skey_derive_kdf256( ctx->key +64,
                                           32,
                                           (ak_uint8 *) "level3",
                                           6,
                                           (ak_uint8 *) &seed,
                                           8,
                                           ctx->key +96,
                                           32 )) != ak_error_ok ) {
         ak_tlstree_state_destroy( ctx );
         return ak_error_message( error, __func__, "incorrect creation of temporary K3 value" );
       }
   }

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx Контекст алгоритма TLSTREE.
 *  \return Функция возвращает указатель на область памяти, внутри контекста алгоритма */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_tlstree_state_get_key( ak_tlstree_state ctx )
{
    if( ctx == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null-pointer to the tlstree context");
      return NULL;
    }

  return ( ctx->key +96 );
 }

/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx Контекст алгоритма TLSTREE.
 *  \return В случае возникновения ошибки возвращается ее код. В случае успеха функция
 *  возвращает ноль `ak_error_ok` (ноль).                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlstree_state_destroy( ak_tlstree_state ctx )
{
    struct random rng;
    int error = ak_error_ok;

    if( ctx == NULL )
      return ak_error_message( ak_error_null_pointer, __func__,
                                     "destroying a null-pointer to the random generator context" );

    if(( error = ak_random_create_lcg( &rng )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect creation of random generator context" );

    if(( error = ak_ptr_wipe( ctx, sizeof( struct tlstree_state ), &rng )) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect wipe of random generator context" );

    ak_random_destroy( &rng );
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации производного ключа используется алгоритм, названный в рекомендациях TLSTREE.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

    \code
      K = TLSTREE( Kin, index ) =
           Divers3( Divers2( Divers1( Kin, Str8( index &C1 )), Str8( index &C2 )), Str8( index &C3))

      Divers1( Ki, S ) = KDF256( Ki, "level1", S )
      Divers2( K,  S ) = KDF256( K,  "level2", S )
      Divers3( K,  S ) = KDF256( K,  "level3", S )
    \endcode

    а `Str8` -- запись целого беззнакового числа в виде последовательности 8 байт в big-endian формате

    \note Особенность реализации данной функции состоит в том, что исходный ключ передается
          в аргументах функции в открытом виде.

    \param master_key Указатель на область памяти.
    \param master_key_size Размер памяти в байтах.
    \param index Порядковый номер вырабатываемого ключа
    \param tlstree Набор констант, являющийся параметром алгоритма
    \param out Указатель на область памяти, в которую помещается выработанное значение
     (память в размере 32 октета должна быть выделена заранее)
    \param size Размер выделенной памяти

    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
    возвращается \ref ak_error_ok (ноль).                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_derive_tlstree( ak_uint8 *master_key, const size_t master_key_size, ak_uint64 index,
                                             tlstree_t tlstree, ak_uint8 *out, const size_t size )
{
    int error = ak_error_ok;
    struct tlstree_state ctx;

   /* безбашенные проверки */
    if( master_key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null-pointer to master key");
    if( !master_key_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                              "using master key with zero length");
    if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null-pointer to output buffer");
    if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                           "using output buffer with zero length");
   /* собственно основной вызов по выработке производного ключа */
    if(( error = ak_tlstree_state_create( &ctx,
                                    master_key, master_key_size, index, tlstree )) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect creation of derivative secret key");
     else  /* переносим данные */
       memcpy( out, ctx.key +96, ak_min( size, 32 ));

    ak_tlstree_state_destroy( &ctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации производного ключа используется алгоритм, названный в рекомендациях TLSTREE.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

    \code
      K = TLSTREE( Kin, index ) =
           Divers3( Divers2( Divers1( Kin, Str8( index &C1 )), Str8( index &C2 )), Str8( index &C3))

      Divers1( Ki, S ) = KDF256( Ki, "level1", S )
      Divers2( K,  S ) = KDF256( K,  "level2", S )
      Divers3( K,  S ) = KDF256( K,  "level3", S )
    \endcode

    а `Str8` -- запись целого беззнакового числа в виде последовательности 8 байт в big-endian формате

    \note Особенность реализации данной функции состоит в том, что исходный ключ передается
          в составе указателя на структуру skey или ее насленика, что обеспечивает контроль
          целостности ключевой информации.

    \param master_key Указатель на корректно созданный ранее контекст секретного ключа `Kin`.
    В качестве типов криптографических механизмов для данного ключа допускаются блочные шифры и
    ключи выработки hmac. Использование ключей с другим установленным значением типа
    криптографического механизма приводит к ошибке.
    \param index Порядковый номер вырабатываемого ключа
    \param tlstree Набор констант, являющийся параметром алгоритма
    \param out Указатель на область памяти, в которую помещается выработанное значение
     (память в размере 32 октета должна быть выделена заранее)
    \param size Размер выделенной памяти

    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
    возвращается \ref ak_error_ok (ноль).                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_derive_tlstree_from_skey( ak_pointer master_key, ak_uint64 index,
                                             tlstree_t tlstree, ak_uint8 *out, const size_t size )
{
    int error = ak_error_ok;
    ak_skey master = ( ak_skey ) master_key;

   /* проверяем указатели */
    if( master_key == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to master key" );
   /* проверяем, что мастер-ключ установлен */
    if( master->oid->mode != algorithm )
      return ak_error_message( ak_error_oid_mode, __func__,
                                   "using the master key which is not a cryptographic algorithm" );
    switch( master->oid->engine ) {
      case block_cipher:
      case hmac_function:
        break;
      default: return ak_error_message_fmt( ak_error_oid_engine, __func__,
                                            "using the master key with unsupported engine (%s)",
                                              ak_libakrypt_get_engine_name( master->oid->engine ));
    }

    if(( master->flags&key_flag_set_key ) == 0 )
      return ak_error_message( ak_error_key_value, __func__,
                                                     "using the master key with undefined value" );
   /* целостность ключа */
    if( master->check_icode( master ) != ak_true )
      return ak_error_message( ak_error_wrong_key_icode,
                                              __func__, "incorrect integrity code of master key" );

  /* только теперь вызываем функцию генерации производного ключа */
    master->unmask( master );
    error = ak_skey_derive_tlstree( master->key, master->key_size, index, tlstree, out, size );
    master->set_mask( master );

    if( error != ak_error_ok )
       ak_error_message( error, __func__, "incorrect creation of derivative secret key value" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для генерации производного ключа используется алгоритм, названный в рекомендациях TLSTREE.
    Вырабатываемый ключ `K` имеет длину 256 бит и определяется равенством

    \code
      K = TLSTREE( Kin, index ) =
           Divers3( Divers2( Divers1( Kin, Str8( index &C1 )), Str8( index &C2 )), Str8( index &C3))

      Divers1( Ki, S ) = KDF256( Ki, "level1", S )
      Divers2( K,  S ) = KDF256( K,  "level2", S )
      Divers3( K,  S ) = KDF256( K,  "level3", S )
    \endcode

     а `Str8` -- запись целого беззнакового числа в виде последовательности 8 байт в big-endian формате

    \note Особенность реализации данной функции состоит в том, что в процессе выполнения функция
     выделяет в памяти область для нового ключа, инициализирует его и присваивает выработанное
     значение, а также устанавливает ресурс ключа.

    \param oid Идентификатор создаваемого ключа
    \param master_key Указатель на корректно созданный ранее контекст секретного ключа `Kin`.
     В качестве типов криптографических механизмов для данного ключа допускаются блочные шифры и
     ключи выработки hmac. Использование ключей с другим установленным значением типа
     криптографического механизма приводит к ошибке.
    \param index Порядковый номер вырабатываемого ключа
    \param tlstree Набор констант, являющийся параметром алгоритма

    \return В случае возникновения ошибки функция возвращает NULL, а код ошибки может быть
    получен с помощью функции ak_error_get_value(). В случае успеха
    возвращает указатель на созданый контекст секретного ключа.                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_new_derive_tlstree_from_skey( ak_oid oid, ak_pointer master_key,
                                                               ak_uint64 index, tlstree_t tlstree )
{
    int error = ak_error_ok;
    struct tlstree_state ctx;
    ak_pointer handle = NULL;
    ak_skey master = ( ak_skey ) master_key;

   /* выполняем проверки */
    if( oid == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid context" );
      return NULL;
    }
    if( oid->func.first.set_key == NULL ) {
      ak_error_message_fmt( ak_error_undefined_function, __func__,
                         "using oid (%s) with unsupported key assigning mechanism", oid->name[0] );
      return NULL;
    }

   /* проверяем указатели */
    if( master_key == NULL )  {
      ak_error_message( ak_error_null_pointer, __func__, "using null pointer to master key" );
      return NULL;
    }

   /* проверяем, что мастер-ключ установлен */
    if( master->oid->mode != algorithm ) {
      ak_error_message( ak_error_oid_mode, __func__,
                                   "using the master key which is not a cryptographic algorithm" );
      return NULL;
    }

    switch( master->oid->engine ) {
      case block_cipher:
      case hmac_function:
        break;
      default: ak_error_message_fmt( ak_error_oid_engine, __func__,
                                            "using the master key with unsupported engine (%s)",
                                              ak_libakrypt_get_engine_name( master->oid->engine ));
               return NULL;
    }

    if(( master->flags&key_flag_set_key ) == 0 ) {
      ak_error_message( ak_error_key_value, __func__,"using the master key with undefined value" );
      return NULL;
    }

   /* целостность ключа */
    if( master->check_icode( master ) != ak_true ) {
      ak_error_message( ak_error_wrong_key_icode,
                                              __func__, "incorrect integrity code of master key" );
      return NULL;
    }

   /* только теперь начинаем криптографические преобразования */
    master->unmask( master );
    error = ak_tlstree_state_create( &ctx, master->key, master->key_size, index, tlstree );
    master->set_mask( master );

   /* проверяем, что все выработано */
    if( error != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect creation of derived key" );
      goto exlab;
    }

  /* погружаем выработанные данные в новый контекст */
   if(( handle = ak_oid_new_object( oid )) == NULL ) {
     ak_error_message( error = ak_error_get_value(), __func__,
                                                  "incorrect creation of new secret key context" );
     goto exlab;
   }
   if(( error = oid->func.first.set_key( handle, ctx.key +96, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assigning a derivative key value" );
     goto exlab;
   }

 /* очищаем память */
  exlab:
    if( error != ak_error_ok )
      handle = ak_oid_delete_object( oid, handle );
    ak_tlstree_state_destroy( &ctx );

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return В случае успеха, функция возвращает истину. В случае возникновения ошибки,
 *  возвращается ложь. Код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_tlstree( void )
{
   int error = ak_error_ok;
   struct tlstree_state ctx;

  /* множество исходных ключей */
   ak_uint8 inkey611[32] = {
     0x58, 0x16, 0x88, 0xD7, 0x6E, 0xFE, 0x12, 0x2B, 0xB5, 0x5F, 0x62, 0xB3, 0x8E, 0xF0, 0x1B, 0xCC,
     0x8C, 0x88, 0xDB, 0x83, 0xE9, 0xEA, 0x4D, 0x55, 0xD3, 0x89, 0x8C, 0x53, 0x72, 0x1F, 0xC3, 0x84
   };
   ak_uint8 inkey612[32] = {
     0xE1, 0x37, 0x64, 0xB5, 0x4B, 0x9E, 0x1B, 0x47, 0xD4, 0x33, 0x98, 0xD6, 0xD2, 0x16, 0xDF, 0x24,
     0xC2, 0x89, 0xA3, 0x96, 0xAB, 0x6C, 0x5B, 0x52, 0x4B, 0xBB, 0x9C, 0x06, 0xF3, 0x9F, 0xEF, 0x01
   };
   ak_uint8 inkey613[32] = {
     0x7B, 0xE6, 0x4E, 0x2C, 0x12, 0x78, 0x7B, 0x5B, 0x8C, 0x87, 0x56, 0xC4, 0x3D, 0x92, 0xFA, 0xEF,
     0x64, 0xF1, 0x5A, 0x3A, 0x3C, 0x10, 0x81, 0xAD, 0x34, 0xBC, 0xA5, 0x06, 0xF0, 0x32, 0x24, 0x15
   };
   ak_uint8 inkey634[32] = {
     0x15, 0xD9, 0x2C, 0x51, 0x47, 0xB2, 0x13, 0x10, 0xED, 0xED, 0xF5, 0x5B, 0x3D, 0x7A, 0xB7, 0x76,
     0x81, 0x7D, 0x6F, 0xE2, 0xFC, 0xF2, 0x30, 0xD7, 0xE3, 0xF2, 0x92, 0x75, 0xF6, 0xE2, 0x41, 0xEC
   };

  /* множество производных ключей */
   ak_uint8 outkey611[32] = {
     0xE1, 0xC5, 0x9B, 0x41, 0x69, 0xD8, 0x96, 0x10, 0x7F, 0x78, 0x45, 0x68, 0x93, 0xA3, 0x75, 0x1E,
     0x15, 0x73, 0x54, 0x3D, 0xAD, 0x8C, 0xB7, 0x40, 0x69, 0xE6, 0x81, 0x4A, 0x51, 0x3B, 0xBB, 0x1C
   };
   ak_uint8 outkey612[32] = {
     0x56, 0xEE, 0x18, 0x13, 0x72, 0x72, 0x49, 0xC9, 0xDC, 0xDF, 0x35, 0x13, 0x78, 0x7E, 0xDB, 0x93,
     0xDF, 0x62, 0xC6, 0x1E, 0xE7, 0xB1, 0x26, 0xC5, 0x0F, 0x26, 0xC0, 0xAA, 0xAF, 0xAE, 0x00, 0xE1
   };
   ak_uint8 outkey613a[32] = {
     0xD4, 0x9A, 0x57, 0x15, 0x49, 0xE7, 0x48, 0x94, 0x9F, 0xA2, 0x4B, 0x88, 0x34, 0x23, 0x2C, 0xA8,
     0x75, 0xD3, 0x7A, 0x26, 0xC4, 0xBB, 0x5C, 0x62, 0xA2, 0x61, 0xDA, 0xB3, 0x72, 0x65, 0x05, 0x26
   };
   ak_uint8 outkey613b[32] = {
     0xB8, 0x2D, 0x78, 0x25, 0xD1, 0x5F, 0xAE, 0x18, 0xA7, 0x01, 0x32, 0x28, 0xB3, 0x1C, 0xB0, 0xC5,
     0x97, 0x52, 0xC6, 0x40, 0x9C, 0x5F, 0x78, 0x99, 0xEC, 0xC6, 0x95, 0x0F, 0x74, 0x63, 0xC0, 0x90
   };
   ak_uint8 outkey634a[32] = {
     0x7B, 0xB8, 0x81, 0x55, 0x35, 0x98, 0xDE, 0xF5, 0x34, 0xFC, 0xAF, 0x9B, 0x77, 0xA3, 0x35, 0x5B,
     0xC3, 0xBC, 0xA3, 0x87, 0x4D, 0x67, 0x40, 0xF6, 0xCB, 0xF5, 0xC1, 0xB6, 0xD3, 0x5C, 0x65, 0xED
   };
   ak_uint8 outkey634b[32] = {
     0x93, 0xD5, 0xD6, 0xE1, 0x03, 0x6F, 0xDF, 0xB3, 0xEF, 0xBF, 0x31, 0xE6, 0xDA, 0x5E, 0xEC, 0xE6,
     0x85, 0x17, 0x1C, 0x97, 0x7F, 0xF9, 0xCD, 0x6C, 0x3A, 0x3F, 0x67, 0xC0, 0x22, 0x4A, 0xB6, 0xEB
   };

  /* массив для хранения выработанных ключей */
   ak_uint8 out[32];

  /* первый пример */
   if(( error = ak_skey_derive_tlstree( inkey611, 32, 5,
                                      tlstree_with_kuznyechik_mgm_s, out, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__,
                        "incorrect creation of derivative secret key, first example in part 6.1" );
     return ak_false;
   }
   if( !ak_ptr_is_equal_with_log( out, outkey611, 32 )) {
     ak_error_message( error, __func__,
                               "wrong value of derivative secret key, first example in part 6.1" );
     return ak_false;
   }
    else {
      if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
              "the first example for tlstree function from R 1323565.1.043–2022, part 6.1 is Ok" );
    }

  /* второй пример */
   if(( error = ak_skey_derive_tlstree( inkey612, 32, 5,
                                      tlstree_with_kuznyechik_mgm_s, out, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__,
                       "incorrect creation of derivative secret key, second example in part 6.1" );
     return ak_false;
   }
   if( !ak_ptr_is_equal_with_log( out, outkey612, 32 )) {
     ak_error_message( error, __func__,
                              "wrong value of derivative secret key, second example in part 6.1" );
     return ak_false;
   }
    else {
      if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
             "the second example for tlstree function from R 1323565.1.043–2022, part 6.1 is Ok" );
    }

  /* третий пример */
   if(( error = ak_skey_derive_tlstree( inkey613, 32, 5,
                                      tlstree_with_kuznyechik_mgm_s, out, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__,
                        "incorrect creation of derivative secret key, third example in part 6.1" );
     return ak_false;
   }
   if( !ak_ptr_is_equal_with_log( out, outkey613a, 32 )) {
     ak_error_message( error, __func__,
                               "wrong value of derivative secret key, third example in part 6.1" );
     return ak_false;
   }
    else {
      if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
              "the third example for tlstree function from R 1323565.1.043–2022, part 6.1 is Ok" );
    }

  /* четвертый пример */
   if(( error = ak_skey_derive_tlstree( inkey613, 32, 15,
                                      tlstree_with_kuznyechik_mgm_s, out, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__,
                       "incorrect creation of derivative secret key, fourth example in part 6.1" );
     return ak_false;
   }
   if( !ak_ptr_is_equal_with_log( out, outkey613b, 32 )) {
     ak_error_message( error, __func__,
                              "wrong value of derivative secret key, fourth example in part 6.1" );
     return ak_false;
   }
    else {
      if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
             "the fourth example for tlstree function from R 1323565.1.043–2022, part 6.1 is Ok" );
    }

  /* пятый пример */
   if(( error = ak_skey_derive_tlstree( inkey634, 32, 100,
                                           tlstree_with_magma_mgm_l, out, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__,
                       "incorrect creation of derivative secret key, fourth example in part 6.3" );
     return ak_false;
   }
   if( !ak_ptr_is_equal_with_log( out, outkey634a, 32 )) {
     ak_error_message( error, __func__,
                              "wrong value of derivative secret key, fourth example in part 6.3" );
     return ak_false;
   }
    else {
      if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
             "the fifth example for tlstree function from R 1323565.1.043–2022, part 6.3 is Ok" );
    }

  /* шестой пример */
   if(( error = ak_skey_derive_tlstree( inkey634, 32, 200,
                                           tlstree_with_magma_mgm_l, out, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__,
                        "incorrect creation of derivative secret key, fifth example in part 6.3" );
     return ak_false;
   }
   if( !ak_ptr_is_equal_with_log( out, outkey634b, 32 )) {
     ak_error_message( error, __func__,
                               "wrong value of derivative secret key, fifth example in part 6.3" );
     return ak_false;
   }
    else {
      if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
              "the sixth example for tlstree function from R 1323565.1.043–2022, part 6.3 is Ok" );
    }

  /* седьмой пример - проверка эквивалентности вычислений проивзодного ключа двумя способами
   * создаем контекст с расчетом на 4096 производных ключей */
   if(( error = ak_tlstree_state_create( &ctx, inkey611, 32, 0,
                                                 tlstree_with_libakrypt_4096 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of tlstree context");
     return ak_false;
   }

  /* вычисляем ключи в цикле и сравниваем */
   do {
       /* вычисляем производный ключ другим способом */
        if(( error = ak_skey_derive_tlstree( inkey611, 32, ctx.key_number,
                                        tlstree_with_libakrypt_4096, out, 32 )) != ak_error_ok ) {
          ak_error_message( error, __func__, "incorrect creation of tlstree derive key");
          goto exlab;
        }
       /* сравниваем производные ключи */
        if( !ak_ptr_is_equal_with_log( out, ak_tlstree_state_get_key( &ctx ), 32 )) {
          ak_error_message_fmt( error = ak_error_not_equal_data, __func__,
                     "wrong value of derivative secret key, iteration: %d", (int) ctx.key_number );
          goto exlab;
        }
        ak_tlstree_state_next( &ctx );
   }
    while ( ctx.key_number < 4200 );

   exlab:
     ak_tlstree_state_destroy( &ctx );
     if( error != ak_error_ok ) return ak_false;


   if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                  "4200 tests for comparison of different realizations of tlstree funcion is Ok" );
  return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
             /* Реализация функций генерации ключей согласно Р 1323565.1.022-2018 */
/* ----------------------------------------------------------------------------------------------- */
 #define ak_uint64_to_ptr( x, ptr ) { \
                                      ptr[0] = ( x >> 56 )&0xFF; \
                                      ptr[1] = ( x >> 48 )&0xFF; \
                                      ptr[2] = ( x >> 40 )&0xFF; \
                                      ptr[3] = ( x >> 32 )&0xFF; \
                                      ptr[4] = ( x >> 24 )&0xFF; \
                                      ptr[5] = ( x >> 16 )&0xFF; \
                                      ptr[6] = ( x >>  8 )&0xFF; \
                                      ptr[7] = x&0xFF;           \
                                    }
 #define ak_ptr_to_uint64( ptr, x ) { \
                                     x = ptr[0]; x <<= 8;\
                                     x += ptr[1]; x <<= 8;\
                                     x += ptr[2]; x <<= 8;\
                                     x += ptr[3]; x <<= 8;\
                                     x += ptr[4]; x <<= 8;\
                                     x += ptr[5]; x <<= 8;\
                                     x += ptr[6]; x <<= 8;\
                                     x += ptr[7]; \
                                    }
/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает промежуточный ключ `K*` и устанавливает начальное состояние
    строки `format`, используемых в дальнейшем для выработки ключевой последовательности.
    Промежуточный ключ `K*` определяется одним из следующих равенств.

 \code
                             NMAC256( seed, Kin )
    K* = KDF1( seed, Kin ) = LSB256( HMAC512( seed, Kin ))
                             seed \oplus Kin, если len(seed) = len(Kin) = 256 (в битах)
 \endcode

    Значение последовательности октетов `format` определяется следующим образом.

 \code
    format = Ki-1 || i || label || L,
 \endcode
   где
   - длина `Ki-1` определяется младшими четырьмя битами типа kdf_t и может принимать
     значения 8, 16, 32 и 64 октетов,
   - длина kdf равна 1 октет,
   - длина i равна 4 октетам (запись целого числа производится в big-endian кодировке),
   - длина поля label определяется значением label_size,
   - длина поля L равна 4 октетам (запись целого числа производится в big-endian кодировке).

    Далее, с помощью промежуточного ключа вырабатывается ключевая информация,
    представленная в виде последовательности блоков `K1`, `K2`, ..., `Kn`.
    Для вычисления указаных блоков используются следующие соотношения.

 \code
    K0 = IV,

    Ki = Mac( K*, Ki-1 || i || label || L ), где L = n*len(Ki) и

    K = K1 || K2 || ... || Kn
 \endcode

   В качестве функции `Mac` могут выступать функции cmac (magma,kuznechik), hmac(512,256), nmac(streebog).
   Согласно Р 1323565.1.022-2018, может быть реализовано 15 вариантов
   указанного преобразования, мнемонические описания которых содержатся в перечислении \ref kdf_t.

    \param state Контекст, сожержащий текущее состояние алгоритма выработки производной ключевой информации
    \param key исходный ключ `Kin`, представляющий собой последовательность октетов
     произвольной, отличной от нуля длины
    \param key_size длина исходного ключа в октетах
    \param kdf функция, используемая для генерации производной ключевой информации
    \param label Используемая в алгоритме метка производного ключа. Может принимать значение NULL.
    \param label_size Длина метки (в октетах). Может принимать значение 0.
    \param seed Используемое в алгоритме инициализирующее значение. Должно быть отлично от NULL.
    \param seed_size Длина инициализирующего значения (в октетах). Должно быть отлично от нуля.
    \param iv Начальное значение `K0` для вырабатываемой последовательности ключей `K1`, `K2`, ...
       Если `iv` принимает значение NULL, то в качестве `K0` используется нулевой вектор.
    \param iv_size Длина начального значения (в октетах).
       Если `iv_size` меньше, чем выход функции `Mac`, то начальное значение `K0` дополняется нулями в старших разрядах.
       Если `iv_size` больше, чем выход функции `Mac`, то старшие разряды отбрасываются.
       Если `iv_size = 0`, то в качестве `K0` используется нулевой вектор.
    \param count Максимальное количество ключей, которое может быть выработано.
    \return В случае возникновения ошибки функция возвращает ее код. В случае успеха
     возвращается \ref ak_error_ok (ноль).                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_kdf_state_create( ak_kdf_state state, ak_uint8 *key, const size_t key_size, kdf_t kdf,
                ak_uint8* label, const size_t label_size, ak_uint8* seed, const size_t seed_size,
                                                  ak_uint8* iv, const size_t iv_size, size_t count )
{
  size_t temp = 0;
  ak_int64 resource = 0;
  int error = ak_error_ok;

 /* выполняем проверки входных параметров */
  if( state == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to state context" );
  if(( key == NULL ) || ( key_size == 0 ))
    return ak_error_message( ak_error_null_pointer, __func__, "using incorrect input secret key");
  if(( seed == NULL ) || ( seed_size == 0 ))
    return ak_error_message( ak_error_null_pointer, __func__, "using incorrect input seed buffer");

 /* вырабатываем промежуточный ключ */
  memset( state, 0, sizeof( struct kdf_state ));
  state->algorithm = kdf;

 /* вырабатываем промежуточный ключ */
  switch(( kdf >> 4 )&0xF ) {
    case 1: /* nmac */
      if(( error = ak_hmac_create_nmac( &state->key.hkey )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect creation of nmac context" );
      if(( error = ak_hmac_set_key( &state->key.hkey, seed, seed_size )) == ak_error_ok ) {
        error = ak_hmac_ptr( &state->key.hkey, key, key_size, state->ivbuffer, 32 );
      }
      ak_hmac_destroy( &state->key.hkey );
      if( error != ak_error_ok )
        return ak_error_message( error, __func__,
                                     "incorrect creation of intermediate key using nmac context" );
      break;

    case 2: /* hmac */
      if(( error = ak_hmac_create_streebog512( &state->key.hkey )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect creation of hmac context" );
      if(( error = ak_hmac_set_key( &state->key.hkey, seed, seed_size )) == ak_error_ok ) {
       /* здесь важно, что ak_hash_context_streebog_finalize помещает в массив interkey
          младшие байты выработанного вектора. При наличии контрольного примера, необходимо проверить это. */
        error = ak_hmac_ptr( &state->key.hkey, key, key_size, state->ivbuffer, 32 );
      }
      ak_hmac_destroy( &state->key.hkey );
      if( error != ak_error_ok )
        return ak_error_message( error, __func__,
                                     "incorrect creation of intermediate key using hmac context" );
      break;

    case 3: /* xor */
      if(( key_size != 32 ) || ( seed_size != 32 )) return ak_error_message(
                        ak_error_wrong_key_length, __func__, "using unsupported key/seed length" );
      for( int i = 0; i < 32; i++ ) state->ivbuffer[i] = key[i]^seed[i];
      break;

    default:
      return ak_error_message( ak_error_undefined_function, __func__,
                          "using unsupported descriptor of intermediate key derivation function" );
      break;
  }

 /* формируем ключ и проверяем ограничения на его использование */
  switch( kdf&0xF ) {
    case 1: /* magma */
      state->block_size = 8;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "magma_cipher_resource" );
      if( state->max*( 1+ state->state_size / state->block_size ) > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                  "the expected number of derivative keys is very large (must be less than %ld)",
                                            resource/( 1+ state->state_size / state->block_size ));
        goto labex;
      }
      if(( error = ak_bckey_create_magma( &state->key.bkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of magma context" );
        goto labex;
      }
      if(( error = ak_bckey_set_key( &state->key.bkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect assigning a secret key to magma context" );
        ak_bckey_destroy( &state->key.bkey  );
        goto labex;
      }
      break;

    case 2: /* kuznechik */
      state->block_size = 16;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "kuznechik_cipher_resource" );
      if( state->max*( 1+ state->state_size / state->block_size ) > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                  "the expected number of derivative keys is very large (must be less than %ld)",
                                            resource/( 1+ state->state_size / state->block_size ));
        goto labex;
      }
      if(( error = ak_bckey_create_kuznechik( &state->key.bkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of kuznechik context" );
        goto labex;
      }
      if(( error = ak_bckey_set_key( &state->key.bkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__,
                                         "incorrect assigning a secret key to kuznechik context" );
        ak_bckey_destroy( &state->key.bkey  );
        goto labex;
      }
      break;

    case 3: /* hmac256 */
      state->block_size = 32;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "hmac_key_count_resource" );
      if( 2*state->max > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                   "the expected number of derivative keys is very large (must be less than %ld)",
                                                                                      resource/2 );
        goto labex;
      }
      if(( error = ak_hmac_create_streebog256( &state->key.hkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of hmac-streebog256 context" );
        goto labex;
      }
      if(( error = ak_hmac_set_key( &state->key.hkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__,
                                  "incorrect assigning a secret key to hmac-streebog256 context" );
        ak_hmac_destroy( &state->key.hkey  );
        goto labex;
      }
      break;

    case 4: /* hmac512 */
      state->block_size = 64;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "hmac_key_count_resource" );
      if( 2*state->max > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                   "the expected number of derivative keys is very large (must be less than %ld)",
                                                                                      resource/2 );
        goto labex;
      }
      if(( error = ak_hmac_create_streebog512( &state->key.hkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of hmac-streebog512 context" );
        goto labex;
      }
      if(( error = ak_hmac_set_key( &state->key.hkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__,
                                  "incorrect assigning a secret key to hmac-streebog512 context" );
        ak_hmac_destroy( &state->key.hkey  );
        goto labex;
      }
      break;

    case 5: /* nmac */
      state->block_size = 32;
      state->state_size = ak_min( state->block_size + label_size + 16, sizeof( state->ivbuffer ));
      /* значение имитовставки + счетчик ключей (8 октетов) + метка +
                                                  + максимальное количество ключей (8 октетов) */
      state->number = 0;
      state->max = ( ak_uint64 )count;
      resource = ak_libakrypt_get_option_by_name( "hmac_key_count_resource" );
      if( 2*state->max > resource ) {
        ak_error_message_fmt( error = ak_error_low_key_resource, __func__,
                   "the expected number of derivative keys is very large (must be less than %ld)",
                                                                                      resource/2 );
        goto labex;
      }
      if(( error = ak_hmac_create_nmac( &state->key.hkey )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of nmac-streebog context" );
        goto labex;
      }
      if(( error = ak_hmac_set_key( &state->key.hkey, state->ivbuffer, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__,
                                  "incorrect assigning a secret key to nmac-streebog context" );
        ak_hmac_destroy( &state->key.hkey  );
        goto labex;
      }
      break;

    default:
      ak_error_message( ak_error_undefined_function, __func__,
                         "using unsupported descriptor of intermediate key derivation algorithm" );
      goto labex;
      break;
  }

 /* в заключение, формируем строку */
  memset( state->ivbuffer, 0, sizeof( state->ivbuffer ));
  if( iv != NULL ) memcpy( state->ivbuffer, iv, ak_min( iv_size, state->block_size ));
  ak_uint64_to_ptr( state->number, ( state->ivbuffer +state->block_size +8 ));

  memcpy( state->ivbuffer +state->block_size +8, label,
                  temp = ak_min( label_size, sizeof( state->ivbuffer ) - state->block_size - 16 ));
 /* последним параметром записываем максимальную длину ключевой информации в битах */
  ak_uint64_to_ptr( state->max*state->block_size, ( state->ivbuffer +state->block_size +8 +temp ));

  labex:
    if( error != ak_error_ok ) memset( state->ivbuffer, 0, sizeof( state->ivbuffer ));

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param state Контекст, содержащий текущее состояние алгоритма выработки производной
    ключевой информации                                                                            */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_kdf_state_get_block_size( ak_kdf_state state )
{
  if( state == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to state context" );
 return state->block_size;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param state Контекст, содержащий текущее состояние алгоритма выработки производной
    ключевой информации
    \param buffer Область памяти, куда помещается выработанная ключевая информайия
    \param buffer_size Размер вырабатываемой ключевой информации (в октетах)
    \return В случае успеха функция возвращает ноль (ak_error_ok),
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_kdf_state_next( ak_kdf_state state, ak_pointer buffer, const size_t buffer_size )
{
  ak_uint64 index = 0;
  size_t i, count, tail;
  ak_uint8 *ptr = buffer;
  ak_function_finalize *mac = NULL;

  if( state == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to state context" );
  if( buffer == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to key buffer" );
  if( buffer_size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                        "using null key buffer with zero length" );
 /* вычисляем количество шагов */
  count = buffer_size / state->block_size;
  tail = buffer_size - count*state->block_size;

  if(( state->number + count + (tail > 0 )) >= state->max )
    return ak_error_message( ak_error_low_key_resource, __func__,
                                                      "resource of key information is exhausted" );
  ak_ptr_to_uint64(( state->ivbuffer +state->block_size ), index );
  if( index != state->number ) return ak_error_message( ak_error_invalid_value,
                                                      __func__, "incorrect internal state value" );
 /* определяем функцию для сжатия */
  switch( state->algorithm&0xF ) {
    case 1:
    case 2: mac = (ak_function_finalize *) ak_bckey_cmac;
      break;
    default: mac = (ak_function_finalize *) ak_hmac_ptr;
      break;
  }

 /* основной цикл */
  for( i = 0; i < count; i++ ) {
    state->number++;
    ak_uint64_to_ptr( state->number, ( state->ivbuffer +state->block_size ));
    mac( &state->key.bkey, state->ivbuffer, state->state_size, state->ivbuffer, state->block_size );
    memcpy( ptr, state->ivbuffer, state->block_size );
    ptr += state->block_size;
  }

  if( tail ) {
    state->number++;
    ak_uint64_to_ptr( state->number, ( state->ivbuffer +state->block_size ));
    mac( &state->key.bkey, state->ivbuffer, state->state_size, state->ivbuffer, state->block_size );
    memcpy( ptr, state->ivbuffer, tail );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param state Контекст, содержащий текущее состояние алгоритма выработки производной 
    ключевой информации
    \return В случае успеха функция возвращает ноль (ak_error_ok),
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_kdf_state_destroy( ak_kdf_state state )
{
  if( state == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to state context" );
  ak_ptr_wipe( state->ivbuffer, sizeof( state->ivbuffer ), &state->key.bkey.key.generator );

  switch( state->algorithm&0xF ) {
  case 1:
  case 2:
    ak_bckey_destroy( &state->key.bkey );
    break;
  case 3:
  case 4:
  case 5:
    ak_hmac_destroy( &state->key.hkey );
    break;
  default:
    return ak_error_message( ak_error_undefined_value, __func__,
                                                        "using state with unsupported algorithm" );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-kdf-state.c                                                                      */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                        ak_kdf.c */
/* ----------------------------------------------------------------------------------------------- */
