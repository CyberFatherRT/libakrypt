/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hmac.с                                                                                 */
/*  - содержит реализацию семейства ключевых алгоритмов хеширования HMAC.                          */
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
/*! \brief Очистка контекста алгоритма hmac.
    \param ctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hmac_internal_clean( ak_pointer ctx )
{
  int error = ak_error_ok;
  ak_hmac hctx = ( ak_hmac ) ctx;
  size_t idx = 0, jdx = 0, len = 0;
  ak_uint8 buffer[64]; /* буффер для хранения промежуточных значений */

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&key_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );

  if( hctx->key.resource.value.counter <= 1 ) return ak_error_message( ak_error_low_key_resource,
                                            __func__, "using hmac key context with low resource" );
                      /* нам надо два раза использовать ключ => ресурс должен быть не менее двух */
  if( hctx->mctx.bsize > sizeof( buffer )) return ak_error_message( ak_error_wrong_length,
                                            __func__, "using hash function with huge block size" );

 /* фомируем маскированное значение ключа */
  len = ak_min( hctx->mctx.bsize, jdx = hctx->key.key_size );
  for( idx = 0; idx < len; idx++, jdx++ ) {
     buffer[idx] = hctx->key.key[idx] ^ 0x36;
     buffer[idx] ^= hctx->key.key[jdx];
  }
  for( ; idx < hctx->mctx.bsize; idx++ ) buffer[idx] = 0x36;

 /* инициализируем начальное состояние контекста хеширования */
  if(( error = ak_hash_clean( &hctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );

 /* обновляем состояние контекста хеширования */
  if(( error = ak_hash_update( &hctx->ctx, buffer, hctx->mctx.bsize )) != ak_error_ok )
    ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* очищаем буффер */
  ak_ptr_wipe( buffer, sizeof( buffer ), &hctx->key.generator );

 /* перемаскируем ключ и меняем его ресурс */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.value.counter--; /* мы использовали ключ один раз */

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обновление состояния контекста сжимающего отображения.
    \param ctx Контекст алгоритма HMAC выработки имитовставки.
    \param data Указатель на обрабатываемые данные.
    \param size Длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемой функции хеширования
    \return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hmac_internal_update( ak_pointer ctx, const ak_pointer in, const size_t size )
{
  ak_hmac hctx = ( ak_hmac ) ctx;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%hctx->mctx.bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&key_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );
  if( hctx->key.resource.value.counter <= 0 ) return ak_error_message( ak_error_low_key_resource,
                                            __func__, "using hmac key context with low resource" );

  return ak_hash_update( &hctx->ctx, in, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обновление состояния и вычисление результата применения сжимающего отображения.
    \param ctx Контекст алгоритма HMAC выработки имитовставки.
    \param data Блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных для используемой функции хеширования
    \param size Длина блока обрабатываемых данных
    \param out Указатель на область памяти, куда будет помещен результат.
    \return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hmac_internal_finalize( ak_pointer ctx,
                    const ak_pointer in, const size_t size, ak_pointer out, const size_t out_size )
{
  int error = ak_error_ok;
  ak_hmac hctx = ( ak_hmac ) ctx;
  size_t idx = 0, jdx = 0, len = 0;
  ak_uint8 temporary[128]; /* первый буффер для хранения промежуточных значений */
  ak_uint8 keybuffer[128]; /* второй буффер для хранения промежуточных значений */

 /* выполняем проверки */
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using a null pointer to hmac context" );
 /* ограничение в связи с константным размером временного буффера */
  if( hctx->ctx.data.sctx.hsize > sizeof( temporary ))
    return ak_error_message( ak_error_wrong_length,
                      __func__, "using a hash context with unsupported huge integrity code size" );
  if( size >= hctx->mctx.bsize ) return ak_error_message( ak_error_zero_length,
                                          __func__ , "using wrong length for authenticated data" );
 /* проверяем наличие ключа (ресурс проверен при вызове clean) */
  if( !((hctx->key.flags)&key_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );
 /* обрабатываем хвост предыдущих данных */
  memset( temporary, 0, sizeof( temporary ));
  if(( error = ak_hash_finalize( &hctx->ctx, in, size, temporary,
                                                            sizeof( temporary ))) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong updating of finalized data" );

 /* фомируем маскированное значение ключа */
  len = ak_min( hctx->mctx.bsize, jdx = hctx->key.key_size );
  for( idx = 0; idx < len; idx++ , jdx++ ) {
     keybuffer[idx] = hctx->key.key[idx] ^ 0x5C;
     keybuffer[idx] ^= hctx->key.key[jdx];
  }
  for( ; idx < hctx->mctx.bsize; idx++ ) keybuffer[idx] = 0x5C;


 /* различие с nmac в последней функции хеширования */
  if( hctx->nmac_second_hash_oid ) {
    ak_hash_destroy( &hctx->ctx );
    hctx->nmac_second_hash_oid->func.first.create( &hctx->ctx );
  }

 /* возвращаем контекст хеширования в начальное состояние */
  if(( error = ak_hash_clean( &hctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );

 /* обновляем состояние контекста хеширования */
  if(( error = ak_hash_update( &hctx->ctx, keybuffer, hctx->mctx.bsize )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* очищаем буффер */
  ak_ptr_wipe( keybuffer, sizeof( keybuffer ), &hctx->key.generator );

 /* ресурс ключа */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.value.counter--; /* мы использовали ключ один раз */

 /* последний update/finalize и возврат результата */
  error = ak_hash_finalize( &hctx->ctx, temporary, hctx->ctx.data.sctx.hsize, out, out_size );

  if( hctx->nmac_second_hash_oid ) {
    ak_hash_destroy( &hctx->ctx );
    ak_hash_create_streebog512( &hctx->ctx );
  }

 /* очищаем контекст функции хеширования, ключ не трогаем */
  ak_hash_clean( &hctx->ctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param oid Идентификатор алгоритма HMAC - ключевой функции хеширования.
    \return В случае успешного завершения функция возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_create_oid( ak_hmac hctx, ak_oid oid )
{
  ak_oid hashoid = NULL;
  int error = ak_error_ok;

 /* выполняем проверку */
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hmac context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to hash function OID" );
 /* проверяем, что OID от правильного алгоритма выработки */
  if( oid->engine != hmac_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );

 /* получаем oid бесключевой функции хеширования */
  if(( hashoid = ak_oid_find_by_name( oid->name[0]+5 )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ ,
                                                       "incorrect searching of hash fuction oid" );
 /* проверяем, что производящая функция определена */
  if( hashoid->func.first.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                            "using hash function oid with undefined constructor" );
 /* инициализируем контекст функции хеширования */
  if(( error = (( ak_function_hash_create *)hashoid->func.first.create )( &hctx->ctx )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                           "invalid creation of %s hash function context", hashoid->name[0] );
 /* инициализируем контекст сжимающего отображения */
  if(( error = ak_mac_create(
                 &hctx->mctx, /* контекст */
                 hctx->ctx.mctx.bsize, /* размер входного блока совпадает с блоком хеш-функции */
                 hctx, /* указатель на объек, которым будут оперировать функции */
                 ak_hmac_internal_clean,
                 ak_hmac_internal_update,
                 ak_hmac_internal_finalize )) != ak_error_ok ) {
    ak_hmac_destroy( hctx );
    return ak_error_message( error, __func__, "invalid creation of mac function context" );
  }

 /* инициализируем контекст секретного ключа */
  if(( error = ak_skey_create( &hctx->key, hctx->ctx.mctx.bsize )) != ak_error_ok ) {
    ak_hmac_destroy( hctx );
    return ak_error_message( error, __func__, "wrong creation of secret key context" );
  }
 /* доопределяем oid ключа */
  hctx->key.oid = oid;
 /* устанавливаем указатель на второй алгоритм хеширования */
  hctx->nmac_second_hash_oid = NULL;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_create_streebog256( ak_hmac hctx )
{ return ak_hmac_create_oid( hctx, ak_oid_find_by_name( "hmac-streebog256" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_create_streebog512( ak_hmac hctx )
{ return ak_hmac_create_oid( hctx, ak_oid_find_by_name( "hmac-streebog512" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма NMAC выработки имитовставки.
    \return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_create_nmac( ak_hmac hctx )
{
  int error = ak_hmac_create_oid( hctx, ak_oid_find_by_name( "hmac-streebog512" ));
  hctx->key.oid = ak_oid_find_by_name( "nmac-streebog" );
  hctx->nmac_second_hash_oid = ak_oid_find_by_name( "streebog256" );
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_destroy( ak_hmac hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hmac context" );
  if(( error = ak_hash_destroy( &hctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of hash context" );
  if(( error = ak_skey_destroy( &hctx->key )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of secret key context" );
  if(( error = ak_mac_destroy( &hctx->mctx )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of mac context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    \param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    \param size Размер данных, на которые указывает `ptr` (размер в байтах).
    Если величина `size` меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только `size` байт (остальные заполняются нулями). Если `size` больше, чем количество выделенной памяти
    под ключ, то в качестве ключа используется хэш-код от `ptr`.

    \return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_set_key( ak_hmac hctx, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hmac context" );
 /* вспоминаем, что если ключ длиннее, чем длина входного блока хэш-функции, то в качестве
                                                                      ключа используется его хэш */
  if( size > hctx->mctx.bsize ) {
    ak_uint8 out[64];
    size_t stag = ak_hash_get_tag_size( &hctx->ctx );

    if(( stag == 0 ) || ( stag > 64 ))
      return ak_error_message( ak_error_wrong_length, __func__ ,
                                   "using hash function with incorrect length of integrity code" );
   /* вычисляем хэш от заданного значения */
    memset( out, 0, sizeof( out ));
    if(( error = ak_hash_ptr( &hctx->ctx, ptr, size, out, sizeof( out ))) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect calculation of integrity code" );

    if(( error = ak_skey_set_key( &hctx->key, out, stag )) != ak_error_ok )
      return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );
    ak_ptr_wipe( out, sizeof( out ), &hctx->key.generator );

  } else { /* здесь ключ используется в явном виде */
      if(( error = ak_skey_set_key( &hctx->key, ptr, size )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );
  }

 /* устанавливаем ресурс ключа */
  if(( error = ak_skey_set_resource_values( &hctx->key,
                          key_using_resource, "hmac_key_count_resource", 0, 0 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect assigning \"hmac_key_count_resource\" option" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу случайное (псевдо-случайное) значение, размер которого определяется
    размером секретного ключа. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    \param hctx Контекст алгоритма HMAC выработки имитовставки. К моменту вызова функции контекст
    должен быть инициализирован.
    \param generator Контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_set_key_random( ak_hmac hctx, ak_random generator )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_skey_set_key_random( &hctx->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 /* устанавливаем ресурс ключа */
  if(( error = ak_skey_set_resource_values( &hctx->key,
                          key_using_resource, "hmac_key_count_resource", 0, 0 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect assigning \"hmac_key_count_resource\" option" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи
    алгоритма PBKDF2, описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    Количество итераций алгоритма PBKDF2 определяется опцией библиотеки `pbkdf2_iteration_count`,
    значение которой может быть опредедено с помощью вызова функции ak_libakrypt_get_option().

    @param hctx Контекст алгоритма HMAC выработки имитовставки. К моменту вызова функции контекст
    должен быть инициализирован.
    @param pass Пароль, представленный в виде строки символов.
    @param pass_size Длина пароля в байтах.
    @param salt Случайная последовательность, представленная в виде строки символов.
    @param salt_size Длина случайной последовательности в байтах.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_set_key_from_password( ak_hmac hctx, const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_skey_set_key_from_password( &hctx->key,
                                          pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 /* устанавливаем ресурс ключа */
  if(( error = ak_skey_set_resource_values( &hctx->key,
                          key_using_resource, "hmac_key_count_resource", 0, 0 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect assigning \"hmac_key_count_resource\" option" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_clean( ak_hmac hctx )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "cleaning null pointer to hash context" );
 return ak_mac_clean( &hctx->mctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param in Указатель на входные данные для которых вычисляется хеш-код.
    \param size Размер входных данных в байтах. Размер может принимать произвольное,
    натуральное значение.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_update( ak_hmac hctx, const ak_pointer in, const size_t size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "updating null pointer to hmac context" );
 return ak_mac_update( &hctx->mctx, in, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param in Указатель на входные данные для которых вычисляется хеш-код.
    \param size Размер входных данных в байтах.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    \param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_finalize( ak_hmac hctx, const ak_pointer in, const size_t size,
                                                           ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "finalizing null pointer to hmac context" );
 return ak_mac_finalize( &hctx->mctx, in, size, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param in Указатель на входные данные для которых вычисляется хеш-код.
    \param size Размер входных данных в байтах.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    \param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_ptr( ak_hmac hctx, const ak_pointer in, const size_t size,
                                                           ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hmac context" );
 return ak_mac_ptr( &hctx->mctx, in, size, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param filename Имя файла, для котрого вычисляется имитовставка.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    \param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_file( ak_hmac hctx, const char * filename,
                                                           ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
 return ak_mac_file( &hctx->mctx, filename, out, out_size );
}


/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return Функция возвращает длину имитовставки в октетах. В случае возникновения ошибки,
    возвращается ноль. Код ошибки может быть получен с помощью вызова функции ak_error_get_value().*/
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hmac_get_tag_size( ak_hmac hctx )
{
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to hash context" );
    return 0;
  }
  if( hctx->nmac_second_hash_oid != NULL ) return 32;

 return hctx->ctx.data.sctx.hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return Функция возвращает длину блока в октетах. В случае возникновения ошибки,
    возвращается ноль. Код ошибки может быть получен с помощью вызова функции ak_error_get_value().*/
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hmac_get_block_size( ak_hmac hctx )
{
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to hash context" );
    return 0;
  }

 return hctx->mctx.bsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Пароль должен представлять собой ненулевую строку символов в utf8
    кодировке. Размер вырабатываемого ключевого вектора может колебаться от 32-х до 64-х байт.
    При выработке используется алгоритм hmac-streebog512.

    @param pass Пароль, строка символов в utf8 кодировке.
    @param pass_size Размер пароля в байтах, должен быть отличен от нуля.
    @param salt Строка с инициализационным вектором (произвольная область памяти). Данное значение
    не является секретным и может храниться или передаваться в открытом виде.
    @param salt_size Размер инициализионного вектора в байтах.
    @param cnt Параметр, определяющий количество однотипных итераций для выработки ключа; данный
    параметр определяет время работы алгоритма; параметр не является секретным и может храниться или
    передаваться в открытом виде.
    @param dklen Длина вырабатываемого ключевого вектора в байтах, величина должна принимать
    значение от 32-х до 64-х.
    @param out Указатель на массив, куда будет помещен результат; под данный массив должна быть
    заранее выделена память не менее, чем dklen байт.

    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_pbkdf2_streebog512( const ak_pointer pass,
         const size_t pass_size, const ak_pointer salt, const size_t salt_size, const size_t cnt,
                                                               const size_t dklen, ak_pointer out )
{
  struct hmac hctx;
  ak_uint8 result[64];
  int error = ak_error_ok;
  size_t idx = 0, jdx = 0;

 /* в начале, многочисленные проверки входных параметров */
  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                 "using null pointer to password" );
  if( !pass_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                   "using a zero length password" );
  if( salt == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                     "using null pointer to salt" );
  if(( dklen < 32 ) || ( dklen > 64 )) return ak_error_message( ak_error_wrong_length,
                                       __func__ , "using a wrong length for resulting key vector" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to resulting key vector" );
 /* создаем контекст алгоритма hmac и определяем его ключ */
  if(( error = ak_hmac_create_streebog512( &hctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of hmac-streebog512 key context" );
  if(( error = ak_hmac_set_key( &hctx, pass, pass_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong initialization of hmac-streebog512 secret key" );
    goto lab_exit;
  }

 /* начальная инициализация промежуточного вектора */
  memset( result, 0, 64 );
  result[3] = 1;

 /* вычисляем значение первой строки U1  */
  if(( error = ak_hmac_clean( &hctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect cleaning of internal hmac context");
    goto lab_exit;
  }
  if(( error = ak_hmac_update( &hctx, salt, salt_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect updating of internal hmac context");
    goto lab_exit;
  }
  if(( error = ak_hmac_finalize( &hctx, result, 4, result, sizeof( result ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect finalizing of internal mac context");
    goto lab_exit;
  }
  memcpy( out, result+64-dklen, dklen );

 /* теперь основной цикл по значению аргумента c */
  for( idx = 1; idx < cnt; idx++ ) {
     ak_hmac_ptr( &hctx, result, 64, result, sizeof( result ));
     for( jdx = 0; jdx < dklen; jdx++ ) ((ak_uint8 *)out)[jdx] ^= result[64-dklen+jdx];
  }
  memset( result, 0, 64 );

  lab_exit: ak_hmac_destroy( &hctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                                      /* интерфейс к aead алгоритму */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Очистка контекста перед вычислением имитовставки */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_ctr_hmac_authentication_clean( ak_pointer actx,
                                      ak_pointer akey, const ak_pointer iv, const size_t iv_size )
{
  return ak_hmac_clean( (ak_hmac) akey );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Очистка контекста перед шифрованием */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_ctr_hmac_encryption_clean( ak_pointer ectx,
                                      ak_pointer ekey, const ak_pointer iv, const size_t iv_size )
{
 /* в случае имитозащиты без шифрования ключ шифрования может быть не определен */
  if( ekey != NULL ) return ak_bckey_ctr( ekey, NULL, NULL, 0, iv, iv_size );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обновление контекста в процессе вычисления имитовставки */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_ctr_hmac_authentication_update( ak_pointer actx,
                                  ak_pointer akey, const ak_pointer adata, const size_t adata_size )
{
  return ak_hmac_update(( ak_hmac )akey, adata, adata_size );
}

/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_ctr_hmac_authentication_finalize( ak_pointer actx,
                                  ak_pointer akey, ak_pointer out, const size_t out_size )
{
  return ak_hmac_finalize(( ak_hmac )akey, NULL, 0, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_ctr_hmac_encryption_update( ak_pointer ectx, ak_pointer ekey,
                           ak_pointer akey, const ak_pointer in, ak_pointer out, const size_t size )
{
  int error = ak_hmac_update( ( ak_hmac )akey, in, size );
  if( error != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect updating an internal mac context" );

  if( ekey != NULL ) return ak_bckey_ctr( ekey, in, out, size, NULL, 0 );

  /* в случае имитозащиты без шифрования ключ шифрования может быть не определен */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_ctr_hmac_decryption_update( ak_pointer ectx, ak_pointer ekey,
                           ak_pointer akey, const ak_pointer in, ak_pointer out, const size_t size )
{
  int error = ak_error_ok;

 /* в случае имитозащиты без шифрования ключ шифрования может быть не определен */
  if( ekey != NULL ) {
    if(( error = ak_bckey_ctr( ekey, in, out, size, NULL, 0 )) != ak_error_ok ) {
      return ak_error_message( error, __func__, "incorrect decryption of input data" );
    }
  }
 return ak_hmac_update(( ak_hmac )akey, out, size );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_aead_create_ctr_hmac_cipher_hash( ak_aead ctx, bool_t crf , char *name )
{
   int error = ak_error_ok;

   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   memset( ctx, 0, sizeof( struct aead ));
   if(( error = ak_aead_create_keys( ctx, crf, name )) != ak_error_ok ) {
     if( ctx->ictx != NULL ) free( ctx->ictx );
     return ak_error_message( error, __func__, "incorrect secret keys context creation" );
   }

  /* контекст такой структуры создается внутри ключа алгоритма hmac */
   ctx->ictx = NULL;
 /* теперь контекст двойного алгоритма (шифрование + имитозащита) */
   ctx->tag_size = ((ak_hmac)ctx->authenticationKey)->ctx.data.sctx.hsize; /* размер имитовставки */
   ctx->block_size = ((ak_hmac)ctx->authenticationKey)->mctx.bsize; /* размер блока входных данных */
   ctx->iv_size = ( crf == ak_true ) ? ((ak_bckey)ctx->encryptionKey)->bsize >> 1 : 0; /* размер синхропосылки */
   ctx->auth_clean = ak_ctr_hmac_authentication_clean;
   ctx->auth_update = ak_ctr_hmac_authentication_update;
   ctx->auth_finalize = ak_ctr_hmac_authentication_finalize;
   ctx->enc_clean = ak_ctr_hmac_encryption_clean;
   ctx->enc_update = ak_ctr_hmac_encryption_update;
   ctx->dec_update = ak_ctr_hmac_decryption_update;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_ctr_hmac_magma_streebog256( ak_aead ctx, bool_t crf )
{
 return ak_aead_create_ctr_hmac_cipher_hash( ctx, crf, "ctr-hmac-magma-streebog256" );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_ctr_hmac_magma_streebog512( ak_aead ctx, bool_t crf )
{
 return ak_aead_create_ctr_hmac_cipher_hash( ctx, crf, "ctr-hmac-magma-streebog512" );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_ctr_hmac_kuznechik_streebog256( ak_aead ctx, bool_t crf )
{
 return ak_aead_create_ctr_hmac_cipher_hash( ctx, crf, "ctr-hmac-kuznechik-streebog256" );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_ctr_hmac_kuznechik_streebog512( ak_aead ctx, bool_t crf )
{
 return ak_aead_create_ctr_hmac_cipher_hash( ctx, crf, "ctr-hmac-kuznechik-streebog512" );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_ctr_nmac_magma( ak_aead ctx, bool_t crf )
{
  int error = ak_aead_create_ctr_hmac_cipher_hash( ctx, crf, "ctr-nmac-magma" );
  if( error == ak_error_ok ) ctx->tag_size = 32;
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_ctr_nmac_kuznechik( ak_aead ctx, bool_t crf )
{
  int error = ak_aead_create_ctr_hmac_cipher_hash( ctx, crf, "ctr-nmac-kuznechik" );
  if( error == ak_error_ok ) ctx->tag_size = 32;
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                            функции для тестирования алгоритма hmac                              */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_hmac_streebog( void )
{
  ak_uint8 key[32] = {
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };

  ak_uint8 data[16] = {
   0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00
  };

  ak_uint8 R256[32] = {
   0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
   0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
  };

  ak_uint8 R512[64] = {
   0xa5, 0x9b, 0xab, 0x22, 0xec, 0xae, 0x19, 0xc6, 0x5f, 0xbd, 0xe6, 0xe5, 0xf4, 0xe9, 0xf5, 0xd8,
   0x54, 0x9d, 0x31, 0xf0, 0x37, 0xf9, 0xdf, 0x9b, 0x90, 0x55, 0x00, 0xe1, 0x71, 0x92, 0x3a, 0x77,
   0x3d, 0x5f, 0x15, 0x30, 0xf2, 0xed, 0x7e, 0x96, 0x4c, 0xb2, 0xee, 0xdc, 0x29, 0xe9, 0xad, 0x2f,
   0x3a, 0xfe, 0x93, 0xb2, 0x81, 0x4f, 0x79, 0xf5, 0x00, 0x0f, 0xfc, 0x03, 0x66, 0xc2, 0x51, 0xe6
  };

  ak_uint32 steps;
  struct hmac hkey;
  struct random rnd;
  int error = ak_error_ok;
  bool_t result = ak_true;
  size_t len = 0, offset = 0;
  int audit = ak_log_get_level();
  ak_uint8 out[64], out2[64], buffer[512], *ptr = NULL;

 /* создаем случайные данные */
  ak_random_create_lcg( &rnd );
  ak_random_ptr( &rnd, buffer, sizeof( buffer ));

 /* 1. тестируем HMAC на основе Стрибог 256 */
  if(( error = ak_hmac_create_streebog256( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog256 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_set_key( &hkey, key, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_ptr( &hkey, data, 16, out, sizeof( out ));
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of hmac code" );
    result = ak_false;
    goto lab_exit;
  }
  if(( result = ak_ptr_is_equal_with_log( out, R256, 32 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "wrong test for hmac-streebog256 from R 50.1.113-2016" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                      "the test for hmac-streebog256 from R 50.1.113-2016 is Ok" );

 /* 2. тестируем случайные блуждания для HMAC на основе Стрибог 256 */
  if(( error =
           ak_hmac_ptr( &hkey, buffer, sizeof( buffer ), out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                               "incorrect hmac evaluation for %u random octets", sizeof( buffer ));
    result = ak_false;
    goto lab_exit;
  }

  steps = 0;
  ptr = buffer;
  offset = sizeof( buffer );
  ak_hmac_clean( &hkey );
  do{
      ak_random_ptr( &rnd, &len, sizeof( len )); len = ak_min( len%16, offset );
      if( len > 0 ) {
        if(( error = ak_hmac_update( &hkey, ptr, len )) != ak_error_ok ) {
           ak_error_message( error, __func__, "incorrect updating of hmac context" );
           result = ak_false;
           goto lab_exit;
        }
        ptr += len;
        offset -= len;
        ++steps;
      }
  } while( offset );
  memset( out2, 0, sizeof( out2 ));
  ak_hmac_finalize( &hkey, NULL, 0, out2, sizeof( out2 ));

  if( ak_ptr_is_equal( out, out2, ak_hmac_get_tag_size( &hkey ))) {
    if( audit >= ak_log_maximum )
      ak_error_message_fmt( ak_error_ok, __func__ ,
            "the random walk test for %s with %u steps is Ok", hkey.key.oid->name[0], steps );
  } else {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
         "the random walk test for %s with %u steps is wrong", hkey.key.oid->name[0], steps );
      ak_log_set_message(( ak_ptr_to_hexstr( out, ak_hmac_get_tag_size( &hkey ), ak_false )));
      ak_log_set_message(( ak_ptr_to_hexstr( out2, ak_hmac_get_tag_size( &hkey ), ak_false )));
      result = ak_false;
      goto lab_exit;
    }
  ak_hmac_destroy( &hkey );

 /* 3. тестируем HMAC на основе Стрибог 512 */
  if(( error = ak_hmac_create_streebog512( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog512 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_set_key( &hkey, key, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_ptr( &hkey, data, 16, out, sizeof( out ));
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of hmac code" );
    result = ak_false;
    goto lab_exit;
  }
  if(( result = ak_ptr_is_equal_with_log( out, R512, 64 )) != ak_true ) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                          "wrong test for hmac-streebog512 from R 50.1.113-2016" );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                      "the test for hmac-streebog512 from R 50.1.113-2016 is Ok" );

 /* 4. тестируем случайные блуждания для HMAC на основе Стрибог 512 */
  if(( error =
           ak_hmac_ptr( &hkey, buffer, sizeof( buffer ), out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                               "incorrect hmac evaluation for %u random octets", sizeof( buffer ));
    result = ak_false;
    goto lab_exit;
  }

  steps = 0;
  ptr = buffer;
  offset = sizeof( buffer );
  ak_hmac_clean( &hkey );
  do{
      ak_random_ptr( &rnd, &len, sizeof( len )); len = ak_min( len%16, offset );
      if( len > 0 ) {
        if(( error = ak_hmac_update( &hkey, ptr, len )) != ak_error_ok ) {
           ak_error_message( error, __func__, "incorrect updating of hmac context" );
           result = ak_false;
           goto lab_exit;
        }
        ptr += len;
        offset -= len;
        ++steps;
      }
  } while( offset );
  memset( out2, 0, sizeof( out2 ));
  ak_hmac_finalize( &hkey, NULL, 0, out2, sizeof( out2 ));

  if( ak_ptr_is_equal( out, out2, ak_hmac_get_tag_size( &hkey ))) {
    if( audit >= ak_log_maximum )
      ak_error_message_fmt( ak_error_ok, __func__ ,
            "the random walk test for %s with %u steps is Ok", hkey.key.oid->name[0], steps );
  } else {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
         "the random walk test for %s with %u steps is wrong", hkey.key.oid->name[0], steps );
      ak_log_set_message(( ak_ptr_to_hexstr( out, ak_hmac_get_tag_size( &hkey ), ak_false )));
      ak_log_set_message(( ak_ptr_to_hexstr( out2, ak_hmac_get_tag_size( &hkey ), ak_false )));
      result = ak_false;
      goto lab_exit;
    }

 lab_exit:
  ak_hmac_destroy( &hkey );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_pbkdf2( void )
{
  ak_uint8 R1[64] = {
   0x64, 0x77, 0x0a, 0xf7, 0xf7, 0x48, 0xc3, 0xb1, 0xc9, 0xac, 0x83, 0x1d, 0xbc, 0xfd, 0x85, 0xc2,
   0x61, 0x11, 0xb3, 0x0a, 0x8a, 0x65, 0x7d, 0xdc, 0x30, 0x56, 0xb8, 0x0c, 0xa7, 0x3e, 0x04, 0x0d,
   0x28, 0x54, 0xfd, 0x36, 0x81, 0x1f, 0x6d, 0x82, 0x5c, 0xc4, 0xab, 0x66, 0xec, 0x0a, 0x68, 0xa4,
   0x90, 0xa9, 0xe5, 0xcf, 0x51, 0x56, 0xb3, 0xa2, 0xb7, 0xee, 0xcd, 0xdb, 0xf9, 0xa1, 0x6b, 0x47
  };

  ak_uint8 R2[64] = {
   0x5a, 0x58, 0x5b, 0xaf, 0xdf, 0xbb, 0x6e, 0x88, 0x30, 0xd6, 0xd6, 0x8a, 0xa3, 0xb4, 0x3a, 0xc0,
   0x0d, 0x2e, 0x4a, 0xeb, 0xce, 0x01, 0xc9, 0xb3, 0x1c, 0x2c, 0xae, 0xd5, 0x6f, 0x02, 0x36, 0xd4,
   0xd3, 0x4b, 0x2b, 0x8f, 0xbd, 0x2c, 0x4e, 0x89, 0xd5, 0x4d, 0x46, 0xf5, 0x0e, 0x47, 0xd4, 0x5b,
   0xba, 0xc3, 0x01, 0x57, 0x17, 0x43, 0x11, 0x9e, 0x8d, 0x3c, 0x42, 0xba, 0x66, 0xd3, 0x48, 0xde
  };

  ak_uint8 R3[64] = {
   0xe5, 0x2d, 0xeb, 0x9a, 0x2d, 0x2a, 0xaf, 0xf4, 0xe2, 0xac, 0x9d, 0x47, 0xa4, 0x1f, 0x34, 0xc2,
   0x03, 0x76, 0x59, 0x1c, 0x67, 0x80, 0x7f, 0x04, 0x77, 0xe3, 0x25, 0x49, 0xdc, 0x34, 0x1b, 0xc7,
   0x86, 0x7c, 0x09, 0x84, 0x1b, 0x6d, 0x58, 0xe2, 0x9d, 0x03, 0x47, 0xc9, 0x96, 0x30, 0x1d, 0x55,
   0xdf, 0x0d, 0x34, 0xe4, 0x7c, 0xf6, 0x8f, 0x4e, 0x3c, 0x2c, 0xda, 0xf1, 0xd9, 0xab, 0x86, 0xc3
  };

  ak_uint8 R4[64] = {
   0x50, 0xdf, 0x06, 0x28, 0x85, 0xb6, 0x98, 0x01, 0xa3, 0xc1, 0x02, 0x48, 0xeb, 0x0a, 0x27, 0xab,
   0x6e, 0x52, 0x2f, 0xfe, 0xb2, 0x0c, 0x99, 0x1c, 0x66, 0x0f, 0x00, 0x14, 0x75, 0xd7, 0x3a, 0x4e,
   0x16, 0x7f, 0x78, 0x2c, 0x18, 0xe9, 0x7e, 0x92, 0x97, 0x6d, 0x9c, 0x1d, 0x97, 0x08, 0x31, 0xea,
   0x78, 0xcc, 0xb8, 0x79, 0xf6, 0x70, 0x68, 0xcd, 0xac, 0x19, 0x10, 0x74, 0x08, 0x44, 0xe8, 0x30
  };

  ak_uint8 password_one[8] = "password",
           password_two[9] = { 'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd' },
           salt_one[4]     = "salt",
           salt_two[5]     = { 's', 'a', 0, 'l', 't' };

  ak_uint8 out[64];
  int error = ak_error_ok;
  int audit = ak_log_get_level();

 /* первый тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_pbkdf2_streebog512( password_one, 8,
                                                     salt_one, 4, 1, 64, out )) != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal_with_log( out, R1, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 1st test for pbkdf2 from R 50.1.111-2016" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 1st test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* второй тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_pbkdf2_streebog512( password_one, 8,
                                                     salt_one, 4, 2, 64, out )) != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal_with_log( out, R2, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 2nd test for pbkdf2 from R 50.1.111-2016" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 2nd test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* третий тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_pbkdf2_streebog512( password_one, 8,
                                                  salt_one, 4, 4096, 64, out )) != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal_with_log( out, R3, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 3rd test for pbkdf2 from R 50.1.111-2016" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 3rd test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* четвертый тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_pbkdf2_streebog512( password_two, 9,
                                                  salt_two, 5, 4096, 64, out )) != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal_with_log( out, R4, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 4th test for pbkdf2 from R 50.1.111-2016" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 4th test for pbkdf2 from R 50.1.111-2016 is Ok" );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hmac.c  */
/* ----------------------------------------------------------------------------------------------- */
