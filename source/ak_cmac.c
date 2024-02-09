/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020, 2022 by Axel Kenzo, axelkenzo@mail.ru                               */
/*                                                                                                 */
/*  Файл ak_cmac.c                                                                                 */
/*  - содержит реализацию общих функций для алгоритмов блочного шифрования.                        */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>
 #ifdef AK_HAVE_ERRNO_H
  #include <errno.h>
 #endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданной области памяти фиксированного размера.
   Используется алгоритм, который также называют OMAC1
   или [CMAC](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf).

   Для данных нулевой длины также вычисляется значение имитовставки.
   Формально следуя рекомендациям ГОСТ Р 34.13-2015, мы определяем значение имитовставки
   значением `Enc( K, K2 )`, где `K2` дополнительный ключ, накладываемый на последний неполный блок.

   @param bkey Ключ алгоритма блочного шифрования, используемый для выработки имитовставки.
   Ключ должен быть создан и определен.
   @param in Указатель на входные данные для которых вычисляется имитовставка.
   @param size Размер входных данных в байтах.
   @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
   Размер выделяемой памяти должен совпадать с длиной блока используемого алгоритма
   блочного шифрования.
   @param out_size Ожидаемый размер имитовставки.

   @return В случае возникновения ошибки функция возвращает ее код, в противном случае
   возвращается \ref ak_error_ok (ноль)                                                            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_cmac( ak_bckey bkey, ak_pointer in,
                                          const size_t size, ak_pointer out, const size_t out_size )
{
  ak_int64 i = 0, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" ),
        #ifdef AK_LITTLE_ENDIAN
           one64[2] = { 0x02, 0x00 },
        #else
           one64[2] = { 0x0200000000000000LL, 0x00 },
        #endif
           blocks = (ak_int64)size/bkey->bsize,
           tail = (ak_int64)size%bkey->bsize;
 ak_uint64 yaout[2], akey[2], *inptr = (ak_uint64 *)in;

 /* мы разрешаем вычисление имитовставки от данных нулевой длины
  if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                              "using a data with zero length" ); */

  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to result buffer" );
  if( !out_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using zero length of result buffer" );
 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                  "incorrect integrity code of secret key value" );

 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.value.counter < ak_max( 1, ( blocks + ( tail > 0 ))))
    return ak_error_message( ak_error_low_key_resource, __func__ ,
                                                              "low resource of block cipher key" );
   else /* уменьшаем ресурс ключа */
     bkey->key.resource.value.counter -= ak_max( 1, ( blocks + ( tail > 0 )));

  memset( akey, 0, sizeof( akey ));
  memset( yaout, 0, sizeof( yaout ));
 /* последний блок всегда существует, за исключением случая, когда входные данные равны нулю */
  if(( tail == 0 ) && ( blocks > 0 )) { tail = bkey->bsize; blocks--; }

 /* основной цикл */
  switch( bkey->bsize ) {
   case  8 :
          /* здесь длина блока равна 64 бита */
            for( i = 0; i < blocks; i++, inptr++ ) {
               yaout[0] ^= inptr[0];
               bkey->encrypt( &bkey->key, yaout, yaout );
            }

          /* теперь ключи для завершения алгоритма */
            bkey->encrypt( &bkey->key, akey, akey );
            if( oc ) akey[0] = bswap_64( akey[0] );
            ak_gf64_mul( akey, akey, one64 );

            if( tail < (ak_int64) bkey->bsize ) {
              ak_gf64_mul( akey, akey, one64 );
              ((ak_uint8 *)akey)[tail] ^= 0x80;
            }

          /* теперь шифруем последний блок */
            if( oc ) {
              ak_int64 xlen = (8 - tail) << 3;
              yaout[0] ^= bswap_64( akey[0] );
             /* мы заменяем цикл
                    for( i = 0; i < tail; i++ ) ((ak_uint8 *)yaout)[7-i] ^= ((ak_uint8 *)inptr)[tail-1-i];
                на двоичный сдвиг */
              yaout[0] ^= (((*inptr) >> xlen) << xlen );
            }
              else {
               yaout[0] ^= akey[0];
               for( i = 0; i < tail; i++ ) ((ak_uint8 *)yaout)[i] ^= ((ak_uint8 *)inptr)[i];
              }
            bkey->encrypt( &bkey->key, yaout, akey );
          break;

   case 16 :
          /* здесь длина блока равна 128 бит */
            for( i = 0; i < blocks; i++, inptr += 2 ) {
               yaout[0] ^= inptr[0];
               yaout[1] ^= inptr[1];
               bkey->encrypt( &bkey->key, yaout, yaout );
            }

          /* вырабатываем ключи для завершения алгортма */
            bkey->encrypt( &bkey->key, akey, akey );
            if( oc ) {
              ak_uint64 tmp = bswap_64( akey[0] );
              akey[0] = bswap_64( akey[1] );
              akey[1] = tmp;
            }
            ak_gf128_mul( akey, akey, one64 );
            if( tail < (ak_int64) bkey->bsize ) {
              ak_gf128_mul( akey, akey, one64 );
              ((ak_uint8 *)akey)[tail] ^= 0x80;
            }

          /* теперь шифруем последний блок*/
            if( oc ) {
               yaout[0] ^= bswap_64( akey[1] );
               yaout[1] ^= bswap_64( akey[0] );
               for( i = 0; i < tail; i++ ) ((ak_uint8 *)yaout)[15-i] ^= ((ak_uint8 *)inptr)[tail-1-i];
            }
             else {
              yaout[0] ^= akey[0];
              yaout[1] ^= akey[1];
              for( i = 0; i < tail; i++ ) ((ak_uint8 *)yaout)[i] ^= ((ak_uint8 *)inptr)[i];
             }
            bkey->encrypt( &bkey->key, yaout, akey );
          break;
  }

 /* копируем нужную часть результирующего массива и завершаем работу */
 if( oc ) memcpy( out, (ak_uint8 *)akey, ak_min( out_size, bkey->bsize ));
  else memcpy( out, (ak_uint8 *)akey+( out_size > bkey->bsize ? 0 : bkey->bsize-out_size ),
                                                                  ak_min( out_size, bkey->bsize ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Алгоритм вычисления имитовставки может быть представлен в виде последовательного вызова
    трех функций

    - ak_bckey_cmac_clean()
    - ak_bckey_cmac_update()
    - ak_bckey_cmac_finalize()

    Первая функция очищает внутреннее состояние контекста секретного ключа. Вторая функция
    обновляет внутреннее состояние, используя для этого данные, длина которых кратна длине блока
    используемого алгоритма блочного шифрования. Последняя функция завершает вычисления и
    возвращает результат.

    Подобное представление характерно для всех алгоритмов итерационного сжатия.
    В качестве примеров можно указать функции хеширования, в частности класс \ref hash,
    а также алгоритмы вычисления имитовставки с помощью алгоритмов хеширования, см. класс \ref hmac.

    Последовательный вызов всех трех функций может быть заменен вызовом функции ak_bckey_cmac().

    \param bkey Контекст секретного ключа блочного алгоритма шифрования.
    \return В случае успеха функция возвращает ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_cmac_clean( ak_bckey bkey )
{
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to block cipher key" );
  bkey->ivector_size = 0;
  memset( bkey->ivector, 0, sizeof( bkey->ivector ));

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Алгоритм вычисления имитовставки может быть представлен в виде последовательного вызова
    трех функций

    - ak_bckey_cmac_clean()
    - ak_bckey_cmac_update()
    - ak_bckey_cmac_finalize()

    Первая функция очищает внутреннее состояние контекста секретного ключа. Вторая функция
    обновляет внутреннее состояние, используя для этого данные, длина которых кратна длине блока
    используемого алгоритма блочного шифрования. Последняя функция завершает вычисления и
    возвращает результат.

    Подобное представление характерно для всех алгоритмов итерационного сжатия.
    В качестве примеров можно указать функции хеширования, в частности класс \ref hash,
    а также алгоритмы вычисления имитовставки с помощью алгоритмов хеширования, см. класс \ref hmac.

    Последовательный вызов всех трех функций может быть заменен вызовом функции ak_bckey_cmac().
    Можно привести следующие примеры вычисления имитоставки.

 \code
    ak_uint8 data[37], imito[8];

    ak_bckey_cmac_clean( &key );
    ak_bckey_cmac_update( &key, data, 16 );
    ak_bckey_cmac_update( &key, data +16, 16 );
    ak_bckey_cmac_finalize( &key, data +32, 5, imito, sizeof( imito ));
 \endcode

    или

 \code
    ak_bckey_cmac_clean( &key );
    ak_bckey_cmac_update( &key, data, 37 );
    ak_bckey_cmac_finalize( &key, NULL, 0, imito, sizeof( imito ));
 \endcode

    \param bkey Контекст секретного ключа блочного алгоритма шифрования.
    \param in Указатель на входные данные для которых вычисляется имитовставка.
    \param size Размер входных данных в октетах.
     Если данные планируется обрабатывать несколькими фрагментами, то size должен быть кратен длине блока.
     В противном случае, считается, что фрагмент данных является последним и
     последующие вызовы функции блокируются. При этом, также,
     игнорирубтся данные, подаваемые на вход функции ak_bckey_cmac_finalize().

    \return В случае успеха функция возвращает ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_cmac_update( ak_bckey bkey, const ak_pointer in, const size_t size )
{
  ak_int64 i, blocks = 0, tail = 0;
  ak_uint64 *yaout = NULL, *lastout = NULL, *inptr = (ak_uint64 *)in;

 /* проверяем указатель на ключ и целостность ключа */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to block cipher key" );
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                  "incorrect integrity code of secret key value" );
 /* определяем количество блоков поступившей на вход информации */
  blocks = (ak_int64)size/bkey->bsize;
  tail = size - ( blocks*bkey->bsize );

 /* проверяем ресурс ключа */
  if( bkey->key.resource.value.counter < ( blocks + ( tail > 0 )))
    return ak_error_message( ak_error_low_key_resource, __func__ ,
                                                              "low resource of block cipher key" );
 /* формируем указатели */
  yaout = (ak_uint64 *) bkey->ivector;
  lastout = (ak_uint64 *) bkey->ivector +4; /* сдвигаемся на 4*8 = 32 байта */

 /* проверяем, остались ли данные с предыдущих вызовов */
  if( bkey->ivector_size > 0 ) {
    if( bkey->ivector_size < bkey->bsize ) { /* здесь находится неполный блок,
                            т.е. дальнейшее вычисление имитовставки невозможно */
      return ak_error_message( ak_error_ok, __func__, "attempt to updating the locked context" );
    }
    bkey->key.resource.value.counter--; /* уменьшаем ресурс ключа */
    switch( bkey->bsize ) {
      case  8 :
         /* здесь длина блока равна 64 бита */
          yaout[0] ^= lastout[0];
          bkey->encrypt( &bkey->key, yaout, yaout );
          break;
      case 16 :
         /* здесь длина блока равна 128 бит */
          yaout[0] ^= lastout[0];
          yaout[1] ^= lastout[1];
          bkey->encrypt( &bkey->key, yaout, yaout );
          break;
    }
    bkey->ivector_size = 0;
    memset( lastout, 0, bkey->bsize ); /* это, чтоб наверняка */
  }

 /* основной цикл */
  switch( bkey->bsize ) {
   case  8 :
         /* здесь длина блока равна 64 бита */
            for( i = 0; i < blocks - ( 1 - ( tail > 0 )); i++, inptr++ ) {
               yaout[0] ^= inptr[0];
               bkey->encrypt( &bkey->key, yaout, yaout );
            }
            break;

   case 16 :
          /* здесь длина блока равна 128 бит */
            for( i = 0; i < blocks - ( 1 - ( tail > 0 )); i++, inptr += 2 ) {
               yaout[0] ^= inptr[0];
               yaout[1] ^= inptr[1];
               bkey->encrypt( &bkey->key, yaout, yaout );
            }
            break;
  }
  bkey->key.resource.value.counter -= ( blocks - ( 1 - ( tail > 0 ))); /* уменьшаем ресурс ключа */

 /* поскольку длина bckey->ivector слишком велика,
    мы можем хранить в нем не только текущее значение шифртекста,
    но и фрагмент открытого текста */
  memcpy( lastout, inptr, bkey->ivector_size = ( tail > 0 ? tail : bkey->bsize ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Алгоритм вычисления имитовставки может быть представлен в виде последовательного вызова
    трех функций

    - ak_bckey_cmac_clean()
    - ak_bckey_cmac_update()
    - ak_bckey_cmac_finalize()

    Первая функция очищает внутреннее состояние контекста секретного ключа. Вторая функция
    обновляет внутреннее состояние, используя для этого данные, длина которых кратна длине блока
    используемого алгоритма блочного шифрования. Последняя функция завершает вычисления и
    возвращает результат.

    Подобное представление характерно для всех алгоритмов итерационного сжатия.
    В качестве примеров можно указать функции хеширования, в частности класс \ref hash,
    а также алгоритмы вычисления имитовставки с помощью алгоритмов хеширования, см. класс \ref hmac.

    Последовательный вызов всех трех функций может быть заменен вызовом функции ak_bckey_cmac().
    Можно привести следующие примеры вычисления имитоставки.

 \code
    ak_uint8 data[37], imito[8];

    ak_bckey_cmac_clean( &key );
    ak_bckey_cmac_update( &key, data, 16 );
    ak_bckey_cmac_update( &key, data +16, 16 );
    ak_bckey_cmac_finalize( &key, data +32, 5, imito, sizeof( imito ));
 \endcode

    или

 \code
    ak_bckey_cmac_clean( &key );
    ak_bckey_cmac_update( &key, data, 37 );
    ak_bckey_cmac_finalize( &key, NULL, 0, imito, sizeof( imito ));
 \endcode

    \param bkey Контекст секретного ключа блочного алгоритма шифрования.
    \param in Указатель на входные данные для которых вычисляется имитовставка.
    \param size Размер входных данных в октетах.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен совпадать с длиной блока используемого алгоритма
    блочного шифрования.
    \param out_size Ожидаемый размер имитовставки.
    \return В случае успеха функция возвращает ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_cmac_finalize( ak_bckey bkey, const ak_pointer in, const size_t size,
                                                           ak_pointer out, const size_t out_size )
{
  int error = ak_error_ok;
  ak_int64 oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" ),
        #ifdef AK_LITTLE_ENDIAN
           one64[2] = { 0x02, 0x00 };
        #else
           one64[2] = { 0x0200000000000000LL, 0x00 };
        #endif
  ak_uint64 i, *yaout, akey[2], *lastout = NULL;

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to block cipher key" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to result buffer" );
  if( !out_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using zero length of result buffer" );
 /* в начале прогоняем входные данные через update */
  if( bkey->ivector_size%bkey->bsize == 0 ) {
   if(( error = ak_bckey_cmac_update( bkey, in, size )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect updating a secret key context" );
  }

 /* теперь данные перемещены в lastout и должны иметь длину от bkey->bsize до 1 октета */
  memset( akey, 0, sizeof( akey ));
  yaout = (ak_uint64 *) bkey->ivector;
  lastout = (ak_uint64 *) bkey->ivector +4; /* сдвигаемся на 4*8 = 32 байта */

  if( bkey->ivector_size > bkey->bsize )
    return ak_error_message( ak_error_wrong_length, __func__,
                                                        "unxepected length of last block length" );
 /* уменьшаем значение ресурса ключа */
  bkey->key.resource.value.counter--;

 /* основной цикл */
  switch( bkey->bsize ) {
   case  8 :
          /* теперь ключи для завершения алгоритма */
            bkey->encrypt( &bkey->key, akey, akey );
            if( oc ) akey[0] = bswap_64( akey[0] );
            ak_gf64_mul( akey, akey, one64 );

            if( bkey->ivector_size < bkey->bsize ) {
              ak_gf64_mul( akey, akey, one64 );
              ((ak_uint8 *)akey)[bkey->ivector_size] ^= 0x80;
            }

          /* теперь шифруем последний блок */
            if( oc ) {
               yaout[0] ^= bswap_64( akey[0] );
               for( i = 0; i < bkey->ivector_size; i++ ) ((ak_uint8 *)yaout)[7-i] ^= ((ak_uint8 *)lastout)[bkey->ivector_size-1-i];
            }
              else {
               yaout[0] ^= akey[0];
               for( i = 0; i < bkey->ivector_size; i++ ) ((ak_uint8 *)yaout)[i] ^= ((ak_uint8 *)lastout)[i];
              }
            bkey->encrypt( &bkey->key, yaout, akey );
          break;

   case 16 :
          /* вырабатываем ключи для завершения алгортма */
            bkey->encrypt( &bkey->key, akey, akey );
            if( oc ) {
              ak_uint64 tmp = bswap_64( akey[0] );
              akey[0] = bswap_64( akey[1] );
              akey[1] = tmp;
            }
            ak_gf128_mul( akey, akey, one64 );
            if( bkey->ivector_size < bkey->bsize ) {
              ak_gf128_mul( akey, akey, one64 );
              ((ak_uint8 *)akey)[bkey->ivector_size] ^= 0x80;
            }

          /* теперь шифруем последний блок*/
            if( oc ) {
               yaout[0] ^= bswap_64( akey[1] );
               yaout[1] ^= bswap_64( akey[0] );
               for( i = 0; i < bkey->ivector_size; i++ ) ((ak_uint8 *)yaout)[15-i] ^= ((ak_uint8 *)lastout)[bkey->ivector_size-1-i];
            }
             else {
              yaout[0] ^= akey[0];
              yaout[1] ^= akey[1];
              for( i = 0; i < bkey->ivector_size; i++ ) ((ak_uint8 *)yaout)[i] ^= ((ak_uint8 *)lastout)[i];
             }
            bkey->encrypt( &bkey->key, yaout, akey );
          break;
  }

 /* копируем нужную часть результирующего массива и завершаем работу */
 if( oc ) memcpy( out, (ak_uint8 *)akey, ak_min( out_size, bkey->bsize ));
  else memcpy( out, (ak_uint8 *)akey+( out_size > bkey->bsize ? 0 : bkey->bsize-out_size ),
                                                                  ak_min( out_size, bkey->bsize ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \note Реализация данной функции не использует методы класса \ref mac, поскольку
    функция ak_bckey_cmac_finalize() не может принимать данные нелевой длины.

    @param key Контекст ключа алгоритма блочного шифрования.
    @param filename Имя файла, для котрого вычисляется хеш-код.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля key.bsize.
    @param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_cmac_file( ak_bckey key, const char *filename, ak_pointer out, const size_t out_size )
{
  struct file file;
  int error = ak_error_ok;
  size_t block_size = 4096; /* оптимальная длина блока для Windows, по-прежнему, не ясна */
  ak_int64 len = 0, readlen = 0;
  ak_uint8 *localbuffer = NULL; /* место для локального считывания информации */

 /* выполняем необходимые проверки */
  if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "use a null pointer to block cipher key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                "use a null pointer to filename" );
  if(( error = ak_file_open_to_read( &file, filename )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__, "incorrect access to file %s (%s)",
                                                                      filename, strerror( errno ));
 /* для файла нулевой длины результатом будет хеш от вектора нулевой длины,
                                 см. замечания к реализации ak_bckey_cmac() */
  if( !file.size ) {
    ak_file_close( &file );
    return ak_bckey_cmac( key, NULL, 0, out, out_size );
  }
 /* готовим область для хранения данных */
  block_size = ak_max( ( size_t )file.blksize, 512 );
 /* здесь мы выделяем локальный буффер для считывания/обработки данных */
  if(( localbuffer = ( ak_uint8 * ) ak_aligned_malloc( block_size )) == NULL ) {
    ak_file_close( &file );
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                      "memory allocation error for local buffer" );
  }

 /* теперь обрабатываем файл с данными */
  ak_bckey_cmac_clean( key );
  read_label:
   readlen += ( len = ( size_t ) ak_file_read( &file, localbuffer, block_size ));
   if( readlen == file.size ) { /* считан последний большой блок */
     size_t qcnt = len / key->bsize,
            tail = len - qcnt*key->bsize;
     if( tail == 0 ) {
       if( qcnt > 0 ) { qcnt--; tail = key->bsize; }
         else {
           error = ak_error_message( ak_error_read_data, __func__,
                                                           "unexpected length of input data");
           goto labex;
         }
     }
     if( qcnt ) ak_bckey_cmac_update( key, localbuffer, qcnt*key->bsize );
     error = ak_bckey_cmac_finalize(key, localbuffer + qcnt*key->bsize, tail, out, out_size );
   }
    else {
           ak_bckey_cmac_update( key, localbuffer, len );
           goto read_label;
         }
  labex:
   if( localbuffer != NULL ) ak_aligned_free( localbuffer );
   ak_file_close( &file );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует последовательную комбинацию режимов из ГОСТ Р 34.12-2015. В начале
    вычисляется имитовставка от объединения ассоциированных данных и
    данных, подлежащих зашифрования. При этом предполагается, что ассоциированные данные
    расположены вначале. После этого, данные зашифровываются.

    Режим `ctr-cmac` \b должен использовать для шифрования и выработки имитовставки два
    различных ключа, при этом длины блоков обрабатываемых данных для ключей должны совпадать
    (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если указатель на ключ шифрования равен `NULL`, то шифрование данных не производится и указатель на
    зашифровываемые (plain data) и зашифрованные (cipher data) данные \b должен быть равен `NULL`;
    длина данных (size) также \b должна принимать нулевое значение.
    В этом случае результат работы функции должен быть эквивалентен результату работы
    функции ak_bckey_cmac().

    Если указатель на ключ выработки имитовставки равен `NULL`, то аутентификация данных не производится.
    Вsw этом случае указатель на ассоциированные данные (associated data) \b должен быть равен `NULL`,
    указатель на имитовставку (icode) \b должен быть равен `NULL`, длина дополнительных данных \b должна
    равняться нулю.
    В этом случае результат работы функции должен быть эквивалентен результату работы
    функции ak_bckey_ctr().

    Ситуация, при которой оба указателя на ключ принимают значение `NULL` воспринимается как ошибка.

    \note В настоящий момент использована наиболее простая реализация алгоритма,
    предполагающая что ассоциированные данные и шифруемые данные находятся в памяти последовательно.
    Если это допущение невыполнено, то результат работы функции может быть непредсказуемым.

    @param encryptionKey ключ шифрования (указатель на struct bckey), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки)
           (указатель на struct bckey), должен быть инициализирован
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
 int ak_bckey_encrypt_ctr_cmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  size_t sizeptr = 0;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                "using null pointers both to encryption and authentication keys" );
  if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
      return ak_error_message( ak_error_wrong_length, __func__,
                                                           "different block sizes for given keys");
  }
  if(( adata != NULL ) && ( adata_size != 0 )) {
    /* проверяем, что данные расположены в памяти последовательно */
     if( in != NULL ) {
       if( ((ak_uint8*)adata)+adata_size != (ak_uint8 *)in ) {
         return ak_error_message( ak_error_linked_data, __func__,
                                          "this function can't be applied to non sequenced data" );
       }
     }
     ptr = adata;
     sizeptr = adata_size + size;
  } else {
      ptr = in;
      sizeptr = size;
    }

  if( authenticationKey != NULL ) {
    if(( error =
             ak_bckey_cmac( authenticationKey, ptr, sizeptr, icode, icode_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect data encryption" );
  }

 /* шифруем только в том случае, когда определен ключ шифрования */
  if( encryptionKey != NULL ) {
    if(( error = ak_bckey_ctr( encryptionKey, in, out, size, iv, iv_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect data encryption" );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных. Требования к передаваемым параметрам
    аналогичны требованиям, предъявляемым к параметрам функции ak_bckey_encrypt_ctr_cmac().

    @param encryptionKey ключ шифрования (указатель на struct bckey), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки)
           (указатель на struct bckey), должен быть инициализирован
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
 int ak_bckey_decrypt_ctr_cmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  size_t sizeptr = 0;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                "using null pointers both to encryption and authentication keys" );
  if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
    if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
      return ak_error_message( ak_error_wrong_length, __func__,
                                                           "different block sizes for given keys");
  }
  if(( adata != NULL ) && ( adata_size != 0 )) {
    /* проверяем, что данные расположены в памяти последовательно */
     if( in != NULL ) {
       if( ((ak_uint8*)adata)+adata_size != (ak_uint8 *)in ) {
         return ak_error_message( ak_error_linked_data, __func__,
                                          "this function can't be applied to non sequenced data" );
       }
     }
     ptr = adata;
     sizeptr = adata_size + size;
  } else {
      ptr = in;
      sizeptr = size;
    }

 /* расшифровываем только в том случае, когда определен ключ шифрования */
  if( encryptionKey != NULL ) {
    if(( error = ak_bckey_ctr( encryptionKey, in, out, size, iv, iv_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect data decryption" );
  }

  if( authenticationKey != NULL ) {
    ak_uint8 icode2[32];
    memset( icode2, 0, sizeof( icode2 ));

    if( ((ak_bckey)authenticationKey)->bsize > icode_size )
      return ak_error_message( ak_error_wrong_length, __func__,
                                                "using block cipher with very huge block length" );
    if(( error =
             ak_bckey_cmac( authenticationKey, ptr, sizeptr, icode2, icode_size )) != ak_error_ok )
      return ak_error_message( error, __func__,
                                             "incorrect calculation of data authentication code" );
     if( ak_ptr_is_equal( icode, icode2, icode_size )) error = ak_error_ok;
       else error = ak_error_not_equal_data;
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                                      /* интерфейс к aead алгоритму */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Очистка контекста перед вычислением имитовставки */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_ctr_cmac_authentication_clean( ak_pointer actx,
                                      ak_pointer akey, const ak_pointer iv, const size_t iv_size )
{
  ak_mac ctx = actx;
  ak_bckey authenticationKey = akey;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to internal mac context");
  if( authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                       "using null pointer to authentication key");
  if( authenticationKey->bsize > 16 ) return ak_error_message( ak_error_wrong_length,
                                                __func__, "using key with very large block size" );
  return ak_mac_clean( ctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Очистка контекста перед шифрованием */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_ctr_cmac_encryption_clean( ak_pointer ectx,
                                      ak_pointer ekey, const ak_pointer iv, const size_t iv_size )
{
  if( ectx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to internal mac context");
  if( ekey != NULL ) return ak_bckey_ctr( ekey, NULL, NULL, 0, iv, iv_size );

  /* в случае имитозащиты без шифрования ключ шифрования может быть не определен */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обновление контекста в процессе вычисления имитовставки */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_ctr_cmac_authentication_update( ak_pointer actx,
                                  ak_pointer akey, const ak_pointer adata, const size_t adata_size )
{
  return ak_mac_update(( ak_mac )actx, adata, adata_size );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_ctr_cmac_authentication_finalize( ak_pointer actx,
                                  ak_pointer akey, ak_pointer out, const size_t out_size )
{
  return ak_mac_finalize(( ak_mac )actx, NULL, 0, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_ctr_cmac_encryption_update( ak_pointer ectx, ak_pointer ekey,
                           ak_pointer akey, const ak_pointer in, ak_pointer out, const size_t size )
{
  int error = ak_mac_update( ( ak_mac )ectx, in, size );
  if( error != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect updating an internal mac context" );

  if( ekey != NULL ) return ak_bckey_ctr( ekey, in, out, size, NULL, 0 );

  /* в случае имитозащиты без шифрования ключ шифрования может быть не определен */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_ctr_cmac_decryption_update( ak_pointer ectx, ak_pointer ekey,
                           ak_pointer akey, const ak_pointer in, ak_pointer out, const size_t size )
{
  int error = ak_error_ok;

 /* в случае имитозащиты без шифрования ключ шифрования может быть не определен */
  if( ekey != NULL ) {
    if(( error = ak_bckey_ctr( ekey, in, out, size, NULL, 0 )) != ak_error_ok ) {
      return ak_error_message( error, __func__, "incorrect decryption of input data" );
    }
  }
 return ak_mac_update(( ak_mac )ectx, out, size );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_ctr_cmac_magma( ak_aead ctx, bool_t crf )
{
   ak_mac mctx = NULL;
   int error = ak_error_ok;

   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   memset( ctx, 0, sizeof( struct aead ));
   if(( ctx->ictx = ( mctx = malloc( sizeof( struct mac )))) == NULL )
     return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   if(( error = ak_aead_create_keys( ctx, crf, "ctr-cmac-magma" )) != ak_error_ok ) {
     if( ctx->ictx != NULL ) free( ctx->ictx );
     return ak_error_message( error, __func__, "incorrect secret keys context creation" );
   }

  /* устанавливаем поля структуры mac,
     которая будет использована исключительно для вычисления имитовставки */
   if(( error = ak_mac_create( mctx, 8, ctx->authenticationKey,
                              (ak_function_clean *)ak_bckey_cmac_clean,
                              (ak_function_update *)ak_bckey_cmac_update,
                              (ak_function_finalize *)ak_bckey_cmac_finalize )) != ak_error_ok ) {
     ak_mac_destroy( mctx );
     ak_aead_destroy( ctx );
     return ak_error_message( error, __func__, "incorrect creation of mac context" );
   }

 /* теперь контекст двойного алгоритма (шифрование + имитозащита) */
   ctx->tag_size = ctx->block_size = 8; /* длина блока алгоритма Магма */
   ctx->iv_size = 4;
   ctx->auth_clean = ak_ctr_cmac_authentication_clean;
   ctx->auth_update = ak_ctr_cmac_authentication_update;
   ctx->auth_finalize = ak_ctr_cmac_authentication_finalize;
   ctx->enc_clean = ak_ctr_cmac_encryption_clean;
   ctx->enc_update = ak_ctr_cmac_encryption_update;
   ctx->dec_update = ak_ctr_cmac_decryption_update;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_aead_create_ctr_cmac_kuznechik( ak_aead ctx, bool_t crf )
{
   ak_mac mctx = NULL;
   int error = ak_error_ok;

   if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to aead context" );
   memset( ctx, 0, sizeof( struct aead ));
   if(( ctx->ictx = ( mctx = malloc( sizeof( struct mac )))) == NULL )
     return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   if(( error = ak_aead_create_keys( ctx, crf, "ctr-cmac-kuznechik" )) != ak_error_ok ) {
     if( ctx->ictx != NULL ) free( ctx->ictx );
     return ak_error_message( error, __func__, "incorrect secret keys context creation" );
   }

  /* устанавливаем поля структуры mac,
     которая будет использована исключительно для вычисления имитовставки */
   if(( error = ak_mac_create( mctx, 16, ctx->authenticationKey,
                              (ak_function_clean *)ak_bckey_cmac_clean,
                              (ak_function_update *)ak_bckey_cmac_update,
                              (ak_function_finalize *)ak_bckey_cmac_finalize )) != ak_error_ok ) {
     ak_mac_destroy( mctx );
     ak_aead_destroy( ctx );
     return ak_error_message( error, __func__, "incorrect creation of mac context" );
   }

 /* теперь контекст двойного алгоритма (шифрование + имитозащита) */
   ctx->tag_size = ctx->block_size = 16; /* длина блока алгоритма Магма */
   ctx->iv_size = 8;
   ctx->auth_clean = ak_ctr_cmac_authentication_clean;
   ctx->auth_update = ak_ctr_cmac_authentication_update;
   ctx->auth_finalize = ak_ctr_cmac_authentication_finalize;
   ctx->enc_clean = ak_ctr_cmac_encryption_clean;
   ctx->enc_update = ak_ctr_cmac_encryption_update;
   ctx->dec_update = ak_ctr_cmac_decryption_update;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                               /* Функции тестирования реализаций */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_cmac( void )
{
  ak_uint8 data[128] =
  { 0xdd, 0x80, 0x65, 0x59, 0xf2, 0xa6, 0x45, 0x07, 0x05, 0x76, 0x74, 0x36, 0xcc, 0x74, 0x4d, 0x23,
    0xa2, 0x42, 0x2a, 0x08, 0xa4, 0x60, 0xd3, 0x15, 0x4b, 0x7c, 0xe0, 0x91, 0x92, 0x67, 0x69, 0x01,
    0x71, 0x4e, 0xb8, 0x8d, 0x75, 0x85, 0xc4, 0xfc, 0x2f, 0x6a, 0x76, 0x43, 0x2e, 0x45, 0xd0, 0x16,
    0xeb, 0xcb, 0x2f, 0x81, 0xc0, 0x65, 0x7c, 0x1f, 0xb1, 0x08, 0x5b, 0xda, 0x1e, 0xca, 0xda, 0xe9,
    0xdd, 0x80, 0x65, 0x59, 0xf2, 0xa6, 0x45, 0x07, 0x05, 0x76, 0x74, 0x36, 0xcc, 0x74, 0x4d, 0x23,
    0xa2, 0x42, 0x2a, 0x08, 0xa4, 0x60, 0xd3, 0x15, 0x4b, 0x7c, 0xe0, 0x91, 0x92, 0x67, 0x69, 0x01,
    0x71, 0x4e, 0xb8, 0x8d, 0x75, 0x85, 0xc4, 0xfc, 0x2f, 0x6a, 0x76, 0x43, 0x2e, 0x45, 0xd0, 0x16,
    0xeb, 0xcb, 0x2f, 0x81, 0xc0, 0x65, 0x7c, 0x1f, 0xb1, 0x08, 0x5b, 0xda, 0x1e, 0xca, 0xda, 0xe7 };

  struct bckey key;
  int error = ak_error_ok;
  bool_t result = ak_true;
  size_t i, blocks;
  ak_uint8 out1[16], out2[16]; /* два значения имитовставки, которые будут сравниваться */

 /* тестируем Магму */
 /* создаем ключ и присваиваем ему какое-то значение */
  if(( error = ak_bckey_create_magma( &key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of secret key" );
    return ak_false;
  }
  ak_bckey_set_key( &key, data, 32 );

 /* основной цикл сравнений */
  blocks = ( sizeof( data )/ key.bsize ) - 1;
  while( blocks > 1 ) {
    for( i = 1; i <= key.bsize; i++ ) {
       ak_bckey_cmac( &key, data, blocks*key.bsize + i, out1, key.bsize );

       ak_bckey_cmac_clean( &key );
       ak_bckey_cmac_update( &key, data, blocks*key.bsize );
       ak_bckey_cmac_finalize( &key, data + blocks*key.bsize, i, out2, key.bsize );
       if( ak_ptr_is_equal_with_log( out1, out2, key.bsize ) != ak_true ) {
         ak_error_message_fmt( ak_error_not_equal_data, __func__,
                            "different values of authentication codes (blocks: %u, offset %u)",
                                                          (unsigned int) blocks, (unsigned int)i );
         result = ak_false;
         goto labm;
       }
    }
    blocks--;
  }

  labm: ak_bckey_destroy( &key );
  if( result != ak_true ) {
    ak_error_message( ak_error_ok, __func__,
                           "testing different realization of cmac mode on magma cipher is wrong" );
    return result;
  }
  if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__,
                              "testing different realization of cmac mode on magma cipher is Ok" );

 /* тестируем Кузнечик */
 /* создаем ключ и присваиваем ему какое-то значение */
  if(( error = ak_bckey_create_kuznechik( &key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of secret key" );
    return ak_false;
  }
  ak_bckey_set_key( &key, data, 32 );

 /* основной цикл сравнений */
  blocks = ( sizeof( data )/ key.bsize ) - 1;
  while( blocks > 1 ) {
    for( i = 1; i <= key.bsize; i++ ) {
       ak_bckey_cmac( &key, data, blocks*key.bsize + i, out1, key.bsize );

       ak_bckey_cmac_clean( &key );
       ak_bckey_cmac_update( &key, data, blocks*key.bsize );
       ak_bckey_cmac_finalize( &key, data + blocks*key.bsize, i, out2, key.bsize );
       if( ak_ptr_is_equal_with_log( out1, out2, key.bsize ) != ak_true ) {
         ak_error_message_fmt( ak_error_not_equal_data, __func__,
                            "different values of authentication codes (blocks: %u, offset %u)",
                                                          (unsigned int) blocks, (unsigned int)i );
         result = ak_false;
         goto labk;
       }
    }
    blocks--;
  }
  labk: ak_bckey_destroy( &key );
  if( result != ak_true ) {
    ak_error_message( ak_error_ok, __func__,
                       "testing different realization of cmac mode on kuznechik cipher is wrong" );
    return result;
  }
  if( ak_log_get_level() >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__,
                          "testing different realization of cmac mode on kuznechik cipher is Ok" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_cmac.c  */
/* ----------------------------------------------------------------------------------------------- */

