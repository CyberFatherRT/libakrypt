/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_xts.c                                                                                  */
/*  - содержит реализацию режимов шифрования, построенных по принципу гамма-коммутатор-гамма.      */
/*     подробности смотри в IEEE P 1619,                                                           */
/*     а также в статье https://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

#ifdef AK_HAVE_STDALIGN_H
 #include <stdalign.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует алгоритм двухключевого шифрования, описываемый в стандарте IEEE P 1619.

    \note Для блочных шифров с длиной блока 128 бит реализация полностью соответствует
    указанному стандарту. Для шифров с длиной блока 64 реализация использует преобразования,
    в частности вычисления к конечном поле \f$ \mathbb F_{2^{128}}\f$,
    определенные для 128 битных шифров.

    @param encryptionKey Ключ, используемый для шифрования информации
    @param authenticationKey Ключ, используемый для преобразования синхропосылки и выработки
    псевдослучайной последовательности
    @param in Указатель на область памяти, где хранятся входные (открытые) данные
    @param out Указатель на область памяти, куда будут помещены зашифровываемые данные
    @param size Размер входных данных (в октетах)
    @param iv Указатель на область памяти, где находится синхропосылка (произвольные данные).
    @param iv_size Размер синхропосылки в октетах, должен быть отличен от нуля.
    Если размер синхропосылки превышает 16 октетов (128 бит), то оставшиеся значения не используются.

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_xts( ak_bckey encryptionKey,  ak_bckey authenticationKey,
                        ak_pointer in, ak_pointer out, size_t size, ak_pointer iv, size_t iv_size )
{
  int error = ak_error_ok;
  ak_int64 jcnt = 0, blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
#ifdef AK_HAVE_STDALIGN_H
 #ifndef AK_HAVE_WINDOWS_H
  alignas(16)
 #endif
#endif
  ak_uint64 tweak[2], t[2], *tptr = t;

 /* проверяем целостность ключа */
  if( encryptionKey->key.check_icode( &encryptionKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                               "incorrect integrity code of encryption key value" );
  if( authenticationKey->key.check_icode( &authenticationKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                           "incorrect integrity code of authentication key value" );

 /* проверяем ресурс ключа аутентификации */
  if( authenticationKey->key.resource.value.counter < (ssize_t)( authenticationKey->bsize >> 3 ))
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of authentication cipher key" );
   else authenticationKey->key.resource.value.counter -= ( authenticationKey->bsize >> 3 );

 /* вырабатываем начальное состояние вектора */
  memset( tweak, 0, sizeof( tweak ));
  memcpy( tweak, iv, ak_min( iv_size, sizeof( tweak )));

  if( authenticationKey->bsize == 8 ) {
    authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );
    tweak[1] ^= tweak[0];
    authenticationKey->encrypt( &authenticationKey->key, tweak+1, tweak+1 );
  } else
      authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );

 /* вычисляем количество блоков */
  blocks = ( ak_int64 )( size/encryptionKey->bsize );
  if( size != blocks*encryptionKey->bsize )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* изменяем ресурс ключа */
  if( encryptionKey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of encryption cipher key" );
   else encryptionKey->key.resource.value.counter -= blocks;

 /* запускаем основной цикл обработки блоков информации */
   switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          *tptr = *inptr^*(tweak+jcnt); inptr++;
          encryptionKey->encrypt( &encryptionKey->key, tptr, tptr );
          *outptr = *tptr ^ *(tweak+jcnt); outptr++;
          --blocks;
          tptr++;

          if( !(jcnt = 1 - jcnt)) { /* изменяем значение tweak */
            tptr = t;
            t[0] = tweak[0] >> 63; t[1] = tweak[1] >> 63;
            tweak[0] <<= 1; tweak[1] <<= 1;
            tweak[1] ^= t[0];
            if( t[1] ) tweak[0] ^= 0x87;
          }
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
         /* шифруем */
          t[0] = *inptr^*tweak; inptr++;
          t[1] = *inptr^*(tweak+1); inptr++;

          encryptionKey->encrypt( &encryptionKey->key, t, t );
          *outptr = t[0]^*tweak; outptr++;
          *outptr = t[1]^*(tweak+1); outptr++;
          --blocks;

         /* изменяем значение tweak */
          t[0] = tweak[0] >> 63;
          t[1] = tweak[1] >> 63;
          tweak[0] <<= 1;
          tweak[1] <<= 1;
          tweak[1] ^= t[0];
          if( t[1] ) tweak[0] ^= 0x87;
       }
       break;
   }

 /* очищаем */
  if(( error = ak_ptr_wipe( tweak, sizeof( tweak ), &encryptionKey->key.generator )) != ak_error_ok )
   ak_error_message( error, __func__ , "wrong wiping of tweak value" );

 /* перемаскируем ключ */
  if(( error = encryptionKey->key.set_mask( &encryptionKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of encryption key" );
  if(( error = authenticationKey->key.set_mask( &authenticationKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of authentication key" );

  return error;
}

/* нижеследующий фрагмент выглядит более современно,
   но дает скорость на 0.5 МБ в секунду медленнее.
   возможно, я что-то делаю совсем не так....

   #include <immintrin.h>

   _m128i gamma = _mm_set_epi64x( tweak[1], tweak[0] );
   _m128i data = _mm_set_epi64x( *(inptr+1), *inptr ); inptr += 2;

         data = _mm_xor_si128( data, gamma );
         encryptionKey->encrypt( &encryptionKey->key, &data, &data );
         data = _mm_xor_si128( data, gamma );
         *outptr = _mm_extract_epi64( data, 0 ); outptr++;
         *outptr = _mm_extract_epi64( data, 1 ); outptr++;
         --blocks;                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует обратное преобразование к алгоритму, реализуемому с помощью
    функции ak_bckey_encrypt_xts().

    @param encryptionKey Ключ, используемый для шифрования информации
    @param authenticationKey Ключ, используемый для преобразования синхропосылки и выработки
    псевдослучайной последовательности
    @param in Указатель на область памяти, где хранятся входные (зашифрованные) данные
    @param out Указатель на область памяти, куда будут помещены расшифрованные данные
    @param size Размер входных данных (в октетах)
    @param iv Указатель на область памяти, где находится синхропосылка (произвольные данные).
    @param iv_size Размер синхропосылки в октетах, должен быть отличен от нуля.
    Если размер синхропосылки превышает 16 октетов (128 бит), то оставшиеся значения не используются.

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_xts( ak_bckey encryptionKey,  ak_bckey authenticationKey,
                        ak_pointer in, ak_pointer out, size_t size, ak_pointer iv, size_t iv_size )
{
  int error = ak_error_ok;
  ak_int64 jcnt = 0, blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
#ifdef AK_HAVE_STDALIGN_H
 #ifndef AK_HAVE_WINDOWS_H
  alignas(16)
 #endif
#endif
  ak_uint64 tweak[2], t[2], *tptr = t;

 /* проверяем целостность ключа */
  if( encryptionKey->key.check_icode( &encryptionKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                               "incorrect integrity code of encryption key value" );
  if( authenticationKey->key.check_icode( &authenticationKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                           "incorrect integrity code of authentication key value" );

 /* проверяем ресурс ключа аутентификации */
  if( authenticationKey->key.resource.value.counter < (ssize_t)( authenticationKey->bsize >> 3 ))
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of authentication cipher key" );
   else authenticationKey->key.resource.value.counter -= ( authenticationKey->bsize >> 3 );

 /* вырабатываем начальное состояние вектора */
  memset( tweak, 0, sizeof( tweak ));
  memcpy( tweak, iv, ak_min( iv_size, sizeof( tweak )));

  if( authenticationKey->bsize == 8 ) {
    authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );
    tweak[1] ^= tweak[0];
    authenticationKey->encrypt( &authenticationKey->key, tweak+1, tweak+1 );
  } else
      authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );

 /* вычисляем количество блоков */
  blocks = ( ak_int64 )( size/encryptionKey->bsize );
  if( size != blocks*encryptionKey->bsize )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* изменяем ресурс ключа */
  if( encryptionKey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of encryption cipher key" );
   else encryptionKey->key.resource.value.counter -= blocks;

 /* запускаем основной цикл обработки блоков информации */
   switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          *tptr = *inptr^*(tweak+jcnt); inptr++;
          encryptionKey->decrypt( &encryptionKey->key, tptr, tptr );
          *outptr = *tptr ^ *(tweak+jcnt); outptr++;
          --blocks;
          tptr++;

          if( !(jcnt = 1 - jcnt)) { /* изменяем значение tweak */
            tptr = t;
            t[0] = tweak[0] >> 63; t[1] = tweak[1] >> 63;
            tweak[0] <<= 1; tweak[1] <<= 1;
            tweak[1] ^= t[0];
            if( t[1] ) tweak[0] ^= 0x87;
          }
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
         /* шифруем */
          t[0] = *inptr^*tweak; inptr++;
          t[1] = *inptr^*(tweak+1); inptr++;

          encryptionKey->decrypt( &encryptionKey->key, t, t );
          *outptr = t[0]^*tweak; outptr++;
          *outptr = t[1]^*(tweak+1); outptr++;
          --blocks;

         /* изменяем значение tweak */
          t[0] = tweak[0] >> 63;
          t[1] = tweak[1] >> 63;
          tweak[0] <<= 1;
          tweak[1] <<= 1;
          tweak[1] ^= t[0];
          if( t[1] ) tweak[0] ^= 0x87;
       }
       break;
   }

 /* очищаем */
  if(( error = ak_ptr_wipe( tweak, sizeof( tweak ), &encryptionKey->key.generator )) != ak_error_ok )
   ak_error_message( error, __func__ , "wrong wiping of tweak value" );

 /* перемаскируем ключ */
  if(( error = encryptionKey->key.set_mask( &encryptionKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of encryption key" );
  if(( error = authenticationKey->key.set_mask( &authenticationKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of authentication key" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_xts.c  */
/* ----------------------------------------------------------------------------------------------- */
