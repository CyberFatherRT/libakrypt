/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 by Petr Mikhalitsyn, myprettycapybara@gmail.com                             */
/*                        Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_acpkm.h                                                                                */
/*  - содержит реализацию криптографических алгоритмов семейства ACPKM из Р 1323565.1.017—2018     */
/* ----------------------------------------------------------------------------------------------- */
 #include "libakrypt-internal.h"

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция вычисляет новое значение секретного ключа в соответствии с соотношениями
    из раздела 4.1, см. Р 1323565.1.017—2018.
    После выработки новое значение помещается вместо старого.
    Одновременно, изменяется ресурс нового ключа: его тип принимает значение - \ref key_using_resource,
    а счетчик принимает значение, определяемое одной из опций

     - `ackpm_section_magma_block_count`,
     - `ackpm_section_kuznechik_block_count`.

    @param bkey Контекст ключа алгоритма блочного шифрования, для которого вычисляется
    новое значение. Контекст должен быть инициализирован и содержать ключевое значение.
    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_next_acpkm_key( ak_bckey bkey )
{
  ssize_t counter = 0;
  int error = ak_error_ok;
  ak_uint8 new_key[32], acpkm[32] = {
     0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
     0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80 };

 /* проверки */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to block cipher key" );
  if( bkey->key.key_size != 32 ) return ak_error_message_fmt( ak_error_wrong_length, __func__,
                                 "using block cipher key with unexpected length %u", bkey->bsize );
 /* целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* выработка нового значения */
   switch( bkey->bsize ) {
      case  8: /* шифр с длиной блока 64 бита */
         bkey->encrypt( &bkey->key, acpkm, new_key );
         bkey->encrypt( &bkey->key, acpkm +8, new_key +8 );
         bkey->encrypt( &bkey->key, acpkm +16, new_key +16 );
         bkey->encrypt( &bkey->key, acpkm +24, new_key +24 );
         counter = ak_libakrypt_get_option_by_name( "acpkm_section_magma_block_count" );
         break;
      case 16: /* шифр с длиной блока 128 бит */
         bkey->encrypt( &bkey->key, acpkm, new_key );
         bkey->encrypt( &bkey->key, acpkm +16, new_key +16 );
         counter = ak_libakrypt_get_option_by_name( "acpkm_section_kuznechik_block_count" );
         break;
      default: return ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
   }

 /* присваиваем ключу значение */
  if(( error = ak_bckey_set_key( bkey, new_key, bkey->key.key_size )) != ak_error_ok )
    ak_error_message( error, __func__ , "can't replace key by new using acpkm" );
   else {
           bkey->key.resource.value.type = key_using_resource;
           bkey->key.resource.value.counter = counter;
        }
  ak_ptr_wipe( new_key, sizeof( new_key ), &bkey->key.generator );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_LITTLE_ENDIAN
  #define acpkm_block64 {\
              nkey.encrypt( &nkey.key, ctr, yaout );\
              ctr[0] += 1;\
              ((ak_uint64 *) outptr)[0] = yaout[0] ^ ((ak_uint64 *) inptr)[0];\
              outptr++; inptr++;\
           }

  #define acpkm_block128 {\
              nkey.encrypt( &nkey.key, ctr, yaout );\
              if(( ctr[0] += 1 ) == 0 ) ctr[1]++;\
              ((ak_uint64 *) outptr)[0] = yaout[0] ^ ((ak_uint64 *) inptr)[0];\
              ((ak_uint64 *) outptr)[1] = yaout[1] ^ ((ak_uint64 *) inptr)[1];\
              outptr += 2; inptr += 2;\
           }

#else
  #define acpkm_block64 {\
              nkey.encrypt( &nkey.key, ctr, yaout );\
              ctr[0] = bswap_64( ctr[0] ); ctr[0] += 1; ctr[0] = bswap_64( ctr[0] );\
              ((ak_uint64 *) outptr)[0] = yaout[0] ^ ((ak_uint64 *) inptr)[0];\
              outptr++; inptr++;\
           }

  #define acpkm_block128 {\
              nkey.encrypt( &nkey.key, ctr, yaout );\
              ctr[0] = bswap_64( ctr[0] ); ctr[0] += 1; ctr[0] = bswap_64( ctr[0] );\
              if( ctr[0] == 0 ) { \
                ctr[1] = bswap_64( ctr[0] ); ctr[1] += 1; ctr[1] = bswap_64( ctr[0] );\
              }\
              ((ak_uint64 *) outptr)[0] = yaout[0] ^ ((ak_uint64 *) inptr)[0];\
              ((ak_uint64 *) outptr)[1] = yaout[1] ^ ((ak_uint64 *) inptr)[1];\
              outptr += 2; inptr += 2;\
           }
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! В режиме `ACPKM` для шифрования используется операция гаммирования - операция сложения
    открытого (зашифровываемого) текста с гаммой, вырабатываемой шифром, по модулю два.
    Поэтому, для зашифрования и расшифрования информациии используется одна и та же функция.

    В процессе шифрования исходные данные разбиваются на секции фиксированной длины, после чего
    каждая секция шифруется на своем ключе. Длина секции является параметром алгоритма и
    не должна превосходить величины, определяемой одной из следующих технических характеристик
    (опций)

     - `ackpm_section_magma_block_count`,
     - `ackpm_section_kuznechik_block_count`.

    Значение синхропосылки `iv` копируется во временную область памяти и, в ходе выполнения
    функции, не изменяется. Повторный вызов функции ak_bckey_ctr_acpkm() с нулевым
    указатетем на синхропосылу, как в случае функции ak_bckey_ctr(), не допускается.

    @param bkey Контекст ключа алгоритма блочного шифрования,
    используемый для шифрования и порождения цепочки производных ключей.
    @param in Указатель на область памяти, где хранятся входные
    (зашифровываемые/расшифровываемые) данные
    @param out Указатель на область памяти, куда помещаются выходные
    (расшифровываемые/зашифровываемые) данные; этот указатель может совпадать с in
    @param size Размер зашировываемых данных (в байтах). Длина зашифровываемых данных может
    принимать любое значение, не превосходящее \f$ 2^{\frac{8n}{2}-1}\f$, где \f$ n \f$
    длина блока алгоритма шифрования (8 или 16 байт).

    @param section_size Размер одной секции в байтах. Данная величина должна быть кратна длине блока
    используемого алгоритма шифрования.

    @param iv имитовставка
    @param iv_size длина имитовставки (в байтах)

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_ctr_acpkm( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                 size_t section_size, ak_pointer iv, size_t iv_size)
{
  struct bckey nkey;
  int error = ak_error_ok;
  ssize_t j = 0, sections = 0, tail = 0, seclen = 0, maxseclen = 0, mcount = 0;
  ak_uint64 yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out, ctr[2] = { 0, 0 };

 /* выполняем проверку размера входных данных */
  if( section_size%bkey->bsize != 0 )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                               __func__ , "the length of section is not divided by block length" );
 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                  "incorrect integrity code of secret key value" );
 /* проверяем размер синхропосылки */
  if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to initialization vector" );
  if( iv_size < ( bkey->bsize >> 1 ))
    return ak_error_message( ak_error_wrong_block_cipher_length,
                                   __func__ , "the length of initialization vector is incorrect" );

 /* получаем максимально возможную длину секции, количество сообщений на одном ключе,
                                                             а также устанавливаем синхропосылку */
  switch( bkey->bsize ) {
    case 8:
       maxseclen = ak_libakrypt_get_option_by_name( "acpkm_section_magma_block_count" );
       mcount = ak_libakrypt_get_option_by_name( "magma_cipher_resource" )/maxseclen;
       #ifdef AK_LITTLE_ENDIAN
         ctr[0] = ((ak_uint64 *)iv)[0] << 32;
       #else
         ctr[0] = ((ak_uint32 *)iv)[0];
       #endif
      break;

    case 16:
       maxseclen = ak_libakrypt_get_option_by_name( "acpkm_section_kuznechik_block_count" );
       mcount = ak_libakrypt_get_option_by_name( "kuznechik_cipher_resource" )/maxseclen;
       ctr[1] = ((ak_uint64 *) iv)[0];
      break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
  }
 /* проверяем, что пользователь определил длину секции не очень большим значением */
  seclen = ( ssize_t )( section_size/bkey->bsize );
  if( seclen > maxseclen ) return ak_error_message( ak_error_wrong_length, __func__,
                                                                 "section has very large length" );
 /* проверяем ресурс ключа перед использованием */
  if( bkey->key.resource.value.type != key_using_resource ) { /* мы пришли сюда в первый раз */
    bkey->key.resource.value.type = key_using_resource;
    bkey->key.resource.value.counter = mcount; /* здесь находится максимальное число сообщений,
                                                  которые могут быть зашифрованы на данном ключе */
  } else {
      if( bkey->key.resource.value.counter < 1 )
        return ak_error_message( ak_error_low_key_resource,
                                __func__ , "low key using resource for block cipher key context" );
       else bkey->key.resource.value.counter--;
     }

 /* теперь размножаем исходный ключ */
  if(( error = ak_bckey_create_and_set_bckey( &nkey, bkey )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect key duplication" );
 /* и меняем ресурс для производного ключа */
  nkey.key.resource.value.counter = maxseclen;

 /* дальнейшие криптографические действия применяются к новому экземпляру ключа */
  sections = ( ssize_t )( size/section_size );
  tail = ( ssize_t )( size - ( size_t )( sections*seclen )*nkey.bsize );
  if( sections > 0 ) {
    do{
       switch( nkey.bsize ) { /* обрабатываем одну секцию */
         case 8: for( j = 0; j < seclen; j++ ) acpkm_block64; break;
         case 16: for( j = 0; j < seclen; j++ ) acpkm_block128; break;
         default: ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
       }
      /* вычисляем следующий ключ */
       if(( error = ak_bckey_next_acpkm_key( &nkey )) != ak_error_ok ) {
         ak_error_message_fmt( error, __func__, "incorrect key generation after %u sections",
                                                                         (unsigned int) sections );
         goto labex;
       }
    } while( --sections > 0 );
  } /* конец обработки случая, когда sections > 0 */

  if( tail ) { /* теперь обрабатываем фрагмент данных, не кратный длине секции */
    if(( seclen = tail/(ssize_t)( nkey.bsize )) > 0 ) {
       switch( nkey.bsize ) { /* обрабатываем данные, кратные длине блока */
         case 8: for( j = 0; j < seclen; j++ ) acpkm_block64; break;
         case 16: for( j = 0; j < seclen; j++ ) acpkm_block128; break;
         default: ak_error_message( ak_error_wrong_block_cipher,
                                            __func__ , "incorrect block size of block cipher key" );
       }
    }
  /* остался последний фрагмент, длина которого меньше длины блока
                      в качестве гаммы мы используем старшие байты */
    if(( tail -= seclen*(ssize_t)( nkey.bsize )) > 0 ) {
      nkey.encrypt( &nkey.key, ctr, yaout );
      for( j = 0; j < tail; j++ ) ((ak_uint8 *) outptr)[j] =
                         ((ak_uint8 *)yaout)[(ssize_t)nkey.bsize-tail+j] ^ ((ak_uint8 *) inptr)[j];
    }
  }

  labex: ak_bckey_destroy( &nkey );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_acpkm( void )
{
  struct bckey key;
  int error = ak_error_ok, audit = ak_log_get_level();
  ak_uint8 skey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
  };
  ak_uint8 iv1[8] = { 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12 };
  ak_uint8 iv2[4] = { 0x78, 0x56, 0x34, 0x12 };

  ak_uint8 out[112], in1[112] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
    0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
    0x33, 0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
    0x44, 0x33, 0x22, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55
  };
  ak_uint8 out1[112] = {
    0xb8, 0xa1, 0xbd, 0x40, 0xa2, 0x5f, 0x7b, 0xd5, 0xdb, 0xd1, 0x0e, 0xc1, 0xbe, 0xd8, 0x95, 0xf1,
    0xe4, 0xde, 0x45, 0x3c, 0xb3, 0xe4, 0x3c, 0xf3, 0x5d, 0x3e, 0xa1, 0xf6, 0x33, 0xe7, 0xee, 0x85,
    0x00, 0xe8, 0x85, 0x5e, 0x27, 0x06, 0x17, 0x00, 0x55, 0x4c, 0x6f, 0x64, 0x8f, 0xeb, 0xce, 0x4b,
    0x46, 0x50, 0x80, 0xd0, 0xaf, 0x34, 0x48, 0x3e, 0x39, 0x94, 0xd0, 0x68, 0xf5, 0x4d, 0x7c, 0x58,
    0x6e, 0x89, 0x8a, 0x6b, 0x31, 0x6c, 0xfc, 0x1c, 0xe1, 0xec, 0xae, 0x86, 0x76, 0xf5, 0x30, 0xcf,
    0x3e, 0x16, 0x23, 0x34, 0x74, 0x3b, 0x4f, 0x0c, 0x46, 0x36, 0x36, 0x81, 0xec, 0x07, 0xfd, 0xdf,
    0x5d, 0xde, 0xd6, 0xfb, 0xe7, 0x21, 0xd2, 0x69, 0xd4, 0xc8, 0xfa, 0x82, 0xc2, 0xa9, 0x09, 0x64
  };
  ak_uint8 in2[56] = {
    0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, /* по сравнению с текстом рекомендаций открытый */
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* текст выведен в блоки по 8 байт и развернут  */
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, /* в обратном порядке, по аналогии со способом, */
    0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, /* использованом в стандарте на блочные шифры   */
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99,
    0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22
  };
  ak_uint8 out2[56] = {
    0xab, 0x4c, 0x1e, 0xeb, 0xee, 0x1d, 0xb8, 0x2a,
    0xea, 0x94, 0x6b, 0xbd, 0xc4, 0x04, 0xe1, 0x68,
    0x6b, 0x5b, 0x2e, 0x6c, 0xaf, 0x67, 0x2c, 0xc7,
    0x2e, 0xb3, 0xf1, 0x70, 0x17, 0xb6, 0xaf, 0x0e,
    0x82, 0x13, 0xed, 0x9e, 0x14, 0x71, 0xae, 0xa1,
    0x6f, 0xec, 0x72, 0x06, 0x18, 0x67, 0xd4, 0xab,
    0xc1, 0x72, 0xca, 0x3f, 0x5b, 0xf1, 0xa2, 0x84
  };

 /* 1. Выполняем тест для алгоритма Магма */
  if(( error = ak_bckey_create_magma( &key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of magma secret key" );
    return ak_false;
  }
  if(( error = ak_bckey_set_key( &key, skey, sizeof( skey ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a key value" ); goto ex1; }

  if(( error = ak_bckey_ctr_acpkm( &key, in2, out, sizeof( in2 ),
                                                       16, iv2, sizeof( iv2 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption of plain text" ); goto ex1; }

  if( memcmp( out, out2, sizeof( in2 )) != 0 ) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
                "incorrect data comparizon after acpkm encryption with magma cipher" ); goto ex1; }

 /* расшифровываем */
  if(( error = ak_bckey_ctr_acpkm( &key, out2, out, sizeof( in2 ),
                                                       16, iv2, sizeof( iv2 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption of plain text" ); goto ex1; }

  if( memcmp( out, in2, sizeof( in2 )) != 0 ) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
                "incorrect data comparizon after acpkm decryption with magma cipher" ); goto ex1; }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                              "acpkm encryption/decryption test for magma is Ok" );
  ex1: ak_bckey_destroy( &key );
  if( error != ak_error_ok ) {
    ak_error_message( ak_error_ok, __func__ , "acpkm mode test for magma is wrong" );
    return ak_false;
  }

 /* 2. Выполняем тест для алгоритма Кузнечик */
  if(( error = ak_bckey_create_kuznechik( &key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of kuznechik secret key" );
    return ak_false;
  }
  if(( error = ak_bckey_set_key( &key, skey, sizeof( skey ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a key value" ); goto ex2; }

  if(( error = ak_bckey_ctr_acpkm( &key, in1, out, sizeof( in1 ),
                                                       32, iv1, sizeof( iv1 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption of plain text" ); goto ex2; }

  if( memcmp( out, out1, sizeof( in1 )) != 0 ) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
            "incorrect data comparizon after acpkm encryption with kuznechik cipher" ); goto ex2; }

 /* расшифровываем */
  if(( error = ak_bckey_ctr_acpkm( &key, out1, out, sizeof( out1 ),
                                                        32, iv1, sizeof( iv1 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption of plain text" ); goto ex2; }

  if( memcmp( out, in1, sizeof( in1 )) != 0 ) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
            "incorrect data comparizon after acpkm decryption with kuznechik cipher" ); goto ex2; }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                          "acpkm encryption/decryption test for kuznechik is Ok" );
  ex2: ak_bckey_destroy( &key );
  if( error != ak_error_ok ) {
    ak_error_message( ak_error_ok, __func__ , "acpkm mode test for kuznechik is wrong" );
    return ak_false;
  }

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_acpkm.c */
/* ----------------------------------------------------------------------------------------------- */
