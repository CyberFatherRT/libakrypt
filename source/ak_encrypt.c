/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2021 - 2022 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_encrypt.c                                                                              */
/*  - содержит реализацию схемы асимметричного шифрования                                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>
 #ifdef AK_HAVE_UNISTD_H
  #include <unistd.h>
 #endif

/* ----------------------------------------------------------------------------------------------- */
/*                                 процедуры зашифрования информации                               */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет, поддерживается ли библиотекой указанная схема шифрования             */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_encrypt_file_is_scheme_valid( scheme_t scheme )
{
 /* в текущей версии библиотеки мы поддерживаем только базовую гибридную схему */
  if( scheme == ecies_scheme ) return ak_true;

 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_encrypt_file_create_header( const char *filename,
       ak_encryption_set set, ak_pointer scheme_key, ak_uint8 *buffer, size_t *len, size_t *head );

 static int ak_encrypt_assign_container_key( ak_bckey kcont, ak_uint8 *salt, size_t salt_size,
                                  ak_uint8 *iv, size_t iv_size, ak_uint8 *vect, size_t vect_size,
                                                    const char *password, const size_t pass_size );

 static int ak_encrypt_assign_encryption_keys( ak_aead ctx,
                               ak_encryption_set set, ak_pointer scheme_key, ak_random generator,
                                  ak_uint8 *salt, size_t salt_size, ak_uint8 *iv, size_t iv_size,
                                 ak_uint8 *vect, size_t vect_size, ak_uint8 *buffer, size_t head );

/* ----------------------------------------------------------------------------------------------- */
/*! Для зашифрования данных используется открытый ключ получателя. 
    Для доступа к контейнеру с данными используется пароль.

    @return В случае успеха функция возвращает ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_encrypt_file( const char *filename, ak_encryption_set set,
                 ak_pointer scheme_key, char *outfile, const size_t outsize, ak_random generator,
                                                    const char *password, const size_t pass_size )
{
  struct aead ctx;
  struct bckey kcont;
  struct file ifp, ofp;
  ak_uint8 buffer[4096];
  int error = ak_error_ok;
  ak_uint8 salt[32], iv[16], vect[32], im[16];
  size_t len = sizeof( buffer ), head = 0;
  ak_int64 total = 0, maxlen = 0, value = 0, sum = 0;

  /* выполняем многочисленные начальные проверки */
   if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to the name of the input file" );
   if( set == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to encryption set" );
   if( !ak_encrypt_file_is_scheme_valid( set->scheme ))
     return ak_error_message( ak_error_encrypt_scheme, __func__,
                                                           "using unsupported encryption scheme" );
   if( set->mode->mode != aead ) return ak_error_message( ak_error_oid_mode, __func__,
                                                       "using non aead mode for data encryption" );
   if( scheme_key == NULL ) return ak_error_message( ak_error_oid_mode, __func__,
                                                              "using null pointer to encrypted " );
   if( outfile == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to the name of the output file" );
   if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to random number generator" );
   if( password == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to password" );
   if( pass_size == 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                               "using password with zero length" );
  /* вырабатываем первичные случайные данные */
   memset( salt, 0, sizeof( salt ));
   memset( iv, 0, sizeof( iv ));
   memset( vect, 0, sizeof( vect ));
   if(( error = ak_random_ptr( generator, salt, 14 )) != ak_error_ok ) {
     return ak_error_message( error, __func__, "wrong generation of initial random data" );
   }

  /* инициализируем ключ доступа к контейнеру */
   if(( error = ak_bckey_create_kuznechik( &kcont )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of container's secret key" );

   if(( error = ak_encrypt_assign_container_key( &kcont, /* устанавливаем первичное значение ключа */
                              salt, 14, iv, 8, vect, 32, password, pass_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assign value of container's secret key" );
     goto lab_exit;
   }

  /* формируем файловые дескрипторы */
   if( outsize > 0 ) {
     if( outsize < 12 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                      "buffer for output file name is too small" );
     ak_random_ptr( &kcont.key.generator, outfile, 12 );
     strncpy( outfile, ak_ptr_to_hexstr( outfile, 12, ak_false ), outsize );
   }
   if(( error = ak_file_open_to_read( &ifp, filename )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__, "wrong open an existing file (%s)", filename );
     goto lab_exit;
   }
   if(( error = ak_file_create_to_write( &ofp, outfile )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__, "wrong creation of a new file (%s)", outfile );
     ak_file_close( &ifp );
     goto lab_exit;
   }

  /* формируем заголовок контейнера, зашифровываем и сохраняем */
   if(( error = ak_encrypt_file_create_header( filename,
                                        set, scheme_key, buffer, &len, &head )) != ak_error_ok ) {
     ak_error_message( error, __func__, "header of encrypted file cannot be created" );
     goto lab_exit2;
   }

   if(( error = ak_bckey_ctr( &kcont, buffer, buffer, len, iv, 8 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect header encryption" );
     goto lab_exit2;
   }
   memcpy( buffer, salt, 14 );
   ak_file_write( &ofp, buffer, len );

  /* создаем ключи шифрования и имитозащиты данных */
   if(( error = ak_aead_create_oid( &ctx, ak_true, set->mode )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect intialization of internal aead context" );
     goto lab_exit2;
   }

  /* выполняем фрагментацию входного файла на фрагменты длины
     от 4096 байт до maxlen, где maxlen определяется
     ресурсом секретного ключа */
   total = ifp.size;
   if(( value = set->fraction.value ) == 0 ) value = 10; /* количество фрагментов по-умолчанию */
   if( strstr( set->mode->name[0], "kuznechik" ) != NULL )
     maxlen = 16*ak_libakrypt_get_option_by_name( "kuznechik_cipher_resource" );
    else maxlen = 8*ak_libakrypt_get_option_by_name( "magma_cipher_resource" );

   if( set->fraction.mechanism == count_fraction ) {
     maxlen = ak_max( 4096, ak_min( total/value, maxlen ));
   }
   if( set->fraction.mechanism == size_fraction ) {
     maxlen = ak_max( 4096, ak_min( value, maxlen ));
   }

  /* основной цикл разбиения входных данных */
   while( total > 0 ) {
     ak_int64 current = maxlen, val = 0, crt = 0;
     if( set->fraction.mechanism == random_size_fraction ) {
       ak_random_ptr( generator, &current, 4 ); /* нам хватит 4х октетов */
       current %= ifp.size;
       if( current > maxlen ) current = maxlen; /* не очень большая */
       current = ak_max( 4096, current );     /* не очень маленькая */
     }
     current = ak_min( current, total );
     if(((total - current) > 0 ) && ((total - current) < 4096 )) current = total;

    /* теперь мы можем зашифровать фрагмент входных данных,
       длина которого определена значением current.
       начинаем с того, что вырабатываем ключи и заголовок фрагмента */
     memset( buffer, 0, sizeof( buffer ));
     if(( error = ak_encrypt_assign_encryption_keys( &ctx, set, scheme_key,
                      generator, vect, 32, iv, 16, salt, 32, buffer, head )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of input data encryption keys" );
        break;
     }

    /* добавляем в буффер значение current, зашифровываем его и сохраняем в файл (head = len + 8) */
     buffer[head -8] = ( current >> 56 )&0xFF;
     buffer[head -7] = ( current >> 48 )&0xFF;
     buffer[head -6] = ( current >> 40 )&0xFF;
     buffer[head -5] = ( current >> 32 )&0xFF;
     buffer[head -4] = ( current >> 24 )&0xFF;
     buffer[head -3] = ( current >> 16 )&0xFF;
     buffer[head -2] = ( current >>  8 )&0xFF;
     buffer[head -1] = current&0xFF;

     ak_bckey_ctr( &kcont, buffer, buffer, head, NULL, 0 );
     ak_file_write( &ofp, buffer, head );

    /* только теперь шифруем входящие даные */
     if(( error = ak_aead_clean( &ctx, iv, ak_min( 16, ctx.tag_size ))) != ak_error_ok ) {
       ak_error_message( error, __func__, "incorrect cleaning of authentication context" );
       break;
     }

     crt = current;
     while( crt > 0 ) {
       if(( val = ak_file_read( &ifp, buffer, ak_min( sizeof( buffer ), crt ))) == 0 ) {
         error = ak_error_message( ak_error_undefined_value, __func__,
                                                             "incorrect loading of input buffer" );
         break;
       }
       if(( error = ak_aead_encrypt_update( &ctx, buffer, buffer, val )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect update of internal state" );
         break;
       }
       ak_file_write( &ofp, buffer, val );
       crt -= val;
     }
    /* проверяем, что цикл завершен успешно */
     if( error != ak_error_ok ) break;
     if(( error = ak_aead_finalize( &ctx, im, ak_min( 16, ctx.tag_size ))) != ak_error_ok ) {
       ak_error_message( error, __func__, "incorrect finalize of internal state" );
       break;
     }

    /* вырабатываем новое значение ключа для доступа к контейнеру */
     if(( error = ak_encrypt_assign_container_key( &kcont,
                              salt, 32, iv, 8, vect, 32, password, pass_size )) != ak_error_ok ) {
       ak_error_message( error, __func__, "incorrect assign value of container's secret key" );
       break;
     }

    /* зашифровываем и сохраняем имитоставку */
     ak_bckey_ctr( &kcont, im, im, ak_min( 16, ctx.tag_size ), iv, 8 );
     ak_file_write( &ofp, im, ak_min( 16, ctx.tag_size ) );

    /* уточняем оставшуюся длину входных данных */
     total -= current;
     sum += current;
   }
   if( sum != ifp.size ) ak_error_message( error = ak_error_wrong_length, __func__,
                         "the length of encrypted data is not equal to the length of plain data" );

  /* очищием файловые дескрипторы, ключевые контексты, промежуточные данные и выходим */
   ak_aead_destroy( &ctx );

  lab_exit2:
   ak_file_close( &ofp );
   ak_file_close( &ifp );

  lab_exit:
   ak_ptr_wipe( &ctx, sizeof( struct aead ), &kcont.key.generator );
   ak_ptr_wipe( salt, sizeof( salt ), &kcont.key.generator );
   ak_ptr_wipe( iv, sizeof( iv ), &kcont.key.generator );
   ak_ptr_wipe( vect, sizeof( vect ), &kcont.key.generator );
   ak_ptr_wipe( buffer, sizeof( buffer ), &kcont.key.generator );
   ak_bckey_destroy( &kcont) ;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция зашифровывает заданный файл с использованием асимметричной схемы шифрования.
    Доступ к контейнеру, хранящему зашифрованные данные, закрывается с использованием заданого
    секретного ключа.

    @return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_encrypt_file_with_key( const char *filename, ak_encryption_set set,
        ak_pointer scheme, char *outfile, const size_t outsize, ak_random generator, ak_skey key )
{
  int error = ak_error_ok;

  if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to container's encryption key" );
  if(( key->flags&key_flag_set_key ) == 0 ) return ak_error_message( ak_error_key_value, __func__,
                                                   "using unassigned container's encryption key" );
 /* отправляем массив ключевой информации в качестве пароля для шифрования файла */
  if(( error = key->unmask( key )) != ak_error_ok ) return ak_error_message( error, __func__,
                                                                   "error key unmasking process" );
  error = ak_encrypt_file( filename, set, scheme, outfile, outsize,
                                               generator, ( const char *)key->key, key->key_size );
  if( key->set_mask( key ) != ak_error_ok ) ak_error_message( error, __func__,
                                                                     "error key masking process" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает asn1 sequence, помещаемую в заголовок зашифрованного файла
    и содержащую информацию, необходимую для расшифрования файла.                                   */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_encrypt_create_public_key_sequence( scheme_t scheme, ak_pointer scheme_key )
{
  ak_tlv sq2 = NULL;

  switch( scheme ) {
    case ecies_scheme:
      if(( sq2 = ak_tlv_new_sequence( )) == NULL ) {
        ak_error_message( ak_error_out_of_memory,  __func__, "wrong creation of asn1 sequence" );
      }
       else {
         ak_ecies_scheme ecs = scheme_key;
        /* помещаем номер открытого ключа */
         ak_asn1_add_octet_string( sq2->data.constructed,
                                   ecs->recipient.vkey.number, ecs->recipient.vkey.number_length );
        /* если в сертификате одержится, то помещаем номер секретного ключа */
         if( ecs->recipient.opts.ext_secret_key_number.is_present ) {
           ak_asn1_add_octet_string( sq2->data.constructed,
                                      ecs->recipient.opts.ext_secret_key_number.number,
                                       sizeof( ecs->recipient.opts.ext_secret_key_number.number ));
         }
       }
      break;

    default:
      ak_error_message( ak_error_encrypt_scheme, __func__, "using unsupported encryption scheme" );
  }

 return sq2;
}

/* ----------------------------------------------------------------------------------------------- */
 static size_t ak_encrypt_public_key_size( scheme_t scheme, ak_pointer scheme_key )
{
  switch( scheme ) {
    case ecies_scheme:
      return 2*sizeof( ak_uint64 )*((( ak_ecies_scheme)scheme_key)->recipient.vkey.wc->size );

    default:
      ak_error_message( ak_error_encrypt_scheme, __func__, "using unsupported encryption scheme" );
  }

 return 0;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_encrypt_file_create_header( const char *filename,
       ak_encryption_set set, ak_pointer scheme_key, ak_uint8 *buffer, size_t *len, size_t *head )
{
   int error = ak_error_ok;
   ak_asn1 header = ak_asn1_new();
   ak_tlv sequence = NULL, sq2 = NULL;

  /* формируем заголовок контейнера */
   if( header == NULL ) return ak_error_message( ak_error_out_of_memory,
                                                   __func__, "incorrect creation os asn1 header" );
   ak_asn1_add_tlv( header, sequence = ak_tlv_new_sequence( ));
   if( sequence == NULL ) {
     ak_asn1_delete( header );
     return ak_error_message( ak_error_out_of_memory,  __func__,
                                                     "incorrect creation of first asn1 sequence" );
   }
  /* a. схема шифрования */
   ak_asn1_add_uint32( sequence->data.constructed, set->scheme );
  /* b. параметры открытого ключа используемой схемы */
   if(( sq2 = ak_encrypt_create_public_key_sequence( set->scheme, scheme_key )) == NULL ) {
     ak_asn1_delete( header );
     return ak_error_message( ak_error_out_of_memory,  __func__,
                                                    "incorrect creation of second asn1 sequence" );
   }
    else ak_asn1_add_tlv( sequence->data.constructed, sq2 );
  /* c. режим шифрования данных */
   ak_asn1_add_algorithm_identifier( sequence->data.constructed, set->mode , NULL );
  /* d. имя файла после расшифрования */
   ak_asn1_add_utf8_string( sequence->data.constructed, filename );
  /* e. размер служебного заголовка в байтах */
   ak_asn1_add_uint32( sequence->data.constructed,
                               *head = ak_encrypt_public_key_size( set->scheme, scheme_key ) + 8 );

  /* кодируем содержимое заголовка */
   memset( buffer, 0, *len );
   if(( error = ak_asn1_encode( header, buffer +16, len )) == ak_error_ok ) {
     buffer[15] = *len&0xFF;
     buffer[14] = (*len - buffer[15])&0xFF;
     *len += 16; /* добавляем к длине 16 октетов  */
   }

   ak_asn1_delete( header );
   if( error != ak_error_ok ) return ak_error_message( error, __func__,
                                                      "encorrect encrypted file header encoding" );
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_encrypt_assign_container_key( ak_bckey kcont, ak_uint8 *salt, size_t salt_size,
                                  ak_uint8 *iv, size_t iv_size, ak_uint8 *vect, size_t vect_size,
                                                    const char *password, const size_t pass_size )
{
   ak_uint8 value[32];
   struct kdf_state state;
   int error = ak_error_ok;

   if(( error = ak_kdf_state_create( &state, (ak_uint8 *)password, pass_size,
                    hmac_hmac512_kdf, NULL, 0, salt, salt_size, NULL, 0, 256 )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "wrong generation of initial secret key" );
   }
   if(( error = ak_kdf_state_next( &state, iv, iv_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect generation of initial vector" );
     goto ex;
   }
   if(( error = ak_kdf_state_next( &state, vect, vect_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect generation of additional vector" );
     goto ex;
   }
   if(( error = ak_kdf_state_next( &state, value, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect generation of secret vector" );
     goto ex;
   }
   if(( error = ak_kdf_state_destroy( &state )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect destroying of internal state" );
     goto ex;
   }

   if(( error = ak_bckey_set_key( kcont, value, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assigning a secret value to container's key" );
   }
   ex:
   ak_ptr_wipe( value, 32, &kcont->key.generator );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_encrypt_assign_encryption_keys( ak_aead ctx,
                               ak_encryption_set set, ak_pointer scheme_key, ak_random generator,
                                  ak_uint8 *salt, size_t salt_size, ak_uint8 *iv, size_t iv_size,
                                 ak_uint8 *vect, size_t vect_size, ak_uint8 *buffer, size_t head )
{
  ak_mpznmax xi;
  size_t cnt = 0;
  struct wpoint U, W;
  ak_wcurve wc = NULL;
  struct kdf_state state;
  int error = ak_error_ok;
  ak_ecies_scheme ecs = (ak_ecies_scheme) scheme_key;

  switch( set->scheme ) {
    case ecies_scheme:
      /* упрощаем доступ */
       wc = ecs->recipient.vkey.wc;
       cnt = sizeof( ak_uint64 )*wc->size;
       if( head != ( 2*wc->size*sizeof( ak_uint64 ) +8 )) {
         ak_error_message( error = ak_error_wrong_length, __func__,
                                                       "using unexpected length of chunk header" );
         break;
       }
      /* вырабатываем случайное число */
       ak_mpzn_set_random_modulo( xi, wc->q, wc->size, generator );
      /* вырабатываем точку W, которая будет использована для генерации ключевой информации */
       ak_wpoint_set_as_unit( &W, wc );
       ak_wpoint_pow( &W, &ecs->recipient.vkey.qpoint, xi, wc->size, wc );
       ak_wpoint_reduce( &W, wc );
       ak_mpzn_to_little_endian( W.x, wc->size, buffer, cnt, ak_true );
       ak_mpzn_to_little_endian( W.y, wc->size, buffer + cnt, cnt, ak_true );

      /* вырабатываем необходимую производную информацию */
       if(( error = ak_kdf_state_create( &state, buffer, 2*cnt,
                    hmac_hmac512_kdf, NULL, 0, salt, salt_size, NULL, 0, 256 )) != ak_error_ok ) {
         ak_error_message( error, __func__, "wrong generation of initial secret key" );
         goto labex;
       }
       if(( error = ak_kdf_state_next( &state, iv, iv_size )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect generation of initial vector" );
         goto labex;
       }
       if(( error = ak_kdf_state_next( &state, vect, vect_size )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect generation of additional vector" );
         goto labex;
       }
       if(( error = ak_kdf_state_next( &state, buffer, 64 )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect generation of secret vector" );
         goto labex;
       }
       labex:
         ak_kdf_state_destroy( &state );
       if( error != ak_error_ok ) break;

      /* присваиваем ключевые значения */
       if(( error = ak_aead_set_keys( ctx, buffer, 32, buffer +32, 32 )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect assigning of secret keys" );
         break;
       }
      /* вырабатываем точку U, которая будет помещена в buffer */
       ak_wpoint_set_as_unit( &U, wc );
       ak_wpoint_pow( &U, &wc->point, xi, wc->size, wc );
       ak_wpoint_reduce( &U, wc );
       ak_mpzn_to_little_endian( U.x, wc->size, buffer, cnt, ak_true );
       ak_mpzn_to_little_endian( U.y, wc->size, buffer +cnt, cnt, ak_true );
      break;

    default:
      ak_error_message( error = ak_error_encrypt_scheme, __func__,
                                                           "using unsupported encryption scheme" );
  }
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 процедуры расшифрования информации                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_pointer ak_decrypt_file_load_secret_key( scheme_t , ak_tlv , const char * );
 static int ak_decrypt_assign_encryption_keys( ak_aead ctx, ak_oid mode,
  scheme_t scheme, ak_signkey key, ak_uint8 *salt, size_t salt_size, ak_uint8 *iv, size_t iv_size,
                                 ak_uint8 *vect, size_t vect_size, ak_uint8 *buffer, size_t head );

/* ----------------------------------------------------------------------------------------------- */
/*!
  \param filename Имя расшифровываемого файла
  \param password пароль доступа к контейнеру, содержащему зашифрованные данные
  \param pass_size длиа пароля (в октетах)
  \param skeyfile Имя файла с секретным ключом (формат секретного ключа зависит от использумой схемы)
   Если имя не определено (skeyfile равен `null`), то функция пытается отыскать секретный ключ
   в стандартных каталогах пользователя библиотеки.

  \param outfile указатель на область, в которой располагается имя расшифрованного файла.
  \param outfile_size Размер области памяти. Если размер равен нулю, то предполагается, что
  используемое для создаваемого файла имя определяется строкой, на которую указывает outfile.
  Если значение `outfile_size` отлично от нуля, то оно задает размер области памяти,
  в которую помещается считываемое из контенера имя файла.

  \return  В случае успеха возвращается ноль (ak_error_ok). В противном случае,
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_decrypt_file( const char *filename, const char *password, const size_t pass_size ,
                                    const char *skeyfile, char *outfile, const size_t outfile_size )
{
  size_t len;
  scheme_t scheme;
  struct aead ctx;
  ak_asn1 asn, seq;
  ak_uint32 head = 0;
  struct bckey kcont;
  ak_uint64 total = 0;
  struct file ifp, ofp;
  ak_uint8 buffer[1024];
  int error = ak_error_ok;
  ak_pointer ptr, skey = NULL;
  ak_oid mode = NULL, params = NULL;
  ak_uint8 salt[32], iv[16], vect[32], im[16];

  /* проверяем корректность аргументов функции */
   if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to name of encrypted file" );
   if( password == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to password" );
   if( pass_size == 0 ) return ak_error_message( ak_error_wrong_length,
                                                     __func__, "using password with zero length" );
   if(( outfile_size == 0 ) && ( outfile == NULL ))
     return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to name of decrypted file" );
   memset( salt, 0, sizeof( salt ));
   memset( iv, 0, sizeof( iv ));
   memset( vect, 0, sizeof( vect ));

 /* 1. Считываем заголовок и проверяем, наше ли это добро */
   if(( error = ak_file_open_to_read( &ifp, filename )) != ak_error_ok ) {
     return ak_error_message_fmt( error, __func__, "wrong open an input file (%s)", filename );
   }
   if( ak_file_read( &ifp, salt, 16 ) != 16 ) {
     ak_error_message( error = ak_error_read_data, __func__,
                                                        "wrong reading the first part of header" );
     goto lab_exit;
   }
   if(( error = ak_bckey_create_kuznechik( &kcont )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of container's secret key" );

   if(( error = ak_encrypt_assign_container_key( &kcont, /* устанавливаем первичное значение ключа */
                              salt, 14, iv, 8, vect, 32, password, pass_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assign value of container's secret key" );
     goto lab_exit2;
   }

   memcpy( buffer, salt, 16 );
   if(( error = ak_bckey_ctr( &kcont, buffer, buffer, 16, iv, 8 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect decryption of the first part of the header" );
     goto lab_exit2;
   }
   if(( len = buffer[14]*256 + buffer[15] ) > 1024 ) {
     ak_error_message( error = ak_error_wrong_length, __func__, "incorrect length of the header" );
     goto lab_exit2;
   }
   ak_file_read( &ifp, buffer, len );
   if(( error = ak_bckey_ctr( &kcont, buffer, buffer, len, NULL, 0 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect decryption of the second part of the header" );
     goto lab_exit2;
   }

  /* 2. Проверяем корректность считанных из заголовка параметров */
   if(( error = ak_asn1_decode( asn = ak_asn1_new(), buffer, len, ak_false )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect decoding of the header" );
     goto lab_exit3;
   }
   ak_asn1_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
        ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) {
     ak_error_message( error, __func__, "header has not a main sequence" );
     goto lab_exit3;
   }

  /* a. считываем и проверяем корректность использованной асимметричной схемы */
   ak_asn1_first( seq = asn->current->data.constructed );
   ak_tlv_get_uint32( seq->current, &scheme );
   if( !ak_encrypt_file_is_scheme_valid( scheme )) {
     ak_error_message( error, __func__, "encrypted file use an unsupported encryption scheme" );
     goto lab_exit3;
   }
  /* b. считываем секретный ключ для расшифрования */
   ak_asn1_next( seq );
   if(( skey = ak_decrypt_file_load_secret_key( scheme, seq->current, skeyfile )) == NULL ) {
     error = ak_error_message( ak_error_get_value(), __func__,
                                                           "incorrect creation of decryption key");
     goto lab_exit3;
   }
  /* c. считываем режим шифрования */
   ak_asn1_next( seq );
   if(( error = ak_tlv_get_algorithm_identifier( seq->current, &mode, &params )) != ak_error_ok ) {
     ak_error_message( error, __func__, "wrong reading an encryption mode" );
     goto lab_exit3;
   }
  /* d. считываем имя расшифрованного файла */
   ak_asn1_next( seq );
   if(( error = ak_tlv_get_utf8_string( seq->current, &ptr )) != ak_error_ok ) {
     ak_error_message( error, __func__, "wrong reading of unencrypted file name" );
     goto lab_exit3;
   }
   if( outfile_size > 0 ) {
     memset( outfile, 0, outfile_size );
     memcpy( outfile, ptr, ak_min( strlen(ptr), outfile_size -1 ));
   }

  /* e. считываем размер служебного заголовка */
   ak_asn1_next( seq );
   if(( error = ak_tlv_get_uint32( seq->current, &head )) != ak_error_ok ) {
     ak_error_message( error, __func__, "wrong reading of local header length" );
     goto lab_exit3;
   }

  /* открываем файл для записи расшифрованных данных */
   if(( error = ak_file_create_to_write( &ofp, outfile )) != ak_error_ok ) {
     ak_error_message( error, __func__, "wrong creation of decrypted file" );
     goto lab_exit3;
   }

  /* начинаем основной цикл опробования фрагментов шифрованного файла */
   total = ifp.size -16 -len;
  /* создаем ключи шифрования и имитозащиты данных */
   if(( error = ak_aead_create_oid( &ctx, ak_true, mode )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect intialization of secret keys" );
     goto lab_exit4;
   }

   while( total > 0 ) {
    ak_uint64 crt, val, current = 0;
   /* 1. получаем значения из локального заголовка (заголовка фрагмента) */
    if( total < head ) { /* проверяем, что данных достаточно */
      ak_error_message( ak_error_wrong_length, __func__, "unexpected length of encrypted file" );
      goto lab_exit4;
    }
    if( ak_file_read( &ifp, buffer, head ) != head ) {
      ak_error_message( ak_error_access_file, __func__, "wrong reading of fragment's header" );
      goto lab_exit4;
    }
    ak_bckey_ctr( &kcont, buffer, buffer, head, NULL, 0 );
    current =  buffer[head -1];
    current += ((ak_uint64)(buffer[head -2]) << 8 );
    current += ((ak_uint64)(buffer[head -3]) << 16 );
    current += ((ak_uint64)(buffer[head -4]) << 24 );
    current += ((ak_uint64)(buffer[head -5]) << 32 );
    current += ((ak_uint64)(buffer[head -6]) << 40 );
    current += ((ak_uint64)(buffer[head -7]) << 48 );
    current += ((ak_uint64)(buffer[head -8]) << 56 );

    if( current > ( total -head -ak_min( 16, ctx.tag_size ))) {
      ak_error_message( ak_error_wrong_length, __func__, "wrong reading of fragment's length" );
      goto lab_exit4;
    }

   /* 2. вырабатываем производные ключи шифрования и имитозащиты */
    if(( error = ak_decrypt_assign_encryption_keys( &ctx, mode, scheme, skey,
                      vect, 32, iv, 16, salt, 32, buffer, head )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect creation of input data encryption keys" );
      goto lab_exit4;
    }

   /* выполняем процедуру расшифрования данных */
    if(( error = ak_aead_clean( &ctx, iv, ak_min( 16, ctx.tag_size ))) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect cleaning of aead context" );
      break;
    }

    crt = current;
    while( crt > 0 ) {
       if(( val = ak_file_read( &ifp, buffer, ak_min( sizeof( buffer ), crt ))) == 0 ) {
         error = ak_error_message( ak_error_undefined_value, __func__,
                                                             "incorrect loading of input buffer" );
         break;
       }
       if(( error = ak_aead_decrypt_update( &ctx, buffer, buffer, val )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect update of internal state" );
         break;
       }
       ak_file_write( &ofp, buffer, val );
       crt -= val;
    }

   /* проверяем, что цикл завершен успешно */
    if( error != ak_error_ok ) break;
    if(( error = ak_aead_finalize( &ctx, im, ak_min( 16, ctx.tag_size ))) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect finalize of internal state" );
      break;
    }

   /* изменяем ключ контейнера и разбираемся с имитоставкой */
    if(( error = ak_encrypt_assign_container_key( &kcont,
                              salt, 32, iv, 8, vect, 32, password, pass_size )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect assign value of container's secret key" );
      break;
    }

    ak_file_read( &ifp, buffer, ak_min( 16, ctx.tag_size ));
    if(( error = ak_bckey_ctr( &kcont, buffer,
                                   buffer, ak_min( 16, ctx.tag_size ), iv, 8 )) != ak_error_ok ) {
      ak_error_message( error, __func__, "data decryption error" );
      break;
    }

    if( memcmp( im, buffer, ak_min( 16, ctx.tag_size)) != 0 ) {
      ak_error_message( error = ak_error_not_equal_data, __func__,
                                               "incorrect authentiction code for decrypted data" );
      break;
    }

   /* уточняем размер оставшихся данных и переходм к следующему фрагменту */
    total -= (current + head + ak_min( 16, ctx.tag_size));
   } /* конец while( total > 0) */

 /* очищием файловые дескрипторы, ключевые контексты, промежуточные данные и выходим */
  lab_exit4:
   ak_aead_destroy( &ctx );
   ak_file_close( &ofp );
   if( error != ak_error_ok ) {
    #ifdef AK_HAVE_UNISTD_H
     unlink( outfile );
    #else
     remove( outfile );
    #endif
   }

  lab_exit3:
   if( skey != NULL ) ak_oid_delete_object( ((ak_skey)skey)->oid, skey );
   if( asn ) ak_asn1_delete( asn );

  lab_exit2:
   ak_bckey_destroy( &kcont );

  lab_exit:
   ak_file_close( &ifp );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_decrypt_file_with_key( const char *filename, ak_skey key , const char *skeyfile,
                                                         char *outfile, const size_t outfile_size )
{
  int error = ak_error_ok;

  if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to container's encryption key" );
  if(( key->flags&key_flag_set_key ) == 0 ) return ak_error_message( ak_error_key_value, __func__,
                                                   "using unassigned container's encryption key" );
 /* отправляем массив ключевой информации в качестве пароля для расшифрования файла */
  if(( error = key->unmask( key )) != ak_error_ok ) return ak_error_message( error, __func__,
                                                                   "error key unmasking process" );
  error = ak_decrypt_file( filename, ( const char *)key->key, key->key_size ,
                                                                 skeyfile, outfile, outfile_size );
  if( key->set_mask( key ) != ak_error_ok ) ak_error_message( error, __func__,
                                                                     "error key masking process" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static ak_pointer ak_decrypt_file_load_secret_key( scheme_t scheme ,
                                                                ak_tlv tlv, const char *skeyfile )
{
  ak_asn1 seq = NULL;
  int error = ak_error_ok;
  size_t pknlen = 0, sknlen = 0;
  ak_pointer key = NULL, pkn = NULL, skn = NULL;

  /* выбор схемы для считывания последовательности */
   switch( scheme ) {    
    case ecies_scheme:
     /* определяем характеристики ожидаемого ключа */
      if( tlv == NULL ) {
        ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to incomming tlv element" );
        return NULL;
      }
      if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) ||
                  ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) {
        ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                      "incommint tlv element has not a sequence" );
        return NULL;
      }
      if(( seq = tlv->data.constructed ) == NULL ) {
        ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 sequence" );
        return NULL;
      }
      ak_asn1_first( seq );
      if( seq->current == NULL ) {
        ak_error_message( ak_error_null_pointer, __func__,
                                                "incomming sequence has not a public key number" );
        return NULL;
      }
      if(( error = ak_tlv_get_octet_string( seq->current, &pkn, &pknlen )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect reading of public key number" );
        return NULL;
      }
      if( ak_asn1_next( seq ) != ak_false ) { /* секретный номер ключа определен и мы можем его считать */
        if( seq->current == NULL ) {
          ak_error_message( ak_error_null_pointer, __func__,
                                                "incomming sequence has not a secret key number" );
          return NULL;
        }
        if(( error = ak_tlv_get_octet_string( seq->current, &skn, &sknlen )) != ak_error_ok ) {
          ak_error_message( error, __func__, "incorrect reading of secret key number" );
          return NULL;
        }
      }

     /* переходим к чтению ключа */
      if( skeyfile != NULL ) { /* самый очевидный случай - чтение из заданного файла */
        if(( key = ak_skey_load_from_file( skeyfile )) == NULL ) {
          ak_error_message( ak_error_get_value(), __func__, "incorrect reading of secret key" );
          return NULL;
        }

        /* проверяем совпадение номеров */
        if( memcmp( pkn, ((ak_signkey)key)->verifykey_number, ak_min( pknlen, 32))) {
          ak_error_message( ak_error_not_equal_data, __func__,  "reading a secret key that "
                                     "does not correspond to the public key used for encryption" );
          if( key != NULL ) ak_oid_delete_object( ((ak_skey)key)->oid, key );
          return NULL;
        }
        if( skn != NULL ) {
          if( memcmp( skn, ((ak_skey)key)->number, ak_min( sknlen, 32))) {
            ak_error_message( ak_error_not_equal_data, __func__,
                                                    "reading a secret key with different number" );
            if( key != NULL ) ak_oid_delete_object( ((ak_skey)key)->oid, key );
            return NULL;
          }
        }
      }
       else {
        /* здесь мы пытаемся найти секретный ключ по имеющимся метаданным */
        /* во-первых, пытаемся найти ключ с заданным номером в стандартном каталоге пользователя */
        /* во-вторых, предлагаем пользователю ввести имя файла с ключом,
           для которого задан номер соотвествующего открытого ключа
           (результат действия aktool k --show-public-key secret.key) */

        ak_error_message( ak_error_null_pointer, __func__,
                "using null pointer to secret key filename, define argument of \"--key\" option" );
        return NULL;
       }
      break;

    default:
      ak_error_message( ak_error_encrypt_scheme, __func__, "using unsupported encryption scheme" );
  }

 return key;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_decrypt_assign_encryption_keys( ak_aead ctx, ak_oid mode,
  scheme_t scheme, ak_signkey key, ak_uint8 *salt, size_t salt_size, ak_uint8 *iv, size_t iv_size,
                                  ak_uint8 *vect, size_t vect_size, ak_uint8 *buffer, size_t head )
{
  size_t cnt;
  struct wpoint U;
  ak_wcurve wc = NULL;
  ak_oid curvoid = NULL;
  struct kdf_state state;
  int error = ak_error_ok;
  ak_mpzn512 k, one = ak_mpzn512_one;

  switch( scheme ) {
    case ecies_scheme:
     /* получаем доступ к параметрам эллиптической кривой, на которой проводятся вычисления */
      if(( curvoid = ak_oid_find_by_data( key->key.data )) == NULL )
        return ak_error_message( ak_error_wrong_oid, __func__,
                        "secret key does not contain a pointer to the elliptic curve identifier" );
      if(( wc = (ak_wcurve)curvoid->data ) == NULL )
        return ak_error_message( ak_error_wrong_oid, __func__,
                        "secret key does not contain a pointer to the elliptic curve parameters" );
      if( head != ( 2*wc->size*sizeof( ak_uint64 ) +8 ))
        return ak_error_message( error = ak_error_wrong_length, __func__,
                                                       "using unexpected length of chunk header" );

     /* вырабатываем точку, которая будет использована для генерации ключевой информации */
      cnt = wc->size*sizeof( ak_uint64 );
      ak_mpzn_set_little_endian( U.x, wc->size, buffer, cnt, ak_true );
      ak_mpzn_set_little_endian( U.y, wc->size, buffer +cnt, cnt, ak_true );
      ak_mpzn_set_ui( U.z, wc->size, 1 );

      if( ak_wpoint_is_ok( &U, wc ) != ak_true )
        return ak_error_message( error = ak_error_curve_point, __func__,
                     "encrypted file contains a point which does not belongs to elliptic curve" );
      if( ak_wpoint_check_order( &U, wc ) != ak_true )
        return ak_error_message( error = ak_error_curve_point_order , __func__,
                                          "encrypted file contains a point with incorrect order" );

     /* возводим точку U в степень секретного ключа */
      ak_mpzn_mul_montgomery( k, ( ak_uint64 *) key->key.key, one, wc->q, wc->nq, wc->size );
      ak_wpoint_pow( &U, &U, k, wc->size, wc );
      ak_mpzn_mul_montgomery( k, ( ak_uint64 *)( key->key.key + key->key.key_size ),
                                                                     one, wc->q, wc->nq, wc->size);
      ak_wpoint_pow( &U, &U, k, wc->size, wc );
      ak_wpoint_reduce( &U, wc );

     /* вырабатываем необходимую производную информацию */
      ak_mpzn_to_little_endian( U.x, wc->size, buffer, cnt, ak_true );
      ak_mpzn_to_little_endian( U.y, wc->size, buffer + cnt, cnt, ak_true );

      if(( error = ak_kdf_state_create( &state, buffer, 2*cnt,
                    hmac_hmac512_kdf, NULL, 0, salt, salt_size, NULL, 0, 256 )) != ak_error_ok ) {
        ak_error_message( error, __func__, "wrong generation of initial secret key" );
        goto labex;
      }
      if(( error = ak_kdf_state_next( &state, iv, iv_size )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect generation of initial vector" );
        goto labex;
      }
      if(( error = ak_kdf_state_next( &state, vect, vect_size )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect generation of additional vector" );
        goto labex;
      }
      if(( error = ak_kdf_state_next( &state, buffer, 64 )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect generation of secret vector" );
        goto labex;
      }
      labex:
        ak_kdf_state_destroy( &state );
      if( error != ak_error_ok ) break;

     /* присваиваем ключевые значения */
      if(( error = ak_aead_set_keys( ctx, buffer, 32, buffer +32, 32 )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect assigning of secret keys" );
        break;
      }
      break;

    default:
      ak_error_message( error = ak_error_encrypt_scheme, __func__,
                                                           "using unsupported encryption scheme" );
  }

 /* в завершение, очищаем стековые и внешние переменные */
  if( error != ak_error_ok ) {
    ak_mpzn_set_ui( k, ak_mpzn512_size, 0 );
    ak_mpzn_set_ui( U.x, ak_mpzn512_size, 0 );
    ak_mpzn_set_ui( U.y, ak_mpzn512_size, 0 );
    ak_mpzn_set_ui( U.z, ak_mpzn512_size, 1 );
    memset( buffer, 0, head );
  }
   else {
     ak_random ernd = &((ak_bckey)ctx->encryptionKey)->key.generator;
     ak_random arnd = &((ak_bckey)ctx->authenticationKey)->key.generator;
     ak_ptr_wipe( buffer, head, arnd );
     ak_ptr_wipe( k, ak_mpzn512_size*sizeof( ak_uint64 ), ernd );
     ak_ptr_wipe( U.x, ak_mpzn512_size*sizeof( ak_uint64 ), ernd );
     ak_ptr_wipe( U.y, ak_mpzn512_size*sizeof( ak_uint64 ), arnd );
     ak_mpzn_set_ui( U.z, ak_mpzn512_size, 1 );
   }
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_encrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
