/* ----------------------------------------------------------------------------------------------- */
/* Тестовый пример, иллюстрирующий работу c aead контекстом (для всех доступных алгоритмов)

   test-aead.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

 /* константные значения ключей из ГОСТ Р 34.13-2015 */
  ak_uint8 authenticationKey[32] = { /* ключ из приложения А */
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 encryptionKey[32] = { /* ключ из приложения Б */
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

 /* тестовые данные */
 ak_uint8 packet[41 + 67] = {
     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA,
    /* зашифровываем с этого момента */
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0xCC, 0xBB, 0xAA };

 /* тестовые синхропосылки */
  ak_uint8 iv[32] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92, 0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f };

 /* глобальные контрольные суммы */
  ak_uint8 packet_hmac256[32], packet_hmac512[64], packet_nmac256[32];
 /* где-то в памяти */
  ak_uint8 *header, *body;


/* ----------------------------------------------------------------------------------------------- */
 static void test_macs( void );
 static int test_packet( ak_aead ctx, ak_pointer header, ak_pointer body );
 static int test_file( ak_aead ctx, ak_pointer header, ak_pointer body );
 static int test_packet_imito( ak_aead ctx, ak_pointer data );
 static int test_file_imito( ak_aead ctx, ak_pointer data );

/* ----------------------------------------------------------------------------------------------- */
/*                                 основная тестовая программа                                     */
/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
   ak_oid oid = NULL;
   int exitcode = EXIT_FAILURE;

  /* по-умолчанию сообщения об ошибках выволятся в журналы syslog
     мы изменяем стандартный обработчик, на вывод сообщений в консоль */
   ak_log_set_level( ak_log_maximum );
   ak_libakrypt_create( ak_function_log_stderr );

  /* выводим контрольные суммы от входных данных
     такие же значения должны получаться в ряде алгоритмов аутентифицированного шифрования */
   test_macs();

  /* перебираем все реализованные в библиотеке алгоритмы аутентифицированного шифрования */
   oid = ak_oid_find_by_mode( aead );
   while( oid != NULL ) {
     struct aead ctx;
     exitcode = EXIT_FAILURE;

    /* создаем контекст алгоритма */
     if(( ak_aead_create_oid( &ctx,
                             ak_true /* создаем два ключа: шифрования и имитозащиты */,
                             oid )) == ak_error_ok )
       printf("\nрежим: %s (%s) [контекст создан успешно]\n", oid->name[0], oid->id[0] );
      else {
        printf("режим: %s (%s) [ошибка создания контекста]\n", oid->name[0], oid->id[0] );
        continue;
      }
     printf(" - размер входного блока: %d\n", (int)ak_aead_get_block_size( &ctx ));
     printf(" - размер синхропосылки:  %d\n", (int)ak_aead_get_iv_size( &ctx ));
     printf(" - размер имитовставки:   %d\n", (int)ak_aead_get_tag_size( &ctx ));

    /* присваиваем ключевые значения */
     if( ak_aead_set_keys( &ctx,
                           encryptionKey, 32,     /* ключ шифрования и его длина */
                           authenticationKey, 32 /* ключ имитозащиты и его длина */
                         ) == ak_error_ok )
       printf(" - ключевые значения успешно присвоены\n");
      else {
        printf(" - ошибка присвоения ключевых значений\n");
        goto loopex;
      }

    /* далее, мы демонстрируем несколько сценариев использование созданного контекста

       1. сценарий первый (шифрование сетевого трафика):
          данные содержатся в одном буфере packet,
          последовательно записаны сначала заголовок (41 байт), потом тело пакета (67)

          сценарий реализуется при помощи функции ak_aead_encrypt() */

      if( test_packet( &ctx, packet, packet +41 ) != ak_error_ok ) {
        printf(" - ошибка тестирования пакетных данных\n");
        goto loopex;
      }

    /* 2. сценарий второй (шифрование областей в памяти):
          ассоциированные данные и данные для шифрования содержатся в двух,
          не последовательных областях памяти,
          длины данных и их значения те же, что и в предыдущем примере

          сценарий также реализуется при помощи функции ak_aead_encrypt() */

      memcpy(( header = malloc( 48 )) +3, packet, 41 );
      memcpy(( body = malloc( 72 )) +5, packet + 41, 67 );

      if( test_packet( &ctx, header +3, body +5 ) != ak_error_ok ) {
        printf(" - вариант с раздельными областями памяти не поддерживается\n");
      }

      free( header ); free( body );

    /* 3. сценарий третий (шифрование файлов):
          ассоциированные данные, а потом и данные для шифрования,
          поступают последовательными фрагментами (считываются в буфер с диска или послупают сетевым потоком),
          длина которых кратна длине блока обрабатываемых данных.
          как и в предыдущем случае, данные могут располагаться в произвольных областях памяти

          сценарий реализуется при помощи функций:
           - ak_aead_auth_clean()
           - ak_aead_auth_update()
           - ak_aead_encrypt_clean()
           - ak_aead_encrypt_update() / ak_aead_decrypt_update()
           - ak_aead_auth_update()                                                                          */

      memcpy(( header = malloc( 48 )) +1, packet, 41 );
      memcpy(( body = malloc( 72 )) +2, packet + 41, 67 );

      if( test_file( &ctx, header +1, body +2 ) != ak_error_ok ) {
        printf(" - ошибка тестирования данных, поступающих фрагментами\n");
        goto loopex;
      }

      free( header ); free( body );

     /* 4. Далее идут сценарии вычисления имитовставки, без шифрования данных.

           сценарий четвертый - все данные для имитозащиты расположены в одной области памяти
           и рассматриваются как ассоциированные данные AEAD алгоритма.
           Данные для зашифрования на вход не подаются.

           сценарий реализуется при помощи функции ak_aead_mac()
           устанавливать значение ключа шифрования не обязательно */

      if( test_packet_imito( &ctx, packet ) != ak_error_ok ) {
        printf(" - ошибка вычисления имитовставки\n");
        goto loopex;
      }

     /* 5. сценарий пятый - данные для имитозащиты поступают фрагментами,
           длина которых кратна длине блока, обрабатываемого AEAD алгоритмом.
           Данные для зашифрования на вход не подаются.

           сценарий реализуется при помощи функций:
            - ak_aead_auth_clean()
            - ak_aead_auth_update()
           - ak_aead_auth_update()                                           */

      if( test_file_imito( &ctx, packet ) != ak_error_ok ) {
        printf(" - ошибка пакетной обработки при вычислении имитовставки\n");
        goto loopex;
      }

    /* уничтожаем контекст алгоритма */
     exitcode = EXIT_SUCCESS;
     loopex:
       ak_aead_destroy( &ctx );
       if( exitcode != EXIT_SUCCESS ) return EXIT_FAILURE;

    /* ищем следующий алгоритм */
     oid = ak_oid_findnext_by_mode( oid, aead );
   }

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/* простая проверка зашифрования/расшифрования данных, расположенных в памяти последовательно      */
/* ----------------------------------------------------------------------------------------------- */
 int test_packet( ak_aead ctx, ak_pointer header, ak_pointer body )
{
  int error = ak_error_ok;
  ak_uint8 tag[64], *control = NULL;

  memset( tag, 0, sizeof( tag ));
 /* шифруем данные */
  if(( error = ak_aead_encrypt( ctx,
                    header,
                    41,
                    body,
                    body,
                    67,
                    iv,
                    ctx->iv_size,
                    tag,
                    ctx->tag_size )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "ошибка зашифрования данных" );
  }
  printf(" - enc: %s ", ak_ptr_to_hexstr( body, 67, ak_false ));

 /* расшифровываем */
  if(( error = ak_aead_decrypt( ctx,
                    header,
                    41,
                    body,
                    body,
                    67,
                    iv,
                    ctx->iv_size,
                    tag, /* сравниваем с вычисленным ранее значением */
                    ctx->tag_size )) != ak_error_ok ) {
    printf("Wrong\n");
    return ak_error_message_fmt( ak_error_not_equal_data, __func__ , "ошибка при расшифровании" );
  }

  printf("Ok\n - mac: %s ", ak_ptr_to_hexstr( tag, ctx->tag_size, ak_false )); fflush( stdout );

 /* сверяем с константными значениями */
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0],
                                                "streebog256" ) != NULL ) control = packet_hmac256;
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0],
                                                "streebog512" ) != NULL ) control = packet_hmac512;
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0], "nmac" ) != NULL )
                                                                          control = packet_nmac256;
  if( control != NULL ) {
    if( ak_ptr_is_equal_with_log( tag, control, ctx->tag_size ))
      printf("[Ok]\n");
     else {
      printf(" - имитовставки не совпадает с вычисленным ранее константным значением\n");
      error = ak_error_not_equal_data;
     }
    return error;
  }
  printf("[%s]\n", __func__ );
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int test_file( ak_aead ctx, ak_pointer header, ak_pointer body )
{
  int error = ak_error_ok;
  ak_uint8 icode[64], icode2[64], *control = NULL;
  size_t blocks, tail;
  ak_uint8 *ptr;
  size_t shift;

/* 1. выполняем поблоковое зашифрование информации:
   мы нарезаем ассоциированные даные и шифртекст на блоки фиксированной длины,
   после чего, выполняем обновление (update) внутреннего состояния aead контекста */
  ptr = header;
  shift = 0;
  blocks = 41/ctx->block_size;
  tail = 41%ctx->block_size;

 /* эта поправка на длину последнего блока нужна для корректной работы режима xtsmac */
  if(( blocks > 0 ) && ( tail > 0 ) && ( tail < ( ctx->block_size >> 1 ))) {
    blocks--; tail += ctx->block_size;
  }

  memset( icode, 0, sizeof( icode ));
  ak_aead_auth_clean( ctx, iv, ctx->iv_size );
  for( size_t i = 0; i < blocks; i++, shift += ctx->block_size ) {
    ak_aead_auth_update( ctx, ptr +shift, ctx->block_size );
  }
  if( tail > 0 ) ak_aead_auth_update( ctx, ptr +shift, tail );

  ptr = body;
  shift = 0;
  blocks = 67/ctx->block_size;
  tail = 67%ctx->block_size;

 /* эта поправка на длину последнего блока нужна для корректной работы режима xtsmac */
  if(( blocks > 0 ) && ( tail > 0 ) && ( tail < ( ctx->block_size >> 1 ))) {
    blocks--; tail += ctx->block_size;
  }

  ak_aead_encrypt_clean( ctx, iv, ctx->iv_size );
  for( size_t i = 0; i < blocks; i++, shift += ctx->block_size ) {
    ak_aead_encrypt_update( ctx, ptr +shift, ptr +shift, ctx->block_size );
  }
  if( tail > 0 )
    ak_aead_encrypt_update( ctx, ptr +shift, ptr +shift, tail );
  ak_aead_finalize( ctx, icode, ctx->tag_size );

  printf(" - enc: %s ", ak_ptr_to_hexstr( body, 67, ak_false ));


 /* 2. совершенно аналогично, также фрагментами, расшифровываем и
    сравниваем значения имитовставок. */
  ptr = header;
  shift = 0;
  blocks = 41/ctx->block_size;
  tail = 41%ctx->block_size;

 /* эта поправка на длину последнего блока нужна для корректной работы режима xtsmac */
  if(( blocks > 0 ) && ( tail > 0 ) && ( tail < ( ctx->block_size >> 1 ))) {
    blocks--; tail += ctx->block_size;
  }

  memset( icode2, 0, sizeof( icode2 ));
  ak_aead_auth_clean( ctx, iv, ctx->iv_size );
  for( size_t i = 0; i < blocks; i++, shift += ctx->block_size ) {
    ak_aead_auth_update( ctx, ptr +shift, ctx->block_size );
  }
  if( tail > 0 ) ak_aead_auth_update( ctx, ptr +shift, tail );

  ptr = body;
  shift = 0;
  blocks = 67/ctx->block_size;
  tail = 67%ctx->block_size;

 /* эта поправка на длину последнего блока нужна для корректной работы режима xtsmac */
  if(( blocks > 0 ) && ( tail > 0 ) && ( tail < ( ctx->block_size >> 1 ))) {
    blocks--; tail += ctx->block_size;
  }

  ak_aead_encrypt_clean( ctx, iv, ctx->iv_size );
  for( size_t i = 0; i < blocks; i++, shift += ctx->block_size ) {
    ak_aead_decrypt_update( ctx, ptr +shift, ptr +shift, ctx->block_size );
  }
  if( tail > 0 )
    ak_aead_decrypt_update( ctx, ptr +shift, ptr +shift, tail );
  ak_aead_finalize( ctx, icode2, ctx->tag_size );

  if( ak_ptr_is_equal( icode2, icode, ctx->tag_size ) == ak_true ) {
    printf("Ok\n - mac: %s ", ak_ptr_to_hexstr( icode2, ctx->tag_size, ak_false )); fflush( stdout );
  } else {
     printf("Wrong\n - mac: %s ", ak_ptr_to_hexstr( icode2, ctx->tag_size, ak_false )); fflush( stdout );
     error = ak_error_not_equal_data;
   }

 /* сверяем с константными значениями */
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0],
                                                "streebog256" ) != NULL ) control = packet_hmac256;
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0],
                                                "streebog512" ) != NULL ) control = packet_hmac512;
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0], "nmac" ) != NULL )
                                                                          control = packet_nmac256;
  if( control != NULL ) {
    if( ak_ptr_is_equal_with_log( icode, control, ctx->tag_size ))
      printf("[Ok]\n");
     else {
      printf(" - имитовставка не совпадает с вычисленным ранее константным значением\n");
      error = ak_error_not_equal_data;
     }
    return error;
  }
  printf("[%s]\n", __func__ );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int test_packet_imito( ak_aead ctx, ak_pointer adata )
{
  int error = ak_error_ok;
  ak_uint8 tag[64], *control = NULL;

  memset( tag, 0, sizeof( tag ));
 /* шифруем данные */
  if(( error = ak_aead_mac( ctx,
                    adata,
                    41+67,
                    iv,
                    ctx->iv_size,
                    tag,
                    ctx->tag_size )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "ошибка зашифрования данных" );
  }

  printf(" - имитовставка вычислена\n - mac: %s ", ak_ptr_to_hexstr( tag, ctx->tag_size, ak_false )); fflush( stdout );

 /* сверяем с константными значениями */
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0],
                                                "streebog256" ) != NULL ) control = packet_hmac256;
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0],
                                                "streebog512" ) != NULL ) control = packet_hmac512;
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0], "nmac" ) != NULL )
                                                                          control = packet_nmac256;
  if( control != NULL ) {
    if( ak_ptr_is_equal_with_log( tag, control, ctx->tag_size ))
      printf("[Ok]\n");
     else {
      printf(" - имитовставка не совпадает с вычисленным ранее константным значением\n");
      error = ak_error_not_equal_data;
     }
    return error;
  }
  printf("[%s]\n", __func__ );
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int test_file_imito( ak_aead ctx, ak_pointer adata )
{
  int error = ak_error_ok;
  ak_uint8 tag[64], tag2[64], *control = NULL;
  size_t blocks, tail;
  ak_uint8 *ptr;
  size_t shift;

 /* вычисление имитовставки (по частям, без нарезки на короткие блоки) */
  memset( tag, 0, ctx->tag_size );
  ak_aead_auth_clean( ctx, iv, ctx->iv_size );
  ak_aead_auth_update( ctx, adata, 41+67 );
  ak_aead_finalize( ctx, tag, ctx->tag_size );
  printf(" - имитовставка по частям вычислена\n - mac: %s ", ak_ptr_to_hexstr( tag, ctx->tag_size, ak_false )); fflush( stdout );

 /* еще раз тоже самое, но теперь с нарезкой на маленькие блоки */
  ptr = adata;
  shift = 0;
  blocks = (41 +67)/ctx->block_size;
  tail = (41 +67)%ctx->block_size;

 /* эта поправка на длину последнего блока нужна для корректной работы режима xtsmac */
  if(( blocks > 0 ) && ( tail > 0 ) && ( tail < ( ctx->block_size >> 1 ))) {
    blocks--; tail += ctx->block_size;
  }

  memset( tag2, 0, sizeof( tag2 ));
  ak_aead_auth_clean( ctx, iv, ctx->iv_size );
  for( size_t i = 0; i < blocks; i++, shift += ctx->block_size ) {
    ak_aead_auth_update( ctx, ptr +shift, ctx->block_size );
  }
  if( tail > 0 ) ak_aead_auth_update( ctx, ptr +shift, tail );
  ak_aead_finalize( ctx, tag2, ctx->tag_size );

  if( ak_ptr_is_equal( tag2, tag, ctx->tag_size ) == ak_true ) {
    printf("[Ok]\n - mac: %s ", ak_ptr_to_hexstr( tag2, ctx->tag_size, ak_false )); fflush( stdout );
  } else {
     printf("[Wrong]\n - mac:%s ", ak_ptr_to_hexstr( tag2, ctx->tag_size, ak_false )); fflush( stdout );
     error = ak_error_not_equal_data;
   }

 /* сверяем с константными значениями */
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0],
                                                "streebog256" ) != NULL ) control = packet_hmac256;
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0],
                                                "streebog512" ) != NULL ) control = packet_hmac512;
  if( strstr( ((ak_skey)ctx->authenticationKey)->oid->name[0], "nmac" ) != NULL )
                                                                          control = packet_nmac256;
  if( control != NULL ) {
    if( ak_ptr_is_equal_with_log( tag, control, ctx->tag_size ))
      printf("[Ok]\n");
     else {
      printf(" - имитовставка не совпадает с вычисленным ранее константным значением\n");
      error = ak_error_not_equal_data;
     }
    return error;
  }
  printf("[%s]\n", __func__ );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 void test_macs( void )
{
  struct hmac ctx;

   printf("тестовые значения имитовставок\n");

  /* hmac-streebog256 */
   ak_hmac_create_streebog256( &ctx );
   ak_hmac_set_key( &ctx, authenticationKey, 32 );
   ak_hmac_ptr( &ctx, packet, 41+67, packet_hmac256, 32 );
   ak_hmac_destroy( &ctx );

  /* hmac-streebog512 */
   ak_hmac_create_streebog512( &ctx );
   ak_hmac_set_key( &ctx, authenticationKey, 32 );
   ak_hmac_ptr( &ctx, packet, 41+67, packet_hmac512, 64 );
   ak_hmac_destroy( &ctx );

  /* nmac */
   ak_hmac_create_nmac( &ctx );
   ak_hmac_set_key( &ctx, authenticationKey, 32 );
   ak_hmac_ptr( &ctx, packet, 41+67, packet_nmac256, 32 );
   ak_hmac_destroy( &ctx );

   printf(" - hmac-streebog256:\n    %s\n\n", ak_ptr_to_hexstr( packet_hmac256, 32, ak_false ));
   printf(" - hmac-streebog512:\n    %s\n\n", ak_ptr_to_hexstr( packet_hmac512, 64, ak_false ));
   printf(" - nmac-streebog:\n    %s\n", ak_ptr_to_hexstr( packet_nmac256, 32, ak_false ));
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    test-aead.c  */
/* ----------------------------------------------------------------------------------------------- */
