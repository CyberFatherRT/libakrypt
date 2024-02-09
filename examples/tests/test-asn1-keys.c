 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>

/* --------------------------------------------------------------------------------------------- */
 int bckey_test( ak_oid );
 int hmac_test( ak_oid );
 int signkey_test( ak_oid );

/* определяем функцию, которая будет имитировать чтение пароля пользователя */
 ssize_t get_user_password( const char *prompt, char *password, size_t psize, password_t flag )
{
  (void)prompt;
  (void)flag;

  memset( password, 0, psize );
  ak_snprintf( password, psize, "password" );
 return strlen( password );
}

/* --------------------------------------------------------------------------------------------- */
 int main(void)
{
  ak_oid oid = NULL;
  int result = EXIT_SUCCESS;

 /* Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* начинаем с того, что определяем функцию чтения пароля */
  ak_libakrypt_set_password_read_function( get_user_password );

 /* тестируем ключи алгоритмов блочного шифрования */
  if(( result = bckey_test( ak_oid_find_by_name( "kuznechik" ))) != EXIT_SUCCESS ) goto lab1;
  if(( result = bckey_test( ak_oid_find_by_name( "magma" ))) != EXIT_SUCCESS ) goto lab1;
  if(( result = hmac_test( ak_oid_find_by_name( "hmac-streebog256" ))) != EXIT_SUCCESS ) goto lab1;
  if(( result = hmac_test( ak_oid_find_by_name( "hmac-streebog512" ))) != EXIT_SUCCESS ) goto lab1;

 /* тестируем ключи алгоритма ЭП для нескольких кривых */
  oid = ak_oid_find_by_mode( wcurve_params );
  while( oid != NULL ) {
     if(( result = signkey_test( oid )) != EXIT_SUCCESS ) goto lab1;
     oid = ak_oid_findnext_by_mode( oid, wcurve_params );
   }
  lab1:

  ak_libakrypt_destroy();
 return result;
}

/* --------------------------------------------------------------------------------------------- */
 int bckey_test( ak_oid oid )
{
  struct bckey bkey, *lkey = NULL;
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38 };
  ak_uint8 testdata[31] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f };
  ak_uint8 out[31], out2[31], im[16], im2[16];
  char filename[128], keylabel[64];
  int result = EXIT_FAILURE;
  ak_pointer key = NULL;

   /* создаем ключ, который будет помещаться в контейнер */
    ak_bckey_create_oid( &bkey, oid );
   /* присваиваем ключу константное значение */
    ak_bckey_set_key( &bkey, testkey, sizeof( testkey ));
   /* шифруем тестируемые данные */
    ak_bckey_ctr( &bkey, testdata, out, sizeof( testdata ), testkey, bkey.bsize );
   /* вычисляем имитовставку от тестируемых данных */
    ak_bckey_cmac( &bkey, testdata, sizeof( testdata ), im, bkey.bsize );
     printf("%-10s: %s ", bkey.key.oid->name[0], ak_ptr_to_hexstr( out, sizeof(out), ak_false ));
     printf("(cmac: %s)\n", ak_ptr_to_hexstr( im, bkey.bsize, ak_false ));
   /* экпортируем ключ в файл (в der-кодировке) */
    ak_snprintf( keylabel, sizeof( keylabel ),
                                            "keylabel-%s-%03u", oid->name[0], bkey.key.number[0] );
    ak_skey_set_label( (ak_skey)&bkey, keylabel, 0 );
    if( ak_skey_export_to_file_with_password( &bkey,
                   "password", 8, filename, sizeof( filename ), asn1_der_format ) == ak_error_ok )
      printf("key exported to %s file\n\n", filename );
   /* удаляем ключ */
    ak_bckey_destroy( &bkey );

   /* импортируем ключ из файла */
    if(( lkey = key = ak_skey_load_from_file( filename )) == NULL ) return EXIT_FAILURE;
   /* дополнительно проверяем код возврата функции,
      однако в случае ошибки, эта часть кода не должна выполняться */
    if( ak_error_get_value() != ak_error_ok ) {
      printf("Exit on error value! Pointer is'nt equal to NULL\n");
      return EXIT_FAILURE;
    }

   /* выводим данные о ключе */
    printf("%s: %s (%s)\n", ak_libakrypt_get_engine_name( ((ak_skey)key)->oid->engine ),
                                        ((ak_skey)key)->oid->name[0], ((ak_skey)key)->oid->id[0] );
    printf("      number: %s\n", ak_ptr_to_hexstr( ((ak_skey)key)->number, 32, ak_false ));
    printf("       label: %s\n", ((ak_skey)key)->label );
    printf("    resource: [type: %u, value: %ld]\n",
           ((ak_skey)key)->resource.value.type, (long int)((ak_skey)key)->resource.value.counter );
    printf("  not before: %s", ctime( &((ak_skey)key)->resource.time.not_before ));
    printf("   not after: %s", ctime( &((ak_skey)key)->resource.time.not_after ));
    printf("       flags: %016llx\n", ((ak_skey)key)->flags );
    printf("      buffer: %s\n", ak_ptr_to_hexstr( ((ak_skey)key)->key,
                                                           2*((ak_skey)key)->key_size, ak_false ));

   /* шифруем тестируемые данные еще раз*/
    if( ak_bckey_ctr( lkey, testdata, out2, sizeof( testdata ),
                                                 testkey, lkey->bsize ) != ak_error_ok ) goto lab1;
   /* вычисляем имитовставку от тестируемых данных */
    if( ak_bckey_cmac( key, testdata, sizeof( testdata ), im2,
                                                          lkey->bsize ) != ak_error_ok ) goto lab1;

    printf("%-10s: %s ", lkey->key.oid->name[0], ak_ptr_to_hexstr( out, sizeof(out), ak_false ));
    printf("(cmac: %s)\n", ak_ptr_to_hexstr( im2, lkey->bsize, ak_false ));

   /* проверяем корректность считывания */
    if( ak_ptr_is_equal_with_log( out, out2, sizeof( testdata ))) printf("encryption: Ok\n");
      else { printf("encryption: Wrong\n"); goto lab1; }
    if( ak_ptr_is_equal_with_log( im, im2, ((ak_bckey)key)->bsize )) printf("cmac: Ok\n\n");
      else { printf("cmac: Wrong\n\n"); goto lab1; }

    result = EXIT_SUCCESS;

   /* самоуничтожение */
    lab1:
     ak_oid_delete_object( lkey->key.oid, key ); // или так ((ak_skey)key)->oid, key );

 return result;
}

/* --------------------------------------------------------------------------------------------- */
 int hmac_test( ak_oid oid )
{
  struct hmac hctx, lctx;
  ak_uint8 testkey[64] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f, 0x00 };

  ak_uint8 data[12] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
  ak_uint8 out[64], out2[64];
  char filename[128];
  int result = EXIT_FAILURE;

  /* создаем ключ, который будет помещаться в контейнер */
   ak_hmac_create_oid( &hctx, oid );
  /* присваиваем ключу константное значение */
   ak_hmac_set_key( &hctx, testkey, sizeof( testkey ));
  /* вычисляем имитовставку */
   ak_hmac_ptr( &hctx, data, sizeof( data ), out, sizeof( out ));
   printf("%s: %s\n", hctx.key.oid->name[0],
                                 ak_ptr_to_hexstr( out, ak_hmac_get_tag_size( &hctx ), ak_false ));
  /* экпортируем ключ в файл (в der-кодировке) */
   ak_skey_export_to_file_with_password( &hctx,
                                    "password", 8, filename, sizeof( filename ), asn1_pem_format );
   printf("key exported to %s file\n\n", filename );
  /* удаляем ключ */
   ak_hmac_destroy( &hctx );

  /* импортируем ключ из файла */
   if( ak_skey_import_from_file( &lctx, hmac_function, filename ) != ak_error_ok )
     return EXIT_FAILURE;

  /* выводим данные о ключе */
   printf("%s: %s (%s)\n", ak_libakrypt_get_engine_name( lctx.key.oid->engine ),
                                                      lctx.key.oid->name[0], lctx.key.oid->id[0] );
   printf("      number: %s\n", ak_ptr_to_hexstr( lctx.key.number, 32, ak_false ));
   printf("       label: %s\n", lctx.key.label );
   printf("    resource: [type: %u, value: %ld]\n",
                         lctx.key.resource.value.type, (long int)lctx.key.resource.value.counter );
   printf("  not before: %s", ctime( &lctx.key.resource.time.not_before ));
   printf("   not after: %s", ctime( &lctx.key.resource.time.not_after ));
   printf("       flags: %016llx\n", lctx.key.flags );

   if( ak_hmac_ptr( &lctx, data, sizeof( data ), out2, sizeof( out2 )) != ak_error_ok ) goto lab1;
   printf("hmac: %s", ak_ptr_to_hexstr( out2, ak_hmac_get_tag_size( &lctx ), ak_false ));

   if( ak_ptr_is_equal_with_log( out, out2, ak_hmac_get_tag_size( &lctx )))
      { printf(" Ok\n\n"); result = EXIT_SUCCESS; }
    else printf(" Wrong\n\n");

   lab1: ak_hmac_destroy( &lctx );

 return result;
}

/* --------------------------------------------------------------------------------------------- */
 int signkey_test( ak_oid curvoid )
{
  int result = EXIT_SUCCESS;
  ak_oid oid = NULL;
  ak_uint8 testkey[64] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f, 0x00 };
  ak_uint8 sign[128];
  char filename[128], tname[256];
  struct signkey skey, lkey;
  struct verifykey vkey;
  struct random generator;

  ak_random_create_lcg( &generator );

   if(( curvoid->engine == identifier ) && ( curvoid->mode == wcurve_params )) {
     ak_signkey_create( &skey, (ak_wcurve)curvoid->data );
     ak_signkey_set_key( &skey, testkey, (((ak_wcurve)curvoid->data)->size << 3 ));
   } else return EXIT_FAILURE;
   printf("---- oid: %s (%s)\n", curvoid->id[0], curvoid->name[0] );

   ak_verifykey_create_from_signkey( &vkey, &skey );       /* этим вызовом мы поместили */
   ak_verifykey_destroy( &vkey );  /* в контекст секретного ключа номер открытого ключа */

   printf("secret key number:\t%s\n",
                         ak_ptr_to_hexstr( skey.key.number, sizeof( skey.key.number ), ak_false ));
   printf("subject key identifier:\t%s\n",
             ak_ptr_to_hexstr( skey.verifykey_number, sizeof( skey.verifykey_number ), ak_false ));

  /* подписываем данные */
   ak_signkey_sign_ptr( &skey, &generator, testkey, 13, sign, sizeof( sign ));
   printf("signature: %s ... \n", ak_ptr_to_hexstr( sign, 8, ak_false ));
   ak_random_destroy( &generator );

  /* создаем необязательное имя для ключа */
   ak_snprintf( tname, sizeof( tname ), "keylabel-%s-%03u", curvoid->name[0], skey.key.number[0] );
   ak_skey_set_label( (ak_skey)&skey, tname, 0 );
  /* сохраняем ключ */
   ak_skey_export_to_file_with_password( &skey,
                                    "password", 8, filename, sizeof( filename ), asn1_der_format );
  /* уничтожаем ключ */
   ak_signkey_destroy( &skey );

  /* считываем ключ */
   if( ak_skey_import_from_file( &lkey, sign_function, filename ) != ak_error_ok )
     return EXIT_FAILURE;

  /* выводим данные о ключе */
   printf("%s: %s (%s)\n", ak_libakrypt_get_engine_name( lkey.key.oid->engine ),
                                                      lkey.key.oid->name[0], lkey.key.oid->id[0] );
   printf("       number: %s\n", ak_ptr_to_hexstr( lkey.key.number, 32, ak_false ));
   printf("        label: %s\n", lkey.key.label );
   printf("     resource: [type: %u, value: %ld]\n",
                         lkey.key.resource.value.type, (long int)lkey.key.resource.value.counter );
   printf("   not before: %s", ctime( &lkey.key.resource.time.not_before ));
   printf("    not after: %s", ctime( &lkey.key.resource.time.not_after ));
   printf("        flags: %016llx\n", lkey.key.flags );

   if(( oid = ak_oid_find_by_data( lkey.key.data )) == NULL ) {
     printf(" incorrect elliptic curve oid\n");
     goto lab1;
   }
   printf("        curve: %s (%s)\n", oid->id[0], oid->name[0] );
   printf("   verify key: %s\n", ak_ptr_to_hexstr( lkey.verifykey_number, 32, ak_false ));

  /* создаем открытый ключ */
   ak_verifykey_create_from_signkey( &vkey, &lkey );
   printf("  created key: %s\n", ak_ptr_to_hexstr( vkey.number, 32, ak_false ));
   printf("verify: ");
   if( ak_verifykey_verify_ptr( &vkey, testkey, 13, sign )) printf("Ok\n\n");
     else { printf("Wrong\n\n"); result = EXIT_FAILURE; }

  lab1:
   ak_signkey_destroy( &lkey );
 return result;
}
