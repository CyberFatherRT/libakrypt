/* ----------------------------------------------------------------------------------------------- */
 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  ak_uint8 data[5004], imito[16];
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38 };
  ak_uint8 imito_magma[8] = { 0xb9, 0x10, 0xf2, 0x8e, 0xbf, 0xfa, 0x52, 0xe3 };
  ak_uint8 imito_kuznechik[16] = { 0x0c, 0xf1, 0xed, 0x90, 0xe4, 0x04, 0x1b, 0x85,
                                   0x60, 0x15, 0x49, 0xc1, 0x90, 0x80, 0x10, 0xc9 };

  int exitcode = EXIT_FAILURE;
  ak_uint32 seed = 1317;
  struct bckey bkey;
  struct random generator;

  ak_libakrypt_create( ak_function_log_stderr );

 /* формируем как бы случайные данные */
  ak_random_create_lcg( &generator );
  ak_random_randomize( &generator, &seed, 4 );
  ak_random_ptr( &generator, data, sizeof( data ));
  printf("random data: %s ... ", ak_ptr_to_hexstr( data, 25, ak_false ));
  printf("%s\n", ak_ptr_to_hexstr( data + sizeof(data) -25, 25, ak_false ));

 /* M1. создаем ключ и вычисляем первое значение имитовставки */
  ak_bckey_create_magma( &bkey );
  ak_bckey_set_key( &bkey, testkey, 32 );
  ak_bckey_cmac( &bkey, data, sizeof( data ), imito, 8 );
  printf("imito: %s (ak_bckey_cmac)\n", ak_ptr_to_hexstr( imito, 8, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_magma, 8 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }

 /* M2. вычисляем имитовставку с помощью update/finalize */
  memset( imito, 0, sizeof( imito ));
  printf("clean:    %d\n", ak_bckey_cmac_clean( &bkey ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data, 5000 ));
  printf("finalize: %d\n", ak_bckey_cmac_finalize( &bkey, data +5000, 4, imito, 8 ));
  printf("imito: %s (ak_bckey_update/finalize - вариант 1)\n", ak_ptr_to_hexstr( imito, 8, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_magma, 8 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }

 /* M3. вычисляем имитовставку с помощью update/finalize */
  memset( imito, 0, sizeof( imito ));
  printf("clean:    %d\n", ak_bckey_cmac_clean( &bkey ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data, 1000 ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data +1000, 1000 ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data +2000, 1000 ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data +3000, 1000 ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data +4000, 1000 ));
  printf("finalize: %d\n", ak_bckey_cmac_finalize( &bkey, data +5000, 4, imito, 8 ));
  printf("imito: %s (ak_bckey_update/finalize - вариант 2)\n", ak_ptr_to_hexstr( imito, 8, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_magma, 8 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }

 /* M4. вычисляем имитовставку с помощью update/finalize */
  memset( imito, 0, sizeof( imito ));
  printf("clean:    %d\n", ak_bckey_cmac_clean( &bkey ));
  printf("finalize: %d\n", ak_bckey_cmac_finalize( &bkey, data, sizeof( data ), imito, 8 ));
  printf("imito: %s (ak_bckey_update/finalize - вариант 3)\n", ak_ptr_to_hexstr( imito, 8, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_magma, 8 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }

 /* M5. вычисляем имитовставку с помощью update/finalize */
  memset( imito, 0, sizeof( imito ));
  printf("clean:    %d\n", ak_bckey_cmac_clean( &bkey ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data, sizeof( data )));
  printf("finalize: %d\n", ak_bckey_cmac_finalize( &bkey, NULL, 0, imito, 8 ));
  printf("imito: %s (ak_bckey_update/finalize - вариант 4)\n", ak_ptr_to_hexstr( imito, 8, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_magma, 8 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }
  ak_bckey_destroy( &bkey );

 /* K1. создаем ключ и вычисляем первое значение имитовставки */
  ak_bckey_create_kuznechik( &bkey );
  ak_bckey_set_key( &bkey, testkey, 32 );
  ak_bckey_cmac( &bkey, data, sizeof( data ), imito, 16 );
  printf("imito: %s (ak_bckey_cmac)\n", ak_ptr_to_hexstr( imito, 16, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_kuznechik, 16 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }

 /* K2. вычисляем имитовставку с помощью update/finalize */
  memset( imito, 0, sizeof( imito ));
  printf("clean:    %d\n", ak_bckey_cmac_clean( &bkey ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data, 4992 ));
  printf("finalize: %d\n", ak_bckey_cmac_finalize( &bkey, data +4992, 12, imito, 16 ));
  printf("imito: %s (ak_bckey_update/finalize - вариант 1)\n", ak_ptr_to_hexstr( imito, 16, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_kuznechik, 16 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }

 /* K3. вычисляем имитовставку с помощью update/finalize */
  memset( imito, 0, sizeof( imito ));
  printf("clean:    %d\n", ak_bckey_cmac_clean( &bkey ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data, 2048 ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data +2048, 2048 ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data +4096, 896 ));
  printf("finalize: %d\n", ak_bckey_cmac_finalize( &bkey, data +4992, 12, imito, 16 ));
  printf("imito: %s (ak_bckey_update/finalize - вариант 2)\n", ak_ptr_to_hexstr( imito, 16, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_kuznechik, 16 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }

 /* K4. вычисляем имитовставку с помощью update/finalize */
  memset( imito, 0, sizeof( imito ));
  printf("clean:    %d\n", ak_bckey_cmac_clean( &bkey ));
  printf("finalize: %d\n", ak_bckey_cmac_finalize( &bkey, data, sizeof( data ), imito, 16 ));
  printf("imito: %s (ak_bckey_update/finalize - вариант 3)\n", ak_ptr_to_hexstr( imito, 16, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_kuznechik, 16 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }

 /* K5. вычисляем имитовставку с помощью update/finalize */
  memset( imito, 0, sizeof( imito ));
  printf("clean:    %d\n", ak_bckey_cmac_clean( &bkey ));
  printf("update:   %d\n", ak_bckey_cmac_update( &bkey, data, sizeof( data )));
  printf("finalize: %d\n", ak_bckey_cmac_finalize( &bkey, NULL, 0, imito, 16 ));
  printf("imito: %s (ak_bckey_update/finalize - вариант 4)\n", ak_ptr_to_hexstr( imito, 16, ak_false ));
  if( ak_ptr_is_equal_with_log( imito, imito_kuznechik, 16 ) != ak_true ) {
    ak_bckey_destroy( &bkey );
    goto ex;
  }
  ak_bckey_destroy( &bkey );

 /* завершаем тестирование */
  exitcode = EXIT_SUCCESS;
  ex:
    ak_libakrypt_destroy();
 return exitcode;
}

