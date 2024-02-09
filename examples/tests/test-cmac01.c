/* ----------------------------------------------------------------------------------------------- */
 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  int j, i = 0, count;
  FILE *fp = NULL;
  struct bckey key;
  ak_uint8 buffer[13] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c };
  ak_uint8 imito[16];
  ak_uint8 check1[16] = { 0x68, 0x4c, 0xbb, 0xf3, 0xde, 0xd6, 0xfa, 0x20,
                          0x37, 0xa0, 0x8a, 0x6e, 0x83, 0xd0, 0x54, 0x0a };
  ak_uint8 check2[16] = { 0x67, 0xd6, 0xaa, 0xc1, 0x2a, 0x76, 0xc4, 0x56,
                          0x73, 0x83, 0xc1, 0xd1, 0x5f, 0xcc, 0x9b, 0xdf };
  ak_uint8 check3[8]  = { 0xea, 0xab, 0x3f, 0x33, 0x5b, 0x5e, 0x43, 0x07 };
  ak_uint8 check4[8]  = { 0x7c, 0x34, 0x17, 0x3e, 0x3c, 0x41, 0x65, 0xd3 };
  ak_uint8 data[5000];

  ak_libakrypt_create( ak_function_log_stderr );

 /* K.1. формируем ключ Кузнечика */
  ak_bckey_create_kuznechik( &key );
  ak_bckey_set_key_from_password( &key, "password", 8, "sugar", 5 );

 /* K.2. вычисляем имитовставку от данных положительной длины */
  printf("cmac (%s): ", ak_bckey_cmac( &key, buffer, sizeof( buffer ),
                                              imito, key.bsize ) == ak_error_ok ? "Ok" : "Wrong" );
  for( i = 0; i < key.bsize; i++ ) printf("%02x ", imito[i] );
  printf("\n");
  if( !ak_ptr_is_equal( imito, check1, key.bsize )) {
    printf("result incorrect\n");
    return EXIT_FAILURE;
  }

 /* K.3. вычисляем имитовставку от данных нулевой длины */
  printf("cmac (%s): ", ak_bckey_cmac( &key, NULL, 0,
                                              imito, key.bsize ) == ak_error_ok ? "Ok" : "Wrong" );
  for( i = 0; i < key.bsize; i++ ) printf("%02X ", imito[i] );
  printf("\n");
  if( !ak_ptr_is_equal( imito, check2, key.bsize )) {
    printf("result incorrect\n");
    return EXIT_FAILURE;
  }

 /* K.4. тестируем вычисление имитовставки от данных */
  count = 0;
  for( i = 0; i <= sizeof( data ); i++ ) {
    bool_t result;
    for( j = 0; j < i; j++ ) data[j] = j;

   /* хешируем память */
    printf("cmac (%s): ",  ak_bckey_cmac( &key, data, i, imito, key.bsize ) == ak_error_ok ? "Ok" : "Wrong" );
    for( int k = 0; k < key.bsize; k++ ) printf("%02X ", imito[k] );
    printf("  [%2d octets]\n", i );
   /* хешируем файл */
    fp = fopen( "testdata", "wb" );
    fwrite( data, 1, i, fp );
    fclose( fp );
    printf("cmac (%s): ",  ak_bckey_cmac_file( &key, "testdata", check1, key.bsize ) == ak_error_ok ? "Ok" : "Wrong" );
    for( int k = 0; k < key.bsize; k++ ) printf("%02X ", check1[k] );
    count += (1 - ( result = ak_ptr_is_equal( imito, check1, key.bsize )));
    printf(" %s\n", result == ak_true ? "Ok" : "Wrong" );
  }

  ak_bckey_destroy( &key );
  if( count > 0 ) {
    printf("%d differences found\n", count );
    return EXIT_FAILURE;
  }


 /* M.1. формируем ключ Магмы */
  ak_bckey_create_magma( &key );
  ak_bckey_set_key_from_password( &key, "password", 8, "sugar", 5 );

 /* M.2. вычисляем имитовставку от данных положительной длины */
  printf("cmac (%s): ", ak_bckey_cmac( &key, buffer, sizeof( buffer ),
                                              imito, key.bsize ) == ak_error_ok ? "Ok" : "Wrong" );
  for( i = 0; i < key.bsize; i++ ) printf("%02X ", imito[i] );
  printf("\n");
  if( !ak_ptr_is_equal( imito, check3, key.bsize )) {
    printf("result incorrect\n");
    return EXIT_FAILURE;
  }

 /* M.3. вычисляем имитовставку от данных нулевой длины */
  printf("cmac (%s): ", ak_bckey_cmac( &key, NULL, 0,
                                              imito, key.bsize ) == ak_error_ok ? "Ok" : "Wrong" );
  for( i = 0; i < key.bsize; i++ ) printf("%02X ", imito[i] );
  printf("\n");
  if( !ak_ptr_is_equal( imito, check4, key.bsize )) {
    printf("result incorrect\n");
    return EXIT_FAILURE;
  }

 /* M.4. тестируем вычисление имитовставки от данных */
  count = 0;
  for( i = 0; i <= sizeof( data ); i++ ) {
    bool_t result;
    for( j = 0; j < i; j++ ) data[j] = j;

   /* возвращаем ресурс ключа */
    key.key.resource.value.counter = 65536;
   /* хешируем память */
    printf("cmac (%s): ",  ak_bckey_cmac( &key, data, i, imito, key.bsize ) == ak_error_ok ? "Ok" : "Wrong" );
    for( int k = 0; k < key.bsize; k++ ) printf("%02X ", imito[k] );
    printf("  [%2d octets]\n", i );
   /* хешируем файл */
    fp = fopen( "testdata", "wb" );
    fwrite( data, 1, i, fp );
    fclose( fp );
    printf("cmac (%s): ",  ak_bckey_cmac_file( &key, "testdata", check1, key.bsize ) == ak_error_ok ? "Ok" : "Wrong" );
    for( int k = 0; k < key.bsize; k++ ) printf("%02X ", check1[k] );
    count += (1 - ( result = ak_ptr_is_equal( imito, check1, key.bsize )));
    printf(" %s\n", result == ak_true ? "Ok" : "Wrong" );
  }

  ak_bckey_destroy( &key );
  if( count > 0 ) {
    printf("%d differences found\n", count );
    return EXIT_FAILURE;
  }
 return EXIT_SUCCESS;
}
