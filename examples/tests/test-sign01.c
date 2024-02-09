/* Пример показывает простейшую процедуру электроной подписи.

   test-sign01.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <libakrypt.h>

 int main( int argc, char *argv[] )
{
  struct signkey sk;
  struct verifykey pk;
  struct random generator;
  int result = EXIT_SUCCESS;
  ak_uint8 sign[128];
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }
 /* создаем генератор псевдослучайных последовательностей */
  if( ak_random_create_lcg( &generator ) != ak_error_ok ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* инициализируем секретный ключ с заданной эллиптической кривой */
  if( ak_signkey_create_str( &sk, "cspa") != ak_error_ok ) {
    result = EXIT_FAILURE;
    goto exlab;
  }
 /* устанавливаем значение ключа */
  ak_signkey_set_key( &sk, testkey, 32 );
 /* подстраиваем ключ и устанавливаем ресурс */
  ak_skey_set_resource_values( &sk.key, key_using_resource,
               "digital_signature_count_resource", 0, time(NULL)+2592000 );
 /* только теперь подписываем данные
    в качестве которых выступает исполняемый файл */
  ak_signkey_sign_file( &sk, &generator, argv[0], sign, sizeof( sign ));
  printf("file:   %s\nsign:   %s\n", argv[0],
         ak_ptr_to_hexstr( sign, ak_signkey_get_tag_size(&sk), ak_false ));

 /* формируем открытый ключ */
  ak_verifykey_create_from_signkey( &pk, &sk );
 /* проверяем подпись */
  if( ak_verifykey_verify_file( &pk, argv[0], sign ) == ak_true )
    printf("verify: Ok\n");
   else { printf("verify: Wrong\n"); result = EXIT_FAILURE; }

  ak_signkey_destroy( &sk );
  ak_verifykey_destroy( &pk );

  exlab:
    ak_random_destroy( &generator );
    ak_libakrypt_destroy();
 return result;
}
