 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>

/* --------------------------------------------------------------------------------------------- */
/* определяем функцию, которая будет имитировать чтение пароля пользователя */
 ssize_t get_user_password( const char *prompt, char *password, size_t psize, password_t flag )
{
   (void)prompt;
   (void)flag;

   memset( password, 0, psize );
   ak_snprintf( password, psize, "hello" );
 return strlen( password );
}

/* --------------------------------------------------------------------------------------------- */
 int main( void )
{
   struct bckey key;
   ak_pointer *pk = NULL;
   struct random generator;
   int exitstatus = EXIT_FAILURE;
   ak_uint8 seed[8] = { 0xc6, 0x53, 0x24, 0xa2, 0x53, 0xa2, 0xc5, 0x21 };
   ak_uint8 in[17] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11 };
   ak_uint8 out[17], dec[17];

  /* инициализируем библиотеку */
   if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

  /* вырабатываем секретный ключ с помощью дсч */
   ak_random_create_lcg( &generator );
   ak_random_randomize( &generator, seed, 8 );
   ak_bckey_create_kuznechik( &key );
   ak_bckey_set_key_random( &key, &generator );

  /* сохраняем данные в файл */
   if(( ak_skey_export_to_file_with_password(
                           &key, "hello", 5, "delme.key", 0, asn1_der_format )) == ak_error_ok ) {
    printf("file export: Ok (with password)\n");
   }
   if(( ak_skey_export_to_file_unencrypted(
                          &key, "delme.unencrypted.key", 0, asn1_der_format )) == ak_error_ok ) {
    printf("file export: Ok (unencrypted)\n");
   }

   printf("ctr: %d\n", ak_bckey_ctr( &key, in, out, 17, seed, 8 ));

  /* удаляем клю из памяти */
   ak_bckey_destroy( &key );
   ak_random_destroy( &generator );

  /*  чтение зашифрованного контейнера*/
   ak_libakrypt_set_password_read_function( get_user_password );
   if(( pk = ak_skey_load_from_file("delme.key")) != NULL ) {
     printf("delme.key Ok\n");
   } else {
       printf("delme.key wrong\n");
       goto endl;
     }

   ak_bckey_ctr( (ak_bckey)pk, out, dec, 17, seed, 8 );
   if( ak_ptr_is_equal( in, dec, 17 )) {
     printf("decrypt Ok\n");
   }
    else printf("decrypt wrong\n");
   ak_skey_delete( pk );

  /*  чтение незашифрованного контейнера*/
   if(( pk = ak_skey_load_from_file("delme.unencrypted.key")) != NULL ) {
     printf("delme.unencrypted.key Ok\n");
   } else {
       printf("delme.unencrypted.key wrong\n");
       goto endl;
     }
   memset( dec, 0, 17 );
   ak_bckey_ctr( (ak_bckey)pk, out, dec, 17, seed, 8 );
   if( ak_ptr_is_equal( in, dec, 17 )) {
     printf("decrypt Ok\n");
   }
    else printf("decrypt wrong\n");
   ak_skey_delete( pk );
   exitstatus = EXIT_SUCCESS;

  endl:
   ak_error_set_value( ak_error_ok );
   ak_libakrypt_destroy();
  return exitstatus;
}
