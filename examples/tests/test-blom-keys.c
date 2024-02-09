/* ----------------------------------------------------------------------------------------------- */
 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>

 int user_test( const ak_uint32 , const ak_uint32 );
 int user_generate_test( const ak_uint32 , const ak_uint32 , ak_uint8 * );
 int user_generate_abonent_test( ak_blomkey , ak_uint8 * );
 int user_generate_pairwise_test( ak_blomkey , ak_blomkey , ak_uint8 *, bool_t );
 int user_import_matrix_test( ak_uint8 * );
 int user_import_abonent_test( ak_uint8 * );

 static char *IDone = "Mr. Eric Arthur Blair known as George Orwell";
 static char *IDtwo = "J. Knot";

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  int error = EXIT_FAILURE;

 /* инициализируем библиотеку и устанавливаем функцию получения пароля */
  ak_libakrypt_create( ak_function_log_stderr );

  if(( error = user_test( 128, ak_galois256_size )) != EXIT_SUCCESS ) goto labex;
  if(( error = user_test( 512, ak_galois256_size )) != EXIT_SUCCESS ) goto labex;
  if(( error = user_test( 1024, ak_galois256_size )) != EXIT_SUCCESS ) goto labex;

  if(( error = user_test( 128, ak_galois512_size )) != EXIT_SUCCESS ) goto labex;
  if(( error = user_test( 512, ak_galois512_size )) != EXIT_SUCCESS ) goto labex;

/* также, при желании, можно потестировать большие значения параметра безопасности

  if(( error = user_test( 2048, ak_galois256_size )) != EXIT_SUCCESS ) goto labex;
  if(( error = user_test( 4096, ak_galois256_size )) != EXIT_SUCCESS ) goto labex;
  if(( error = user_test( 1024, ak_galois512_size )) != EXIT_SUCCESS ) goto labex;
                                                                                    */
  if(( error = user_test( 5, ak_galois256_size )) != EXIT_SUCCESS ) goto labex;
  labex: ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int user_test( const ak_uint32 size, const ak_uint32 count )
{
  time_t timea;
  ak_uint8 check[64];

  memset( check, 0, sizeof( check ));
  printf("\n%s [size: %u, field: GF(2^%u)]\n", __func__, size, count << 3 );

  timea = clock();
   if( user_generate_test( size, count, check ) != EXIT_SUCCESS ) return EXIT_FAILURE;
  timea = clock() - timea;
  printf("user_generate_test - running time %f\n", (double) timea / (double) CLOCKS_PER_SEC );

  timea = clock();
   if( user_import_matrix_test( check ) != EXIT_SUCCESS ) return EXIT_FAILURE;
  timea = clock() - timea;
  printf("user_import_matrix_test - running time %f\n",
                                                     (double) timea / (double) CLOCKS_PER_SEC );

  timea = clock();
   if( user_import_abonent_test( check ) != EXIT_SUCCESS ) return EXIT_FAILURE;
  timea = clock() - timea;
  printf("user_import_abonent_test - running time %f\n",
                                                     (double) timea / (double) CLOCKS_PER_SEC );
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int user_generate_test( const ak_uint32 size, const ak_uint32 count, ak_uint8 *check )
{
  ak_uint32 i, j;
  struct blomkey master;
  struct random generator;
  int exitcode = EXIT_FAILURE;

 /* вырабатываем мастер-ключ */
  ak_random_create_lcg( &generator );
  if( ak_blomkey_create_matrix( &master, size, count, &generator ) == ak_error_ok )
    printf("%s - generation of initial matrix is Ok\n", __func__ );
   else goto labex;

 /* вывод ключевой информации */
  if( master.size <= 5 ) {
    printf("matrix (%u bytes):\n", master.size*master.size*master.count );
    for( i = 0; i < ak_min( 5, master.size ); i++ ) {
      for( j = 0; j < ak_min( 5, master.size ); j++ ) {
         printf("a[%u,%u]: %s\n", i, j, ak_ptr_to_hexstr(
                       ak_blomkey_get_element_by_index( &master, i, j ), master.count, ak_false ));
      }
      printf("\n");
    }
    printf("\n");
  }

 /* сохраняем мастер-ключ в файл */
  if( ak_blomkey_export_to_file_with_password( &master,
                                                    "hello", 5, "master.key", 0 ) == ak_error_ok )
    printf("%s - initial matrix saved to \"master.key\" file\n", __func__);
   else {
    printf("%s - wrong export of initial matrix to \"master.key\" file\n", __func__ );
    goto labex1;
  }

  exitcode = user_generate_abonent_test( &master, check );

  labex1:
    ak_blomkey_destroy( &master );

  labex:
    ak_random_destroy( &generator );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int user_generate_abonent_test( ak_blomkey master, ak_uint8 *check )
{
  int exitcode = EXIT_FAILURE;
  struct blomkey abonent_one, abonent_two;

  if( ak_blomkey_create_abonent_key( &abonent_one, master, IDone, strlen( IDone )) == ak_error_ok )
    printf("%s - generation of secret key for \"%s\" is Ok\n", __func__, IDone );
   else {
     printf("%s - incorrect generation of secret key for \"%s\"\n", __func__, IDone );
     return exitcode;
   }

  if( ak_blomkey_export_to_file_with_password( &abonent_one,
                                                "hello", 5, "client-one.key", 0 ) == ak_error_ok )
    printf("%s - secret key for abonent \"%s\" saved to \"client-one.key\" file\n",
                                                                                 __func__, IDone );
   else {
     printf("%s - wrong import a secret key for abonent \"%s\" to \"client-one.key\" file\n",
                                                                                 __func__, IDone );
     goto labex1;
   }

  if( ak_blomkey_create_abonent_key( &abonent_two, master, IDtwo, strlen( IDtwo )) == ak_error_ok )
    printf("%s - generation of secret key for \"%s\" is Ok\n", __func__, IDtwo );
   else {
     printf("%s - incorrect generation of secret key for \"%s\"\n", __func__, IDtwo );
     goto labex1;
   }
  if( ak_blomkey_export_to_file_with_password( &abonent_two,
                                                "hello", 5, "client-two.key", 0 ) == ak_error_ok )
    printf("%s - secret key for abonent \"%s\" saved to \"client-two.key\" file\n",
                                                                                 __func__, IDtwo );
   else {
     printf("%s - wrong import a secret key for abonent \"%s\" to \"client-two.key\" file\n",
                                                                                 __func__, IDtwo );
     goto labex2;
   }
                          /* false => значение вектора check вырабатывается, но не проверяется */
   exitcode = user_generate_pairwise_test( &abonent_one, &abonent_two, check, ak_false );

   labex2:
    ak_blomkey_destroy( &abonent_two );

   labex1:
    ak_blomkey_destroy( &abonent_one );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int user_generate_pairwise_test( ak_blomkey abonent_one, ak_blomkey abonent_two,
                                                               ak_uint8 *check, bool_t check_flag )
{
  ak_oid oid = NULL;
  ak_pointer oneKey, twoKey;
  ak_uint8 onehmac[64], twohmac[64];
  int exitcode = EXIT_FAILURE;

  if( abonent_one->count == 32 ) oid = ak_oid_find_by_name( "hmac-streebog256" );
  if( abonent_one->count == 64 ) oid = ak_oid_find_by_name( "hmac-streebog512" );
  if( oid == NULL ) {
    printf("%s - incorrect value of abonent's count (%u)\n", __func__ , abonent_one->count );
    return EXIT_FAILURE;
  }

 /* вычисляем ключи парной связи и проверяем, что они совпадают */
  if(( oneKey = ak_blomkey_new_pairwise_key( abonent_one, IDtwo, strlen( IDtwo ), oid )) != NULL ) {
    printf("%s - creation of %s pairwise key for \"%s\" is Ok\n", __func__, oid->name[0], IDone );
    ak_hmac_ptr( oneKey, "make love not war", 16, onehmac, ak_hmac_get_tag_size( oneKey ));
  }
   else {
    printf("%s - creation of %s pairwise key for \"%s\" is wrong\n", __func__, oid->name[0], IDone );
    return EXIT_FAILURE;
   }

  if(( twoKey = ak_blomkey_new_pairwise_key( abonent_two, IDone, strlen( IDone ), oid )) != NULL ) {
    printf("%s - creation of %s pairwise key for \"%s\" is Ok\n", __func__, oid->name[0], IDtwo );
    ak_hmac_ptr( twoKey, "make love not war", 16, twohmac, ak_hmac_get_tag_size( twoKey ));
  }
   else {
    printf("%s - creation of %s pairwise key for \"%s\" is wrong\n", __func__, oid->name[0], IDtwo );
    goto labex1;
   }

 /* сравниваем полученные значения */
  if( ak_ptr_is_equal( onehmac, twohmac, ak_hmac_get_tag_size( oneKey )))
    printf("%s - all keys Ok\n", __func__ );
   else {
     printf("%s - something wrong with generated keys.... \n", __func__ );
     goto labex2;
   }

  if( check_flag ) {
    if( ak_ptr_is_equal( onehmac, check, ak_hmac_get_tag_size( oneKey ))) {
      printf("%s - checked value is Ok\n", __func__ );
      printf("check: %s\n", ak_ptr_to_hexstr( check, ak_hmac_get_tag_size( oneKey ), ak_false ));
      exitcode = EXIT_SUCCESS;
    }
     else {
      printf("%s - checked value is Wrong\n", __func__ );
      printf("value: %s\n", ak_ptr_to_hexstr( onehmac, ak_hmac_get_tag_size( oneKey ), ak_false ));
      printf("check: %s\n", ak_ptr_to_hexstr( check, ak_hmac_get_tag_size( oneKey ), ak_false ));
     }
  } else {
      memcpy( check, onehmac, ak_hmac_get_tag_size( oneKey ));
      printf("check: %s\n", ak_ptr_to_hexstr( check, ak_hmac_get_tag_size( oneKey ), ak_false ));
      exitcode = EXIT_SUCCESS;
  }

 labex2:
   ak_oid_delete_object( oid, twoKey );
 labex1:
   ak_oid_delete_object( oid, oneKey );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int user_import_matrix_test( ak_uint8 *check )
{
  ak_uint32 i, j;
  struct blomkey master;
  int exitcode = EXIT_FAILURE;

 /* считываем мастер-ключ */
  if( ak_blomkey_import_from_file_with_password( &master, "hello", 5, "master.key" ) == ak_error_ok )
    printf("%s - import of initial matrix is Ok\n", __func__ );
   else return exitcode;

 /* вывод ключевой информации */
  if( master.size <= 5 ) {
    printf("matrix (%u bytes):\n", master.size*master.size*master.count );
    for( i = 0; i < ak_min( 5, master.size ); i++ ) {
      for( j = 0; j < ak_min( 5, master.size ); j++ ) {
         printf("a[%u,%u]: %s\n", i, j, ak_ptr_to_hexstr(
                       ak_blomkey_get_element_by_index( &master, i, j ), master.count, ak_false ));
      }
      printf("\n");
    }
    printf("\n");
  }

  exitcode = user_generate_abonent_test( &master, check );
  ak_blomkey_destroy( &master );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int user_import_abonent_test( ak_uint8 *check )
{
  int exitcode = EXIT_FAILURE;
  struct blomkey abonent_one, abonent_two;

  if( ak_blomkey_import_from_file_with_password( &abonent_one, "hello", 5,
                                                               "client-one.key" ) == ak_error_ok )
    printf("%s - import a secret key for \"%s\" is Ok\n", __func__, IDone );
   else {
     printf("%s - incorrect import of secret key for \"%s\"\n", __func__, IDone );
     return exitcode;
   }

  if( ak_blomkey_import_from_file_with_password( &abonent_two, "hello", 5,
                                                               "client-two.key" ) == ak_error_ok )
    printf("%s - import a secret key for \"%s\" is Ok\n", __func__, IDtwo );
   else {
     printf("%s - incorrect import of secret key for \"%s\"\n", __func__, IDtwo );
     goto labex1;
   }
                                            /* true => значение вектора check проверяется */
   exitcode = user_generate_pairwise_test( &abonent_one, &abonent_two, check, ak_true );
   ak_blomkey_destroy( &abonent_two );

   labex1:
    ak_blomkey_destroy( &abonent_one );

 return exitcode;
}
