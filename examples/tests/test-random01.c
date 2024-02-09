/* Тестовый пример для оценки скорости реализации некоторых
   генераторов псевдо-случайных чисел.

   test-random01.c
*/

 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <libakrypt.h>

/* основная тестирующая функция */
 int test_function( ak_function_random create, const char *result )
{ 
 clock_t time;
 struct random generator;
 ak_uint8 seed[4] = { 0x13, 0xAE, 0x4F, 0x0E }; /* константа */
 int i = 0, retval = ak_true;
 ak_uint8 buffer[1024];
 const char *string = NULL;

 /* создаем генератор */
  create( &generator );
  printf( "%13s: ", generator.oid->name[0] ); fflush( stdout );
  memset( buffer, 0, sizeof( buffer ));

 /* инициализируем константным значением */
  if( generator.randomize_ptr != NULL )
    ak_random_randomize( &generator, seed, sizeof( seed ));

 /* теперь вырабатываем необходимый тестовый объем данных */
  time = clock();
  for( i = 0; i < 1024*4; i++ ) ak_random_ptr( &generator, buffer, 1024 );
  time = clock() - time;

  printf("%s (%f sec) ", string = ak_ptr_to_hexstr( buffer, 32, ak_false ),
                                             (double)time / (double)CLOCKS_PER_SEC );

 /* проверка только для тех, кому устанавливали начальное значение */
  if( result ) {
    if( strncmp( result, string, 32 ) != 0 ) { printf("Wrong\n"); retval = ak_false; }
     else { printf("Ok\n"); retval = ak_true; }
  } else { printf("\n"); retval = ak_true; }

  ak_random_destroy( &generator );
 return retval;
}

 int main( void )
{
 int error = EXIT_SUCCESS;

 printf(" random number generators speed test for libakrypt, version %s\n\n", ak_libakrypt_version( ));
 if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* последовательно запускаем генераторы на тестирование */
   if( test_function( ak_random_create_lcg,
      "47b7ef2b729133a3e9853e0f4ffe040154a7622b7827e71bc6e48dff98c27f61" ) != ak_true )
     error = EXIT_FAILURE;

   if( test_function( ak_random_create_nlfsr,
      "564efe09877d05d4929b52aaf89a7923b1d6a4af4d2c180686e58e231c71826e" ) != ak_true )
     error = EXIT_FAILURE;

   if( test_function( ak_random_create_hrng,
      "ea225f4cf869abf48af25ae23c42a9408b2589d5bc0a218ad0e809e270f40913" ) != ak_true )
     error = EXIT_FAILURE;

  #ifdef _WIN32
   if( test_function( ak_random_create_winrtl, NULL ) != ak_true ) error = EXIT_FAILURE;
  #endif

  #if defined(__unix__) || defined(__APPLE__)
   if( test_function( ak_random_create_random, NULL ) != ak_true ) error = EXIT_FAILURE;
   if( test_function( ak_random_create_urandom, NULL ) != ak_true ) error = EXIT_FAILURE;
  #endif

   printf("\n");
   ak_libakrypt_destroy();
 return error;
}
