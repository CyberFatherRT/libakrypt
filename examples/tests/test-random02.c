/* Тестовый пример для оценки генератора псевдослучайных чисел hrng

   test-random02.c
*/

 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <libakrypt.h>

/* структура генератора, хранящая его внутреннее состояние */
 struct random_hrng {
   struct hash hctx;
   ak_mpzn512 counter;
   ak_uint8 buffer[64];
   size_t capacity;
 } *hs;

 int main( void )
{
  struct random hrng;
  int i, error = ak_error_ok;

  ak_log_set_level( ak_log_standard );
  ak_libakrypt_create( ak_function_log_stderr );

  printf("hrng create code: %d\n", error = ak_random_create_hrng( &hrng ));
  if( error != ak_error_ok ) return EXIT_FAILURE;

 /* это код выводит внутреннее состояние генератора
    в практических приложениях его использование нецелесообразно */
  hs = (struct random_hrng *)hrng.data.ctx;
  printf("counter:  %s\n", ak_ptr_to_hexstr( hs->counter, 64, ak_false ));
  printf("buffer:   %s\n", ak_ptr_to_hexstr( hs->buffer, 64, ak_false ));
  printf("capacity: %lld\n\n", (long long int)hs->capacity );

 /* выводим пятнадцать случаныйх фрагментов разной длины */
  for( i = 0; i < 15; i++ ) {
     ak_uint8 buffer[16];
     size_t length = rand()%16;

     ak_random_ptr( &hrng, buffer, length );
     printf("data: %s\n", ak_ptr_to_hexstr( buffer, length, ak_false ));
  }

  printf("hrng destroy code: %d\n", error = ak_random_destroy( &hrng ));
  if( error != ak_error_ok ) return EXIT_FAILURE;

  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
