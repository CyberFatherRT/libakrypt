 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <libakrypt.h>

/* основная тестирующая программа */
 int main( void )
{
  mpz_t xm, ym;
  ak_mpzn256 x, y;
  size_t i = 0, j = 0, len, count = 100000; /* количество тестов */
  struct random generator;
  char sx[160], *sy;
  size_t cntstr = 0, cntmpz = 0, cntrev = 0;
  int exitcode = EXIT_SUCCESS, error = ak_error_ok;

  mpz_init( xm );
  mpz_init( ym );
  ak_libakrypt_create( ak_function_log_stderr );
  ak_random_create_lcg( &generator );

 /* путь преобразования и сравнения (функции сравнения считаются корректными):

    random -> mpzn (x) -> mpz (xm) -> mpzn (y) -> str (sy) -> mpzn (ym)
               |
               -> str (sx)

    1) sx == sy (сравнение строк)
    2) xm == ym (сравнение mpz)
 */

  for( i = 0; i < count; i++ ) {
    /* генерация случайного числа */
     ak_mpzn_set_random( x, ak_mpzn256_size, &generator );
    /* преобразование в mpz_t */
     ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
    /* обратное преобразование */
     ak_mpz_to_mpzn( xm, y, ak_mpzn256_size );

     if( ak_ptr_is_equal( x, y, ak_mpzn256_size*sizeof( ak_uint64 ))) cntstr++;

    /* преобразование строки в число mpz_t */
     mpz_set_str( ym, ak_mpzn_to_hexstr( y, ak_mpzn256_size ), 16 );
    /* сравнение двух чисел типа mpz_t */
     if( !mpz_cmp( xm, ym )) cntmpz++;
  }
  mpz_clear( ym );
  mpz_clear( xm );
  printf(" string comparison: %lu equals from %lu\n", cntstr, count );
  printf(" mpz_t comparison:  %lu equals from %lu\n", cntmpz, count );
  if( cntstr != count ) exitcode = EXIT_FAILURE;
  if( cntmpz != count ) exitcode = EXIT_FAILURE;


  /*
    random -> str (sx) -> mpzn (x) -> str (sy)

    сравнение sx == sy
  */

  char digits[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  cntstr = 0; cntmpz = 0; cntrev = 0;
  for( len = 1; len <= 64; len++ ) {
   /* тестируем строки всех длин от 1 до 64 символов (64 = 2*32 байта = 2* 256 бит) */

   for( i = 0; i < count; i++ ) {
      /* генерим случайную строку */
       memset( sx, 0, sizeof( sx ));
       for( j = 0; j < len; j++ ) {
         ak_uint8 byte;
         generator.random( &generator, &byte, 1 );
         sx[j] = digits[byte&0xF];
       }
       if(( error = ak_mpzn_set_hexstr( x, ak_mpzn256_size, sx )) != ak_error_ok ) cntstr++;
       if(( sy = (char *)ak_mpzn_to_hexstr( x, ak_mpzn256_size )) == NULL ) cntrev++;
       if( !strncmp( sx, sy+64-len, 160 )) cntmpz++;
   }

   printf(" len: %2lu [correct: %lu, errors: create - %lu, convert - %lu]\n", len, cntmpz, cntstr, cntrev );
   if( cntstr > 0 )  exitcode = EXIT_FAILURE;
   if( cntrev > 0 )  exitcode = EXIT_FAILURE;
   cntmpz = cntstr = cntrev = 0;
  }

  ak_random_destroy( &generator );
  ak_libakrypt_destroy();

  printf("exitcode: %d\n", exitcode );
 return exitcode;
}
