 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <libakrypt.h>
 #include <gmp.h>

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции сложения чисел */
 bool_t add_test( size_t size, size_t count )
{
  size_t i = 0, val = 0;
  mpz_t xm, ym, zm, tm;
  ak_mpznmax x, y, z;
  struct random generator;

  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);
  ak_random_create_lcg( &generator );

 /*
    в одном цикле
     random -> mpzn (x) - ........... -> mpz (xm)
                 |                         |
                 + -> z -> mpz (zm)        + -> mpz (tm)
                 |                         |
     random -> mpzn (y) - ........... -> mpz (ym)

     сравнение zm == tm
 */

  for( i = 0; i < count; i++ ) {
    memset( x, 0, ak_mpznmax_size*sizeof(ak_uint64));
    memset( y, 0, ak_mpznmax_size*sizeof(ak_uint64));
    memset( z, 0, ak_mpznmax_size*sizeof(ak_uint64));
    ak_mpzn_set_random( x, size, &generator );
    ak_mpzn_set_random( y, size, &generator );
    ak_mpzn_to_mpz( x, size, xm );
    ak_mpzn_to_mpz( y, size, ym );

    z[size] = ak_mpzn_add( z, x, y, size );

    ak_mpzn_to_mpz( z, size+1, zm ); /* не забываем знак переноса */
    mpz_add( tm, xm, ym );

    if( mpz_cmp(tm, zm) == 0 ) val++;
  }
  printf(" correct additions %ld from %ld\n", val, count );
  ak_random_destroy( &generator );
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);

 return ( val == count );
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операций сравнения и вычитания чисел */
 bool_t sub_test( size_t size, size_t count )
{
  int res = 0;
  size_t i = 0, val = 0, zerocnt = 0, limbwrong = 0;
  mpz_t xm, ym, zm, tm;
  ak_mpznmax x, y, z;
  ak_uint64 limb = 0;
  struct random generator;

  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);
  ak_random_create_lcg( &generator );

 /*
    в одном цикле
     random -> mpzn (x) - ........... -> mpz (xm)
                 |
                 if ( x > y ) (mpzn) z = x - y |
                                               |->  z -> mpz (zm)
                  else (mpzn) z = y - x        |
                 |
     random -> mpzn (y) - ........... -> mpz (ym)

     сравнение 1)     zm == xm - ym
               2) или zm == ym - xm
 */

  for( i = 0; i < count; i++ ) {
     memset( x, 0, ak_mpznmax_size*sizeof(ak_uint64));
     memset( y, 0, ak_mpznmax_size*sizeof(ak_uint64));
     memset( z, 0, ak_mpznmax_size*sizeof(ak_uint64));
     ak_mpzn_set_random( x, size, &generator );
     ak_mpzn_set_random( y, size, &generator );
     ak_mpzn_to_mpz( x, size, xm );
     ak_mpzn_to_mpz( y, size, ym );

     res = ak_mpzn_cmp( x, y, size );
     if( res  == 1 ) {
       if((limb = ak_mpzn_sub( z, x, y, size )) != 0 ) limbwrong++;
       ak_mpzn_to_mpz( z, size, zm );
       mpz_sub( tm, xm, ym );
     } else {
              if( !res ) zerocnt++;
              if(( limb = ak_mpzn_sub( z, y, x, size )) != 0 ) limbwrong++;
              ak_mpzn_to_mpz( z, size, zm );
              mpz_sub( tm, ym, xm );
            }

     if( mpz_cmp(tm, zm) == 0 ) val++;
  }
  printf(" correct substractions %ld from %ld (with %ld zeroes and %ld errors)\n",
                                                                   val, count, zerocnt, limbwrong );
  ak_random_destroy( &generator );
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);
 return ( val == count );
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции умножения чисел */
 bool_t mul_test( size_t size, size_t count )
{
  size_t i = 0, val = 0;
  mpz_t xm, ym, zm, tm;
  ak_mpznmax x, y, z;
  struct random generator;

  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);
  ak_random_create_lcg( &generator );

 /*
    в одном цикле
     random -> mpzn (x) - ........... -> mpz (xm)
                 |                         |
                 * -> z -> mpz (zm)        * -> mpz (tm)
                 |                         |
     random -> mpzn (y) - ........... -> mpz (ym)

     сравнение zm == tm
 */

  for( i = 0; i < count; i++ ) {
   /* обнуляем данные */
    memset( x, 0, ak_mpznmax_size*sizeof(ak_uint64));
    memset( y, 0, ak_mpznmax_size*sizeof(ak_uint64));
    memset( z, 0, ak_mpznmax_size*sizeof(ak_uint64));

   /* генерим случайные значения и копируем их в mpz */
    ak_mpzn_set_random( x, size, &generator );
    ak_mpzn_set_random( y, size, &generator );
    ak_mpzn_to_mpz( x, size, xm );
    ak_mpzn_to_mpz( y, size, ym );
    ak_mpzn_mul( z, x, y, size );

    ak_mpzn_to_mpz( z, 2*size, zm );
    mpz_mul( tm, xm, ym );
    if( mpz_cmp(tm, zm) == 0 ) val++;
  }

  printf(" correct multiplications %ld from %ld\n", val, count );
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);
  ak_random_destroy( &generator );

 return ( val == count );
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции умножения большого числа на одноразрядное */
 bool_t mul_ui_test( size_t size, size_t count )
{
  size_t i = 0, val = 0;
  ak_uint64 d = 0;
  mpz_t xm, zm, tm;
  ak_mpznmax x, z;
  struct random generator;

  mpz_init(xm);
  mpz_init(zm);
  mpz_init(tm);
  ak_random_create_lcg( &generator );

 /*
    в одном цикле
     random -> mpzn (x) - ........... -> mpz (xm)
                 |                         |
                 * -> z -> mpz (zm)        * -> mpz (tm)
                 |                         |
     random -> (int) d - ........... -> int (d)

     сравнение zm == tm
 */

  for( i = 0; i < count; i++ ) {
   /* обнуляем данные */
    memset( x, 0, ak_mpznmax_size*sizeof(ak_uint64));
    memset( z, 0, ak_mpznmax_size*sizeof(ak_uint64));

   /* генерим случайные значения и копируем их в mpz */
    ak_mpzn_set_random( x, size, &generator );
    generator.random( &generator, &d, sizeof( ak_pointer ));
     /* для 32х битной системы gmp под ui имеет только 4 байта,
        что отличается от 8ми байт, подразумеваемых нашей библиотекой
        это дает неверные значения при тестировании */

    ak_mpzn_to_mpz( x, size, xm );
    z[size] = ak_mpzn_mul_ui( z, x, size, d );

    ak_mpzn_to_mpz( z, size+1, zm );
    mpz_mul_ui( tm, xm, d );
    if( mpz_cmp(tm, zm) == 0 ) val++;
  }

  printf(" correct multiplications %ld from %ld\n", val, count );
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(xm);
  ak_random_destroy( &generator );

 return ( val == count );
}


/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  int totalmany = 8, howmany = 0;
  size_t count = 1000000;

  printf(" - ak_mpzn_add() function test for ak_mpzn256 started\n");
  if( add_test( ak_mpzn256_size, count )) howmany++;

  printf(" - ak_mpzn_add() function test for ak_mpzn512 started\n");
  if( add_test( ak_mpzn512_size, count )) howmany++;

  printf(" - ak_mpzn_sub() & ak_mpzn_cmp() functions test for ak_mpzn256 started\n");
  if( sub_test( ak_mpzn256_size, count )) howmany++;

  printf(" - ak_mpzn_sub() & ak_mpzn_cmp() functions test for ak_mpzn512 started\n");
  if( sub_test( ak_mpzn512_size, count )) howmany++;

  printf(" - ak_mpzn_mul() function test for ak_mpzn256 started\n");
  if( mul_test( ak_mpzn256_size, count )) howmany++;

  printf(" - ak_mpzn_mul() function test for ak_mpzn512 started\n");
  if( mul_test( ak_mpzn512_size, count )) howmany++;

  printf(" - ak_mpzn_mul_ui() function test for ak_mpzn256 started\n");
  if( mul_ui_test( ak_mpzn256_size, count )) howmany++;

  printf(" - ak_mpzn_mul_ui() function test for ak_mpzn512 started\n");
  if( mul_ui_test( ak_mpzn512_size, count )) howmany++;


  printf("\n total arithmetic tests: %d (passed: %d)\n", totalmany, howmany );
  if( totalmany == howmany ) return EXIT_SUCCESS;
 return EXIT_FAILURE;
}
