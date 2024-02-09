 #include <stdio.h>
 #include <stdlib.h>
 #include <time.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции сложения вычетов в представлении монтгомери */
 bool_t add_montgomery_test( size_t size, const char *prime, size_t count )
{
  size_t i = 0, val = 0;
  mpz_t xm, ym, zm, tm, pm;
  ak_mpznmax x, y, z, p;
  struct random generator;
  clock_t tmr;

  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);
  mpz_init(pm);
  ak_random_create_lcg( &generator );

  if( ak_mpzn_set_hexstr( p, size, prime ) != ak_error_ok ) goto lab_exit;
  ak_mpzn_to_mpz( p, size, pm );

  for( i = 0; i < count; i++ ) {
     ak_mpzn_set_random_modulo( x, p, size, &generator );
     ak_mpzn_set_random_modulo( y, p, size, &generator );
     ak_mpzn_to_mpz( x, size, xm );
     ak_mpzn_to_mpz( y, size, ym );
     // z <- (x+y)
     ak_mpzn_add_montgomery( z, x, y, p, size );
     ak_mpzn_to_mpz( z, size, zm );

     mpz_add( tm, xm, ym );
     mpz_mod( tm, tm, pm );
     if( mpz_cmp(tm, zm) == 0 ) val++;
  }
  printf(" correct montgomery additions %ld from %ld\n", val, count );

  /* тест на скорость */
  ak_mpzn_set_random_modulo( x, p, size, &generator );
  ak_mpzn_set_random_modulo( y, p, size, &generator );
  ak_mpzn_to_mpz( x, size, xm );
  ak_mpzn_to_mpz( y, size, ym );

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     ak_mpzn_add_montgomery( z, x, y, p, size );
     ak_mpzn_add_montgomery( x, y, z, p, size );
     ak_mpzn_add_montgomery( y, z, x, p, size );
  }
  tmr = clock() - tmr;
  printf(" mpzn time: %.3fs\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf(" y = %s\n", ak_mpzn_to_hexstr( y, size ));

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     mpz_add( zm, xm, ym ); // mpz_mod( zm, zm, pm ); так быстрее ))
     mpz_add( xm, ym, zm ); // mpz_mod( xm, xm, pm );
     mpz_add( ym, zm, xm ); mpz_mod( ym, ym, pm );
  }
  tmr = clock() - tmr;
  printf(" gmp time:  %.3fs\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf(" y = "); mpz_out_str( stdout, 16, ym ); printf("\n\n");


  lab_exit: ak_random_destroy( &generator );
  mpz_clear(pm);
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);

 return ( val == count );
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции умножения вычетов в представлении монтгомери */
 bool_t mul_montgomery_test( size_t size, const char *prime, ak_uint64 n0, size_t count )
{
  size_t i = 0, errors_gmp = 0, val = 0;
  mpz_t xm, ym, zm, tm, pm, rm, gm, sm, um, nm;
  ak_mpznmax x, y, n, p, z;
  struct random generator;
  clock_t tmr;

  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);
  mpz_init(pm);
  mpz_init(rm);
  mpz_init(gm);
  mpz_init(sm);
  mpz_init(um);
  mpz_init(nm);
  ak_random_create_lcg( &generator );

  mpz_set_str( pm, prime, 16 );
  mpz_set_ui( rm, 2 ); mpz_pow_ui( rm, rm, size*64 );
  mpz_gcdext( gm, sm, nm, rm, pm );
  if( mpz_cmp_si( nm, 0 ) < 0 ) mpz_neg( nm, nm );
   else mpz_sub( nm, rm, nm );

  ak_mpz_to_mpzn( nm, n, size );
  ak_mpz_to_mpzn( pm, p, size );
  if( n0 != n[0] ) {
    printf("%llu (old)\n%llu (new)\n", n0, n[0] );
    goto lab_exit;
  }

 // основной цикл проверок
  for( i = 0; i < count; i++ ) {
     ak_mpzn_set_random_modulo( x, p, size, &generator );
     ak_mpzn_set_random_modulo( y, p, size, &generator );
     ak_mpzn_to_mpz( x, size, xm );
     ak_mpzn_to_mpz( y, size, ym );

     // тестовый пример для умножения: результат x*y*r^{-1}
     mpz_mul( zm, xm, ym ); mpz_mul( zm, zm, sm ); mpz_mod( zm, zm, pm );

     // теперь то же в форме Монтгомери
     mpz_mul( tm, xm, ym );
     mpz_mul( um, tm, nm );
     mpz_mod( um, um, rm );
     mpz_mul( um, um, pm );
     mpz_add( um, um, tm );
     mpz_div_2exp( um, um, size*64 );
     if( mpz_cmp( um, pm ) == 1 ) mpz_sub( um, um, pm );
     if( mpz_cmp( um, zm ) != 0 ) errors_gmp++;

     ak_mpzn_mul_montgomery( z, x, y, p, n0, size );
     ak_mpzn_to_mpz( z, size, zm );
     if( mpz_cmp( um, zm ) == 0 ) val++;
  }
  printf(" correct montgomery multiplications %ld from %ld with %ld gmp errors\n", val, count, errors_gmp );

  val=0;
 // дополнительный цикл проверок
  for( i = 0; i < count; i++ ) {
     ak_mpzn_set_random_modulo( x, p, size, &generator );
     ak_mpzn_to_mpz( x, size, xm );

     // тестовый пример для умножения: результат 2x (mod p)
     mpz_mul_ui( zm, xm, 2 ); mpz_mod( zm, zm, pm );
     ak_mpzn_lshift_montgomery( x, x, p, size );
     ak_mpzn_to_mpz( x, size, um );
     if( mpz_cmp( um, zm ) == 0 ) val++;
  }
  printf(" correct montgomery left shiftings (multiplication by 2) %ld from %ld\n\n multiplications:\n", val, count );

  // speed test
  ak_mpzn_set_random_modulo( x, p, size, &generator );
  ak_mpzn_set_random_modulo( y, p, size, &generator );
  ak_mpzn_to_mpz( x, size, xm );
  ak_mpzn_to_mpz( y, size, ym );

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     ak_mpzn_mul_montgomery( z, x, y, p, n[0], size );
     ak_mpzn_mul_montgomery( x, y, z, p, n[0], size );
     ak_mpzn_mul_montgomery( y, z, x, p, n[0], size );
  }
  tmr = clock() - tmr;
  printf(" mpzn time: %.3fs [", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf("y = %s]\n", ak_mpzn_to_hexstr( y, size ));

  ak_mpz_to_mpzn( xm, x, size );
  ak_mpz_to_mpzn( ym, y, size );
  ak_mpz_to_mpzn( zm, z, size );

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     mpz_mul( zm, xm, ym ); mpz_mul( zm, zm, sm ); mpz_mod( zm, zm, pm );
     mpz_mul( xm, ym, zm ); mpz_mul( xm, xm, sm ); mpz_mod( xm, xm, pm );
     mpz_mul( ym, zm, xm ); mpz_mul( ym, ym, sm ); mpz_mod( ym, ym, pm );
  }
  tmr = clock() - tmr;
  printf(" gmp time:  %.3fs [", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf("y = "); mpz_out_str( stdout, 16, ym ); printf("]\n");

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     mpz_mul( zm, xm, ym ); mpz_mod( zm, zm, pm );
     mpz_mul( xm, ym, zm ); mpz_mod( xm, xm, pm );
     mpz_mul( ym, zm, xm ); mpz_mod( ym, ym, pm );
  }
  tmr = clock() - tmr;
  printf(" gmp time:  %.3fs [only multiplication with modulo reduction]\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));

  // -----------------------
  printf("\n shiftings (multiplication by 2):\n");
  ak_mpzn_set_random_modulo( x, p, size, &generator );
  ak_mpzn_to_mpz( x, size, xm );
  tmr = clock();
  for( i = 0; i < count; i++ ) {
     ak_mpzn_lshift_montgomery( x, x, p, size );
  }
  tmr = clock() - tmr;
  printf(" mpzn time: %.3fs [", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf("x = %s]\n", ak_mpzn_to_hexstr( x, size ));

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     mpz_mul_ui( xm, xm, 2 ); mpz_mod( xm, xm, pm );
  }
  tmr = clock() - tmr;
  printf(" gmp time:  %.3fs [", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf("z = "); mpz_out_str( stdout, 16, xm ); printf("]\n\n");

  lab_exit: ak_random_destroy( &generator );
  mpz_clear(nm);
  mpz_clear(gm);
  mpz_clear(sm);
  mpz_clear(um);
  mpz_clear(rm);
  mpz_clear(pm);
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);

 return ( val == count );
}

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  const char *str = NULL;
  ak_oid oid = NULL;
  size_t count = 1000000;
  int totalmany = 0, howmany = 0;

  ak_libakrypt_create( ak_function_log_stderr );

 /* организуем цикл по перебору всех известных простых чисел */
  oid = ak_oid_find_by_engine( identifier );
  while( oid != NULL ) {
    if( oid->mode == wcurve_params ) {
     /* достаем простое число */
      ak_wcurve wc = ( ak_wcurve ) oid->data;
      if( wc->size == ak_mpzn256_size ) {
        printf(" - p: %s\n", str = ak_mpzn_to_hexstr_alloc( wc->p, wc->size ));
        printf(" - ak_mpzn_add_montgomery() function test for ak_mpzn256 started\n");
        totalmany++;
        if( add_montgomery_test( wc->size, str, count )) howmany++;
        printf(" - ak_mpzn_mul_montgomery() function test for ak_mpzn256 started\n");
        totalmany++;
        if( mul_montgomery_test( wc->size, str, wc->n, count )) howmany++;
        if( str ) free( (void *)str );

  // добавить modpow!!

      }
      if( wc->size == ak_mpzn512_size ) {
        printf(" - p: %s\n", str = ak_mpzn_to_hexstr_alloc( wc->p, wc->size ));
        printf(" - ak_mpzn_add_montgomery() function test for ak_mpzn512 started\n");
        totalmany++;
        if( add_montgomery_test( wc->size, str, count )) howmany++;
        printf(" - ak_mpzn_mul_montgomery() function test for ak_mpzn512 started\n");
        totalmany++;
        if( mul_montgomery_test( wc->size, str, wc->n, count )) howmany++;
        if( str ) free( (void *)str );
      }
    }
    oid = ak_oid_findnext_by_engine( oid, identifier );
  }

  printf("\n total montgomery arithmetic tests: %d (passed: %d)\n", totalmany, howmany );
 return ak_libakrypt_destroy();
}
