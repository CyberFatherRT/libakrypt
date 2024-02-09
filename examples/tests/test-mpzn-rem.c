 #include <stdio.h>
 #include <stdlib.h>
 #include <time.h>
 #include <libakrypt.h>
 #include <gmp.h>

/* ----------------------------------------------------------------------------------------------- */
 int mpzn_rem_test( ak_wcurve wc, size_t count )
{
  int rescount = 0;
  size_t j = 0, mycount = 0, mpzcount = 0;
  ak_mpznmax x, r, l;
  ak_uint64 *p = wc->p;
  mpz_t xp, rp, pp;
  struct random generator;

  mpz_init( xp );
  mpz_init( rp );
  mpz_init( pp );
  ak_random_create_lcg( &generator );

 /* первый тест - модуль p */
  ak_mpzn_to_mpz( p, wc->size, pp );
  printf(" - p: "); mpz_out_str( stdout, 16, pp ); printf("\n");

  for( j = 0; j < count; j++ ) {
     ak_mpzn_set_random( x, wc->size, &generator );
     ak_mpzn_rem( r, x, p, wc->size ); /* r <- x (mod p) */

     ak_mpzn_to_mpz( x, wc->size, xp );
     mpz_mod( rp, xp, pp ); /* rp <- xp (mod pp) */

     ak_mpzn_to_mpz( r, wc->size, xp ); if( !mpz_cmp( rp, xp )) mpzcount++;
     ak_mpz_to_mpzn( rp, l, wc->size ); if( !ak_mpzn_cmp( r, l, wc->size )) mycount++;
  }
  printf(" %lu (%lu) tests passed successfully from %lu \n", mpzcount, mycount, count );
  if(( mpzcount == count ) && (  mycount == count )) rescount++;

 /* второй тест - модуль q */

  ak_mpzn_to_mpz( p = wc->q, wc->size, pp );
  printf(" - q: "); mpz_out_str( stdout, 16, pp ); printf("\n");

  mpzcount = mycount = 0;
  for( j = 0; j < count; j++ ) {
     ak_mpzn_set_random( x, wc->size, &generator );
     ak_mpzn_rem( r, x, p, wc->size ); /* r <- x (mod p) */

     ak_mpzn_to_mpz( x, wc->size, xp );
     mpz_mod( rp, xp, pp ); /* rp <- xp (mod pp) */

     ak_mpzn_to_mpz( r, wc->size, xp ); if( !mpz_cmp( rp, xp )) mpzcount++;
     ak_mpz_to_mpzn( rp, l, wc->size ); if( !ak_mpzn_cmp( r, l, wc->size )) mycount++;
  }
  printf(" %lu (%lu) tests passed successfully from %lu \n", mpzcount, mycount, count );
  if(( mpzcount == count ) && (  mycount == count )) rescount++;

  ak_random_destroy( &generator );
  mpz_clear( xp );
  mpz_clear( rp );
  mpz_clear( pp );

 return rescount;
}

/* ----------------------------------------------------------------------------------------------- */
 int mpz_gmp_rem32_test( unsigned int num, size_t count )
{
  int cl = 0;
  unsigned int i = 0;
  ak_mpznmax x;
  mpz_t xm, rm;
  ak_uint64 deg2 = 2;
  struct random generator;
  ak_uint32 rem = 0, ops = 0;
  clock_t tmr;

  mpz_init( xm );
  mpz_init( rm );
  ak_random_create_lcg( &generator );


 /* создаем числа */
  for( i = 0; i < num; i++ ) {
   ak_mpzn_set_random( x, ak_mpznmax_size, &generator );
   ak_mpzn_to_mpz( x, ak_mpznmax_size, xm );
   fprintf( stdout, "%2u: number %s\n", i+1, ak_mpzn_to_hexstr( x, ak_mpznmax_size ));

 /* вычисляем остатки и сравниваем */
   fprintf( stdout, "running rem_uint32 test for %llu values\n", (unsigned long long int)count );
   for( rem = 2; rem <= count; rem++ ) {
      if( rem == deg2 ) {
         fprintf( stdout, "\r up to %llu Ok ", deg2 ); fflush( stdout );
         deg2 *= 2;
      }
      if(  ak_mpzn_rem_uint32( x, ak_mpznmax_size, rem ) == mpz_mod_ui( rm, xm, rem )) ops++;
   }
   if( ops == count-1 ) {
     cl++;
     fprintf( stdout, "\n");
   } else fprintf( stdout, " -- incorrect sum\n");
   ops = 0;
   deg2 = 2;

   fprintf( stdout, "running rem_uint32 test for large %llu values\n", (unsigned long long int)count );
   for( rem = 4294967295; rem >= 4294967295-count; rem-- ) {
      if(  ak_mpzn_rem_uint32( x, ak_mpznmax_size, rem ) == mpz_mod_ui( rm, xm, rem )) ops++;
   }
   if( ops == count+1 ) {
     cl++;
     fprintf( stdout, "Ok\n");
   } else fprintf( stdout, " -- incorrect sum (calculate: %llu, need: %llu)\n",
                                                                  (ak_uint64)ops, (ak_uint64)count+1 );
   ops = 0;
  }

  fprintf( stdout, "speed test\n" );
  tmr = clock();
  for( rem = 4294967295; rem >= 4294967295-count; rem-- )
     ak_mpzn_rem_uint32( x, ak_mpznmax_size, rem );
  tmr = clock() - tmr;
  printf(" mpzn time: %.3fs (%.8fs per one number)\n",
    ((double) tmr) / ((double) CLOCKS_PER_SEC), ((double) tmr) / (((double) CLOCKS_PER_SEC) * count ));

  tmr = clock();
  for( rem = 4294967295; rem >= 4294967295-count; rem-- )
     mpz_mod_ui( rm, xm, rem );
  tmr = clock() - tmr;
  printf("  mpz time: %.3fs\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));

  ak_random_destroy( &generator );
  mpz_clear( xm );
  mpz_clear( rm );

 return cl;
}

/* ----------------------------------------------------------------------------------------------- */
/* основная тестирующая программа */
 int main( void )
{
  unsigned int num = 2;
  ak_oid oid = NULL;
  int totalmany = 0, howmany = 0;
  ak_libakrypt_create( ak_function_log_stderr );

 /* организуем цикл по перебору всех известных простых чисел */
  oid = ak_oid_find_by_engine( identifier );

  while( oid != NULL ) {
    if( oid->mode == wcurve_params ) {
     /* достаем простое число */
      totalmany += 2;
      howmany += mpzn_rem_test( (ak_wcurve)(oid->data), 1000000 );
    }
    oid = ak_oid_findnext_by_engine( oid, identifier );
  }

  totalmany += 2*num;
  howmany += mpz_gmp_rem32_test( num, 10000000 );

  printf("\n total remainder tests: %d (passed: %d)\n", totalmany, howmany );
 return ak_libakrypt_destroy();
}
