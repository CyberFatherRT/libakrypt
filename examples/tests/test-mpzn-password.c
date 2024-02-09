 #include <stdio.h>
 #include <string.h>
 #include <gmp.h>
 #include <libakrypt.h>

 const static ak_uint8 prime[32] = {
    67,  71,  73,  79,  83,  89,  97, 101, 103, 107, 109, 113, 127, 131, 139, 149,
   151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233
 };

/* ----------------------------------------------------------------------------------------------- */
 typedef struct passctx
{
  ak_int64 n;
  mpq_t b, r, t, alpha, delta;
  ak_uint32 x[32], z[32];
} passctx_t;


/* ----------------------------------------------------------------------------------------------- */
 void passctx_init( passctx_t *pctx, char *password, char *salt )
{
  struct hash ctx;
  ak_uint8 out[64];
  int i = 0, j = 0;

 /* считаем хэш от пароля */
  ak_hash_create_streebog512( &ctx );
  ak_hash_ptr( &ctx, password, strlen( password ), out, sizeof( out ));
  for( i = 0, j = 0; i < 32; i++, j += 2 ) pctx->x[i] = 1 + out[j] + out[j+1]*256;

 /* считаем хэш от соли */
  ak_hash_ptr( &ctx, salt, strlen( salt ), out, sizeof( out ));
  for( i = 0, j = 0; i < 32; i++, j += 2 ) pctx->z[i] = out[j] + out[j+1]*256;
  ak_hash_destroy( &ctx );

 /* инициализация больших чисел */
  pctx->n = -1;
  mpq_init( pctx->b );
  mpq_init( pctx->r );
  mpq_init( pctx->t );
  mpq_init( pctx->alpha );
  mpq_init( pctx->delta );

  mpq_set_ui( pctx->b, 256, 1 );
  mpq_set_ui( pctx->r, 0, 1 );
  mpq_set_ui( pctx->t, 0, 1 );
  mpq_set_ui( pctx->alpha, 0, 1 );
  mpq_set_ui( pctx->delta, 0, 1 );
}

/* ----------------------------------------------------------------------------------------------- */
 void passctx_clean( passctx_t *pctx )
{
  mpq_clear( pctx->b );
  mpq_clear( pctx->r );
  mpq_clear( pctx->t );
  mpq_clear( pctx->alpha );
  mpq_clear( pctx->delta );
  memset( pctx, 0, sizeof( struct  passctx ));
}

/* ----------------------------------------------------------------------------------------------- */
 void passctx_rn( passctx_t *pctx, ak_int64 n )
{
  int i = 0;
  mpq_set_ui( pctx->r, 0, 1 );
  for( i = 0; i < 32; i++ ) {
     mpq_set_ui( pctx->t, pctx->z[i], (ak_uint64)(prime[i]*( 65536*n + pctx->x[i] )));
     //mpq_canonicalize( pctx->t );
     mpq_add( pctx->r, pctx->r, pctx->t );
  }
  //mpq_canonicalize( pctx->r );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 passctx_next( passctx_t *pctx, int *error )
{
  ak_uint32 a;

 /* вычисляем b*delta_{n-1} + R(n) */
  pctx->n++;
  mpq_mul( pctx->alpha, pctx->delta, pctx->b );
  passctx_rn( pctx, pctx->n );
  mpq_add( pctx->alpha, pctx->alpha, pctx->r ); /* alpha = b*delta + R(n) */

  a = (ak_uint32)( mpq_get_d( pctx->alpha ));

  mpq_set_ui( pctx->t, a, 1 );
  mpq_sub( pctx->delta, pctx->alpha, pctx->t );

  if( a > 255 ) *error = 1; /* проверка корректности знака */
   else *error = 0;

 return a&0xFF;
}

/* ----------------------------------------------------------------------------------------------- */
 int passctx_get_key( char *password, char *salt, ak_uint8 out[32] )
{
  int i, error = 0;
  passctx_t pctx; /* инициализируем контекст  */
  passctx_init( &pctx, password, salt );

  memset( out, 0, 32 );
  for( i = 0; i < 1024; i++ ) passctx_next( &pctx, &error );
  for( i = 0; i < 32; i++ ) { /* вычисляем ключ, начиная с индекса 1024 */
     out[i] = passctx_next( &pctx, &error );
     if( error ) return ak_error_undefined_value;
  }
  passctx_clean( &pctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/* основная тестирующая программа */
 int main( void )
{
  ak_uint8 key[32];
  int i, error = 0;
  char *salt = "saltstr";
  char *pass = "passwordstr";

  if(( error = passctx_get_key( pass, salt, key )) != ak_error_ok )
   printf("incorrect executing\n");

  printf("key: ");
  for( i = 0; i < 32; i++ ) { printf("%02X", key[i] ); }
  printf("\n");


 return 0;
}
