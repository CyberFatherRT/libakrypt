/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*  Copyright (c) 2019 by Diffractee                                                               */
/*                                                                                                 */
/*  Файл ak_gf2n.c                                                                                 */
/*  - содержит реализацию функций умножения элементов конечных полей характеристики 2.             */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_BUILTIN_CLMULEPI64
 #include <wmmintrin.h>
#endif
#ifdef _MSC_VER
 #include <stdlib.h>
 /* требуется для определени функции rand() */
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{64}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{64} + x^4 + x^3 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf64_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0;
 ak_uint64 zv = 0, n1,
#ifdef AK_LITTLE_ENDIAN
   t = ((ak_uint64 *)y)[0], s = ((ak_uint64 *)x)[0];
#else
   t = bswap_64( ((ak_uint64 *)y)[0] ), s = bswap_64( ((ak_uint64 *)x)[0] );
#endif
 for( i = 0; i < 64; i++ ) {

   if( t&0x1 ) zv ^= s;
   t >>= 1;
   n1 = s&0x8000000000000000LL;
   s <<= 1;
   if( n1 ) s ^= 0x1B;
 }
#ifdef AK_LITTLE_ENDIAN
 ((ak_uint64 *)z)[0] = zv;
#else
 ((ak_uint64 *)z)[0] = bswap_64(zv);
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf128_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0;
 ak_uint64 t,
#ifdef AK_LITTLE_ENDIAN
  s0 = ((ak_uint64 *)x)[0], s1 = ((ak_uint64 *)x)[1];
#else
  s0 = bswap_64( ((ak_uint64 *)x)[0] ), s1 = bswap_64( ((ak_uint64 *)x)[1] );
#endif

 /* обнуляем результирующее значение */
 ((ak_uint64 *)z)[0] = 0; ((ak_uint64 *)z)[1] = 0;

 /* вычисляем  произведение для младшей половины */
#ifdef AK_LITTLE_ENDIAN
  t = ((ak_uint64 *)y)[0];
#else
  t = bswap_64( ((ak_uint64 *)y)[0] );
#endif
 for( i = 0; i < 64; i++ ) {
   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   ak_gf128_mul_theta( s1, s0 );
 }

 /* вычисляем  произведение для старшей половины */
#ifdef AK_LITTLE_ENDIAN
  t = ((ak_uint64 *)y)[1];
#else
  t = bswap_64( ((ak_uint64 *)y)[1] );
#endif

 for( i = 0; i < 63; i++ ) {

   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   ak_gf128_mul_theta( s1, s0 );
 }

 if( t&0x1 ) {
   ((ak_uint64 *)z)[0] ^= s0;
   ((ak_uint64 *)z)[1] ^= s1;
 }
#ifdef AK_BIG_ENDIAN
   ((ak_uint64 *)z)[0] = bswap_64( ((ak_uint64 *)z)[0] );
   ((ak_uint64 *)z)[1] = bswap_64( ((ak_uint64 *)z)[1] );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{256}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{256} + x^{10} + x^5 + x^2 + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf256_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0, g = 0;
 ak_uint64 t, n,
#ifdef AK_LITTLE_ENDIAN
  s0 = ((ak_uint64 *)x)[0], s1 = ((ak_uint64 *)x)[1],
  s2 = ((ak_uint64 *)x)[2], s3 = ((ak_uint64 *)x)[3];
#else
  s0 = bswap_64( ((ak_uint64 *)x)[0] ), s1 = bswap_64( ((ak_uint64 *)x)[1] ),
  s2 = bswap_64( ((ak_uint64 *)x)[2] ), s3 = bswap_64( ((ak_uint64 *)x)[3] );
#endif

 /* обнуляем результирующее значение */
 ((ak_uint64 *)z)[0] = 0; ((ak_uint64 *)z)[1] = 0;
 ((ak_uint64 *)z)[2] = 0; ((ak_uint64 *)z)[3] = 0;

 /* вычисляем  произведение для младших 3-х четвертей (t0 - t2) */
 for( g = 0; g < 3; g++ ) { //вроде должно работать. Код полностью дублируется,
                            //кроме части под макросами, которую и меняю.
  #ifdef AK_LITTLE_ENDIAN
    t = ((ak_uint64 *)y)[g];
  #else
    t = bswap_64( ((ak_uint64 *)y)[g] );
  #endif
   for( i = 0; i < 64; i++ ) {
     if( t&0x1 ) {
       ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1;
       ((ak_uint64 *)z)[2] ^= s2; ((ak_uint64 *)z)[3] ^= s3;
     }
     t >>= 1;
     n = ( s3 >> 63 );
     s3 <<= 1; s3 ^= ( s2 >> 63 );
     s2 <<= 1; s2 ^= ( s1 >> 63 );
     s1 <<= 1; s1 ^= ( s0 >> 63 );
     s0 <<= 1;
     if( n ) s0 ^= 0x425;
   }
 }

 /* вычисляем  произведение для старшей четверти (t3) */
#ifdef AK_LITTLE_ENDIAN
  t = ((ak_uint64 *)y)[3];
#else
  t = bswap_64( ((ak_uint64 *)y)[3] );
#endif
 for( i = 0; i < 63; i++ ) {
   if( t&0x1 ) {
     ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1;
     ((ak_uint64 *)z)[2] ^= s2; ((ak_uint64 *)z)[3] ^= s3;
   }
   t >>= 1;
   n = ( s3 >> 63 );
   s3 <<= 1; s3 ^= ( s2 >> 63 );
   s2 <<= 1; s2 ^= ( s1 >> 63 );
   s1 <<= 1; s1 ^= ( s0 >> 63 );
   s0 <<= 1;
   if( n ) s0 ^= 0x425;
 }

 if( t&0x1 ) {
   ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1;
   ((ak_uint64 *)z)[2] ^= s2; ((ak_uint64 *)z)[3] ^= s3;
 }
#ifdef AK_BIG_ENDIAN
   ((ak_uint64 *)z)[0] = bswap_64( ((ak_uint64 *)z)[0] );
   ((ak_uint64 *)z)[1] = bswap_64( ((ak_uint64 *)z)[1] );
   ((ak_uint64 *)z)[2] = bswap_64( ((ak_uint64 *)z)[2] );
   ((ak_uint64 *)z)[3] = bswap_64( ((ak_uint64 *)z)[3] );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{512}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{512} + x^8 + x^5 + x^2 + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf512_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0, g = 0;
 ak_uint64 t, n,
#ifdef AK_LITTLE_ENDIAN
  s0 = ((ak_uint64 *)x)[0], s1 = ((ak_uint64 *)x)[1],
  s2 = ((ak_uint64 *)x)[2], s3 = ((ak_uint64 *)x)[3],
  s4 = ((ak_uint64 *)x)[4], s5 = ((ak_uint64 *)x)[5],
  s6 = ((ak_uint64 *)x)[6], s7 = ((ak_uint64 *)x)[7];
#else
  s0 = bswap_64( ((ak_uint64 *)x)[0] ), s1 = bswap_64( ((ak_uint64 *)x)[1] ),
  s2 = bswap_64( ((ak_uint64 *)x)[2] ), s3 = bswap_64( ((ak_uint64 *)x)[3] ),
  s4 = bswap_64( ((ak_uint64 *)x)[4] ), s5 = bswap_64( ((ak_uint64 *)x)[5] ),
  s6 = bswap_64( ((ak_uint64 *)x)[6] ), s7 = bswap_64( ((ak_uint64 *)x)[7] );
#endif

 /* обнуляем результирующее значение */
 ((ak_uint64 *)z)[0] = 0; ((ak_uint64 *)z)[1] = 0;
 ((ak_uint64 *)z)[2] = 0; ((ak_uint64 *)z)[3] = 0;
 ((ak_uint64 *)z)[4] = 0; ((ak_uint64 *)z)[5] = 0;
 ((ak_uint64 *)z)[6] = 0; ((ak_uint64 *)z)[7] = 0;

 /* вычисляем  произведение для младших 7-ми восьмых (t0 - t6) */
 for( g = 0; g < 7; g++ ) { //вроде должно работать. Код полностью дуюлируется,
                            //кроме части под макросами, которую и меняю.
  #ifdef AK_LITTLE_ENDIAN
    t = ((ak_uint64 *)y)[g];
  #else
    t = bswap_64( ((ak_uint64 *)y)[g] );
  #endif
   for( i = 0; i < 64; i++ ) {
     if( t&0x1 ) {
       ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1;
       ((ak_uint64 *)z)[2] ^= s2; ((ak_uint64 *)z)[3] ^= s3;
       ((ak_uint64 *)z)[4] ^= s4; ((ak_uint64 *)z)[5] ^= s5;
       ((ak_uint64 *)z)[6] ^= s6; ((ak_uint64 *)z)[7] ^= s7;
     }
     t >>= 1;
     n = ( s7 >> 63 );
     s7 <<= 1; s7 ^= ( s6 >> 63 );
     s6 <<= 1; s6 ^= ( s5 >> 63 );
     s5 <<= 1; s5 ^= ( s4 >> 63 );
     s4 <<= 1; s4 ^= ( s3 >> 63 );
     s3 <<= 1; s3 ^= ( s2 >> 63 );
     s2 <<= 1; s2 ^= ( s1 >> 63 );
     s1 <<= 1; s1 ^= ( s0 >> 63 );
     s0 <<= 1;
     if( n ) s0 ^= 0x125;
   }
 }

 /* вычисляем  произведение для старшей одной восьмой (t7) */
#ifdef AK_LITTLE_ENDIAN
  t = ((ak_uint64 *)y)[7];
#else
  t = bswap_64( ((ak_uint64 *)y)[7] );
#endif
 for( i = 0; i < 63; i++ ) {
   if( t&0x1 ) {
     ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1;
     ((ak_uint64 *)z)[2] ^= s2; ((ak_uint64 *)z)[3] ^= s3;
     ((ak_uint64 *)z)[4] ^= s4; ((ak_uint64 *)z)[5] ^= s5;
     ((ak_uint64 *)z)[6] ^= s6; ((ak_uint64 *)z)[7] ^= s7;
   }
   t >>= 1;
   n = ( s7 >> 63 );
   s7 <<= 1; s7 ^= ( s6 >> 63 );
   s6 <<= 1; s6 ^= ( s5 >> 63 );
   s5 <<= 1; s5 ^= ( s4 >> 63 );
   s4 <<= 1; s4 ^= ( s3 >> 63 );
   s3 <<= 1; s3 ^= ( s2 >> 63 );
   s2 <<= 1; s2 ^= ( s1 >> 63 );
   s1 <<= 1; s1 ^= ( s0 >> 63 );
   s0 <<= 1;
   if( n ) s0 ^= 0x125;
 }

 if( t&0x1 ) {
   ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1;
   ((ak_uint64 *)z)[2] ^= s2; ((ak_uint64 *)z)[3] ^= s3;
   ((ak_uint64 *)z)[4] ^= s4; ((ak_uint64 *)z)[5] ^= s5;
   ((ak_uint64 *)z)[6] ^= s6; ((ak_uint64 *)z)[7] ^= s7;
 }
#ifdef AK_BIG_ENDIAN
   ((ak_uint64 *)z)[0] = bswap_64( ((ak_uint64 *)z)[0] );
   ((ak_uint64 *)z)[1] = bswap_64( ((ak_uint64 *)z)[1] );
   ((ak_uint64 *)z)[2] = bswap_64( ((ak_uint64 *)z)[2] );
   ((ak_uint64 *)z)[3] = bswap_64( ((ak_uint64 *)z)[3] );
   ((ak_uint64 *)z)[4] = bswap_64( ((ak_uint64 *)z)[4] );
   ((ak_uint64 *)z)[5] = bswap_64( ((ak_uint64 *)z)[5] );
   ((ak_uint64 *)z)[6] = bswap_64( ((ak_uint64 *)z)[6] );
   ((ak_uint64 *)z)[7] = bswap_64( ((ak_uint64 *)z)[7] );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_BUILTIN_CLMULEPI64

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{64}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{64} + x^4 + x^3 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf64_mul_pcmulqdq( ak_pointer z, ak_pointer x, ak_pointer y )
{
#ifdef _MSC_VER
	 __m128i gm, xm, ym, cm, cx;

	 gm.m128i_u64[0] = 0x1B; gm.m128i_u64[1] = 0;
	 xm.m128i_u64[0] = ((ak_uint64 *)x)[0]; xm.m128i_u64[1] = 0;
	 ym.m128i_u64[0] = ((ak_uint64 *)y)[0]; ym.m128i_u64[1] = 0;

	 cm = _mm_clmulepi64_si128(xm, ym, 0x00);
	 cx.m128i_u64[0] = cm.m128i_u64[1]; cx.m128i_u64[1] = 0;

	 xm = _mm_clmulepi64_si128(cx, gm, 0x00);
	 xm.m128i_u64[1] ^= cx.m128i_u64[0];
	 ym.m128i_u64[0] = xm.m128i_u64[1]; ym.m128i_u64[1] = 0;
	 xm = _mm_clmulepi64_si128(ym, gm, 0x00);

	 ((ak_uint64 *)z)[0] = cm.m128i_u64[0] ^ xm.m128i_u64[0];
#else
  const __m128i gm = _mm_set_epi64x( 0, 0x1B );
  __m128i xm = _mm_set_epi64x( 0, ((ak_uint64 *)x)[0] );
  __m128i ym = _mm_set_epi64x( 0, ((ak_uint64 *)y)[0] );

  __m128i cm = _mm_clmulepi64_si128( xm, ym, 0x00 );
  __m128i cx = _mm_set_epi64x( 0, cm[1] );

  xm = _mm_clmulepi64_si128( cx, gm, 0x00 ); xm[1] ^= cx[0];
  ym = _mm_set_epi64x( 0, xm[1] );
  xm = _mm_clmulepi64_si128( ym, gm, 0x00 );

  ((ak_uint64 *)z)[0] = cm[0]^xm[0];
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf128_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b )
{
#ifdef _MSC_VER
	 __m128i am, bm, cm, dm, em, fm;
	 ak_uint64 x3, D;

	 am.m128i_u64[0] = ((ak_uint64 *)a)[0];  am.m128i_u64[1] = ((ak_uint64 *)a)[1];
	 bm.m128i_u64[0] = ((ak_uint64 *)b)[0];  bm.m128i_u64[1] = ((ak_uint64 *)b)[1];

	 /* умножение */
	 cm = _mm_clmulepi64_si128(am, bm, 0x00); // c = a0*b0
	 dm = _mm_clmulepi64_si128(am, bm, 0x11); // d = a1*b1
	 em = _mm_clmulepi64_si128(am, bm, 0x10); // e = a0*b1
	 fm = _mm_clmulepi64_si128(am, bm, 0x01); // f = a1*b0

	/* приведение */
	 x3 = dm.m128i_u64[1];
	 D = dm.m128i_u64[0] ^ em.m128i_u64[1] ^ fm.m128i_u64[1] ^ (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57);

	 cm.m128i_u64[0] ^= D ^ (D << 1) ^ (D << 2) ^ (D << 7);
	 cm.m128i_u64[1] ^= em.m128i_u64[0] ^ fm.m128i_u64[0] ^ x3 ^ (x3 << 1) ^ (D >> 63) ^ (x3 << 2) ^ (D >> 62) ^ (x3 << 7) ^ (D >> 57);

	 ((ak_uint64 *)z)[0] = cm.m128i_u64[0];
	 ((ak_uint64 *)z)[1] = cm.m128i_u64[1];
#else
	 __m128i am = _mm_set_epi64x(((ak_uint64 *)a)[1], ((ak_uint64 *)a)[0]);
	 __m128i bm = _mm_set_epi64x(((ak_uint64 *)b)[1], ((ak_uint64 *)b)[0]);

	 /* умножение */
	 __m128i cm = _mm_clmulepi64_si128(am, bm, 0x00); // c = a0*b0
	 __m128i dm = _mm_clmulepi64_si128(am, bm, 0x11); // d = a1*b1
	 __m128i em = _mm_clmulepi64_si128(am, bm, 0x10); // e = a0*b1
	 __m128i fm = _mm_clmulepi64_si128(am, bm, 0x01); // f = a1*b0

	 /* приведение */
	 ak_uint64 x3 = dm[1];
	 ak_uint64 D = dm[0] ^ em[1] ^ fm[1] ^ (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57);

	 cm[0] ^= D ^ (D << 1) ^ (D << 2) ^ (D << 7);
	 cm[1] ^= em[0] ^ fm[0] ^ x3 ^ (x3 << 1) ^ (D >> 63) ^ (x3 << 2) ^ (D >> 62) ^ (x3 << 7) ^ (D >> 57);

	 ((ak_uint64 *)z)[0] = cm[0];
	 ((ak_uint64 *)z)[1] = cm[1];
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{256}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{256} + x^10 + x^5 + x^2 + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf256_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b )
{
#ifdef _MSC_VER
     __m128i a1a0, a3a2, b1b0, b3b2;
     __m128i a0b0, a1b0, a2b0, a3b0;
     __m128i a0b1, a1b1, a2b1, a3b1;
     __m128i a0b2, a1b2, a2b2, a3b2;
     __m128i a0b3, a1b3, a2b3, a3b3;
     ak_uint64 r0, r1, r2, r3, r4, r5, r6, r7; //хранит ответ. r4-r7 при желании можно оптимизировать в 2 переменные.

     a1a0.m128i_u64[0] = ((ak_uint64 *)a)[0];   a1a0.m128i_u64[1] = ((ak_uint64 *)a)[1];
     a3a2.m128i_u64[0] = ((ak_uint64 *)a)[2];   a3a2.m128i_u64[1] = ((ak_uint64 *)a)[3];

     b1b0.m128i_u64[0] = ((ak_uint64 *)b)[0];   b1b0.m128i_u64[1] = ((ak_uint64 *)b)[1];
     b3b2.m128i_u64[0] = ((ak_uint64 *)b)[2];   b3b2.m128i_u64[1] = ((ak_uint64 *)b)[3];

    /* умножение */
     a0b0 = _mm_clmulepi64_si128(a1a0, b1b0, 0x00);
     a1b0 = _mm_clmulepi64_si128(a1a0, b1b0, 0x01);
     a2b0 = _mm_clmulepi64_si128(a3a2, b1b0, 0x00);
     a3b0 = _mm_clmulepi64_si128(a3a2, b1b0, 0x01);

     a0b1 = _mm_clmulepi64_si128(a1a0, b1b0, 0x10);
     a1b1 = _mm_clmulepi64_si128(a1a0, b1b0, 0x11);
     a2b1 = _mm_clmulepi64_si128(a3a2, b1b0, 0x10);
     a3b1 = _mm_clmulepi64_si128(a3a2, b1b0, 0x11);

     a0b2 = _mm_clmulepi64_si128(a1a0, b3b2, 0x00);
     a1b2 = _mm_clmulepi64_si128(a1a0, b3b2, 0x01);
     a2b2 = _mm_clmulepi64_si128(a3a2, b3b2, 0x00);
     a3b2 = _mm_clmulepi64_si128(a3a2, b3b2, 0x01);

     a0b3 = _mm_clmulepi64_si128(a1a0, b3b2, 0x10);
     a1b3 = _mm_clmulepi64_si128(a1a0, b3b2, 0x11);
     a2b3 = _mm_clmulepi64_si128(a3a2, b3b2, 0x10);
     a3b3 = _mm_clmulepi64_si128(a3a2, b3b2, 0x11);

    /* суммирование, потом приведение */
     r7 = a3b3.m128i_u64[1];                                                                          //sum
     r6 = a3b3.m128i_u64[0] ^ a2b3.m128i_u64[1] ^ a3b2.m128i_u64[1];                                                      //sum
     r5 = a2b3.m128i_u64[0] ^ a1b3.m128i_u64[1] ^ a3b2.m128i_u64[0] ^ a2b2.m128i_u64[1] ^ a3b1.m128i_u64[1];                                  //sum
     r4 = a1b3.m128i_u64[0] ^ a0b3.m128i_u64[1] ^ a2b2.m128i_u64[0] ^ a1b2.m128i_u64[1] ^ a3b1.m128i_u64[0] ^ a2b1.m128i_u64[1] ^ a3b0.m128i_u64[1];              //sum
     r4^= (r7 >> 54) ^ (r7 >> 59) ^ (r7 >> 62);                                             //mod

     r3 = a0b3.m128i_u64[0] ^ a1b2.m128i_u64[0] ^ a0b2.m128i_u64[1] ^ a2b1.m128i_u64[0] ^ a1b1.m128i_u64[1] ^ a3b0.m128i_u64[0] ^ a2b0.m128i_u64[1];              //sum
     r3^= (r7 << 10) ^ (r7 << 5) ^ (r7 << 2) ^ r7 ^ (r6 >> 54) ^ (r6 >> 59) ^ (r6 >> 62);   //mod

     r2 = a0b2.m128i_u64[0] ^ a1b1.m128i_u64[0] ^ a0b1.m128i_u64[1] ^ a2b0.m128i_u64[0] ^ a1b0.m128i_u64[1];                                  //sum
     r2^= (r6 << 10) ^ (r6 << 5) ^ (r6 << 2) ^ r6 ^ (r5 >> 54) ^ (r5 >> 59) ^ (r5 >> 62);   //mod
     r1 = a0b1.m128i_u64[0] ^ a1b0.m128i_u64[0] ^ a0b0.m128i_u64[1];                                                      //sum
     r1^= (r5 << 10) ^ (r5 << 5) ^ (r5 << 2) ^ r5 ^ (r4 >> 54) ^ (r4 >> 59) ^ (r4 >> 62);   //mod
     r0 = a0b0.m128i_u64[0];                                                                          //sum
     r0^= (r4 << 10) ^ (r4 << 5) ^ (r4 << 2) ^ r4;                                          //mod

     ((ak_uint64 *)z)[0] = r0;
     ((ak_uint64 *)z)[1] = r1;
     ((ak_uint64 *)z)[2] = r2;
     ((ak_uint64 *)z)[3] = r3;
#else
     __m128i a1a0 = _mm_set_epi64x(((ak_uint64 *)a)[1], ((ak_uint64 *)a)[0]);
     __m128i a3a2 = _mm_set_epi64x(((ak_uint64 *)a)[3], ((ak_uint64 *)a)[2]);

     __m128i b1b0 = _mm_set_epi64x(((ak_uint64 *)b)[1], ((ak_uint64 *)b)[0]);
     __m128i b3b2 = _mm_set_epi64x(((ak_uint64 *)b)[3], ((ak_uint64 *)b)[2]);

     /* умножение */
     __m128i a0b0 = _mm_clmulepi64_si128(a1a0, b1b0, 0x00);
     __m128i a1b0 = _mm_clmulepi64_si128(a1a0, b1b0, 0x01);
     __m128i a2b0 = _mm_clmulepi64_si128(a3a2, b1b0, 0x00);
     __m128i a3b0 = _mm_clmulepi64_si128(a3a2, b1b0, 0x01);

     __m128i a0b1 = _mm_clmulepi64_si128(a1a0, b1b0, 0x10);
     __m128i a1b1 = _mm_clmulepi64_si128(a1a0, b1b0, 0x11);
     __m128i a2b1 = _mm_clmulepi64_si128(a3a2, b1b0, 0x10);
     __m128i a3b1 = _mm_clmulepi64_si128(a3a2, b1b0, 0x11);

     __m128i a0b2 = _mm_clmulepi64_si128(a1a0, b3b2, 0x00);
     __m128i a1b2 = _mm_clmulepi64_si128(a1a0, b3b2, 0x01);
     __m128i a2b2 = _mm_clmulepi64_si128(a3a2, b3b2, 0x00);
     __m128i a3b2 = _mm_clmulepi64_si128(a3a2, b3b2, 0x01);

     __m128i a0b3 = _mm_clmulepi64_si128(a1a0, b3b2, 0x10);
     __m128i a1b3 = _mm_clmulepi64_si128(a1a0, b3b2, 0x11);
     __m128i a2b3 = _mm_clmulepi64_si128(a3a2, b3b2, 0x10);
     __m128i a3b3 = _mm_clmulepi64_si128(a3a2, b3b2, 0x11);

     /* суммирование, потом приведение */
     ak_uint64 r0, r1, r2, r3, r4, r5, r6, r7; //хранит ответ. r4-r7 при желании можно оптимизировать в 2 переменные.
     r7 = a3b3[1];                                                                          //sum
     r6 = a3b3[0] ^ a2b3[1] ^ a3b2[1];                                                      //sum
     r5 = a2b3[0] ^ a1b3[1] ^ a3b2[0] ^ a2b2[1] ^ a3b1[1];                                  //sum
     r4 = a1b3[0] ^ a0b3[1] ^ a2b2[0] ^ a1b2[1] ^ a3b1[0] ^ a2b1[1] ^ a3b0[1];              //sum
     r4^= (r7 >> 54) ^ (r7 >> 59) ^ (r7 >> 62);                                             //mod
     r3 = a0b3[0] ^ a1b2[0] ^ a0b2[1] ^ a2b1[0] ^ a1b1[1] ^ a3b0[0] ^ a2b0[1];              //sum
     r3^= (r7 << 10) ^ (r7 << 5) ^ (r7 << 2) ^ r7 ^ (r6 >> 54) ^ (r6 >> 59) ^ (r6 >> 62);   //mod
     r2 = a0b2[0] ^ a1b1[0] ^ a0b1[1] ^ a2b0[0] ^ a1b0[1];                                  //sum
     r2^= (r6 << 10) ^ (r6 << 5) ^ (r6 << 2) ^ r6 ^ (r5 >> 54) ^ (r5 >> 59) ^ (r5 >> 62);   //mod
     r1 = a0b1[0] ^ a1b0[0] ^ a0b0[1];                                                      //sum
     r1^= (r5 << 10) ^ (r5 << 5) ^ (r5 << 2) ^ r5 ^ (r4 >> 54) ^ (r4 >> 59) ^ (r4 >> 62);   //mod
     r0 = a0b0[0];                                                                          //sum
     r0^= (r4 << 10) ^ (r4 << 5) ^ (r4 << 2) ^ r4;                                          //mod

     ((ak_uint64 *)z)[0] = r0;
     ((ak_uint64 *)z)[1] = r1;
     ((ak_uint64 *)z)[2] = r2;
     ((ak_uint64 *)z)[3] = r3;
#endif
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{512} + x^8 + x^5 + x^2 + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.
    \todo может быть имеет смысл разбить на 2 ifdef, а середину сделать общей?                     */
/* ----------------------------------------------------------------------------------------------- */
void ak_gf512_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b )
{
#ifdef _MSC_VER
     __m128i a1a0, a3a2, a5a4, a7a6, b1b0, b3b2, b5b4, b7b6;
     __m128i a0b0, a1b0, a2b0, a3b0, a4b0, a5b0, a6b0, a7b0;
     __m128i a0b1, a1b1, a2b1, a3b1, a4b1, a5b1, a6b1, a7b1;
     __m128i a0b2, a1b2, a2b2, a3b2, a4b2, a5b2, a6b2, a7b2;
     __m128i a0b3, a1b3, a2b3, a3b3, a4b3, a5b3, a6b3, a7b3;
     __m128i a0b4, a1b4, a2b4, a3b4, a4b4, a5b4, a6b4, a7b4;
     __m128i a0b5, a1b5, a2b5, a3b5, a4b5, a5b5, a6b5, a7b5;
     __m128i a0b6, a1b6, a2b6, a3b6, a4b6, a5b6, a6b6, a7b6;
     __m128i a0b7, a1b7, a2b7, a3b7, a4b7, a5b7, a6b7, a7b7;
     ak_uint64 r0, r1, r2, r3, r4, r5, r6, r7,
             r8, r9, r10, r11, r12, r13, r14, r15;      //хранит ответ. r8-r15 при желании можно (?) оптимизировать в 2 переменные.

     a1a0.m128i_u64[0] = ((ak_uint64 *)a)[0];   a1a0.m128i_u64[1] = ((ak_uint64 *)a)[1];
     a3a2.m128i_u64[0] = ((ak_uint64 *)a)[2];   a3a2.m128i_u64[1] = ((ak_uint64 *)a)[3];
     a5a4.m128i_u64[0] = ((ak_uint64 *)a)[4];   a5a4.m128i_u64[1] = ((ak_uint64 *)a)[5];
     a7a6.m128i_u64[0] = ((ak_uint64 *)a)[6];   a7a6.m128i_u64[1] = ((ak_uint64 *)a)[7];

     b1b0.m128i_u64[0] = ((ak_uint64 *)b)[0];   b1b0.m128i_u64[1] = ((ak_uint64 *)b)[1];
     b3b2.m128i_u64[0] = ((ak_uint64 *)b)[2];   b3b2.m128i_u64[1] = ((ak_uint64 *)b)[3];
     b5b4.m128i_u64[0] = ((ak_uint64 *)b)[4];   b5b4.m128i_u64[1] = ((ak_uint64 *)b)[5];
     b7b6.m128i_u64[0] = ((ak_uint64 *)b)[6];   b7b6.m128i_u64[1] = ((ak_uint64 *)b)[7];

    /* умножение */
     a0b0 = _mm_clmulepi64_si128(a1a0, b1b0, 0x00);
     a1b0 = _mm_clmulepi64_si128(a1a0, b1b0, 0x01);
     a2b0 = _mm_clmulepi64_si128(a3a2, b1b0, 0x00);
     a3b0 = _mm_clmulepi64_si128(a3a2, b1b0, 0x01);
     a4b0 = _mm_clmulepi64_si128(a5a4, b1b0, 0x00);
     a5b0 = _mm_clmulepi64_si128(a5a4, b1b0, 0x01);
     a6b0 = _mm_clmulepi64_si128(a7a6, b1b0, 0x00);
     a7b0 = _mm_clmulepi64_si128(a7a6, b1b0, 0x01);

     a0b1 = _mm_clmulepi64_si128(a1a0, b1b0, 0x10);
     a1b1 = _mm_clmulepi64_si128(a1a0, b1b0, 0x11);
     a2b1 = _mm_clmulepi64_si128(a3a2, b1b0, 0x10);
     a3b1 = _mm_clmulepi64_si128(a3a2, b1b0, 0x11);
     a4b1 = _mm_clmulepi64_si128(a5a4, b1b0, 0x10);
     a5b1 = _mm_clmulepi64_si128(a5a4, b1b0, 0x11);
     a6b1 = _mm_clmulepi64_si128(a7a6, b1b0, 0x10);
     a7b1 = _mm_clmulepi64_si128(a7a6, b1b0, 0x11);


     a0b2 = _mm_clmulepi64_si128(a1a0, b3b2, 0x00);
     a1b2 = _mm_clmulepi64_si128(a1a0, b3b2, 0x01);
     a2b2 = _mm_clmulepi64_si128(a3a2, b3b2, 0x00);
     a3b2 = _mm_clmulepi64_si128(a3a2, b3b2, 0x01);
     a4b2 = _mm_clmulepi64_si128(a5a4, b3b2, 0x00);
     a5b2 = _mm_clmulepi64_si128(a5a4, b3b2, 0x01);
     a6b2 = _mm_clmulepi64_si128(a7a6, b3b2, 0x00);
     a7b2 = _mm_clmulepi64_si128(a7a6, b3b2, 0x01);

     a0b3 = _mm_clmulepi64_si128(a1a0, b3b2, 0x10);
     a1b3 = _mm_clmulepi64_si128(a1a0, b3b2, 0x11);
     a2b3 = _mm_clmulepi64_si128(a3a2, b3b2, 0x10);
     a3b3 = _mm_clmulepi64_si128(a3a2, b3b2, 0x11);
     a4b3 = _mm_clmulepi64_si128(a5a4, b3b2, 0x10);
     a5b3 = _mm_clmulepi64_si128(a5a4, b3b2, 0x11);
     a6b3 = _mm_clmulepi64_si128(a7a6, b3b2, 0x10);
     a7b3 = _mm_clmulepi64_si128(a7a6, b3b2, 0x11);


     a0b4 = _mm_clmulepi64_si128(a1a0, b5b4, 0x00);
     a1b4 = _mm_clmulepi64_si128(a1a0, b5b4, 0x01);
     a2b4 = _mm_clmulepi64_si128(a3a2, b5b4, 0x00);
     a3b4 = _mm_clmulepi64_si128(a3a2, b5b4, 0x01);
     a4b4 = _mm_clmulepi64_si128(a5a4, b5b4, 0x00);
     a5b4 = _mm_clmulepi64_si128(a5a4, b5b4, 0x01);
     a6b4 = _mm_clmulepi64_si128(a7a6, b5b4, 0x00);
     a7b4 = _mm_clmulepi64_si128(a7a6, b5b4, 0x01);

     a0b5 = _mm_clmulepi64_si128(a1a0, b5b4, 0x10);
     a1b5 = _mm_clmulepi64_si128(a1a0, b5b4, 0x11);
     a2b5 = _mm_clmulepi64_si128(a3a2, b5b4, 0x10);
     a3b5 = _mm_clmulepi64_si128(a3a2, b5b4, 0x11);
     a4b5 = _mm_clmulepi64_si128(a5a4, b5b4, 0x10);
     a5b5 = _mm_clmulepi64_si128(a5a4, b5b4, 0x11);
     a6b5 = _mm_clmulepi64_si128(a7a6, b5b4, 0x10);
     a7b5 = _mm_clmulepi64_si128(a7a6, b5b4, 0x11);


     a0b6 = _mm_clmulepi64_si128(a1a0, b7b6, 0x00);
     a1b6 = _mm_clmulepi64_si128(a1a0, b7b6, 0x01);
     a2b6 = _mm_clmulepi64_si128(a3a2, b7b6, 0x00);
     a3b6 = _mm_clmulepi64_si128(a3a2, b7b6, 0x01);
     a4b6 = _mm_clmulepi64_si128(a5a4, b7b6, 0x00);
     a5b6 = _mm_clmulepi64_si128(a5a4, b7b6, 0x01);
     a6b6 = _mm_clmulepi64_si128(a7a6, b7b6, 0x00);
     a7b6 = _mm_clmulepi64_si128(a7a6, b7b6, 0x01);

     a0b7 = _mm_clmulepi64_si128(a1a0, b7b6, 0x10);
     a1b7 = _mm_clmulepi64_si128(a1a0, b7b6, 0x11);
     a2b7 = _mm_clmulepi64_si128(a3a2, b7b6, 0x10);
     a3b7 = _mm_clmulepi64_si128(a3a2, b7b6, 0x11);
     a4b7 = _mm_clmulepi64_si128(a5a4, b7b6, 0x10);
     a5b7 = _mm_clmulepi64_si128(a5a4, b7b6, 0x11);
     a6b7 = _mm_clmulepi64_si128(a7a6, b7b6, 0x10);
     a7b7 = _mm_clmulepi64_si128(a7a6, b7b6, 0x11);

    /* суммирование, потом приведение */

     r15 = a7b7.m128i_u64[1];                                                                             //sum
     r14 = a7b7.m128i_u64[0] ^ a6b7.m128i_u64[1] ^ a7b6.m128i_u64[1];                                                         //sum
     r13 = a6b7.m128i_u64[0] ^ a5b7.m128i_u64[1] ^ a7b6.m128i_u64[0] ^ a6b6.m128i_u64[1] ^ a7b5.m128i_u64[1];                                     //sum
     r12 = a5b7.m128i_u64[0] ^ a4b7.m128i_u64[1] ^ a6b6.m128i_u64[0] ^ a5b6.m128i_u64[1] ^ a7b5.m128i_u64[0] ^ a6b5.m128i_u64[1] ^ a7b4.m128i_u64[1];                 //sum
     r11 = a4b7.m128i_u64[0] ^ a3b7.m128i_u64[1] ^ a5b6.m128i_u64[0] ^ a4b6.m128i_u64[1] ^ a6b5.m128i_u64[0] ^ a5b5.m128i_u64[1] ^ a7b4.m128i_u64[0]
             ^ a6b4.m128i_u64[1] ^ a7b3.m128i_u64[1];                                                               //sum
     r10 = a3b7.m128i_u64[0] ^ a2b7.m128i_u64[1] ^ a4b6.m128i_u64[0] ^ a3b6.m128i_u64[1] ^ a5b5.m128i_u64[0] ^ a4b5.m128i_u64[1] ^ a6b4.m128i_u64[0]
             ^ a5b4.m128i_u64[1] ^ a7b3.m128i_u64[0] ^ a6b3.m128i_u64[1] ^ a7b2.m128i_u64[1];                                           //sum
     r9  = a2b7.m128i_u64[0] ^ a1b7.m128i_u64[1] ^ a3b6.m128i_u64[0] ^ a2b6.m128i_u64[1] ^ a4b5.m128i_u64[0] ^ a3b5.m128i_u64[1] ^ a5b4.m128i_u64[0]
             ^ a4b4.m128i_u64[1] ^ a6b3.m128i_u64[0] ^ a5b3.m128i_u64[1] ^ a7b2.m128i_u64[0] ^ a6b2.m128i_u64[1] ^ a7b1.m128i_u64[1];                       //sum
     r8  = a1b7.m128i_u64[0] ^ a0b7.m128i_u64[1] ^ a2b6.m128i_u64[0] ^ a1b6.m128i_u64[1] ^ a3b5.m128i_u64[0] ^ a2b5.m128i_u64[1] ^ a4b4.m128i_u64[0]
             ^ a3b4.m128i_u64[1] ^ a5b3.m128i_u64[0] ^ a4b3.m128i_u64[1] ^ a6b2.m128i_u64[0] ^ a5b2.m128i_u64[1] ^ a7b1.m128i_u64[0] ^ a6b1.m128i_u64[1] ^ a7b0.m128i_u64[1];   //sum
     r8 ^= (r15 >> 56) ^ (r15 >> 59) ^ (r15 >> 62);                                             //mod

     r7  = a0b7.m128i_u64[0] ^ a1b6.m128i_u64[0] ^ a0b6.m128i_u64[1] ^ a2b5.m128i_u64[0] ^ a1b5.m128i_u64[1] ^ a3b4.m128i_u64[0] ^ a2b4.m128i_u64[1]
             ^ a4b3.m128i_u64[0] ^ a3b3.m128i_u64[1] ^ a5b2.m128i_u64[0] ^ a4b2.m128i_u64[1] ^ a6b1.m128i_u64[0] ^ a5b1.m128i_u64[1] ^ a7b0.m128i_u64[0] ^ a6b0.m128i_u64[1];   //sum
     r7 ^= (r15 << 8) ^ (r15 << 5) ^ (r15 << 2) ^ r15 ^ (r14 >> 56) ^ (r14 >> 59) ^ (r14 >> 62);//mod

     r6  = a0b6.m128i_u64[0] ^ a1b5.m128i_u64[0] ^ a0b5.m128i_u64[1] ^ a2b4.m128i_u64[0] ^ a1b4.m128i_u64[1] ^ a3b3.m128i_u64[0] ^ a2b3.m128i_u64[1]
             ^ a4b2.m128i_u64[0] ^ a3b2.m128i_u64[1] ^ a5b1.m128i_u64[0] ^ a4b1.m128i_u64[1] ^ a6b0.m128i_u64[0] ^ a5b0.m128i_u64[1];                       //sum
     r6 ^= (r14 << 8) ^ (r14 << 5) ^ (r14 << 2) ^ r14 ^ (r13 >> 56) ^ (r13 >> 59) ^ (r13 >> 62);//mod

     r5  = a0b5.m128i_u64[0] ^ a1b4.m128i_u64[0] ^ a0b4.m128i_u64[1] ^ a2b3.m128i_u64[0] ^ a1b3.m128i_u64[1] ^ a3b2.m128i_u64[0] ^ a2b2.m128i_u64[1]
             ^ a4b1.m128i_u64[0] ^ a3b1.m128i_u64[1] ^ a5b0.m128i_u64[0] ^ a4b0.m128i_u64[1];                                           //sum
     r5 ^= (r13 << 8) ^ (r13 << 5) ^ (r13 << 2) ^ r13 ^ (r12 >> 56) ^ (r12 >> 59) ^ (r12 >> 62);//mod

     r4  = a0b4.m128i_u64[0] ^ a1b3.m128i_u64[0] ^ a0b3.m128i_u64[1] ^ a2b2.m128i_u64[0] ^ a1b2.m128i_u64[1] ^ a3b1.m128i_u64[0] ^ a2b1.m128i_u64[1]
             ^ a4b0.m128i_u64[0] ^ a3b0.m128i_u64[1];                                                               //sum
     r4 ^= (r12 << 8) ^ (r12 << 5) ^ (r12 << 2) ^ r12 ^ (r11 >> 56) ^ (r11 >> 59) ^ (r11 >> 62);//mod

     r3  = a0b3.m128i_u64[0] ^ a1b2.m128i_u64[0] ^ a0b2.m128i_u64[1] ^ a2b1.m128i_u64[0] ^ a1b1.m128i_u64[1] ^ a3b0.m128i_u64[0] ^ a2b0.m128i_u64[1];                 //sum
     r3 ^= (r11 << 8) ^ (r11 << 5) ^ (r11 << 2) ^ r11 ^ (r10 >> 56) ^ (r10 >> 59) ^ (r10 >> 62);//mod

     r2  = a0b2.m128i_u64[0] ^ a1b1.m128i_u64[0] ^ a0b1.m128i_u64[1] ^ a2b0.m128i_u64[0] ^ a1b0.m128i_u64[1];                                     //sum
     r2 ^= (r10 << 8) ^ (r10 << 5) ^ (r10 << 2) ^ r10 ^ (r9 >> 56) ^ (r9 >> 59) ^ (r9 >> 62);   //mod

     r1  = a0b1.m128i_u64[0] ^ a1b0.m128i_u64[0] ^ a0b0.m128i_u64[1];                                                         //sum
     r1 ^= (r9 << 8) ^ (r9 << 5) ^ (r9 << 2) ^ r9 ^ (r8 >> 56) ^ (r8 >> 59) ^ (r8 >> 62);       //mod

     r0  = a0b0.m128i_u64[0];                                                                             //sum
     r0 ^= (r8 << 8) ^ (r8 << 5) ^ (r8 << 2) ^ r8;                                              //mod

     ((ak_uint64 *)z)[0] = r0;
     ((ak_uint64 *)z)[1] = r1;
     ((ak_uint64 *)z)[2] = r2;
     ((ak_uint64 *)z)[3] = r3;
     ((ak_uint64 *)z)[4] = r4;
     ((ak_uint64 *)z)[5] = r5;
     ((ak_uint64 *)z)[6] = r6;
     ((ak_uint64 *)z)[7] = r7;
#else
     __m128i a1a0 = _mm_set_epi64x(((ak_uint64 *)a)[1], ((ak_uint64 *)a)[0]);
     __m128i a3a2 = _mm_set_epi64x(((ak_uint64 *)a)[3], ((ak_uint64 *)a)[2]);
     __m128i a5a4 = _mm_set_epi64x(((ak_uint64 *)a)[5], ((ak_uint64 *)a)[4]);
     __m128i a7a6 = _mm_set_epi64x(((ak_uint64 *)a)[7], ((ak_uint64 *)a)[6]);
     __m128i b1b0 = _mm_set_epi64x(((ak_uint64 *)b)[1], ((ak_uint64 *)b)[0]);
     __m128i b3b2 = _mm_set_epi64x(((ak_uint64 *)b)[3], ((ak_uint64 *)b)[2]);
     __m128i b5b4 = _mm_set_epi64x(((ak_uint64 *)b)[5], ((ak_uint64 *)b)[4]);
     __m128i b7b6 = _mm_set_epi64x(((ak_uint64 *)b)[7], ((ak_uint64 *)b)[6]);

     /* умножение */
     __m128i a0b0 = _mm_clmulepi64_si128(a1a0, b1b0, 0x00);
     __m128i a1b0 = _mm_clmulepi64_si128(a1a0, b1b0, 0x01);
     __m128i a2b0 = _mm_clmulepi64_si128(a3a2, b1b0, 0x00);
     __m128i a3b0 = _mm_clmulepi64_si128(a3a2, b1b0, 0x01);
     __m128i a4b0 = _mm_clmulepi64_si128(a5a4, b1b0, 0x00);
     __m128i a5b0 = _mm_clmulepi64_si128(a5a4, b1b0, 0x01);
     __m128i a6b0 = _mm_clmulepi64_si128(a7a6, b1b0, 0x00);
     __m128i a7b0 = _mm_clmulepi64_si128(a7a6, b1b0, 0x01);

     __m128i a0b1 = _mm_clmulepi64_si128(a1a0, b1b0, 0x10);
     __m128i a1b1 = _mm_clmulepi64_si128(a1a0, b1b0, 0x11);
     __m128i a2b1 = _mm_clmulepi64_si128(a3a2, b1b0, 0x10);
     __m128i a3b1 = _mm_clmulepi64_si128(a3a2, b1b0, 0x11);
     __m128i a4b1 = _mm_clmulepi64_si128(a5a4, b1b0, 0x10);
     __m128i a5b1 = _mm_clmulepi64_si128(a5a4, b1b0, 0x11);
     __m128i a6b1 = _mm_clmulepi64_si128(a7a6, b1b0, 0x10);
     __m128i a7b1 = _mm_clmulepi64_si128(a7a6, b1b0, 0x11);


     __m128i a0b2 = _mm_clmulepi64_si128(a1a0, b3b2, 0x00);
     __m128i a1b2 = _mm_clmulepi64_si128(a1a0, b3b2, 0x01);
     __m128i a2b2 = _mm_clmulepi64_si128(a3a2, b3b2, 0x00);
     __m128i a3b2 = _mm_clmulepi64_si128(a3a2, b3b2, 0x01);
     __m128i a4b2 = _mm_clmulepi64_si128(a5a4, b3b2, 0x00);
     __m128i a5b2 = _mm_clmulepi64_si128(a5a4, b3b2, 0x01);
     __m128i a6b2 = _mm_clmulepi64_si128(a7a6, b3b2, 0x00);
     __m128i a7b2 = _mm_clmulepi64_si128(a7a6, b3b2, 0x01);

     __m128i a0b3 = _mm_clmulepi64_si128(a1a0, b3b2, 0x10);
     __m128i a1b3 = _mm_clmulepi64_si128(a1a0, b3b2, 0x11);
     __m128i a2b3 = _mm_clmulepi64_si128(a3a2, b3b2, 0x10);
     __m128i a3b3 = _mm_clmulepi64_si128(a3a2, b3b2, 0x11);
     __m128i a4b3 = _mm_clmulepi64_si128(a5a4, b3b2, 0x10);
     __m128i a5b3 = _mm_clmulepi64_si128(a5a4, b3b2, 0x11);
     __m128i a6b3 = _mm_clmulepi64_si128(a7a6, b3b2, 0x10);
     __m128i a7b3 = _mm_clmulepi64_si128(a7a6, b3b2, 0x11);


     __m128i a0b4 = _mm_clmulepi64_si128(a1a0, b5b4, 0x00);
     __m128i a1b4 = _mm_clmulepi64_si128(a1a0, b5b4, 0x01);
     __m128i a2b4 = _mm_clmulepi64_si128(a3a2, b5b4, 0x00);
     __m128i a3b4 = _mm_clmulepi64_si128(a3a2, b5b4, 0x01);
     __m128i a4b4 = _mm_clmulepi64_si128(a5a4, b5b4, 0x00);
     __m128i a5b4 = _mm_clmulepi64_si128(a5a4, b5b4, 0x01);
     __m128i a6b4 = _mm_clmulepi64_si128(a7a6, b5b4, 0x00);
     __m128i a7b4 = _mm_clmulepi64_si128(a7a6, b5b4, 0x01);

     __m128i a0b5 = _mm_clmulepi64_si128(a1a0, b5b4, 0x10);
     __m128i a1b5 = _mm_clmulepi64_si128(a1a0, b5b4, 0x11);
     __m128i a2b5 = _mm_clmulepi64_si128(a3a2, b5b4, 0x10);
     __m128i a3b5 = _mm_clmulepi64_si128(a3a2, b5b4, 0x11);
     __m128i a4b5 = _mm_clmulepi64_si128(a5a4, b5b4, 0x10);
     __m128i a5b5 = _mm_clmulepi64_si128(a5a4, b5b4, 0x11);
     __m128i a6b5 = _mm_clmulepi64_si128(a7a6, b5b4, 0x10);
     __m128i a7b5 = _mm_clmulepi64_si128(a7a6, b5b4, 0x11);


     __m128i a0b6 = _mm_clmulepi64_si128(a1a0, b7b6, 0x00);
     __m128i a1b6 = _mm_clmulepi64_si128(a1a0, b7b6, 0x01);
     __m128i a2b6 = _mm_clmulepi64_si128(a3a2, b7b6, 0x00);
     __m128i a3b6 = _mm_clmulepi64_si128(a3a2, b7b6, 0x01);
     __m128i a4b6 = _mm_clmulepi64_si128(a5a4, b7b6, 0x00);
     __m128i a5b6 = _mm_clmulepi64_si128(a5a4, b7b6, 0x01);
     __m128i a6b6 = _mm_clmulepi64_si128(a7a6, b7b6, 0x00);
     __m128i a7b6 = _mm_clmulepi64_si128(a7a6, b7b6, 0x01);

     __m128i a0b7 = _mm_clmulepi64_si128(a1a0, b7b6, 0x10);
     __m128i a1b7 = _mm_clmulepi64_si128(a1a0, b7b6, 0x11);
     __m128i a2b7 = _mm_clmulepi64_si128(a3a2, b7b6, 0x10);
     __m128i a3b7 = _mm_clmulepi64_si128(a3a2, b7b6, 0x11);
     __m128i a4b7 = _mm_clmulepi64_si128(a5a4, b7b6, 0x10);
     __m128i a5b7 = _mm_clmulepi64_si128(a5a4, b7b6, 0x11);
     __m128i a6b7 = _mm_clmulepi64_si128(a7a6, b7b6, 0x10);
     __m128i a7b7 = _mm_clmulepi64_si128(a7a6, b7b6, 0x11);

     /* суммирование, потом приведение */
     ak_uint64 r0, r1, r2, r3, r4, r5, r6, r7,
             r8, r9, r10, r11, r12, r13, r14, r15;      //хранит ответ. r8-r15 при желании можно (?) оптимизировать в 2 переменные.

     r15 = a7b7[1];                                                                             //sum
     r14 = a7b7[0] ^ a6b7[1] ^ a7b6[1];                                                         //sum
     r13 = a6b7[0] ^ a5b7[1] ^ a7b6[0] ^ a6b6[1] ^ a7b5[1];                                     //sum
     r12 = a5b7[0] ^ a4b7[1] ^ a6b6[0] ^ a5b6[1] ^ a7b5[0] ^ a6b5[1] ^ a7b4[1];                 //sum
     r11 = a4b7[0] ^ a3b7[1] ^ a5b6[0] ^ a4b6[1] ^ a6b5[0] ^ a5b5[1] ^ a7b4[0]
             ^ a6b4[1] ^ a7b3[1];                                                               //sum
     r10 = a3b7[0] ^ a2b7[1] ^ a4b6[0] ^ a3b6[1] ^ a5b5[0] ^ a4b5[1] ^ a6b4[0]
             ^ a5b4[1] ^ a7b3[0] ^ a6b3[1] ^ a7b2[1];                                           //sum
     r9  = a2b7[0] ^ a1b7[1] ^ a3b6[0] ^ a2b6[1] ^ a4b5[0] ^ a3b5[1] ^ a5b4[0]
             ^ a4b4[1] ^ a6b3[0] ^ a5b3[1] ^ a7b2[0] ^ a6b2[1] ^ a7b1[1];                       //sum
     r8  = a1b7[0] ^ a0b7[1] ^ a2b6[0] ^ a1b6[1] ^ a3b5[0] ^ a2b5[1] ^ a4b4[0]
             ^ a3b4[1] ^ a5b3[0] ^ a4b3[1] ^ a6b2[0] ^ a5b2[1] ^ a7b1[0] ^ a6b1[1] ^ a7b0[1];   //sum
     r8 ^= (r15 >> 56) ^ (r15 >> 59) ^ (r15 >> 62);                                             //mod
     r7  = a0b7[0] ^ a1b6[0] ^ a0b6[1] ^ a2b5[0] ^ a1b5[1] ^ a3b4[0] ^ a2b4[1]
             ^ a4b3[0] ^ a3b3[1] ^ a5b2[0] ^ a4b2[1] ^ a6b1[0] ^ a5b1[1] ^ a7b0[0] ^ a6b0[1];   //sum
     r7 ^= (r15 << 8) ^ (r15 << 5) ^ (r15 << 2) ^ r15 ^ (r14 >> 56) ^ (r14 >> 59) ^ (r14 >> 62);//mod
     r6  = a0b6[0] ^ a1b5[0] ^ a0b5[1] ^ a2b4[0] ^ a1b4[1] ^ a3b3[0] ^ a2b3[1]
             ^ a4b2[0] ^ a3b2[1] ^ a5b1[0] ^ a4b1[1] ^ a6b0[0] ^ a5b0[1];                       //sum
     r6 ^= (r14 << 8) ^ (r14 << 5) ^ (r14 << 2) ^ r14 ^ (r13 >> 56) ^ (r13 >> 59) ^ (r13 >> 62);//mod
     r5  = a0b5[0] ^ a1b4[0] ^ a0b4[1] ^ a2b3[0] ^ a1b3[1] ^ a3b2[0] ^ a2b2[1]
             ^ a4b1[0] ^ a3b1[1] ^ a5b0[0] ^ a4b0[1];                                           //sum
     r5 ^= (r13 << 8) ^ (r13 << 5) ^ (r13 << 2) ^ r13 ^ (r12 >> 56) ^ (r12 >> 59) ^ (r12 >> 62);//mod
     r4  = a0b4[0] ^ a1b3[0] ^ a0b3[1] ^ a2b2[0] ^ a1b2[1] ^ a3b1[0] ^ a2b1[1]
             ^ a4b0[0] ^ a3b0[1];                                                               //sum
     r4 ^= (r12 << 8) ^ (r12 << 5) ^ (r12 << 2) ^ r12 ^ (r11 >> 56) ^ (r11 >> 59) ^ (r11 >> 62);//mod
     r3  = a0b3[0] ^ a1b2[0] ^ a0b2[1] ^ a2b1[0] ^ a1b1[1] ^ a3b0[0] ^ a2b0[1];                 //sum
     r3 ^= (r11 << 8) ^ (r11 << 5) ^ (r11 << 2) ^ r11 ^ (r10 >> 56) ^ (r10 >> 59) ^ (r10 >> 62);//mod
     r2  = a0b2[0] ^ a1b1[0] ^ a0b1[1] ^ a2b0[0] ^ a1b0[1];                                     //sum
     r2 ^= (r10 << 8) ^ (r10 << 5) ^ (r10 << 2) ^ r10 ^ (r9 >> 56) ^ (r9 >> 59) ^ (r9 >> 62);   //mod
     r1  = a0b1[0] ^ a1b0[0] ^ a0b0[1];                                                         //sum
     r1 ^= (r9 << 8) ^ (r9 << 5) ^ (r9 << 2) ^ r9 ^ (r8 >> 56) ^ (r8 >> 59) ^ (r8 >> 62);       //mod
     r0  = a0b0[0];                                                                             //sum
     r0 ^= (r8 << 8) ^ (r8 << 5) ^ (r8 << 2) ^ r8;                                              //mod

     ((ak_uint64 *)z)[0] = r0;
     ((ak_uint64 *)z)[1] = r1;
     ((ak_uint64 *)z)[2] = r2;
     ((ak_uint64 *)z)[3] = r3;
     ((ak_uint64 *)z)[4] = r4;
     ((ak_uint64 *)z)[5] = r5;
     ((ak_uint64 *)z)[6] = r6;
     ((ak_uint64 *)z)[7] = r7;
#endif
}

#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование операции умножения в поле \f$ \mathbb F_{2^{64}}\f$. */
 static bool_t ak_gf64_multiplication_test( void )
{
 int i = 0;
 ak_uint8 values8[64] = { /* последовательный набор байт в памяти */
    0x61, 0x30, 0xD1, 0xDE, 0x01, 0x73, 0x01, 0x30, 0x11, 0x0E, 0x1F, 0xE9, 0xA3, 0x06, 0x1C, 0x6B,
    0x14, 0x1A, 0xD5, 0x69, 0xFE, 0xF4, 0xA8, 0x26, 0x03, 0xCA, 0x3F, 0x74, 0x0C, 0x2F, 0x3A, 0x97,
    0x3F, 0x3D, 0x85, 0x40, 0xED, 0x56, 0x5C, 0x89, 0xCE, 0x5E, 0x5E, 0xC6, 0x29, 0x02, 0x34, 0xAE,
    0xE2, 0x8C, 0xA1, 0x03, 0xDE, 0xDB, 0x71, 0xFE, 0x52, 0x5E, 0xBD, 0xBB, 0x63, 0x1C, 0xE6, 0x18 };
 ak_uint64 values[8] =
#ifdef AK_LITTLE_ENDIAN
  {
    0x30017301ded13061LL, 0x6b1c06a3e91f0e11LL, 0x26a8f4fe69d51a14LL, 0x973a2f0c743fca03LL,
    0x895c56ed40853d3fLL, 0xae340229c65e5eceLL, 0xfe71dbde03a18ce2LL, 0x18e61c63bbbd5e52LL };
#else
  {
    0x6130D1DE01730130LL, 0x110E1FE9A3061C6BLL, 0x141AD569FEF4A826LL, 0x03CA3F740C2F3A97LL,
    0x3F3D8540ED565C89LL, 0xCE5E5EC6290234AELL, 0xE28CA103DEDB71FELL, 0x525EBDBB631CE618LL };
#endif
 ak_uint64 x, y, z = 0, z1 = 0;

 /* сравниваем исходные данные */
  for( i = 0; i < 8; i++ ) {
    if( !ak_ptr_is_equal( values8+i*8, &values[i], 8 )) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__,
                                              "wrong constant V[%d] in memory representation", i );
      return ak_false;
    }
  }

 /* сравнение с контрольными примерами */
#ifdef AK_LITTLE_ENDIAN
  y = 0xF000000000000011LL; x = 0x00001aaabcda1115LL;
#else
  y = 0x11000000000000F0LL; x = 0x1511dabcaa1a0000LL;
#endif
 (void)z1; /* неиспользуемая переменная */

 for( i = 0; i < 8; i++ ) {
    ak_gf64_mul_uint64( &z, &x, &y );
    if( z != values[i] ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                         "uint64 calculated %s on iteration %d",
                                                           ak_ptr_to_hexstr( &z, 8, ak_true ), i );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                         "uint64 expected   %s on iteration %d",
                                                   ak_ptr_to_hexstr( &values[i], 8, ak_true ), i );
      return ak_false;
    }
    x = y; y = z;
  }

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "comparison between two implementations included");

 /* сравнение с контрольными примерами */
 y = 0xF000000000000011LL; x = 0x1aaabcda1115LL; z = 0;
 for( i = 0; i < 8; i++ ) {
    ak_gf64_mul_pcmulqdq( &z, &x, &y );
    if( z != values[i] ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                           "pcmulqdq calculated %s on iteration %d",
                                                           ak_ptr_to_hexstr( &z, 8, ak_true ), i );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                           "pcmulqdq expected   %s on iteration %d",
                                                   ak_ptr_to_hexstr( &values[i], 8, ak_true ), i );
      return ak_false;
    }
    x = y; y = z;
  }

 /* проверка идентичности работы двух реализаций */
 y = 0xF1abcd5421110011LL; x = 0x1aaabcda1115LL; z = 0;
 for( i = 0; i < 1000; i++ ) {
    ak_gf64_mul_uint64( &z, &x, &y );
    ak_gf64_mul_pcmulqdq( &z1, &x, &y );
    if( z != z1 ) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated   %s",
                                                               ak_ptr_to_hexstr( &z, 8, ak_true ));
      ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s",
                                                              ak_ptr_to_hexstr( &z1, 8, ak_true ));
      return ak_false;
    }
    x = y; y = z;
  }
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "one thousand iterations for random values is Ok");
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование операции умножения в поле \f$ \mathbb F_{2^{128}}\f$. */
 static bool_t ak_gf128_multiplication_test( void )
{
 int i = 0;
 ak_uint8 a8[16] = {
      0x5d, 0x47, 0x53, 0x5d, 0x72, 0x6f, 0x74, 0x63, 0x65, 0x56, 0x74, 0x73, 0x65, 0x54, 0x5b, 0x7b };
 ak_uint8 b8[16] = {
      0x5d, 0x6e, 0x6f, 0x72, 0x65, 0x75, 0x47, 0x5b, 0x29, 0x79, 0x61, 0x68, 0x53, 0x28, 0x69, 0x48 };
 ak_uint8 m8[16] = {
      0xd2, 0x06, 0x35, 0x32, 0xda, 0x10, 0x4e, 0x7e, 0x2e, 0xd1, 0x5e, 0x9a, 0xa0, 0x29, 0x02, 0x04 };
 ak_uint8 result[16], result2[16];

 ak_uint128 a, b, m;
#ifdef AK_LITTLE_ENDIAN
  a.q[0] = 0x63746f725d53475dLL; a.q[1] = 0x7b5b546573745665LL;
  b.q[0] = 0x5b477565726f6e5dLL; b.q[1] = 0x4869285368617929LL;
  m.q[0] = 0x7e4e10da323506d2LL; m.q[1] = 0x040229a09a5ed12eLL;
#else
  a.q[0] = 0x5d47535d726f7463LL; a.q[1] = 0x6556747365545b7bLL;
  b.q[0] = 0x5d6e6f726575475bLL; b.q[1] = 0x2979616853286948LL;
  m.q[0] = 0xd2063532da104e7eLL; m.q[1] = 0x2ed15e9aa0290204LL;
#endif
  memset( result, 0, 16 );
  memset( result2, 0, 16 );
  (void)i;

 /* сравниваем данные */
 if( !ak_ptr_is_equal( a8, a.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant A in memory representation");
   return ak_false;
 }
 if( !ak_ptr_is_equal( b8, b.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant B in memory representation");
   return ak_false;
 }
 if( !ak_ptr_is_equal( m8, m.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant M in memory representation");
   return ak_false;
 }

 /* проверяем пример из white paper для GCM (применение pcmulqdq для GCM)
    a = 0x7b5b54657374566563746f725d53475d
    b = 0x48692853686179295b477565726f6e5d
    GFMUL128 (a, b) = 0x40229a09a5ed12e7e4e10da323506d2 */

 ak_gf128_mul_uint64( result, &a, &b );
 if( !ak_ptr_is_equal_with_log( result, m8, 16 )) goto lexit;

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "comparison between two implementations included");

 ak_gf128_mul_pcmulqdq( result2, &a, &b );
 /* сравнение с константой */
 if( !ak_ptr_is_equal_with_log( result2, m8, 16 )) {
   ak_error_message( ak_error_ok, __func__,
                                      "result with pcmulqdq differs from predefined const value" );
   goto lexit;
 }
 /* сравнение с другим способом вычисления */
 if( !ak_ptr_is_equal_with_log( result2, result, 16 )) {
   ak_error_message( ak_error_ok, __func__,
                               "result with pcmulqdq differs from standard method of evaluation" );
   goto lexit;
 }

 /* сравнение для двух способов на нескольких значениях */
 for( i = 1; i < 1000; i++ ) {
   a.q[0] = b.q[1]; a.q[1] = b.q[0];
   memcpy( b.b, result, 16 );

   ak_gf128_mul_uint64( result, &a, &b );
   ak_gf128_mul_pcmulqdq( result2, &a, &b );
   if( !ak_ptr_is_equal_with_log( result, result2, 16 )) {
     ak_error_message_fmt( ak_error_ok, __func__,
            "result with pcmulqdq differs from standard method of evaluation on iteration %d", i );
     goto lexit;
   }
 }
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "one thousand iterations for random values is Ok");
#endif

 return ak_true;

  lexit: ak_error_set_value( ak_error_not_equal_data );
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование операции умножения в поле \f$ \mathbb F_{2^{256}}\f$. */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_gf256_multiplication_test( void )
{
  int i = 0;
  ak_uint64 theta[4] = { 0x2LL, 0x0LL, 0x0LL, 0x0LL },
             unit[4] = { 0x2LL, 0x0LL, 0x0LL, 0x0LL }, temp[4];

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
  ak_uint64 temp2[4], temp3[4];
#endif

 /* проверяем корректность возведения в степень примитивного элемента */
  for( i = 254; i >= 0; i-- ) {
     ak_gf256_mul_uint64( temp, unit, unit );
     unit[0] = temp[0]^theta[0];
     unit[1] = temp[1]^theta[1];
     unit[2] = temp[2]^theta[2];
     unit[3] = temp[3]^theta[3];
     if( ak_ptr_is_equal( theta, unit, sizeof( theta ))) {
       ak_error_message( ak_error_undefined_value, __func__, "the second circle detected" );
       ak_error_message( ak_error_undefined_value, __func__,
                                          "incorrect result of primitive element exponentiation" );
       return ak_false;
     }
  }
  if( ak_ptr_is_equal_with_log( theta, temp, sizeof( theta )) != ak_true ) {
    ak_error_message( ak_error_undefined_value, __func__,
                                          "incorrect result of primitive element exponentiation" );
    return ak_false;
  }

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "comparison between two implementations included");

 /* перемножаем произвольные константы */
  theta[0] = 0x22LL; theta[1] = 0x33LL; theta[2] = 0x44LL; theta[3] = 0xae12a7LL;
  unit[0] = 0x2110eLL; unit[1] = 0x13acd4LL; unit[2] = 0x00114aLL;
  unit[3] = 0xaFFFFFFF00000000LL+ (ak_uint32)rand();

  for( i = 0; i < 1000; i++ ) {
     ak_gf256_mul_uint64( temp, theta, unit );
     ak_gf256_mul_pcmulqdq( temp2, theta, unit );
     if( ak_ptr_is_equal_with_log( temp, temp2, sizeof( theta )) != ak_true ) {
       ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                  "pcmulqdq calculated %s on iteration %d",
                                          ak_ptr_to_hexstr( temp2, sizeof( temp2 ), ak_true ), i );
       ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                  "uint64 calculated %s on iteration %d",
                                            ak_ptr_to_hexstr( temp, sizeof( temp ), ak_true ), i );
       return ak_false;
     }
     ak_gf256_mul_uint64( temp, unit, theta );
     ak_gf256_mul_pcmulqdq( temp3, unit, theta );
     if( ak_ptr_is_equal( temp, temp3, sizeof( theta )) != ak_true ) {
       ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                       "pcmulqdq calculated %s on iteration %d",
                                          ak_ptr_to_hexstr( temp3, sizeof( temp3 ), ak_true ), i );
       ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                       "uint64 calculated %s on iteration %d",
                                            ak_ptr_to_hexstr( temp, sizeof( temp ), ak_true ), i );
       return ak_false;
     }
     if( ak_ptr_is_equal( temp2, temp3, sizeof( temp2 )) != ak_true ) {
       ak_error_message_fmt( ak_error_not_equal_data, __func__,
                                               "non commutative operation released in GF(2^256)" );
       return ak_false;
     }
     memcpy( theta, temp, sizeof( temp ));
  }

 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "one thousand iterations for random values is Ok");

#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование операции умножения в поле \f$ \mathbb F_{2^{512}}\f$. */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_gf512_multiplication_test( void )
{
  int i = 0;
  ak_uint64 theta[8] = { 0x2LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL },
             unit[8] = { 0x2LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL }, temp[8];

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
  ak_uint64 temp2[8], temp3[8];
#endif

 /* проверяем корректность возведения в степень примитивного элемента */
  for( i = 510; i >= 0; i-- ) {
     ak_gf512_mul_uint64( temp, unit, unit );
     unit[0] = temp[0]^theta[0];
     unit[1] = temp[1]^theta[1];
     unit[2] = temp[2]^theta[2];
     unit[3] = temp[3]^theta[3];
     unit[4] = temp[4]^theta[4];
     unit[5] = temp[5]^theta[5];
     unit[6] = temp[6]^theta[6];
     unit[7] = temp[7]^theta[7];
     if( ak_ptr_is_equal( theta, unit, sizeof( theta ))) {
       ak_error_message( ak_error_undefined_value, __func__, "the second circle detected" );
       ak_error_message( ak_error_undefined_value, __func__,
                                          "incorrect result of primitive element exponentiation" );
       return ak_false;
     }
  }
  if( ak_ptr_is_equal_with_log( theta, temp, sizeof( theta )) != ak_true ) {
    ak_error_message( ak_error_undefined_value, __func__,
                                          "incorrect result of primitive element exponentiation" );
    return ak_false;
  }

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "comparison between two implementations included");

 /* перемножаем произвольные константы */
  theta[0] = 0x22LL; theta[1] = 0x33LL; theta[2] = 0x44LL; theta[3] = 0xae12a7LL;
  theta[4] = 0x01acee122LL; theta[5] = 0x12121aLL; theta[6] = 0x3LL; theta[7] = 0x7aac321432LL;
  unit[0] = 0x2110eLL; unit[1] = 0x13acd4LL; unit[2] = 0x00114aLL; unit[3] = 0x11a2110eLL;
  unit[4] = 0xa2a3a6c12LL; unit[5] = 0x01454ddff1LL; unit[6] = 0x121afffc03114aLL;
  unit[3] = 0xaFFFFFFF00000000LL+ (ak_uint32)rand();

  for( i = 0; i < 1000; i++ ) {
     ak_gf512_mul_uint64( temp, theta, unit );
     ak_gf512_mul_pcmulqdq( temp2, theta, unit );
     if( ak_ptr_is_equal( temp, temp2, sizeof( theta )) != ak_true ) {
       ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                      "pcmulqdq calculated %s on iteration %d",
                                          ak_ptr_to_hexstr( temp2, sizeof( temp2 ), ak_true ), i );
       ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                      "uint64 calculated %s on iteration %d",
                                            ak_ptr_to_hexstr( temp, sizeof( temp ), ak_true ), i );
       return ak_false;
     }
     ak_gf512_mul_uint64( temp, unit, theta );
     ak_gf512_mul_pcmulqdq( temp3, unit, theta );
     if( ak_ptr_is_equal( temp, temp3, sizeof( theta )) != ak_true ) {
       ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                   "pcmulqdq calculated %s on iteration %d",
                                         ak_ptr_to_hexstr( temp3, sizeof( temp3 ), ak_true ), i );
       ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                   "uint64 calculated %s on iteration %d",
                                           ak_ptr_to_hexstr( temp, sizeof( temp ), ak_true ), i );
       return ak_false;
     }
     if( ak_ptr_is_equal( temp2, temp3, sizeof( temp2 )) != ak_true ) {
       ak_error_message_fmt( ak_error_not_equal_data, __func__,
                                               "non commutative operation released in GF(2^512)" );
       return ak_false;
     }
     memcpy( theta, temp, sizeof( temp ));
  }

 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "one thousand iterations for random values is Ok");

#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_gfn_multiplication( void )
{
 int audit = ak_log_get_level();

 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing the Galois fileds arithmetic started");

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ ,
                                      "using pcmulqdq for multiplication in finite Galois fields");
#endif

 if( ak_gf64_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^64)");
   return ak_false;
 } else
    if( audit >= ak_log_maximum )
     ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^64) is OK");


 if( ak_gf128_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^128)");
   return ak_false;
 } else
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^128) is OK");


 if( ak_gf256_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^256)");
   return ak_false;
 } else
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^256) is OK");


 if( ak_gf512_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^512)");
   return ak_false;
 } else
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^512) is OK");


 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ ,
                                        "testing the Galois fileds arithmetic ended successfully");
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_gf2n.c  */
/* ----------------------------------------------------------------------------------------------- */
