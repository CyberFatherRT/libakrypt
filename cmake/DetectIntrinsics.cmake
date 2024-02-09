# -------------------------------------------------------------------------------------------------- #
include(CheckCSourceCompiles)

# -------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <sys/types.h>
  int main( void ) {
    #if defined( __x86_64__ )
      u_int64_t w1, w0, u = 1, v = 2;
      __asm__ (\"mulq %3\" : \"=a,a\" (w0), \"=d,d\" (w1) : \"%0,0\" (u), \"r,m\" (v));
      return 0;
    #else
      #error Unsupported architecture
    #endif
  }" AK_HAVE_BUILTIN_MULQ_GCC )

if( AK_HAVE_BUILTIN_MULQ_GCC )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_HAVE_BUILTIN_MULQ_GCC" )
endif()

# -------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <wmmintrin.h>
  int main( void ) {

   __m128i a, b, c;
   c = _mm_clmulepi64_si128( a, b, 0x00 );

  return 0;
 }" AK_HAVE_BUILTIN_CLMULEPI64 )

if( AK_HAVE_BUILTIN_CLMULEPI64 )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_HAVE_BUILTIN_CLMULEPI64" )
endif()

# -------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------- #
check_c_source_compiles("
  #include <immintrin.h>
  int main( void ) {

   __m256i theta = _mm256_setr_epi64x( 0x425, 0, 0, 0 );
   __m256i m2 = _mm256_srli_epi64( theta, 63 );

   __m128i count = _mm_setr_epi32( 1, 0, 0, 0 );
   __m256i m3 = _mm256_sll_epi64( theta, count );

  return 0;
 }" AK_HAVE_BUILTIN_MM256_SLL )

if( AK_HAVE_BUILTIN_MM256_SLL )
    set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_HAVE_BUILTIN_MM256_SLL" )
endif()
