/* ----------------------------------------------------------------------------------------------- */
 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>

/* -----------------------------------------------------------------------------------------------
  Тест проверяет идентичность реализации алгоритмов выработки произсводных ключей
  для различных архитектур
  ----------------------------------------------------------------------------------------------- */
 ak_uint8 kin[88] = {
   0xa1, 0xb2, 0xc4, 0x31, 0xa0, 0xff, 0xac, 0x13, 0x11, 0x10, 0xaa, 0x12, 0x73, 0x53, 0x4a, 0x01,
   0xC6, 0x00, 0xFD, 0x9D, 0xD0, 0x49, 0xCF, 0x8A, 0xBD, 0x2F, 0x5B, 0x32, 0xE8, 0x40, 0xD2, 0xCB,
   0x0E, 0x41, 0xEA, 0x44, 0xDE, 0x1C, 0x15, 0x5D, 0xCD, 0x88, 0xDC, 0x84, 0xFE, 0x58, 0xA8, 0x55,
   0xff, 0xff, 0x54, 0x36, 0x27, 0x1c, 0x21, 0xff, 0x67, 0x0c, 0x09, 0x81, 0x2f, 0xaa, 0x1a, 0xc6,
   0x01, 0x0a, 0x21, 0x11, 0xad, 0xc7, 0x58, 0x75, 0x00, 0x21, 0x21, 0x21, 0x11, 0x1f, 0xff, 0xff,
   0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0 };

 ak_uint8 seed[32] = "abcdefghijklmnopqrstuvwxyz012345";
 ak_uint8 iv[64] = {
   0x40, 0x39, 0xd4, 0x68, 0xd2, 0xd9, 0x35, 0xc1, 0x4f, 0x22, 0x42, 0xb6, 0xe3, 0x9d, 0xb3, 0xb5,
   0xd5, 0x99, 0x95, 0xc1, 0xe7, 0xa0, 0x11, 0x87, 0xf6, 0xf7, 0xa3, 0xd7, 0xe3, 0xc2, 0x6a, 0xc3,
   0x19, 0x12, 0xf4, 0xc2, 0x4e, 0x1d, 0x64, 0xfe, 0x62, 0xec, 0x44, 0xad, 0x48, 0xd8, 0xa4, 0x6b,
   0x7a, 0x9e, 0xf8, 0xe4, 0xab, 0x7f, 0x7b, 0x3b, 0x47, 0x95, 0x18, 0x3d, 0xf6, 0x73, 0x1c, 0x1e };

 ak_uint8 label[77] =
  "jhljdfhlajhadbfbjr=QQ387452nad,mfn8bkhagbdfkhadhgfafnaba98z7cz987s987csa98c6w";

/* ----------------------------------------------------------------------------------------------- */
 void genkey( kdf_t type, ak_uint8 *key, size_t key_size )
{
  struct kdf_state ks;

  if((( type >> 4 )&0xF ) != 3 ) {
    if( ak_kdf_state_create( &ks, kin, sizeof(kin), type,
                           label, 77, seed, 32, iv, 64, 32768 ) != ak_error_ok ) return;
  } /* здесь допускается только key_size = seed_size = 32 */
   else {
    if( ak_kdf_state_create( &ks, kin, 32, type,
                           label, 77, seed, 32, iv, 64, 32768 ) != ak_error_ok ) return;
   }

/* printf("algorithm:  0x%X\n", ks.algorithm );
   printf("block_size: %u\n", (unsigned int) ks.block_size );
   printf("number:     %llu\n", (unsigned long long int) ks.number );
   printf("maximum:    %llu\n", (unsigned long long int) ks.max );
   printf("ivbuffer:   %s (%u bytes)\n", ak_ptr_to_hexstr( ks.ivbuffer, ks.state_size, ak_false ),
                                                                    (unsigned int)ks.state_size ); */

  ak_kdf_state_next( &ks, key, key_size );
  ak_kdf_state_destroy( &ks );
}

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  const char *ptr;
  ak_uint8 key[88];

 /* инициализируем библиотеку */
  ak_libakrypt_create( ak_function_log_stderr );

/* nmac */
  printf("NMAC Family:\n");
  genkey( nmac_cmac_magma_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "cf472a4f16b9cfba6d52e953b15e1c42d7824079e84c9616e61c7dbcfd65b760a149998ca098623dfb6b", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( nmac_cmac_kuznechik_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "ed6c4301894df685b7ad3feb0e3d2ae5c466a1301ff32eb2451acfa68187731aa130588bd5fbfb95f654", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( nmac_hmac256_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "73e45393ccab9e74f506e103a8c7a8784668f8af502e3a1c25db85a51f78d0bcf14fb5cf32595b658c99", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( nmac_hmac512_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "9be420dd12410a1559b3467886afc7b3c2a139e4630ff50125cf44e4271d2e11fe54f1a777b7fa06262b", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( nmac_nmac_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "34f52583950d3d7db2ca00cc5c3cf2f107c0fe1202b75cd9d031e53b39c519ce1ff8fd7c3f56db7f0b37", 42 ) != 0 )
    return EXIT_FAILURE;

/* hmac */
  printf("HMAC Family:\n");
  genkey( hmac_cmac_magma_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "d013a4274d78a928ca7468fee55f0d98a78fa766343389ad8fd9c0e469022d8f2a6fa3a4b133f61f430d", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( hmac_cmac_kuznechik_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "a3dca49a528fce27bd54ee863447650c6beb9b5f08fbfd8d11c8064f433dc419659ea28ad3f4277290ca", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( hmac_hmac256_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "7faa1ac1a20a49ed3ee703d53b5a67919e93727d87de70f72eccd4ebf503d3c77be501b3e50e22094895", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( hmac_hmac512_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "ba5c5a55e02a3164a071447325493012466b6b68371618d260fe4bf3ce82fb217ee8e641bf3438379106", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( hmac_nmac_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "38e90b7977f2a4a847db3b663333bea017d3456ec1c6643ea4037004a8564b7d17985d2bed553daedbdb", 42 ) != 0 )
    return EXIT_FAILURE;


/* xor */
  printf("XOR Family:\n");
  genkey( xor_cmac_magma_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "bee7ab53052152e1acc0a4827d34fafb692cc9026716da72473ae472afe46e83332b2cd43947cfcd89b7", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( xor_cmac_kuznechik_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "05e4b1b02604153221797c67cc6eb9b66e605e12bd8bab1c7f220711fe50ace9eb60020fbc567d5fb8c6", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( xor_hmac256_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "fcb18fa33fe3ca6463c2dc1e40532e5954f412a50126e58a46dbd5d637f537e904f2cdf5bf494b3ffeed", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( xor_hmac512_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "7dbfc7fac82a871cd5c9ad9e6cb0b6640bbe6875e5342a863009fcb753582f4e1e8beaecc0961e9400d9", 42 ) != 0 )
    return EXIT_FAILURE;

  genkey( xor_nmac_kdf, key, 42 );
  printf("key: %s (%d bytes)\n", ptr = ak_ptr_to_hexstr( key, 42, ak_false ), 42 );
  if( strncmp( ptr, "7021e470615353420609e2236d253140b10c7309565f7790516c9202b1708b47ec1b80d5e8e260c18124", 42 ) != 0 )
    return EXIT_FAILURE;

  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
