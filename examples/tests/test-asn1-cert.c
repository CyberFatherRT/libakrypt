 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>

/* функция для вывода информации о полях сертификата */
 int certificate_out( const char *message ) {
   fprintf( stdout, "%s", message );
  return ak_error_ok;
 }

 int main( int argc, char *argv[] )
{
  struct certificate_opts opts;
  struct verifykey subject_key;
  char *filename = "openssl512_ca.crt";

  ak_libakrypt_create( ak_function_log_stderr );

  if( argc > 1 ) filename = argv[1];
  ak_verifykey_import_from_certificate( &subject_key, NULL, filename, &opts, certificate_out );

 /* освобождаем память */
  if( opts.created ) {
    ak_verifykey_destroy( &subject_key );
  }
  ak_certificate_opts_destroy( &opts );



//  if( opts.created )
//    ak_libakrypt_print_certificate( )

//  if( opts.created ) {
//    ak_oid curvoid = ak_oid_find_by_data( subject_key.wc );
//    printf("certificate:\n");
//    printf("    version: v%d\n", 1 + opts.version );
//    printf("    serial number:\n       %s\n",
//                                  ak_ptr_to_hexstr( opts.serialnum, opts.serialnumlen, ak_false ));
//    printf("    issuer: "); ak_tlv_print_global_name( opts.issuer_name, stdout ); printf("\n");
//    printf("    validity:\n");
//    printf("       not before: %s", ctime( &subject_key.time.not_before ));
//    printf("        not after: %s", ctime( &subject_key.time.not_after ));
//    printf("    subject: "); ak_tlv_print_global_name( subject_key.name, stdout ); printf("\n");
//    printf("    algorithm: %s (%s)\n", subject_key.oid->name[0], subject_key.oid->id[0] );
//    printf("    key:\n");
//    printf("       px: %s\n", ak_mpzn_to_hexstr( subject_key.qpoint.x, subject_key.wc->size ));
//    printf("       py: %s\n", ak_mpzn_to_hexstr( subject_key.qpoint.y, subject_key.wc->size ));
//    printf("    curve: %s (%s)\n", curvoid->name[0], curvoid->id[0] );

//    if( opts.version >= 2 ) {
//      printf("x509v3 extensions:\n");
//      if( opts.ca.is_present ) {
//        printf("    basic constraints:\n");
//        printf("       ca: %s, pathlen: %u\n",
//                                 ( opts.ca.value ? "true" : "false" ), opts.ca.pathlenConstraint );
//      }
//      if( opts.key_usage.is_present ) {
//        printf("    key usage:\n       values: ");
//         if( opts.key_usage.bits&bit_decipherOnly) printf("decipher ");
//         if( opts.key_usage.bits&bit_encipherOnly) printf("encipher ");
//         if( opts.key_usage.bits&bit_cRLSign) printf("crl sign ");
//         if( opts.key_usage.bits&bit_keyCertSign) printf("cert sign ");
//         if( opts.key_usage.bits&bit_keyAgreement) printf("key agreement ");
//         if( opts.key_usage.bits&bit_dataEncipherment) printf("data encipherment ");
//         if( opts.key_usage.bits&bit_keyEncipherment) printf("key encipherment ");
//         if( opts.key_usage.bits&bit_contentCommitment) printf("content commitment ");
//         if( opts.key_usage.bits&bit_digitalSignature) printf("digital signature");
//        printf("\n");
//      }
//      if( opts.subject_key_identifier.is_present ) {
//        printf("    subject key identifier:\n");
//        printf("       keyid: %s\n", ak_ptr_to_hexstr( subject_key.number,
//                                                   opts.subject_key_identifier.length, ak_false ));
//      }
//      if( opts.authority_key_identifier.is_present ) {
//        printf("    authority key identifier:\n");
////        if( opts.authority_key_identifier.issuer_subjkeylen )
////          printf("       keyid: %s\n",
////            ak_ptr_to_hexstr( opts.authority_key_identifier.issuer_subjkey,
////                                      opts.authority_key_identifier.issuer_subjkeylen, ak_false ));
//      }
//    }
//    ak_error_set_value( ak_error_ok );
//    ak_verifykey_destroy( &subject_key );
//  }

  ak_certificate_opts_destroy( &opts );
  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
