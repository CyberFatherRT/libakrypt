/* ----------------------------------------------------------------------------------------------- */
/* Тестовый пример, иллюстрирующий работу xtsmac - режима шифрования с аутентификацией.

   test-xstmac.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <libakrypt.h>
 #include <libakrypt-internal.h>

/* Kлюч (закомментированы значения, скопированные из текста рекомендаций )
   88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF */

 static ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 static ak_uint8 keyAnnexABlockReverse[32] = {
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe };

/*  A:
   ­ 02 02 02 02 02 02 02 02 01 01 01 01 01 01 01 01
    04 04 04 04 04 04 04 04 03 03 03 03 03 03 03 03
    EA 05 05 05 05 05 05 05 05                       */
 static ak_uint8 associated[41] = {
     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA };

/*­  P:
    11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
    00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
    11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
    22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11
    AA BB CC                                        */
 static ak_uint8 plain[67] = {
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0xCC, 0xBB, 0xAA };

/* ­ nonce:
    11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88 */
 static ak_uint8 iv128[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  size_t len = 0, off = 0;
  struct bckey ekey, ikey;
  int error, result = EXIT_FAILURE;
 #ifdef AK_HAVE_STDALIGN_H
  #ifndef AK_HAVE_WINDOWS_H
   alignas(32)
  #endif
 #endif
  ak_uint8 ina[32 +sizeof(associated)], inp[32 +sizeof(plain)], otp[32 + sizeof(plain)];
  ak_uint8 out[32 +sizeof(plain)], icode[16];
  struct random lcg;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем ключи */
  ak_bckey_create_magma( &ekey );
  ak_bckey_set_key( &ekey, keyAnnexA, sizeof( keyAnnexA ));
  ak_bckey_create_magma( &ikey );
  ak_bckey_set_key( &ikey, keyAnnexABlockReverse, sizeof( keyAnnexABlockReverse ));

 /* создаем генератор */
  ak_random_create_lcg( &lcg );

 /* проводим тестирование в двух циклах:
    - внеший цикл тестирует смещение исходных данных от выравнивания по границе в 32 байта
    - внутренний цикл тестирует длину зашифровываемых данных (для всех допустимых значений) */

  for( off = 0; off < 31; off++ ) { /* 0 .. 25 */
     ak_uint32 roff = ak_random_value()%32;
     ak_uint32 otff = ak_random_value()%32;
     void *ina_ptr = ina +off;
     void *inp_ptr = inp +roff;
     void *otp_ptr = otp +otff;

     printf("[associated offset = %2u, plain offset = %2u, output offset = %2u]\n",
                                                (unsigned) off, (unsigned) roff, (unsigned) otff );
     memcpy( ina_ptr, associated, sizeof( associated ));
     memcpy( inp_ptr, plain, sizeof( plain ));

     for( len = 8; len <= sizeof( plain ); len++ ) {
       /* память */
        memset( icode, 0, 16 );
       /* зашифровываем */
        if(( error = ak_bckey_encrypt_xtsmac(
          &ekey,              /* ключ, используемый для шифрования данных */
          &ikey,            /* ключ, используемый для имитозащиты данных */
          ina_ptr,                /* указатель на ассоциированные данные */
          sizeof( associated ),          /* длина ассоциированных данных */
          inp_ptr,                /* указатель на зашифровываемые данные */
          otp_ptr,                        /* указатель на область памяти,
                               в которую помещаются зашифрованные данные */
          len,              /* размер зашифровываемых данных */
          iv128,             /* синхропосылка (инициализационный вектор) */
          sizeof( iv128 ),                       /* размер синхропосылки */
          icode,                          /* указатель на область памяти,
                                       в которую помещается имитовставка */
          16                                      /* размер имитовставки */
        )) != ak_error_ok ) {
         ak_error_message( error, __func__, "ошибка зашифрования данных" );
         goto exlab;
        }

       /* при желании, можно ознакомиться с шифртекстом и имитовставкой
        printf(" mac: %s\n", ak_ptr_to_hexstr( icode, 16, ak_false ));
        printf(" enc: %s [len: %u]\n", ak_ptr_to_hexstr( otp_ptr, len, ak_false ), (unsigned) len ); */

       /* расшифровываем */
        memset( out, 0, sizeof( plain ));
        error = ak_bckey_decrypt_xtsmac(
          &ekey,             /* ключ, используемый для шифрования данных */
          &ikey,            /* ключ, используемый для имитозащиты данных */
          ina_ptr,                /* указатель на ассоциированные данные */
          sizeof( associated ),          /* длина ассоциированных данных */
          otp_ptr,                /* указатель на зашифровываемые данные */
          out,                            /* указатель на область памяти,
                               в которую помещаются зашифрованные данные */
          len,              /* размер зашифровываемых данных */
          iv128,             /* синхропосылка (инициализационный вектор) */
          sizeof( iv128 ),                       /* размер синхропосылки */
          icode,                          /* указатель на область памяти,
                    в которой хранится контрольное значение имитовставки */
          16                                      /* размер имитовставки */
        );
        if( ak_ptr_is_equal( plain, out, len ) != ak_true ) {
           printf(" шифртекст: %s Wrong\n\n", ak_ptr_to_hexstr( out, len, ak_false ));
           error = ak_error_not_equal_data;
         }
        if( error != ak_error_ok ) {
         ak_error_message( error, __func__, "ошибка расшифрования данных" );
         goto exlab;
        }
        printf(".");
     }

     printf("\n");
  }

 /* удаляем ключи и завершаем работу с библиотекой */
  result = EXIT_SUCCESS;
  exlab:
   ak_random_destroy( &lcg );
   ak_bckey_destroy( &ekey );
   ak_bckey_destroy( &ikey );
   ak_libakrypt_destroy();

 return result;
}
