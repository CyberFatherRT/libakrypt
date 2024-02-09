/* Тестовый пример, иллюстрирующий работу режима шифрования с аутентификацией.

   Пример использует неэкспортируемые функции.

   test-mgm01.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <libakrypt.h>

/* тестовые значения взяты из проекта рекомендаций
   "Режимы работы блочных шифров, реализующие аутентифицированное шифрование"
   Все значения в тексте рекомендаций записаны в big endian то есть,
   в начале (слева) идут значения со старшими индексами, в конце (справа) - с младшими */

/* Kлюч (закомментированы значения, скопированные из текста рекомендаций )
   88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF */

 static ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

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

/*  T (результирующая имитовставка):
    CF 5D 65 6F 40 C3 4F 5C 46 E8 BB 0E 29 FC DB 4C */
 static ak_uint8 icodeOne[16] = {
    0x4C, 0xDB, 0xFC, 0x29, 0x0E, 0xBB, 0xE8, 0x46, 0x5C, 0x4F, 0xC3, 0x40, 0x6F, 0x65, 0x5D, 0xCF };

 int main( void )
{
  int result;
  struct bckey key; /* ключ блочного алгоритма шифрования */
  ak_uint8 frame[124];

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();
  ak_libakrypt_set_openssl_compability( ak_false );
                             /* контрольный пример расчитан для несовместимого режима */
 /* формируем фрейм */
  memcpy( frame, associated, sizeof ( associated ));        /* ассоциированные данные */
  memcpy( frame + sizeof( associated ), plain, sizeof( plain ));  /* шифруемые данные */
  memset( frame + ( sizeof( associated ) + sizeof( plain )), 0, 16 ); /* имитовставка */

 /* инициализируем ключ */
  ak_bckey_create_kuznechik( &key );
  ak_bckey_set_key( &key, keyAnnexA, sizeof( keyAnnexA ));

 /* зашифровываем данные и одновременно вычисляем имитовставку */
  ak_bckey_encrypt_mgm(
    &key,              /* ключ, используемый для шифрования данных */
    &key,             /* ключ, используемый для имитозащиты данных */
    frame,                  /* указатель на ассоциированные данные */
    sizeof( associated ),          /* длина ассоциированных данных */
    plain,                  /* указатель на зашифровываемые данные */
    frame + sizeof( associated ),   /* указатель на область памяти,
                         в которую помещаются зашифрованные данные */
    sizeof( plain ),              /* размер зашифровываемых данных */
    iv128,             /* синхропосылка (инициализационный вектор) */
    sizeof( iv128 ),                       /* размер синхропосылки */
                                    /* указатель на область памяти,
                                 в которую помещается имитовставка */
    frame + sizeof( associated ) + sizeof( plain ),
    16                                      /* размер имитовставки */
  );

 /* выводим результат и проверяем полученное значение */
  printf("encrypted frame: %s [", ak_ptr_to_hexstr( frame, sizeof( frame ), ak_false ));
  if( memcmp( frame + sizeof( associated ) + sizeof( plain ), icodeOne, 16 )) {

    printf(" Wrong]\n");
    printf("frame: %s\n",
                 ak_ptr_to_hexstr( frame + sizeof( associated ) + sizeof( plain ), 16, ak_false ));
    printf("icode: %s\n", ak_ptr_to_hexstr( icodeOne, 16, ak_false ));
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  } else printf(" Ok]\n\n");

 /* расшифровываем и проверяем имитовставку */
  result = ak_bckey_decrypt_mgm(
    &key,           /* ключ, используемый для расшифрования данных */
    &key,             /* ключ, используемый для имитозащиты данных */
    frame,                  /* указатель на ассоциированные данные */
    sizeof( associated ),          /* длина ассоциированных данных */
                           /* указатель на расшифровываемые данные */
    frame + sizeof( associated),
    frame + sizeof( associated ),   /* указатель на область памяти,
                        в которую помещаются расшифрованные данные */
    sizeof( plain ),                /* размер зашифрованных данных */
    iv128,             /* синхропосылка (инициализационный вектор) */
    sizeof( iv128 ),                       /* размер синхропосылки */
                                    /* указатель на область памяти,
                в которой находится вычисленная ранее имитовставка
                       (с данным значением производится сравнение) */
    frame + sizeof( associated ) + sizeof( plain ),
    16                                      /* размер имитовставки */
  );

  printf("decrypted frame: %s [", ak_ptr_to_hexstr( frame, sizeof( frame ), ak_false ));
  if( result == ak_error_ok ) printf("Correct]\n");
    else printf("Incorrect]\n");

 /* уничтожаем контекст ключа */
  ak_bckey_destroy( &key );
  ak_libakrypt_destroy();

 if( result == ak_error_ok ) return EXIT_SUCCESS;
  else return EXIT_FAILURE;
}
