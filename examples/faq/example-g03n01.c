/* --------------------------------------------------------------------------------- */
/* Пример example-g03n01.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 /* код ошибки, возвращаемый функциями библиотеки */
  int error = ak_error_ok;
 /* статус выполнения программы */
  int exitstatus = EXIT_FAILURE;
 /* контекст алгоритма блочного шифрования */
  struct bckey ctx;
 /* константное значение ключа */
  ak_uint8 key[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01,
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38  };
 /* синхропосылка */
  ak_uint8 iv[8] = { 0x01, 0x02, 0x03, 0x04, 0x11, 0xaa, 0x4e, 0x12 };
 /* данные для зашифрования */
  char plain_data[498] = "Eh bien, mon prince. Gênes et Lucques "
   "ne sont plus que des apanages, des поместья, de la famille Buonaparte. "
   "Non, je vous préviens que si vous ne me dites pas que nous avons "
   "la guerre, si vous vous permettez encore de pallier toutes les infamies, "
   "toutes les atrocites de cet Antichrist (ma parole, j'y crois) — je ne vous "
   "connais plus, vous n'êtes plus mon ami, vous n'êtes plus мой верный раб, "
   "comme vous dites. Ну, здравствуйте, здравствуйте.";

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( NULL ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* выполняем последовательный вызов двух функций:
    создаем ключ алгоритма Магма и присваиваем ему константное значение */
  ak_bckey_create_magma( &ctx );
  ak_bckey_set_key( &ctx, key, 32 );
                      /* длина ключей алгоритмов блочного
                         шифрования должна составлять 32 байта,
                         при других значениях функция возвратит код ошибки */

 /* зашифровываем тестовый вектор в режиме гаммирования с обратной связью по выходу
    - мы помещаем результат преобразования в тот же самый статический массив
    - для данного режима длина синхропосылки должна совпадать
                 с длиной блока алгоритма шифрования, т.е. 8 для Магмы */
  if(( error = ak_bckey_ofb( &ctx,        /* контекст секретного ключа */
                              plain_data, /* открытые данные */
                              plain_data, /* шифртекст  */
                              498,        /* длина открытого текста в байтах*/
                              iv,         /* синхропосылка */
                              8           /* длина синхропосылки в байтах*/
                           )) != ak_error_ok ) goto exlab;
 /* выводим результат зашифрования */
  printf("шифртекст: %s\n\n", ak_ptr_to_hexstr( plain_data, 498, ak_false ));

 /* реализуем обратное преобразование - расшифровываем тестовый вектор */
  if(( error = ak_bckey_ofb( &ctx, plain_data,
                       plain_data, 498, iv, 8 )) != ak_error_ok ) goto exlab;
 /* выводим результат расшифрования */
  printf("открытый текст: %s\n", plain_data );

 /* после использования необходимо удалить контекст секретного ключа */
  exlab: ak_bckey_destroy( &ctx );

 /* завершаем работу */
  if( error == ak_error_ok ) exitstatus = EXIT_SUCCESS;
  ak_libakrypt_destroy();
 return exitstatus;
}
