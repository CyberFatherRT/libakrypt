/* --------------------------------------------------------------------------------- */
/* Пример example-g02n04.c                                                           */
/*                                                                                   */
/* Иллюстрация работы с функциями, реализующими кодирование/декодирование в base64   */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
  int i = 0, error = ak_error_ok;
 /* данные для преобразования в base64 и обратно */
  ak_uint8 in[26] =
    { 0x1a, 0x2b, 0x3c, 0x4d, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x30, 0x4a, 0x5b,
      0x6c, 0x7e, 0x8f, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0x7f, 0x65, 0x9a, 0x12, 0x34 };

 /* массив для обратного декодирования символной строки в двоичные данные */
  ak_uint8 out[sizeof( in )];

 /* основной цикл программы, перебирающий все допустимые значения длины входных данных */
  for( i = 1; i <= sizeof(in); i++ ) {
    const char *str = NULL;
    ak_uint8 *newbuf = NULL;

   /* выводим исходные данные для кодирования и их длину */
    printf("%52s :bin | ", ak_ptr_to_hexstr( in, i, ak_false ));

   /* выводим результат кодирования и длину полученной строки символов */
    printf("base64: %s ", str = ak_ptr_to_base64( (ak_uint8 *)in, i, plain_base64_format ));

   /* преобразуем данные обратно в двоичным массив,
      для этого - указываем максимально доступный объем памяти,
      в которую будет помещен результат преобразования  */
    size_t len = sizeof( out );

   /* декодируем (преобразуем строку в байты) и
    * получаем в переменной len реальную длину данных */
    newbuf = ak_base64_to_ptr( str, out, &len );

   /* сравниваем декодированное значение (указатель newbuf) с исходным
      начинаем со сравнения длин, потом данных */
    if( len != i ) {
      printf("Wrong [length]\n");
      error = ak_error_wrong_length;
      goto exlab1;
    }
    if( ak_ptr_is_equal_with_log( in, newbuf, len )) printf("Ok\n");
     else {
      printf("Error (not equal)\n");
      error = ak_error_not_equal_data;
      goto exlab1;
     }

   /* при необходимости, освобождаем память */
    exlab1:
     if( newbuf != out ) {
       free( newbuf );
       printf("memory freed for index %d\n", i );
     }
     if( error != ak_error_ok ) return EXIT_FAILURE;
  }

 return EXIT_SUCCESS;
}
