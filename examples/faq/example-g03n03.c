/* --------------------------------------------------------------------------------- */
/* Пример example-g03n03.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 int i = 0;
 /* контекст секретного ключа */
  struct bckey ctx;
 /* контекст генератора псевдослучайных последовательностей */
  struct random generator;

 /* массив данных для зашифрования длины 313 байт (19*16 + 9 = 6*48 + 25) */
  ak_uint8 data[215];
 /* массив, в который будет помещаться вычисленное значение */
  ak_uint8 im[16];

 /* инициализируем криптобиблиотеку
    и явно указываем функцию вывода сообщений аудита */
  if( ak_libakrypt_create( NULL ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }
 /* формируем данные, для которых будет вырабатываться имитовставка */
  for( i = 0; i < sizeof( data ); i++ ) data[i] = (ak_uint8)i+1;

 /* создаем генератор псевдослучайных последовательностей
    и инициализируем его константным значением */
  ak_random_create_nlfsr( &generator );
  ak_random_randomize( &generator, "hello", 5 );
 /* создаем ключ и присваиваем ему значение, выработанное
    с помощью генератора псевдослучайных последовательностей */
  ak_bckey_create_kuznechik( &ctx );
  ak_bckey_set_key_random( &ctx,&generator );

 /* вычисляем значение имитовставки */
  ak_bckey_cmac( &ctx, data, sizeof( data ), im, 8 );

 /* выводим вычисленное значение */
  printf("im: %s\n", ak_ptr_to_hexstr( im, 8, ak_false ));
 /* выводим ожидаемое значение */
  printf("im: fd8c53a457f96d42 (expected)\n");
 /* освобождаем контекст секретного ключа и контекст генератора */
  ak_bckey_destroy( &ctx );
  ak_random_destroy( &generator );
  ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
