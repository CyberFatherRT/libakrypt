/* --------------------------------------------------------------------------------- */
/* Пример example-g04n02.c                                                           */
/* Вычисление случайных последовательностей согласно Р 1323565.1.006-2017            */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
  int i = 0;
  ak_uint8 buffer[16];

 /* определяем контекст генератора псевдослучайных значений */
  struct random generator;

 /* вызываем конструктор генератора */
  ak_random_create_hrng( &generator );

 /* вырабатываем случайные значения */
  for( i = 0; i < 15; i++ ) {
     ak_random_ptr( &generator, buffer, 16 );
     printf("data: %s\n", ak_ptr_to_hexstr( buffer, 16, ak_false ));
  }

 /* вызываем деструктор генератора */
  ak_random_destroy( &generator );
 return EXIT_SUCCESS;
}
