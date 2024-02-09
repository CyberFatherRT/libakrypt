/* --------------------------------------------------------------------------------- */
/* Пример example-g04n01.c                                                           */
/* Вычисление площади круга методом Монте Карло                                      */
/* --------------------------------------------------------------------------------- */
 #include <math.h>
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
  int i = 0;
 /* контекст генератора псевдослучайных значений */
  struct random generator;
 /* вспомогательные переменные */
  ak_uint32 val, count = 0;
 /* служебные переменные */
  double x, y, xpi = 0, epsilon = 3.1415926535;

 /* инициализируем криптобиблиотеку
    и явно указываем функцию вывода сообщений аудита */
  if( ak_libakrypt_create( NULL ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* создаем генератор */
  ak_random_create_nlfsr( &generator );

 /* формируем множество точек вида (x,y) внутри единичного квадрата
    при этом, для генерации действительных значений вырабатывается
    4 случайных байта, после чего вычисляется рациональная дробь  */
  for( i = 1; i < 25000001; i++ ) {
     ak_random_ptr( &generator, &val, 4 ); x = ((double)val)/4294967296;
     ak_random_ptr( &generator, &val, 4 ); y = ((double)val)/4294967296;
     if( x*x+y*y < 1 ) count++;
     if( i%1000000 == 0 ) {
       xpi = (double)(4*count)/(double)i;
       printf("pi = %f (after %7u iterations)\n",
                                       (double)(4*count)/(double)i, i );
     }
  }
 /* выводим точное значение и погрешность */
  printf("pi = 3,1415926535 (epsilon: %f)\n", epsilon-xpi );

 /* освобождаем контекст генератора и закрываем библиотеку */
  ak_random_destroy( &generator );
  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
