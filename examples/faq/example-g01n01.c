/* --------------------------------------------------------------------------------- */
/* Пример example-g01n01.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
  if( ak_libakrypt_create( NULL ) != ak_true ) {
   /* инициализация выполнена не успешно, следовательно, выходим из программы */
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* ... здесь основной код программы ... */

  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
