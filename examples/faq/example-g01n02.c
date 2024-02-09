/* --------------------------------------------------------------------------------- */
/* Пример example-g01n02.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

/* --------------------------------------------------------------------------------- */
/* предварительное определение пользовательской функции аудита */
 static int ak_function_my_audit( const char * );

 int main( void )
{
 /* устанавливаем максимальный уровень аудита */
  ak_log_set_level( ak_log_maximum );

 /* передаем пользовательсткую функцию аудита
    в качестве параметра функции ak_libakrypt_create() */
  if( ak_libakrypt_create( ak_function_my_audit ) != ak_true ) {
   /* инициализация выполнена не успешно, следовательно, выходим из программы */
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* ... здесь основной код программы ... */

  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}

/* --------------------------------------------------------------------------------- */
/* реализация пользовательской функции аудита */
 static int ak_function_my_audit( const char *message )
{
  if( message != NULL ) fprintf( stderr, "%s\n", message );
 return ak_error_ok;
}
