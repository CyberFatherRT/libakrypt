/* пример иллюстрирует процедуру вывода в консоль  */
/* произвольного ini-файла                         */
 #include <stdio.h>
 #include <libakrypt-base.h>

 int user_handler( void *user , const char *section , const char *name , const char *value )
{
 printf("section: %s, name: %s, value: %s\n", section, name, value );
 return 1; /* ненулевое значение - успешное завершение обработчика */
}

 int main( int argc, char *argv[] )
{
    if( argc < 2 ) {
      printf("usage: %s ini-file\n", argv[0] );
      return EXIT_SUCCESS;
    }

    if( ak_ini_parse( argv[1], user_handler, NULL ) != ak_error_ok )
      printf("incorrect parsing of test string\n");

 return EXIT_SUCCESS;
}
