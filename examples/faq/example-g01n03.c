/* --------------------------------------------------------------------------------- */
/* Пример example-g01n03.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 /* запрещаем вывод всех служебных сообщений (кроме сообщений об ошибках) */
  ak_log_set_level( ak_log_none );

 /* устанавливаем вывод сообщений аудита в стандартный поток вывода ошибок */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
   /* инициализация выполнена не успешно, следовательно, выходим из программы */
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* выводим тестовые сообщения, иллюстрирующие работу функций аудита:
    первый аргумент:
       - определяет код ошибки
    второй аргумент:
       - определяет строку с именем функции, инициировавшей ошибку
        ( макрос __func__ подставляем имя текущей функции )
     последующие аргументы:
       - форматная строка с выводимым сообщением                      */

  ak_error_message( ak_error_null_pointer, __func__, "simple message" );
  ak_error_message_fmt( ak_error_access_file, __func__,
                         "another message with parameters: %s and %x", "weight", 32 );
  ak_error_message( ak_error_ok, "my_function_name", "last message" );

  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
