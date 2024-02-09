 #include <stdio.h>
 #include <libakrypt-base.h>

/* функция, которая будет обрабатывать найденные файлы */
 int user_function( const tchar *name, ak_pointer ptr )
{
  struct file file;

  ak_file_open_to_read( &file, name );
  fprintf( stdout, "%3u: %s [%llu B]\n", ++(*(ak_uint32 *)ptr), name,
                                                     (long long unsigned int) file.size );
  ak_file_close( &file );
  return ak_error_ok;
}

 int main( void )
{
  ak_uint32 count = 0;

  ak_file_find( ".",           /* ищем файлы в текущем каталоге */
                "*ak*",        /* с заданным шаблоном имени */
                user_function, /* функция, вызываемая для обработки найденного файла */
                &count,        /* указатель на данные, передаваемые в функцию */
                ak_true        /* производится поиск по вложенным каталогам */
              );

 return 0;
}
