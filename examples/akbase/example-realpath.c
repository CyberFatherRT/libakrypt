 #include <stdio.h>
 #include <libakrypt-base.h>

 int main( void )
{
    int error = ak_error_ok;
    char resolved_path[1024];

   /* преобразование простого имени файла */
    printf(" 1. result: %d, path: %s\n",
                      error = ak_realpath("hello-im-file.txt", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;
    printf(" 2. result: %d, path: %s\n",
                     error = ak_realpath("hello i'm file.too", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;
    printf(" 3. result: %d, path: %s\n",
                             error = ak_realpath(".hello.txt", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;

   /* преобразование имени, начинающегося с / */
    printf(" 4. result: %d, path: %s\n",
                             error = ak_realpath("/some-file", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;
    printf(" 5. result: %d, path: %s\n", error =
          ak_realpath("/usr/share/doc/some-packet/readme.txt", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;

   /* преобразование имени, начинающегося с ./ */
    printf(" 6. result: %d, path: %s\n",
                     error = ak_realpath("./current-file.txt", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;
    printf(" 7. result: %d, path: %s\n", error =
                    ak_realpath("./another-special-file.docx", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;

   /* преобразование имени, начинающегося с ../ */
    printf(" 8. result: %d, path: %s\n",
                           error = ak_realpath("../hello.txt", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;
    printf(" 9. result: %d, path: %s\n",
            error = ak_realpath("../build-all/CMakeLists.txt", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;
    printf("10. result: %d, path: %s\n",
                        error = ak_realpath("~/.fluxbox/menu", resolved_path, 1024 ), resolved_path );
    if( error != ak_error_ok ) return EXIT_FAILURE;

 return EXIT_SUCCESS;
}
