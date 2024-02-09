 #include <stdio.h>
 #include <stdlib.h>
 #include <libakrypt-base.h>

/* пример иллюстрирует доступ к файлу через mmap() */
 int main( int argc, char *argv[] )
{
  ak_int64 i = 0;
  struct file ifp;
  ak_uint8 *addr = NULL;

  if( argc <= 1 ) {
    printf( "usage: example-mmap file\n");
    return EXIT_SUCCESS;
  }
  ak_log_set_level( ak_log_maximum );
  ak_log_set_function( ak_function_log_stderr );

  printf("open error:  %d\n",
    ak_file_open_to_read( &ifp, argv[1] ));

 #ifdef AK_HAVE_SYSMMAN_H
  addr = ak_file_mmap( &ifp, NULL, ifp.size, PROT_READ, MAP_PRIVATE, 0 );
  printf("mmap error:  %d\n", ak_error_get_value());
 #else
   printf("mmap is unsupported\n");
   return EXIT_FAILURE;
 #endif

  for( i = 0; i < ifp.mmaped_size; i++ ) {
    printf("%02x ", addr[i] );
    if(( i > 1 ) && ( i%16 == 15 )) printf("\n");
  }
  printf("\n %s\n", (char *)ifp.addr);

  printf("unmap error:  %d\n",
    ak_file_unmap( &ifp ));

  printf("close error: %d\n",
    ak_file_close( &ifp ));

 return EXIT_SUCCESS;
}
