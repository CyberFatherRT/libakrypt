/* --------------------------------------------------------------------------------- */
/* Пример example-g05n03.c                                                           */
/*                                                                                   */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{  /* значение исходной ключевой информации */
    ak_uint8 key[32] = {
      0x58, 0x16, 0x88, 0xD7, 0x6E, 0xFE, 0x12, 0x2B,
      0xB5, 0x5F, 0x62, 0xB3, 0x8E, 0xF0, 0x1B, 0xCC,
      0x8C, 0x88, 0xDB, 0x83, 0xE9, 0xEA, 0x4D, 0x55,
      0xD3, 0x89, 0x8C, 0x53, 0x72, 0x1F, 0xC3, 0x84 };
   /* начальное значение номера производного ключа */
    int index = 0;

   /* контекст внутреннего состояния алгоритма tlstree */
    struct tlstree_state ctx;

   /* инициализируем библиотеку */
    ak_libakrypt_create( NULL );

   /* устанавливаем начальное состояние и сразу же вырабатываем производный ключ */
    ak_tlstree_state_create( &ctx, key, sizeof( key ),
                                              index, tlstree_with_libakrypt_65536 );

   /* выводим производный ключ, вырабатываем следующий, и так, пока не надоест ))) */
    do {
        printf("key[%03d]: %s\n", (int) ctx.key_number,
                ak_ptr_to_hexstr( ak_tlstree_state_get_key( &ctx ), 32, ak_false ));

       /* вызов именно этой функции приводит к изменению номера счетчика ключа
        * и выработке нового значения производного ключа */
        ak_tlstree_state_next( &ctx );
    }
     while( ctx.key_number < 10 );

    ak_libakrypt_destroy();
 return ( ak_error_get_value() == ak_error_ok ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
