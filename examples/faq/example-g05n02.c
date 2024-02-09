/* --------------------------------------------------------------------------------- */
/* Пример example-g05n02.c                                                           */
/*                                                                                   */
/* Иллюстрация выработки нескольких различных производных ключей                     */
/* при помощи вызова функции ak_skey_new_derive_tlstree_from_skey()                  */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{  /* значение исходной ключевой информации */
    ak_uint8 mkey[32] = {
      0x58, 0x16, 0x88, 0xD7, 0x6E, 0xFE, 0x12, 0x2B,
      0xB5, 0x5F, 0x62, 0xB3, 0x8E, 0xF0, 0x1B, 0xCC,
      0x8C, 0x88, 0xDB, 0x83, 0xE9, 0xEA, 0x4D, 0x55,
      0xD3, 0x89, 0x8C, 0x53, 0x72, 0x1F, 0xC3, 0x84 };
   /* контекст исходного ключа */
    struct bckey master_key;

   /* константная синхропосылка */
    ak_uint8 iv[4] = { 0xe0, 0xe1, 0xe2, 0xe3 };
   /* константная строка для зашифрования */
    ak_uint8 data[19] = {
                 0x01, 0x02, 0x03, 0x04, 0x05, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
                 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xf6, 0xf7, 0xf8, 0xf9
               };
    ak_uint8 buffer[19];

   /* какая-то переменная */
    int index = 0;

   /* инициализируем библиотеку */
    ak_libakrypt_create( NULL );

   /* создаем контекст исходного ключа и присваиваем ему значение */
    ak_bckey_create_magma( &master_key );
    ak_bckey_set_key( &master_key, mkey, 32 );

   /* основной цикл генерации десяти производных ключей */
    do {
         ak_bckey psk = ak_skey_new_derive_tlstree_from_skey(
                              ak_oid_find_by_name( "magma" ),
                              &master_key,
                              index,
                              tlstree_with_libakrypt_65536 );
         if( psk == NULL ) break;

        /* теперь шифруем данные и выводим шифртекст в консоль */
         ak_bckey_ctr( psk, data, buffer, sizeof( data ), iv, 4 );
         printf("key[%03d]: %s ", index,
                      ak_ptr_to_hexstr( buffer, sizeof( buffer ), ak_false ));

        /* расшифровываем и проверяем совпадение */
         ak_bckey_ctr( psk, buffer, buffer, sizeof( buffer ), iv, 4 );
         if( ak_ptr_is_equal_with_log( buffer, data, sizeof( data )))
           printf("Ok\n");

        /* уничтожаем ключ */
         ak_skey_delete( psk );

    } while ( ++index < 16 );

   /* очищаем память */
    ak_bckey_destroy( &master_key );
    ak_libakrypt_destroy();

 return ( ak_error_get_value() == ak_error_ok ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
