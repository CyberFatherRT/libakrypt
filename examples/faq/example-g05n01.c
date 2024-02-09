/* --------------------------------------------------------------------------------- */
/* Пример example-g05n01.c                                                           */
/*                                                                                   */
/* Простейшая иллюстрация вызова функции ak_skey_derive_tlstree()                    */
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

    ak_uint8 outkey[32] = {
      0xE1, 0xC5, 0x9B, 0x41, 0x69, 0xD8, 0x96, 0x10,
      0x7F, 0x78, 0x45, 0x68, 0x93, 0xA3, 0x75, 0x1E,
      0x15, 0x73, 0x54, 0x3D, 0xAD, 0x8C, 0xB7, 0x40,
      0x69, 0xE6, 0x81, 0x4A, 0x51, 0x3B, 0xBB, 0x1C };

   /* массив для хранения производного ключа */
    ak_uint8 out[32];

   /* инициализируем библиотеку */
    ak_libakrypt_create( NULL );

   /* вырабатываем производный ключ с номером пять */
    ak_skey_derive_tlstree( key, 32, 5, tlstree_with_kuznyechik_mgm_l, out, 32 );

   /* сравниваем то, что вычислили с тем, что хотели бы получить */
    if( ak_ptr_is_equal_with_log( out, outkey, 32 ))
       printf("derived key: %s\n", ak_ptr_to_hexstr( out, 32, ak_false ));

    ak_libakrypt_destroy();
 return ( ak_error_get_value() == ak_error_ok ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
