/* Created by Anton Sakharov on 2019-08-03, modified by Axel Kenzo
   test-asn1-build.c

   Тестовый пример для иллюстрации процедур создания и кодирования ASN.1 деревьев.
   В результате выполнения программы должен быть получен следующий вывод.

┌SEQUENCE┐
│        ├BOOLEAN TRUE
│        ├BOOLEAN FALSE
│        ├INTEGER 2415919098
│        ├INTEGER 8388607
│        ├INTEGER 254
│        ├INTEGER 17
│        ├SEQUENCE┐
│        │        ├BOOLEAN FALSE
│        │        ├OCTET STRING 01
│        │        ├OCTET STRING 0102
│        │        ├OCTET STRING 010203
│        │        ├OCTET STRING 01020304
│        │        └OCTET STRING 0102030405
│        ├NULL
│        └OCTET STRING 0102030405060708090a0b0c0e
└SEQUENCE┐
         ├OBJECT IDENTIFIER 1.2.3.4.5.6.7.891521.51.1
         └UTF8 STRING this is a description for identifier    */

 #include <stdlib.h>
 #include <libakrypt.h>

 int main(void)
{
  size_t len = 0;
  struct file file;
  ak_uint32 u32 = 0;
  bool_t bl = ak_true;
  ak_uint32 i = 0;
  int result = EXIT_FAILURE;
  ak_uint8 buf[13] = { 0x01, 0x02, 0x03, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xe },
           array[1024];
  struct asn1 root, *asn1 = NULL, *asn_down_level = NULL;
  struct hash ctx;
  const char *str = NULL;
  ak_uint8 out[32], tmp[32] = {
   0x30, 0x44, 0x8a, 0x0a, 0x41, 0x3d, 0x43, 0x13, 0x73, 0x15, 0x0e, 0x90, 0xd3, 0xad, 0x4e, 0xcf,
   0x1b, 0x52, 0x29, 0x1e, 0x90, 0xca, 0x52, 0xa8, 0x47, 0x54, 0xa9, 0xd5, 0xae, 0x08, 0x07, 0xa5 };

 /* Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

  if( ak_asn1_create( asn1 = malloc( sizeof( struct asn1 ))) == ak_error_ok )
    printf(" level asn1 created succesfully ... \n");

 /* создаем вложенный уровень дерева, используя указатель asn1,
    и добавляем в него булевы элементы */
  ak_asn1_add_bool( asn1, bl ); /* используется инициализированная ячейка памяти */
  ak_asn1_add_bool( asn1, ak_false ); /* используется константа */

   /* иллюстрируем доступ к данным, хранящимся в узлах дерева
      и проверяем значение последней булевой переменной */
     if( ak_tlv_get_bool( asn1->current, &bl ) == ak_error_ok )
       printf(" bool variable: %u (must be false)\n", bl );

 /* добавляем во вложенный уровень целые, 32-х битные числа */
  ak_asn1_add_uint32( asn1, 0x8FFFFFFa ); /* используется константа,
                                             которая должна занимать в памяти 5 октетов */
  ak_asn1_add_uint32( asn1, 8388607 ); /* используется константа,
                                          которая должна занимать в памяти 3 октета */
  ak_asn1_add_uint32( asn1, 254 ); /* используется константа,
                                      которая должна занимать в памяти 2 октета */
  ak_asn1_add_uint32( asn1, 17 ); /* используется константа,
                                     которая должна занимать в памяти 1 октет */

   /* иллюстрируем доступ к данным, хранящимся в узлах дерева
      и проверяем добавленные значения */
      for( i = 0; i < 4; i++ ) {
         if( ak_tlv_get_uint32( asn1->current, &u32 ) == ak_error_ok )
           printf(" uint32 variable: %u (0x%x)\n", u32, u32 );
         ak_asn1_prev( asn1 );
      }

 /* создаем указатель на новый уровень */
  ak_asn1_create( asn_down_level = malloc( sizeof( struct asn1 )));
   /* добавляем булево значение */
    ak_asn1_add_bool( asn_down_level, ak_false );
   /* добавляем произвольные данные, интерпретируемые как строки октетов */
    for( i = 1; i < 6; i++ ) ak_asn1_add_octet_string( asn_down_level, buf, i );
   /* вкладываем новый уровень  */
    ak_asn1_add_asn1( asn1, TSEQUENCE, asn_down_level );

 /* добавляем к верхнему уровню новые значения */
  ak_asn1_add_utf8_string( asn1, NULL ); /* так создается элемент NULL */
  ak_asn1_add_octet_string( asn1, buf, sizeof( buf ));

 /* теперь мы формируем самый верхний уровень дерева */
  ak_asn1_create( &root );
 /* вкладываем в него низлежащий уровень */
  ak_asn1_add_asn1( &root, TSEQUENCE, asn1 );

 /* создаем еще один вложенный уровень */
  ak_asn1_create( asn_down_level = malloc( sizeof( struct asn1 )));
   /* добавляем в него идентификатор */
    ak_asn1_add_oid( asn_down_level, "1.2.3.4.5.6.7.891521.51.1" );
  /* и произвольную строку символов */
    ak_asn1_add_utf8_string( asn_down_level, "this is a description for identifier" );

 /* вкладываем созданный уровень */
  ak_asn1_add_asn1( &root, TSEQUENCE, asn_down_level );

 /* выводим сформированное дерево */
  fprintf( stdout, "\n" );
  ak_asn1_print( &root );

 /* кодируем сформированное дерево */
  len = sizeof( array );
  ak_asn1_encode( &root, array, &len );

  printf("\nencoded (size %u): ", (ak_uint32)len );
  for( i = 0; i < len; i++ ) printf("%02x", array[i] );
  printf("\n");

 /* сохраняем сформированный буффер в файл,
    теперь его можно разобрать сторонними программными средствами */
  ak_file_create_to_write( &file, "test.der" );
  ak_file_write( &file, array, len );
  ak_file_close( &file );

 /* Проверяем контрольную сумму */
  ak_hash_create_streebog256( &ctx );
  ak_hash_file( &ctx, "test.der", out, len = ak_hash_get_tag_size( &ctx ));
  printf("streebog256: %s", str = ak_ptr_to_hexstr( out, len, ak_false ));
  if( ak_ptr_is_equal_with_log( out, tmp, len )) {
    result = EXIT_SUCCESS;
    printf(" Ok\n");
  }
   else printf(" Wrong\n");
  ak_hash_destroy( &ctx );

 /* уничтожаем дерево и выходим */
  ak_asn1_destroy( &root );
  ak_libakrypt_destroy();
 return result;
}
