/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2021 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_cert.c                                                                            */
/*  - содержит реализацию функций, предназначенных для экспорта/импорта открытых ключей            */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#endif
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \details по-умолчанию, каталогу для хранения доверенных сертификатов присваивается значение,
   определенное при конфигурации библиотеки.
   изменение данного пути возможно путем вызова cmake -D AK_CA_PATH="каталог"                      */
/* ----------------------------------------------------------------------------------------------- */
 static char ca_repository_path[FILENAME_MAX] = LIBAKRYPT_CA_PATH;

/* ----------------------------------------------------------------------------------------------- */
                  /* Функции экспорта открытых ключей в запрос на сертификат */
/* ----------------------------------------------------------------------------------------------- */
 int ak_request_destroy( ak_request req )
{
  int error = ak_error_ok;
  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to request options context" );
  if(( error = ak_verifykey_destroy( &req->vkey )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroying of verifykey context" );

  if( req->opts.subject != NULL ) {
    ak_tlv_delete( req->opts.subject );
    req->opts.subject = NULL;
  }

  memset( req, 0, sizeof( struct request ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует фрагмент asn1 дерева, содержащий параметры открытого ключа.
    \param vk контекст открытого ключа
    \return Функция возвращает указатель на tlv узел, содержащий сформированную структуру.
    В случае ошибки возвращается `NULL`.                                                           */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_export_to_asn1_value( ak_verifykey vk )
{
  ak_oid ec = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_tlv tlv = NULL, os = NULL;
  ak_asn1 asn = NULL, basn = NULL;
  size_t val64 = sizeof( ak_uint64 )*vk->wc->size;          /* количество октетов в одном вычете */
  ak_uint8 data[ 2*sizeof(ak_uint64)*ak_mpznmax_size ];    /* asn1 представление открытого ключа */
  ak_uint8 encode[ 4 + sizeof( data )];                             /* кодированная octet string */
  size_t sz = sizeof( encode );

  if(( error = ak_asn1_add_oid( asn = ak_asn1_new(), vk->oid->id[0] )) != ak_error_ok ) goto labex;
  if(( error = ak_asn1_add_asn1( asn, TSEQUENCE, ak_asn1_new( ))) != ak_error_ok ) goto labex;
  if(( ec = ak_oid_find_by_data( vk->wc )) == NULL ) {
    ak_error_message( ak_error_wrong_oid, __func__,
                                 "public key has incorrect pointer to elliptic curve parameters" );
    goto labex;
  }
  ak_asn1_add_oid( asn->current->data.constructed, ec->id[0] );
  ak_asn1_add_oid( asn->current->data.constructed, vk->ctx.oid->id[0] );

  if(( basn = ak_asn1_new()) == NULL ) goto labex;
  if(( error = ak_asn1_add_asn1( basn, TSEQUENCE, asn )) != ak_error_ok ) {
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }

 /* кодируем открытый ключ => готовим octet string */
  memset( data, 0, sizeof( data ));
  if(( os = ak_tlv_new_primitive( TOCTET_STRING, ( val64<<1 ), data, ak_false )) == NULL ){
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }
 /* помещаем в нее данные */
  ak_wpoint_reduce( &vk->qpoint, vk->wc );
  ak_mpzn_to_little_endian( vk->qpoint.x, vk->wc->size, data, val64, ak_false );
  ak_mpzn_to_little_endian( vk->qpoint.y, vk->wc->size, data+val64, val64, ak_false );
  if(( error = ak_tlv_encode( os, encode, &sz )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of temporary tlv context" );
    if( os != NULL ) ak_tlv_delete( os );
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }
  bs.value = encode;
  bs.len = sz;
  bs.unused = 0;
  ak_asn1_add_bit_string( basn, &bs );
  if(( tlv = ak_tlv_new_constructed( TSEQUENCE^CONSTRUCTED, basn )) == NULL ) {
    ak_asn1_delete( basn );
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect addition the bit sting with public key value" );
  }

  ak_tlv_delete( os );
 return  tlv;

 labex:
  if( asn != NULL ) ak_asn1_delete( asn );
  ak_error_message( error, __func__, "incorrect export of public key into request asn1 tree" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Выполняются следующие действия:

    - формируется tlv элемент, содержащий имя владельца, параметры алгоритма и значение ключа,
    - tlv элемент кодируется в der-последовательность,
    - вырабатывается подпись под der-последовательностью,
    - идентификатор алгоритма выработки подписи и значение подписи также помещаются в asn1 дерево.

   \param req контекст запроса на сертификат, содержащий в себе
    открытый ключ и ряд параметров экспорта
   \param sk контекст секретного ключа, соответствующего экспортируемому открытому ключу
   \param a уровень asn1 дерева, в который помещается запрос на сертификат.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_request_export_to_asn1( ak_request req, ak_signkey sk, ak_random generator, ak_asn1 a )
{
  ak_asn1 asn = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_uint8 data[4096], s[128];
  size_t size = sizeof( data );
  ak_verifykey vk = &req->vkey;
  ak_tlv tlv = NULL, pkey = NULL;

  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to request context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( a == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 context" );
  if( !ak_ptr_is_equal( vk->number, sk->verifykey_number, sizeof( vk->number )))
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                     "secret key not correspondig to public key" );
  if( ak_signkey_get_tag_size( sk ) > sizeof( s ))
    ak_error_message( ak_error_wrong_length, __func__,
                                   "using digital signature algorithm with very large signature" );

 /* 1. Создаем последовательность, которая будет содержать данные запроса */
  if(( error = ak_asn1_add_asn1( a, TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new())) != ak_error_ok ) {
    if( asn != NULL ) ak_asn1_delete( asn );
    return ak_error_message( error, __func__, "incorrect creation of first level sequence");
  }

 /* 2. Создаем tlv элемент, для которого, потом, будет вычисляться электронная подпись */
   tlv = ak_tlv_new_constructed( TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new( ));
  /* добавляем ноль */
   ak_asn1_add_uint32( asn, 0 );
  /* копируем asn1 дерево с расширенным именем из структуры открытого ключа
     в asn1 дерево формируемого запроса */
   ak_asn1_add_tlv( asn, ak_tlv_duplicate_global_name( req->opts.subject ));

  /* помещаем информацию об алгоритме и открытом ключе */
   ak_asn1_add_tlv( asn, pkey = ak_verifykey_export_to_asn1_value( vk ));
   if( pkey == NULL ) {
     if( tlv != NULL ) ak_tlv_delete( tlv );
     return ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect export of public key into tlv context" );
   }
  /* 0x00 это помещаемое в CONTEXT_SPECIFIC значение */
   ak_asn1_add_asn1( asn, CONTEXT_SPECIFIC^0x00, ak_asn1_new( ));

  /* 3. Помещаем tlv элемент в основное дерево */
   ak_asn1_add_tlv( a->current->data.constructed, tlv );

  /* 4. Помещаем идентификатор алгоритма выработки подписи */
   ak_asn1_add_asn1( a->current->data.constructed, TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new());
   ak_asn1_add_oid( asn, sk->key.oid->id[0] );

  /* 4. Помещаем bit-string со значением подписи */
   if(( error =  ak_tlv_encode( tlv, data, &size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect encoding of asn1 context");

   memset( s, 0, sizeof( s ));
   if(( error = ak_signkey_sign_ptr( sk, generator, data, size, s, sizeof( s ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect signing internal data" );
   bs.value = s;
   bs.len = ak_signkey_get_tag_size( sk );
   bs.unused = 0;
   if(( error = ak_asn1_add_bit_string( a->current->data.constructed, &bs )) != ak_error_ok )
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию
    и сохраняет созданное дерево в файл, который называется "запросом на сертификат".

   \note Контекст секретного ключа `sk` должен соответствовать контексту открытого ключа `vk`,
   помещеному в конеткст запроса.
   В противном случае нельзя будет проверить электронную подпись под открытым ключом, поскольку
   запрос на сертификат, по сути, является урезанной версией самоподписанного сертификата.
   Отсюда следует, что нельзя создать запрос на сертификат ключа, который не поддерживает
   определенный библиотекой алгоритм подписи (например ключ на кривой в 640 бит).
   Такие ключи должны сразу помещаться в сертификат.

   \param req контекст запроса на сертификат, содержащий в себе
    открытый ключ и ряд параметров экспорта
   \param sk Контекст секретного ключа, соответствующий открытому ключу
   \param generator Генератор псевдослучайных последовательностей, используемый для выработки
    электронной подписи под запросом на сертификат
   \param filename Указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  Размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format Формат, в котором сохраняются данные - der или pem.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_request_export_to_file( ak_request req, ak_signkey sk, ak_random generator,
                                       char *filename, const size_t size, export_format_t format )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to request context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null pointer to file name" );

 /* 1. При необходимости, формируем имя файла для экспорта открытого ключа
       Формируемое имя совпадает с номером ключа и однозначно зависит от его значения */
  if( size != 0 ) {
    memset( filename, 0, size );
    if( size < 12 ) return ak_error_message( ak_error_wrong_length, __func__,
                                               "using small buffer to storing request file name" );
     else ak_snprintf( filename, size, "%s.csr",
                          ak_ptr_to_hexstr( req->vkey.number, req->vkey.number_length, ak_false ));
  }

 /* 2. Создаем asn1 дерево */
  if(( error = ak_request_export_to_asn1( req, sk, generator,
                                                         asn = ak_asn1_new( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation af asn1 context" );
    goto labexit;
  }

 /* 3. Сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( asn,
                                filename, format, public_key_request_content )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "incorrect export asn1 context to file %s", filename );
    goto labexit;
  }

  labexit:
    if( asn != NULL ) ak_asn1_delete( asn );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                 /* Функции импорта открытых ключей из запроса на сертификат */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_value( ak_verifykey vkey, ak_asn1 asnkey )
{
  size_t size = 0;
  ak_oid oid = NULL;
  struct bit_string bs;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = asnkey, asnl1;
  ak_uint32 val = 0, val64 = 0;

 /* проверяем наличие последовательности верхнего уровня */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                               "the first next level element must be a sequence" );
 /* получаем алгоритм электронной подписи */
  ak_asn1_first( asnl1 = asn->current->data.constructed );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                          "the first element of child asn1 context must be an object identifier" );
  if(( error = ak_tlv_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                                                   "using unsupported object identifier %s", ptr );
  if(( oid->engine != verify_function ) || ( oid->mode != algorithm ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* получаем параметры элиптической кривой */
  ak_asn1_next( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
             "the second element of child asn1 context must be a sequence of object identifiers" );
  asnl1 = asnl1->current->data.constructed;

  ak_asn1_first( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                     "the first element of last child asn1 context must be an object identifier" );
  if(( error = ak_tlv_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                            "import an unsupported object identifier %s for elliptic curve", ptr );
  if(( oid->engine != identifier ) || ( oid->mode != wcurve_params ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* создаем контекст */
  asnl1 = NULL;
  if(( error = ak_verifykey_create( vkey, (const ak_wcurve )oid->data )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of verify key context" );

 /* получаем значение открытого ключа */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect reading a bit string" );
    goto lab1;
  }

 /* считали битовую строку, проверяем что это der-кодировка некоторого целого числа */
  if(( error = ak_asn1_decode( asnl1 = ak_asn1_new(),
                                                  bs.value, bs.len, ak_false )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect decoding a value of public key" );
    goto lab1;
  }
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOCTET_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                                        "the public key must be an octet string" );
    goto lab1;
  }

 /* считываем строку и разбиваем ее на две половинки */
  val = ( ak_uint32 )vkey->wc->size;
  val64 = sizeof( ak_uint64 )*val;
  ak_tlv_get_octet_string( asnl1->current, &ptr, &size );
  if( size != 2*val64 ) {
    ak_error_message_fmt( error = ak_error_wrong_length, __func__ ,
        "the size of public key is equal to %u (must be %u octets)", (unsigned int)size, 2*val64 );
    goto lab1;
  }

 /* копируем данные и проверям, что точка действительно принадлежит кривой */
  ak_mpzn_set_little_endian( vkey->qpoint.x, val, ptr, val64, ak_false );
  ak_mpzn_set_little_endian( vkey->qpoint.y, val, ((ak_uint8*)ptr)+val64, val64, ak_false );
  ak_mpzn_set_ui( vkey->qpoint.z, val, 1 );
  if( ak_wpoint_is_ok( &vkey->qpoint, vkey->wc ) != ak_true ) {
    ak_error_message_fmt( error = ak_error_curve_point, __func__ ,
                                                  "the public key isn't on given elliptic curve" );
    goto lab1;
  }

 /* устанавливаем флаг */
  vkey->flags = key_flag_set_key;

 lab1:
  if( asnl1 != NULL ) ak_asn1_delete( asnl1 );
  if( error != ak_error_ok ) ak_verifykey_destroy( vkey );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция получает значение открытого ключа из запроса на сертификат,
    разобранного в ASN.1 дерево, и создает контекст открытого ключа.

    Функция считывает oid алгоритма подписи и проверяет, что он соответствует ГОСТ Р 34.12-2012,
    потом функция считывает параметры эллиптической кривой и проверяет, что библиотека поддерживает
    данные параметры. В заключение функция считывает открытый ключ и проверяет,
    что он принадлежит кривой со считанными ранее параметрами.

    После выполнения всех проверок, функция создает (действие `create`) контекст открытого ключа,
    а также присваивает (действие `set_key`) ему считанное из asn1 дерева значение.

    \param req контекст запроса на сертификат для
    создаваемого открытого ключа асимметричного криптографического алгоритма
    \param asnkey считанное из файла asn1 дерево
    \param reqopt опции запроса на сертификат, считываемые вместе со значением открытого ключа


    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_request_import_from_asn1_tree( ak_request req, ak_asn1 asnkey )
{
  ak_uint32 val = 0;
  ak_asn1 asn = asnkey; /* копируем адрес */

 /* проверяем, что первым элементом содержится ноль */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                     "the first element of root asn1 context must be an integer" );
  ak_tlv_get_uint32( asn->current, &val );
 /* проверяемое нами значение 0 соотвествует единственному
    поддерживаемому формату запроса не сертифкат */
  if( val ) return ak_error_message( ak_error_invalid_asn1_content, __func__ ,
                                              "the first element of asn1 context must be a zero" );
  req->opts.version = val+1;

 /* второй элемент содержит имя владельца ключа,
    этот элемент будет перенесен в контекст опций открытого ключа после проверки подписи */
  ak_asn1_next( asn );

 /* третий элемент должен быть SEQUENCE с набором oid и значением ключа */
  if( ak_asn1_next( asn ) != ak_true )
    return ak_error_message( ak_error_invalid_asn1_count, __func__, "unexpected end of asn1 tree" );

 /* проверяем наличие последовательности верхнего уровня */
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                      "the element of root asn1 tree must be a sequence with object identifiers" );
  asn = asn->current->data.constructed;

 return ak_verifykey_import_from_asn1_value( &req->vkey, asn );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_request_import_from_asn1( ak_request req, ak_asn1 root )
{
  size_t size = 0;
  ak_tlv tlv = NULL;
  ak_asn1 asn = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_uint8 buffer[1024], *ptr = NULL;

 /* стандартные проверки */
  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to request context" );
  if( root == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to root asn1 context" );

 /* проверяем, что данные содержат хоть какое-то значение */
  if(( root->count == 0 ) || ( root->current == NULL )) {
    ak_error_message_fmt( error = ak_error_null_pointer, __func__, "using zero ASN.1 context");
    goto lab1;
  }

 /* здесь мы считали asn1, декодировали и должны убедиться, что это то самое дерево */
  ak_asn1_first( root );
  tlv = root->current;
  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) {
    ak_error_message( error = ak_error_invalid_asn1_tag,
                                                 __func__, "incorrect structure of asn1 context" );
    goto lab1;
  }

 /* проверяем количество узлов */
  if(( asn = tlv->data.constructed )->count != 3 ) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_count, __func__,
                                          "root asn1 context contains incorrect count of leaves" );
    goto lab1;
  }

 /* первый узел позволит нам получить значение открытого ключа
    (мы считываем параметры эллиптической кривой, инициализируем контекст значением
    открытого ключа и проверяем, что ключ принадлежит указанной кривой ) */
  ak_asn1_first( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                                           "incorrect structure of asn1 context" );
    goto lab1;
  }
  if(( error = ak_request_import_from_asn1_tree( req,
                                               asn->current->data.constructed )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect structure of request" );
    goto lab1;
  }
 /* 4. На основе считанных данных формируем номер ключа */
  if(( error = ak_verifykey_set_number( &req->vkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation on public key number" );
    goto lab1;
  }

 /* второй узел, в нашей терминологии, содержит идентификатор секретного ключа
    и бесполезен, поскольку вся информация об открытом ключе проверки подписи,
    эллиптической кривой и ее параметрах уже считана. */
  ak_asn1_next( asn );


 /* третий узел -> остается только проверить подпись,
    расположенную в последнем, третьем узле запроса. */

 /* 1. Начинаем с того, что готовим данные, под которыми должна быть проверена подпись */
  ak_asn1_first( asn );
  if(( error = ak_tlv_evaluate_length( asn->current, &size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect evaluation of encoded tlv context length");
    goto lab1;
  }
  if( size > sizeof( buffer )) { /* выделяем память, если статической не хватает */
    if(( ptr = malloc( size )) == NULL ) {
      ak_error_message( ak_error_out_of_memory, __func__, "memory allocation error");
      goto lab1;
    }
     else memset( ptr, 0, size );
  }
   else {
     ptr = buffer;
     memset( buffer, 0, size = sizeof( buffer ));
   }

  if(( error = ak_tlv_encode( asn->current, ptr, &size )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                 "incorrect encoding of tlv context contains of %u octets", (unsigned int) size );
    goto lab1;
  }

 /* 2. Теперь получаем значение подписи из asn1 дерева и сравниваем его с вычисленным значением */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error , __func__ , "incorrect value of bit string in root asn1 context" );
    goto lab1;
  }

 /* 3. Только сейчас проверяем подпись под данными */
  if( ak_verifykey_verify_ptr( &req->vkey, ptr, size, bs.value ) != ak_true ) {
    ak_error_message( error = ak_error_not_equal_data, __func__, "digital signature isn't valid" );
   /* удаляем goto lab1; */
  }
   else { /* копируем значение подписи в опции запроса на сертификат */
       memset( req->opts.signature, 0, sizeof( req->opts.signature ));
       memcpy( req->opts.signature, bs.value, ak_min( sizeof( req->opts.signature ),
                                                        2*ak_hash_get_tag_size( &req->vkey.ctx )));
   }

 /* 5. В самом конце, после проверки подписи,
    изымаем узел, содержащий имя владельца открытого ключа -- далее этот узел будет перемещен
    в сертификат открытого ключа.
    Все проверки пройдены ранее и нам точно известна структура asn1 дерева. */
  ak_asn1_first( asn );
  if(( asn = asn->current->data.constructed ) != NULL ) {
   ak_asn1_first( asn );
   ak_asn1_next( asn ); /* нужен второй узел */
   req->opts.subject = ak_asn1_exclude( asn );
  }

 lab1:
  if(( ptr != NULL ) && ( ptr != buffer )) free( ptr );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_request_import_from_file( ak_request req, const char *filename )
{
  ak_asn1 root = NULL;
  int error = ak_error_ok;

 /* стандартные проверки */
  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to request context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );

 /* считываем сертификат и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_import_from_file( root = ak_asn1_new(), filename, NULL )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
    goto lab1;
  }

 /* собственно выполняем импорт данных */
  if(( error = ak_request_import_from_asn1( req, root )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong import of public key from asn.1 context" );
  }

  lab1: if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                      /* Служебные функции для работы с сертификатами */
/* ----------------------------------------------------------------------------------------------- */
/*! Данный номер зависит от номера секретного ключа, подписывающего открытый ключ и,
    тем самым, может принимать различные значения для каждого из подписывающих ключей.

    Серийный номер сертификата, по-умолчанию, образуют младшие 32 байта результата хеширования
    последовательной конкатенации номеров открытого и секретного ключей.
    Для хеширования используется функция, определенная в контексте `секретного` ключа,
    т.е. Стрибог512 для длинной подписи и Стрибог256 для короткой.

   \code
    result[0 .. size-1] = LSB( size, Hash( vk->number || sk->number ))
   \endcode

    Вычисленное значение не размещается в контексте открытого ключа, а
    помещается в заданную область памяти. Это позволяет использовать данную функцию как при экспорте,
    так и при импорте сертификатов открытых ключей (в момент разбора цепочек сертификации).

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \param buf буффер, в котором размещается серийный номер.
   \param size размер буффера (в октетах).
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_generate_serial_number( ak_verifykey vk, ak_signkey sk,
                                                                 ak_uint8 *buf, const size_t size )
{
  if( vk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to verifykey context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( size > ak_hash_get_tag_size( &sk->ctx ))
    return ak_error_message( ak_error_wrong_length, __func__,
                                                 "the buffer size exceeds the permissible bound" );
 /* используем для хеширования контекст секретного ключа */
  ak_hash_clean( &sk->ctx );
  ak_hash_update( &sk->ctx, vk->number, sizeof( vk->number ));
  ak_hash_finalize( &sk->ctx, sk->key.number, sizeof( sk->key.number ), buf, size );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param cert контекст сертификата открытого ключа
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль), в противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_opts_create( ak_certificate_opts opts )
{
  if( opts == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "initializing null pointer to certificate options" );
 /* значения по умолчанию */
  memset( opts, 0, sizeof( struct certificate_opts ));
  opts->subject = NULL;
  opts->issuer = NULL;
  opts->ext_ca.is_present = ak_false;
  opts->ext_key_usage.is_present = ak_false;
  opts->ext_subjkey.is_present = ak_false;
  opts->ext_authoritykey.is_present = ak_false;
  opts->created = ak_false;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_destroy( ak_certificate cert )
{
  int error = ak_error_ok;
  if( cert == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to certificate context" );
  if( cert->opts.created ) { /* проверяем, был ли создан сертификат */
    if(( error = ak_verifykey_destroy( &cert->vkey )) != ak_error_ok )
      ak_error_message( error, __func__, "wrong destroying of verifykey context" );
  }
  if( cert->opts.subject != NULL ) cert->opts.subject = ak_tlv_delete( cert->opts.subject );
  if( cert->opts.issuer != NULL ) cert->opts.issuer = ak_tlv_delete( cert->opts.issuer );

 /* очистку установленных полей не производим
    memset( cert, 0, sizeof( struct certificate )); */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                   Функции создания расширений x509v3 для сертификатов                           */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение x509v3 следующего вида.

 \code
   ├SEQUENCE┐
            ├OBJECT IDENTIFIER 2.5.29.14 (subject-key-identifier)
            └OCTET STRING
               04 14 9B 85 5E FB 81 DC 4D 59 07 51 63 CF BE DF
               DA 2C 7F C9 44 3C
               ├ ( decoded 22 octets)
               └OCTET STRING
                  9B 85 5E FB 81 DC 4D 59 07 51 63 CF BE DF DA 2C  // данные, на которые
                  7F C9 44 3C                                      // указывает ptr
 \endcode

 \param ptr указатель на область памяти, содержащую идентификатор ключа
 \param size размер области памяти
 \return Функция возвращает указатель на структуру узла. Данная структура должна
  быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
  удаления дерева, в который данный узел будет входить.
  В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
  функции ak_error_get_value().                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_subject_key_identifier( ak_pointer ptr, const size_t size )
{
  ak_uint8 encode[256]; /* очень длинные идентификаторы это плохо */
  ak_tlv tlv = NULL, os = NULL;
  size_t len = sizeof( encode );

  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "2.5.29.14" );
 /* добавляем закодированный идентификатор (номер) ключа */
  memset( encode, 0, sizeof( encode ));
  if(( os = ak_tlv_new_primitive( TOCTET_STRING, size, ptr, ak_false )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );
 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение x509v3, определяемое следующей структурой

  \code
   id-ce-basicConstraints OBJECT IDENTIFIER ::=  { 2 5 29 19 }

   BasicConstraints ::= SEQUENCE {
        cA                      BOOLEAN DEFAULT FALSE,
        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
  \endcode


  Пример иерархического представления данного расширения выгдядит следующим образом.

 \code
   └SEQUENCE┐
            ├OBJECT IDENTIFIER 2.5.29.19 (basic-constraints)
            ├BOOLEAN TRUE                 // расширение является критичным
            └OCTET STRING
               30 06 01 01 FF 02 01 00
               ├ ( decoded 8 octets)
               └SEQUENCE┐
                        ├BOOLEAN TRUE     //  сертификат может создавать цепочки сертификации (cA)
                        └INTEGER 0x0      //  длина цепочки равна 1
                                          // (количество промежуточных сертификатов равно ноль)
 \endcode

  RFC5280: Расширение для базовых ограничений (basic constraints) указывает, является ли `субъект`
  сертификата центром сертификации (certificate authority), а также максимальную глубину действительных
  сертификационных путей, которые включают данный сертификат. Булевское значение сА указывает,
  принадлежит ли сертифицированный открытый ключ центру сертификации.
  Если булевское значение сА не установлено,
  то бит keyCertSign в расширении использования ключа (keyUsage) не должен быть установлен.
  Поле pathLenConstrant имеет смысл, только если булевское значение сА установлено, и в расширении
  использования ключа установлен бит keyCertSign. В этом случае данное поле определяет максимальное
  число несамовыпущенных промежуточных сертификатов, которые *могут* следовать за данным сертификатом
  в действительном сертификационном пути.
  Сертификат является самовыпущенным (самоподписаным), если номера ключей,
  которые присутствуют в полях субъекта и выпускающего (эмитента), являются одинаковыми и не пустыми.
  Когда pathLenConstraint не присутствует, никаких ограничений не предполагается.

 \note Данное расширение должно присутствовать как критичное во всех сертификатах центра сертификации,
 которые содержат открытые ключи, используемые для проверки цифровых подписей в сертификатах.
 Данное расширение *может* присутствовать как критичное или некритичное расширение в сертификатах
 центра сертификации, которые содержат открытые ключи, используемые для целей, отличных от проверки
 цифровых подписей в сертификатах. Такие сертификаты содержат открытые ключи, используемые
 исключительно для проверки цифровых подписей в CRLs,
 и сертификатами, которые содержат открытые ключи для управления ключом, используемым в протоколах
 регистрации сертификатов.

 \param ca флаг возможности создавать цепочки сертификации
 \param pathLen длина цепочки сертифкации
 \return Функция возвращает указатель на структуру узла. Данная структура должна
  быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
  удаления дерева, в который данный узел будет входить.
  В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
  функции ak_error_get_value().                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_basic_constraints( bool_t ca, const ak_uint32 pathLen )
{
  ak_uint8 encode[256]; /* очень длинные идентификаторы это плохо */
  ak_tlv tlv = NULL, os = NULL;
  size_t len = sizeof( encode );

  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "2.5.29.19" );
  ak_asn1_add_bool( tlv->data.constructed, ak_true ); /* расширение всегда критическое */

 /* добавляем закодированный идентификатор (номер) ключа */
  if(( os = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }

  ak_asn1_add_bool( os->data.constructed, ca );
  if( ca ) ak_asn1_add_uint32( os->data.constructed, pathLen );

  memset( encode, 0, sizeof( encode ));
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );

 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение x509v3 следующего вида.

 \code
    └SEQUENCE┐
             ├OBJECT IDENTIFIER 2.5.29.15 (key-usage)
             └OCTET STRING
                03 02 00 84
                ├ (decoded 4 octets)
                └BIT STRING
                   84
 \endcode

 \param bits набор флагов
 \return Функция возвращает указатель на структуру узла. Данная структура должна
  быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
  удаления дерева, в который данный узел будет входить.
  В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
  функции ak_error_get_value().                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_key_usage( const ak_uint32 bits )
{
  ak_uint8 buffer[2], /* значащими битами являются младшие 9,
            поэтому нам хватит двух байт для хранения флагов */
           encode[16];  /* массив для кодирования битовой строки */
  struct bit_string bs;
  ak_tlv tlv = NULL, os = NULL;
  size_t len = sizeof( encode );

  if( !bits ) {
    ak_error_message( ak_error_zero_length, __func__, "using undefined set of keyUsage flags" );
    return NULL;
  }
  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "2.5.29.15" );

  buffer[0] = ( bits >> 1 )&0xFF;
  if( bits&0x01 ) { /* определен бит decipherOnly */
    buffer[1] = 0x80;
    bs.unused = 7;
    bs.len = 2;
  } else {
      buffer[1] = 0;
      bs.unused = 0;
      bs.len = 1;
   }
  bs.value = buffer;

 /* добавляем закодированную последовательность бит */
  if(( os = ak_tlv_new_primitive( TBIT_STRING, bs.len+1, NULL, ak_true )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  os->data.primitive[0] = bs.unused;
  memcpy( os->data.primitive+1, bs.value, bs.len );

  memset( encode, 0, sizeof( encode ));
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );

 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение x509v3 определяемое следующей структурой

 \code
    KeyIdentifier ::= ОСТЕТ SТRING

    AuthorityKeyIdentifier ::= SEQUENCE {
       keyIdentifier       [О] KeyIdentifier OPTIONAL,
       authorityCertIssuer [1] GeneralNames OPTIONAL,
       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
    }
 \endcode

   Пример данного расширения выглядит следующим образом (взято из сертификата,
   подписанного корневым сертификатом ГУЦ)

 \code
└SEQUENCE┐
         ├[0] 8b983b891851e8ef9c0278b8eac8d420b255c95d
         ├[1]┐
         │   └[4]┐
         │       └SEQUENCE┐
         │                ├SET┐
         │                │   └SEQUENCE┐
         │                │            ├OBJECT IDENTIFIER 1.2.840.113549.1.9.1 (email-address)
         │                │            └IA5 STRING dit@minsvyaz.ru
         │                ├SET┐
         │                │   └SEQUENCE┐
         │                │            ├OBJECT IDENTIFIER 2.5.4.6 (country-name)
         │                │            └PRINTABLE STRING RU
         │                ├SET┐
         │                │   └SEQUENCE┐
         │                │            ├OBJECT IDENTIFIER 2.5.4.8 (state-or-province-name)
         │                │            └UTF8 STRING 77 г. Москва
         │                └SET┐
         │                    └SEQUENCE┐
         │                             ├OBJECT IDENTIFIER 2.5.4.3 (common-name)
         │                             └UTF8 STRING Головной удостоверяющий центр
         └[2] 34681e40cb41ef33a9a0b7c876929a29
 \endcode

   Метке `[0]` соответствует номер ключа подписи (поле verifykey.number),
   метке `[1]`  - расширенное имя ключа подписи (поле verifykey.name),
   метке `[2]`  - серийный номер выпущенного сертификата открытого ключа (однозначно вычисляется из
   номеров секретного ключа и ключа подписи).

   RFC 5280: Расширение для идентификатора ключа сертификационного центра предоставляет способ
   идентификации открытого ключа, соответствующего закрытому ключу, который использовался для
   подписывания сертификата. Данное расширение используется, когда выпускающий имеет несколько ключей
   для подписывания. Идентификация может быть основана либо на идентификаторе ключа
   (идентификатор ключа субъекта в сертификате выпускающего), либо на имени выпускающего и
   серийном номере сертификата.

   \note Поле `keyIdentifier` расширения authorityKeyIdentifier должно быть включено во все
   сертификаты, выпущенные цетром сертификации для обеспечения возможности создания
   сертификационного пути. Существует одно исключение: когда центр сертификации распространяет свой
   открытый ключ в форме самоподписанного сертификата, идентификатор ключа уполномоченного органа
   может быть опущен. Подпись для самоподписанного сертификата создается закрытым ключом,
   соответствующим открытому ключу субъекта. ЭТО доказывает, что выпускающий обладает как открытым
   ключом, так и закрытым.

   \param issuer_cert сертификат открытого ключа эмитента (лица, подписывающего сертификат)
   \param include_name булево значение; если оно истинно,
   то в расширение помещается глобальное имя владельца указанных ключей
   \return Функция возвращает указатель на структуру узла. Данная структура должна
   быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
   удаления дерева, в который данный узел будет входить.
   В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
   функции ak_error_get_value().                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_authority_key_identifier( ak_certificate issuer_cert, bool_t include_name )
{
  ak_uint8 encode[512];  /* массив для кодирования */
  size_t len = sizeof( encode );
  ak_tlv tlv = NULL, os = NULL;
  ak_asn1 asn = NULL, asn1 = NULL;

  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }

 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "2.5.29.35" );

 /* добавляем закодированную последовательность, содержащую перечень имен */
  if(( os = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }

 /* добавляем [0] */
  ak_asn1_add_tlv( os->data.constructed,
                 ak_tlv_new_primitive( CONTEXT_SPECIFIC^0x00,
                             issuer_cert->vkey.number_length, issuer_cert->vkey.number, ak_true ));
 /* добавляем [1] */
  if( include_name ) {
    ak_asn1_add_tlv( os->data.constructed,
                  ak_tlv_new_constructed( CONSTRUCTED^CONTEXT_SPECIFIC^0x01, asn = ak_asn1_new()));
    ak_asn1_add_tlv( asn,
                 ak_tlv_new_constructed( CONSTRUCTED^CONTEXT_SPECIFIC^0x04, asn1 = ak_asn1_new()));
    ak_asn1_add_tlv( asn1, ak_tlv_duplicate_global_name( issuer_cert->opts.subject ));
  }
 /* добавляем [2] */
  if( issuer_cert->opts.serialnum_length ) {
    ak_asn1_add_tlv( os->data.constructed,
            ak_tlv_new_primitive( CONTEXT_SPECIFIC^0x02,
                       issuer_cert->opts.serialnum_length, issuer_cert->opts.serialnum, ak_true ));
  }

  memset( encode, 0, sizeof( encode ));
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );

 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение сертификата открытого ключа,
    содержащее номер секретного ключа, соответсвующего открытому ключу.
    Расширение имеет следующий вид.

 \code
   ├SEQUENCE┐
 \endcode

 \param ptr указатель на область памяти, содержащую номер секретного ключа
 \param size размер области памяти
 \return Функция возвращает указатель на структуру узла. Данная структура должна
  быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
  удаления дерева, в который данный узел будет входить.
  В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
  функции ak_error_get_value().                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_secret_key_number( ak_pointer ptr, const size_t size )
{
  ak_uint8 encode[256]; /* очень длинные идентификаторы это плохо */
  ak_tlv tlv = NULL, os = NULL;
  size_t len = sizeof( encode );

  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "1.2.643.2.52.1.98.1" );
 /* добавляем закодированный идентификатор (номер) ключа */
  memset( encode, 0, sizeof( encode ));
  if(( os = ak_tlv_new_primitive( TOCTET_STRING, size, ptr, ak_false )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );
 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
                     /* Функции экспорта открытых ключей в сертификат */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание tlv узла, содержащего структуру TBSCertificate версии 3
    в соответствии с Р 1323565.1.023-2018.

   Структура `tbsCertificate` определяется следующим образом

   \code
    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  Extensions OPTIONAL
                             -- If present, version MUST be v3 --  }
   \endcode

   Перечень добавляемых расширений определяется значениями аргумента `opts`.

   \param subject_cert контекст сертификата открытого ключа, помещаемого в asn1 дерево сертификата
   \param issuer_skey контекст ключа подписи
   \param issuer_cert контект сертификата ключа проверки подписи
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_certificate_export_to_tbs( ak_certificate subject_cert, ak_signkey issuer_skey,
                                                                       ak_certificate issuer_cert )
{
  ak_mpzn256 serialNumber;
  ak_tlv tbs = NULL, tlv = NULL;
  ak_asn1 asn = NULL, tbasn = NULL;

  if(( tbs = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
   else tbasn = tbs->data.constructed;

 /* теперь создаем дерево сертификата в соответствии с Р 1323565.1.023-2018
    version: начинаем с размещения версии сертификата, т.е. ветки следующего вида
     ┐
     ├[0]┐
     │   └INTEGER 2 (величина 2 является максимально возможным значением ) */

  ak_asn1_add_asn1( tbasn, CONTEXT_SPECIFIC^0x00, asn = ak_asn1_new( ));
  if( asn != NULL ) ak_asn1_add_uint32( asn, 2 );
    else {
      ak_error_message( ak_error_get_value(), __func__,
                                              "incorrect creation of certificate version context");
      goto labex;
    }

 /* serialNumber: вырабатываем и добавляем номер сертификата */
  ak_certificate_generate_serial_number( &subject_cert->vkey, issuer_skey,
                                                                   subject_cert->opts.serialnum,
              subject_cert->opts.serialnum_length = sizeof( subject_cert->opts.issuer_serialnum ));
  ak_mpzn_set_little_endian( serialNumber, ak_mpzn256_size,
                     subject_cert->opts.serialnum, subject_cert->opts.serialnum_length, ak_true );
  ak_asn1_add_mpzn( tbasn, TINTEGER, serialNumber, ak_mpzn256_size );

 /* signature: указываем алгоритм подписи (это будет повторено еще раз при выработке подписи) */
  ak_asn1_add_algorithm_identifier( tbasn, issuer_skey->key.oid, NULL );

 /* issuer: вставляем информацию о расширенном имени лица, подписывающего ключ
    (эмитента, выдающего сертификат) */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( issuer_cert->opts.subject ));

 /* validity: вставляем информацию в времени действия ключа */
  ak_asn1_add_validity( tbasn, subject_cert->opts.time.not_before,
                                                               subject_cert->opts.time.not_after );
 /* subject: вставляем информацию о расширенном имени владельца ключа  */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( subject_cert->opts.subject ));

 /* subjectPublicKeyInfo: вставляем информацию об открытом ключе */
  ak_asn1_add_tlv( tbasn, tlv = ak_verifykey_export_to_asn1_value( &subject_cert->vkey ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect generation of subject public key info" );
    goto labex;
  }

 /* далее мы реализуем возможности сертификатов третьей версии, а именно
    вставляем перечень расширений
    0x03 это помещаемое в CONTEXT_SPECIFIC значение */
  ak_asn1_add_asn1( tbasn, CONTEXT_SPECIFIC^0x03, asn = ak_asn1_new( ));
  if( asn == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                      "incorrect creation of certificate extensions asn1 context");
    goto labex;
  }
  ak_asn1_add_tlv( asn, ak_tlv_new_sequence( ));
  asn = asn->current->data.constructed;

 /* 1. В обязательном порядке добавляем номер открытого ключа */
  ak_asn1_add_tlv( asn, tlv = ak_tlv_new_subject_key_identifier( subject_cert->vkey.number,
                                                               subject_cert->vkey.number_length ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
    goto labex;
  }

 /* 2. Если определено расширение BasicConstraints, то добавляем его
      (расширение может добавляться не только в самоподписаные сертификаты) */
  if( subject_cert->opts.ext_ca.is_present ) {
    ak_asn1_add_tlv( asn, tlv = ak_tlv_new_basic_constraints( subject_cert->opts.ext_ca.value,
                                                    subject_cert->opts.ext_ca.pathlenConstraint ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* 3. Если определены флаги keyUsage, то мы добавляем соответствующее расширение */
  if( subject_cert->opts.ext_key_usage.is_present ) {
    ak_asn1_add_tlv( asn, tlv = ak_tlv_new_key_usage( subject_cert->opts.ext_key_usage.bits ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* 4. Добавляем имена для поиска ключа проверки подписи (Authority Key Identifier)
                                                       данное расширение будет добавляться всегда */
  ak_asn1_add_tlv( asn, tlv = ak_tlv_new_authority_key_identifier( issuer_cert,
                                               subject_cert->opts.ext_authoritykey.include_name ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                    "incorrect generation of Authority Key Identifier extension" );
    goto labex;
  }

 /* 5. Добавляем номер секретного ключа, соответствующего открытому ключу */
  if( subject_cert->opts.ext_secret_key_number.is_present ) {
    ak_asn1_add_tlv( asn,
      tlv = ak_tlv_new_secret_key_number( subject_cert->opts.ext_secret_key_number.number,
                                       sizeof( subject_cert->opts.ext_secret_key_number.number )));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                             "incorrect generation of SecretKeyNumber extension" );
      goto labex;
    }
  }

 return tbs;

  labex: if( tbs != NULL ) ak_tlv_delete( tbs );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param subject_cert контекст сертификата, помещаемого в asn1 дерево
    \param issuer_skey контекст ключа подписи
    \param issuer_cert контект сертификата ключа проверки подписи,
     содержащий параметры центра сертификации
    \param generator геератор случайных последовательностей, используемый для подписи сертификата
    \return Функция возвращает указатель на созданный объект.
    В случае ошибки возвращается NULL.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_asn1 ak_certificate_export_to_asn1( ak_certificate subject_cert,
                          ak_signkey issuer_skey, ak_certificate issuer_cert, ak_random generator )
{
  size_t len = 0;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  time_t current = time( NULL );
  ak_uint8 encode[4096], out[128];
  ak_tlv tlv = NULL, ta = NULL, tbs = NULL;

 /* 1. Необходимые проверки */
  if( subject_cert == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                           "using null pointer to subject's certificate context" );
    return NULL;
  }
  if( issuer_skey == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to issuer's secret key context" );
    return NULL;
  }
  if( issuer_cert == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                            "using null pointer to issuer's certificate context" );
    return NULL;
  }

 /* 2. Проверяем, разрешено ли issuer_cert подписывать сертификаты.
       Для создания подписи расширение BasicConstraints должно быть определено,
                                             а поле value установлено в "true".
       Создание самоподписаных сертификатов разрешено в любом случае.            */
  if( subject_cert != issuer_cert ) {
    if( !issuer_cert->opts.ext_ca.is_present || !issuer_cert->opts.ext_ca.value ) {
      ak_error_message( ak_error_certificate_ca, __func__, "issuer is not certificate's authority" );
      return NULL;
    }
  }

 /* 3. Проверяем, что текущее время попадает во время действия сертификата подписи. */
  if( current < issuer_cert->opts.time.not_before ||
      current > issuer_cert->opts.time.not_after ) {
    ak_error_message( ak_error_certificate_validity, __func__,
                                                             "issuer's certificate time expired" );
    return NULL;
  }

 /* 4. Проверям, что секретный ключ соответствует сертификату ключа подписи */
  if( issuer_cert->vkey.number_length != 32 ) {
   /* мы работаем только со своими секретными ключами,
      а у них длина номера - фиксирована и равна 32 октетам */
    ak_error_message( ak_error_wrong_length, __func__,
                                               "the issuer public key's number has wrong length" );
    return NULL;
  }
  if( memcmp( issuer_skey->verifykey_number, issuer_cert->vkey.number, 32 ) != 0 ) {
    ak_error_message( ak_error_not_equal_data, __func__,
                           "the issuer's secret key does not correspond to the given public key" );
    return NULL;
  }

 /* 5. Создаем контейнер для сертификата */
  if(( error = ak_asn1_add_tlv( certificate = ak_asn1_new(),
                                         tlv = ak_tlv_new_sequence( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect addition of tlv context" );
    goto labex;
  }
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "incorrect creation of tlv context" );
    goto labex;
  }

 /* 6. Создаем поле tbsCertificate */
  if(( tbs = ak_certificate_export_to_tbs( subject_cert, issuer_skey, issuer_cert )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of tbsCertificate element" );
    goto labex;
  }

 /* вставляем в основное дерево созданный элемент */
  ak_asn1_add_tlv( tlv->data.constructed, tbs );
 /* добавляем информацию о алгоритме подписи */
  ak_asn1_add_tlv( tlv->data.constructed, ta = ak_tlv_new_sequence( ));
  if( ta == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                          "incorrect generation of digital signature identifier" );
    goto labex;
  }
  ak_asn1_add_oid( ta->data.constructed, issuer_skey->key.oid->id[0] );

 /* 7. Вырабатываем подпись */
  len = sizeof( encode );
  if(( error = ak_tlv_encode( tbs, encode, &len )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of tbsCertificate element" );
    goto labex;
  }
  if(( error = ak_signkey_sign_ptr( issuer_skey, generator, encode,
                                                      len, out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect generation of digital signature" );
    goto labex;
  }

 /* добавляем подпись в основное дерево */
  bs.value = out;
  bs.len = ak_signkey_get_tag_size( issuer_skey );
  bs.unused = 0;
  if(( error = ak_asn1_add_bit_string( tlv->data.constructed, &bs )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );
    goto labex;
  }
 return certificate;

  labex: if( certificate != NULL ) ak_asn1_delete( certificate );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию,
    помещает в это же asn1 дерево информацию о подписывающем лице и правилах применения ключа.
    После этого сформированное дерево сохраняется в файл (сертификат открытого ключа)
    в заданном пользователем формате.

   \param subject_cert контекст создаваемого сертификата, содержащий как открытый ключ,
   также опции и расширения создаваемого сертификата;
   \param issuer_skey контекст секретного ключа, с помощью которого подписывается создаваемый сертификат;
   \param issuer_cert контекст сертификата открытого ключа, соответствующий секретному ключу подписи;
   данный контекст используется для получения расширенного имени лица,
   подписывающего сертификат (issuer), а также для проверки разрешений на использование сертификата;
   для самоподписанных сертификатов должен принимать значение, совпадающее с subject_cert;
   \param generator генератор случайных чисел, используемый для подписи сертификата.
   \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format формат, в котором сохраняются данные, допутимые значения
   \ref asn1_der_format или \ref asn1_pem_format.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_export_to_file( ak_certificate subject_cert,
                   ak_signkey issuer_skey, ak_certificate issuer_cert, ak_random generator,
                                       char *filename, const size_t size, export_format_t format )
{
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  const char *file_extensions[] = { /* имена параметризуются значениями типа export_format_t */
   "cer",
   "crt"
  };

  /* вырабатываем asn1 дерево */
  if(( certificate = ak_certificate_export_to_asn1(
                                    subject_cert, issuer_skey, issuer_cert, generator )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                            "incorrect creation of asn1 context for certificate" );
 /* формируем имя файла для хранения ключа
    поскольку один и тот же ключ может быть помещен в несколько сертификатов,
    то имя файла в точности совпадает с серийным номером сертификата */
  if( size ) {
    if( size < ( 5 + 2*sizeof( subject_cert->opts.serialnum )) ) {
      ak_error_message( error = ak_error_out_of_memory, __func__,
                                              "insufficent buffer size for certificate filename" );
      goto labex;
    }
    if( subject_cert->opts.serialnum_length == 0 ) {
      ak_certificate_generate_serial_number( &subject_cert->vkey, issuer_skey,
                                                                   subject_cert->opts.serialnum,
              subject_cert->opts.serialnum_length = sizeof( subject_cert->opts.issuer_serialnum ));

    }
    ak_snprintf( filename, size, "%s.%s", ak_ptr_to_hexstr( subject_cert->opts.serialnum,
           subject_cert->opts.serialnum_length, ak_false ), file_extensions[ak_min( 1, format )] );

  } /* конец if(size) */

 /* сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( certificate, filename,
                                        format, public_key_certificate_content )) != ak_error_ok )
    ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in pem format", filename );

  labex: if( certificate != NULL ) ak_asn1_delete( certificate );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция формирует полное имя, состоящее из пути к репозиторию и имени файла,
    созданного из серийного номера сертификата с расширением "cer"
    (сертификат хранится в репозитории в формате der).

    @param full_name Указатель на область памяти, куда помещается создаваемое имя
    @param full_name_size Размер области памяти (в октетах)
    @param serial_number Последовательность октетов, содержащая серийный номер сертификата
    @param serial_number_size Размер серийного номера (в октетах)
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ceritifcate_generate_repository_name( char *full_name, size_t full_name_size,
                                   const ak_uint8 *serial_number, const size_t serial_number_size )
{
   if( full_name == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                              "using null pointer");
   if( full_name_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                "using zero length of output (full_name) buffer " );
   if( serial_number_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                             "using zero length of input (serial_number) buffer " );

 return
   ak_snprintf( full_name, full_name_size, "%s%s%s.cer", ak_certificate_get_repository(),
         #ifdef AK_HAVE_WINDOWS_H
           "\\"
         #else
           "/"
         #endif
         , ak_ptr_to_hexstr( serial_number, serial_number_size, ak_false ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию,
    помещает в это же asn1 дерево информацию о подписывающем лице и правилах применения ключа.
    После этого сформированное дерево сохраняется в виде сертификата открытого ключа и
    помещается в хранилище сертификатов открытых ключей.

   \param subject_cert контекст создаваемого сертификата, содержащий как открытый ключ,
   также опции и расширения создаваемого сертификата;
   \param issuer_skey контекст секретного ключа, с помощью которого подписывается создаваемый сертификат;
   \param issuer_cert контекст сертификата открытого ключа, соответствующий секретному ключу подписи;
   данный контекст используется для получения расширенного имени лица,
   подписывающего сертификат (issuer), а также для проверки разрешений на использование сертификата;
   для самоподписанных сертификатов должен принимать значение, совпадающее с subject_cert;
   \param generator генератор случайных чисел, используемый для подписи сертификата.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_export_to_repository(  ak_certificate subject_cert,
                           ak_signkey issuer_skey, ak_certificate issuer_cert, ak_random generator )
{
  char filename[FILENAME_MAX];

   /* входнфе данные */
    if( subject_cert == NULL )
      return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to subject certificate" );
   /* проверяем, что номер сертификата определен */
    if( subject_cert->opts.serialnum_length == 0 ) {
      ak_certificate_generate_serial_number( &subject_cert->vkey, issuer_skey,
                                                                   subject_cert->opts.serialnum,
              subject_cert->opts.serialnum_length = sizeof( subject_cert->opts.issuer_serialnum ));

    }
   /* файл сохраняется в der-кодировке, имя файла образуется из серийного номера сертификата */
    ak_ceritifcate_generate_repository_name( filename, FILENAME_MAX-1,
                                subject_cert->opts.serialnum, subject_cert->opts.serialnum_length );

  return ak_certificate_export_to_file( subject_cert, issuer_skey, issuer_cert,
                                                          generator, filename, 0, asn1_der_format );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param error код ошибки
    \return Функция возвращает указатель на константную строку                                     */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_certificate_get_error_message( int error )
{
     switch( error ) {
       case ak_error_not_equal_data:
          return "certificate has wrong signature";

       case ak_error_certificate_verify_key:
          return "CA certificate not found";

       case ak_error_certificate_verify_names:
          return "inappropriate CA certificate";

       case ak_error_certificate_validity:
          return "certificate expired";

       case ak_error_oid_engine:
          return "unsupported digital signature algorithm";

       default:
          return "unexpected format of certificate";
     }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выбирает путь к репозиторию по-умолчанию (см. функцию ak_certificate_get_repository()).
    Перед сохранением выполняется проверка сертификата. В случае неуспешной проверки возвращается
    код, описывающий причину неуспеха. Получить символьное представление ошибки можно
    с помощью функции ak_certificate_get_error_message().

   \param filename имя файла с сертификатом открытого ключа
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_add_file_to_repository( const char *filename )
{
    int error = ak_error_ok;
    ak_uint8 buffer[4096], *ptr = NULL;
    size_t size = 0;

    if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to certificate's file name");

    if(( ptr = ak_ptr_load_from_file( buffer, &size, filename )) == NULL )
      return ak_error_message_fmt( ak_error_get_value(), __func__,
                                                        "incorrect reading of file %s", filename );

    if(( error = ak_certificate_add_ptr_to_repository( ptr, size )) != ak_error_ok )
      ak_error_message_fmt( error, __func__, "the file %s is not added to repository", filename );

    if( ptr != buffer ) free( ptr );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выбирает путь к репозиторию по-умолчанию (см. функцию ak_certificate_get_repository()).
    Перед сохранением выполняется проверка сертификата. В случае неуспешной проверки возвращается
    код, описывающий причину неуспеха. Получить символьное представление ошибки можно
    с помощью функции ak_certificate_get_error_message().

   \param ptr указатель на область памяти, в которой расположен сертификат в der-кодировке
   \param size размер области памяти  (в октетах)
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_add_ptr_to_repository( ak_uint8 *buffer, const size_t size )
{
    ak_asn1 root = NULL;
    int error = ak_error_ok;

    if( buffer == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to input buffer" );
    if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                              "using zero length of input buffer" );

   /* выполняем преобразование */
    if(( error = ak_asn1_decode( root = ak_asn1_new(), buffer, size, ak_false )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect decoding of input data" );
    }
     else {
      /* сохраняем сертификат */
       if(( error = ak_certificate_add_asn1_to_repository( root )) != ak_error_ok )
         ak_error_message( error, __func__, "the buffer is not added to repository" );
     }

    if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выбирает путь к репозиторию по-умолчанию (см. функцию ak_certificate_get_repository()).
    Перед сохранением выполняется проверка сертификата. В случае неуспешной проверки возвращается
    код, описывающий причину неуспеха. Получить символьное представление ошибки можно
    с помощью функции ak_certificate_get_error_message().

   \param root корень asn1 дерева, сожержащего сертификат открытого ключа
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_add_asn1_to_repository( ak_asn1 root )
{
    int error = ak_error_ok;
    struct certificate cert;
    char cert_name[FILENAME_MAX];

   /* проверяем, что получили сертификат */
    if( ak_asn1_is_certificate( root ) != ak_true ) {
      return ak_error_message( ak_error_get_value(), __func__,
                                                     "given asn1 tree is not correct certificate" );
    }

   /* проверяем, что сертификат валиден */
    ak_certificate_opts_create( &cert.opts );
    if(( error = ak_certificate_import_from_asn1( &cert, NULL, root )) != ak_error_ok ) {
      return ak_error_message_fmt( error, __func__, "certificate is'nt valid (reason: %s)",
                                                        ak_certificate_get_error_message( error ));
    }

   /* сохраняем сертификат в der-формате */
    ak_ceritifcate_generate_repository_name( cert_name, FILENAME_MAX-1,
                                                 cert.opts.serialnum, cert.opts.serialnum_length );
   /* освобождаем выделенную память */
    ak_certificate_destroy( &cert );

   if(( error = ak_asn1_export_to_derfile( root, cert_name )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                        "wrong export certificate to repository (%s)", cert_name );
   }

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup cert-export-doc Функции экспорта и импорта открытых ключей
@{
 Для импорта открытых ключей из сертификатов в библиотеке реализованы следующие функции:

 В процессе импорта сертификата (вне зависимости о того, какая из указанных функций вызывается пользователем)
 возможно возникновение трех ситуаций:

 - сертификат является самоподписанным
   (в этом случае в функции импорта передается указатель на создаваемый контекст и NULL,
    в качестве указателя на контекст ключа проверки, после импорта для проверки подписи под сертификатом
    используется считанный ключ);

 - сертификат не является самоподписанным и пользователь указывает сертификат с ключом проверки
   (в этом случае в функции импорта передается указатель на создаваемый контекст и
    указатель на созданый (импортированный) ранее пользователем сертификат ключа проверки подписи);

 - сертификат не является самоподписанным, но пользователь об этом не догадывается
   (в этом случае в функции импорта передается указатель на создаваемый контекст и NULL,
    в качестве указателя на контекст ключа проверки; в момент импорта сертификата
    библиотека определяет серийный номер сертификата подписи и ищет его в хранилище (репозитории)
    доверенных сертификатов; в случае успешного поиска
    ключ считывается без уведомления пользователя).
@} */

/* ----------------------------------------------------------------------------------------------- */
                     /* Функции импорта открытых ключей из сертификата */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct certificate_ptr {
  /*! \brief указатель на область памяти, где располагается создаваемый ключ */
   ak_certificate subject;
  /*! \brief указатель на область памяти, где располагается ключ эмитента (УЦ) */
   ak_certificate issuer;
  /*! \brief место хранения сертификата, считываемого в процессе импорта */
   struct certificate real_issuer;
} *ak_certificate_ptr;

/* ----------------------------------------------------------------------------------------------- */
 static int ak_certificate_import_from_asn1_tbs( ak_certificate_ptr, ak_tlv );
 static int ak_certificate_import_from_asn1_tbs_base( ak_certificate_ptr, ak_asn1 );
 static int ak_certificate_import_from_asn1_extension( ak_certificate_ptr, ak_asn1 );

/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает из заданного файла сертификат открытого ключа,
    хранящийся в виде asn1 дерева, определяемого Р 1323565.1.023-2018.
    Собственно asn1 дерево может храниться в файле в виде обычной der-последовательности,
    либо в виде der-последовательности, дополнительно закодированной в `base64` (формат `pem`).

    Функция является конструктором контекста `subject_cert`,
    в случае возникновения некритичных ошибок, создает контекст `subject_cert` и инициирует
    опции сертификата некоторыми значениями. Под некритичными понимаются ошибки
    интерпретирования данных, содержащихся в asn1 дереве (например, неподдерживаемые алгоритмы
    или значения). Критичными являются ошибки нарушения формата x509
    (формата представления данных).

    В случаях, когда ошибок импорта не возникает, создается контекст открытого ключа,
    поле `subject_cert->opts.created` устанавливается истинным (`ak_true`).
    Контекст должен позднее уничтожаться пользователем с помощью вызова ak_certificate_destroy().

    Сертификат, содержащий ключ проверки должен быть предварительно создан и передаваться с помощью
    указателя `issuer_cert` (если номер сертификата проверки подписи или расширенное имя владельца
    не совпадают с тем, что содержится в issuer_cert, то возбуждается ошибка).

    Если указатель `issuer_cert` равен `NULL`, то функция ищет сертифкат с соответствующим серийным
    номером в устанавливаемом библиотекой `libakrypt` каталоге; данный каталог указывается при сборке
    библотеки из исходных текстов в параметре `AK_CA_PATH`; для unix-like систем значением по
    умолчанию является каталог `\usr\share\ca-certificates\libakrypt`.

    \param subject_cert контекст импортируемого сертификата открытого ключа
    асимметричного криптографического алгоритма,
    \param issuer_cert сертификат открытого ключа, с помощью которого можно проверить подпись под сертификатом;
    может принимать значение `NULL`
    \param filename имя файла, из которого считываются значения параметров открытого ключа
    \return Функция возвращает \ref ak_error_ok (ноль) в случае валидности созданноего
    ключа, иначе - возвращается код ошибки.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_import_from_file( ak_certificate subject_cert, ak_certificate issuer_cert,
                                                                              const char *filename )
{
  ak_asn1 root = NULL;
  int error = ak_error_ok;

 /* стандартные проверки */
  if( subject_cert == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                           "using null pointer to subject's certificate context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );

 /* считываем сертификат и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_import_from_file( root = ak_asn1_new(), filename, NULL )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
    goto lab1;
  }

 /* собственно выполняем импорт данных */
  if(( error = ak_certificate_import_from_asn1( subject_cert, issuer_cert, root )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong import of public key from asn.1 context" );
  }

  lab1: if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция предполагает, что в области памяти `ptr` располагается сертификат открытого ключа,
    записанныей в der-кодировке.
    Причина использования даной фукции заключается в раскодировании сертификатов,
    передаваемых в ходе выполнения криптографических протоколов, и считываемых, вместе с
    другими данными, в оперативную память.

    Поведение и возвращаетмые значения функции аналогичны поведению и возвращаемым
    значениям функции ak_verifykey_import_from_certificate().

    \param subject_cert контекст импортируемого сертификата открытого ключа
    асимметричного криптографического алгоритма,
    \param issuer_cert сертификат открытого ключа, с помощью которого можно проверить подпись под сертификатом;
    может принимать значение `NULL`
    \param указатель на область памяти, в которой распологается сертификат открытого ключа
    \param size размер сертификата (в октетах)

    \return Функция возвращает \ref ak_error_ok (ноль) в случае валидности созданноего
    ключа, иначе - возвращается код ошибки.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_import_from_ptr( ak_certificate subject_cert, ak_certificate issuer_cert,
                                                          const ak_pointer ptr, const size_t size )
{
  ak_asn1 root = NULL;
  int error = ak_error_ok;

 /* стандартные проверки */
  if( subject_cert == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                           "using null pointer to subject's certificate context" );
  if(( ptr == NULL ) || ( size == 0 ))
    return ak_error_message( ak_error_null_pointer, __func__,
                                       "using null pointer or zero length data with certificate" );

 /* считываем сертификат и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_decode( root = ak_asn1_new(), ptr, size, ak_false )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "incorrect decoding of ASN.1 context from data buffer");
    goto lab1;
  }

 /* собственно выполняем импорт данных */
  if(( error = ak_certificate_import_from_asn1( subject_cert, issuer_cert, root )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong import of public key from asn.1 context" );
  }

  lab1: if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает из репозитория сертификат открытого ключа. Сертификат разыскивается по
    серийному номеру, заданному в виде последовательности октетов
    (номер определяет запись сертификата в репозитории).
    После формирования имени файла, для чтения используется функция ak_certificate_impor_from_file().

    Так же, как и функция ak_certificate_impor_from_file(), эта
    функция является конструктором контекста `subject_cert`,
    в случае возникновения некритичных ошибок, создает контекст `subject_cert` и инициирует
    опции сертификата некоторыми значениями. Под некритичными понимаются ошибки
    интерпретирования данных, содержащихся в asn1 дереве (например, неподдерживаемые алгоритмы
    или значения). Критичными являются ошибки нарушения формата x509
    (формата представления данных).

    В случаях, когда ошибок импорта не возникает, создается контекст открытого ключа,
    поле `subject_cert->opts.created` устанавливается истинным (`ak_true`).
    Контекст должен позднее уничтожаться пользователем с помощью вызова ak_certificate_destroy().

    Сертификат, содержащий ключ проверки должен быть предварительно создан и передаваться с помощью
    указателя `issuer_cert` (если номер сертификата проверки подписи или расширенное имя владельца
    не совпадают с тем, что содержится в issuer_cert, то возбуждается ошибка).

    Если указатель `issuer_cert` равен `NULL`, то функция ищет сертифкат с соответствующим серийным
    номером в устанавливаемом библиотекой `libakrypt` каталоге; данный каталог указывается при сборке
    библотеки из исходных текстов в параметре `AK_CA_PATH`; для unix-like систем значением по
    умолчанию является каталог `\usr\share\ca-certificates\libakrypt`.

    \param subject_cert контекст импортируемого сертификата открытого ключа
    асимметричного криптографического алгоритма,
    \param issuer_cert сертификат открытого ключа, с помощью которого можно проверить подпись под сертификатом;
    может принимать значение `NULL`
    \param ptr последовательность октетов, определяющая серийный номер
    \param size размер последовательности (в октетах)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае валидности созданноего
    ключа, иначе - возвращается код ошибки.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_import_from_repository( ak_certificate subject_cert,
                                ak_certificate issuer_cert, const ak_uint8 *ptr, const size_t size )
{
    int error = ak_error_ok;
    char filename[FILENAME_MAX];

   /* входнфе данные */
    if( subject_cert == NULL )
      return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to subject certificate" );
   /* имя файла образуется из серийного номера сертификата */
    if(( error = ak_ceritifcate_generate_repository_name( filename,
                                                     FILENAME_MAX-1, ptr, size )) != ak_error_ok )
      return ak_error_message( error, __func__, "wrong creation of certificate name");

   /* считываем файл из сформированного имени */
 return ak_certificate_import_from_file( subject_cert, issuer_cert, filename );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Основная процедера разбора asn1 дерева.                                                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_import_from_asn1( ak_certificate subject_cert,
                                                         ak_certificate issuer_cert, ak_asn1 root )
{
  size_t size = 0;
  ak_tlv tbs = NULL;
  ak_asn1 lvs = NULL;
  struct bit_string bs;
  ak_uint8 buffer[4096];
  int error = ak_error_ok;
  time_t now = time( NULL );
  struct certificate_ptr vptr = {
   .subject = subject_cert,
   .issuer = issuer_cert,
  };
  memset( &vptr.real_issuer, 0, sizeof( struct certificate ));

 /* 1. проверяем устройство asn1 дерева */
  if( root->count != 1 )  {
    /* здесь мы проверяем, что это сертификат, а не коллекция сертификатов, т.е.
       asn1 дерево содержит только 1 элемент верхнего уровня */
    ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                         "unexpected count of top level elements (certificates)" );
    goto lab1;
  }
  if(( DATA_STRUCTURE( root->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( root->current->tag ) != TSEQUENCE )) {
   /* здесь мы проверили, что внутри находится sequence */
     ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__ ,
                      "unexpected type of certificate's container (tag: %x)", root->current->tag );
     goto lab1;
  } else lvs = root->current->data.constructed;

  if( lvs->count != 3 )  {
   /* здесь мы проверяем, что это последовательность из трех элементов
      - tbs
      - параметры подписи
      - собственно сама подпись */
    ak_error_message_fmt( error = ak_error_invalid_asn1_count, __func__,
                      "incorrect count of top level certificate elements (value: %u, must be: 3)",
                                                                       (unsigned int) lvs->count );
    goto lab1;
  }

 /* 2. считываем информацию о ключе из tbsCertificate */
  ak_asn1_first( lvs );
  tbs = lvs->current;
  if(( DATA_STRUCTURE( tbs->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( tbs->tag ) != TSEQUENCE )) {
   /* здесь мы проверили, что внутри находится sequence */
     ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__ ,
                  "unexpected type of TBSCertificate's container (tag: %x)", root->current->tag );
     goto lab1;
  }

 /* устанавливаем флаг, что ключ не создан, и переходим к его созданию
    после завершения функции могут быть варианты
     error  = ak_error_ok => можно проверять подпись
     error != ak_error_ok
        1. opts->created = true
        2. opts->created = false
        в обоих случаях проверка валидности сертификата не проводится. */
  vptr.subject->opts.created = ak_false;
  if(( error = ak_certificate_import_from_asn1_tbs( &vptr, tbs )) != ak_error_ok ) {
    if( vptr.subject->opts.created )
      ak_error_message( error, __func__, "incorrect validating of TBSCertificate's parameters");
     else ak_error_message( error, __func__ ,
                                         "incorrect decoding of TBSCertificate's asn1 container" );
     goto lab1;
  }
  if( !vptr.subject->opts.created ) {
    ak_error_message( error = ak_error_undefined_function, __func__ ,
                                           "incorrect import TBSCertificate from asn1 container" );
    goto lab1;
  }

 /* 3. проверяем валидность сертификата */
 /* 3.1 - наличие ключа проверки */
  if( vptr.issuer == NULL ) {
    ak_error_message( error = ak_error_certificate_verify_key, __func__,
                                   "using an undefined public key to verify a given certificate" );
    goto lab1;
  }
 /* 3.2 - проверяем срок действия сертификата */
  if(( vptr.subject->opts.time.not_before > now ) || ( vptr.subject->opts.time.not_after < now )) {
    ak_error_message( error = ak_error_certificate_validity, __func__,
             "the certificate has expired (the current time is not within the specified bounds)" );
    goto lab1;
  }

 /* 3.3 - теперь ничего не остается, как проверять подпись под сертификатом
    3.3.1 - начинаем с того, что готовим данные, под которыми должна быть проверена подпись */
  memset( buffer, 0, size = sizeof( buffer ));
  ak_asn1_first( lvs );
  if(( error = ak_tlv_encode( lvs->current, buffer, &size )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                 "incorrect encoding of tlv context contains of %u octets", (unsigned int) size );
    goto lab1;
  }

 /* 3.3.2 - теперь получаем значение подписи из asn1 дерева и сравниваем его с вычисленным значением */
  ak_asn1_last( lvs );
  if(( DATA_STRUCTURE( lvs->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( lvs->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( lvs->current, &bs )) != ak_error_ok ) {
    ak_error_message( error , __func__ , "incorrect value of bit string in root asn1 context" );
    goto lab1;
  }
 /* сохраняем данные для последующего вывода */
  memcpy( vptr.subject->opts.signature, bs.value,
                                          ak_min( bs.len, sizeof( vptr.subject->opts.signature )));

 /* 3.3.3  - только сейчас проверяем подпись под данными */
  if( ak_verifykey_verify_ptr( &vptr.issuer->vkey, buffer, size, bs.value ) != ak_true ) {
     ak_error_message( error = ak_error_not_equal_data, __func__, "digital signature isn't valid" );
     goto lab1;
  }

 /* 4. если открытый ключ проверки подписи был создан в ходе работы функции, его надо удалить */
  lab1:
   /* проверка, что ключ эмитента создавался в рамках данной функции */
    if( vptr.issuer == &vptr.real_issuer ) {
      ak_certificate_destroy( &vptr.real_issuer );
    }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция импортирует в секретный ключ значения, содержащиеся
    в последовательности TBSCerfificate                                                            */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_certificate_import_from_asn1_tbs( ak_certificate_ptr vptr, ak_tlv tbs )
{
  ak_asn1 sequence = NULL;
  int error = ak_error_ok;

 /* считываем основные поля сертификата, определеные для версий 1 или 2. */
  if(( error = ak_certificate_import_from_asn1_tbs_base( vptr,
                                            sequence = tbs->data.constructed )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "incorrect loading a base part of certificate" );
  }

 /* пропускаем поля второй версии и переходим к третьей версии, а именно, к расширениям.
    поля расширений должны нам разъяснить, является ли данный ключ самоподписанным или нет.
    если нет, и issuer_vkey не определен, то мы должны считать его с диска */
  ak_asn1_last( sequence );
  if( vptr->subject->opts.version != 2 ) return error; /* нам достался сертификат версии один или два */

 /* проверяем узел */
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     (( DATA_CLASS( sequence->current->tag )) != CONTEXT_SPECIFIC ) ||
     ( TAG_NUMBER( sequence->current->tag ) != 0x3 )) {
    return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
              "incorrect tag value for certificate extensions (tag: %x)", sequence->current->tag );
  }

 /* считываем доступные расширения сертификата */
  if(( error = ak_certificate_import_from_asn1_extension( vptr,
                                           sequence->current->data.constructed )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect loading a certificate's extensions" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_import_from_asn1_tbs_base( ak_certificate_ptr vptr, ak_asn1 sequence )
{
  size_t len;
  ak_pointer ptr = NULL;
  ak_tlv subject_name = NULL;
  time_t not_before, not_after;
  ak_oid algoid = NULL, paroid = NULL;
  int error = ak_error_ok, yaerror = ak_error_ok;

 /* 1. получаем версию сертификата */
  ak_asn1_first( sequence );
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( DATA_CLASS( sequence->current->tag ) != ( CONTEXT_SPECIFIC^0x00 ))) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__,
               "incorrect tag value for certificate's version (tag: %x)", sequence->current->tag );
    goto lab1;
  }
   else
    if(( error = ak_tlv_get_uint32( sequence->current->data.constructed->current,
                                                &vptr->subject->opts.version )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect reading of certificate's version" );
      goto lab1;
    }

 /* 2. определяем серийный номер сертификата (вырабатывается при подписи сертификата)
       и помещаем его в структуру с опциями */
  ak_asn1_next( sequence );
  if(( DATA_STRUCTURE( sequence->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TINTEGER )) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__,
         "incorrect tag value for certificate's serial number (tag: %x)", sequence->current->tag );
    goto lab1;
  }

  len = vptr->subject->opts.serialnum_length;
  if(( ak_tlv_get_octet_string( sequence->current,
                                               &ptr, &len ) != ak_error_ok ) || ( ptr == NULL )) {
    ak_error_message( error, __func__, "incorrect reading of certificate's serial number" );
    goto lab1;
  } else {
      memset( vptr->subject->opts.serialnum, 0, sizeof( vptr->subject->opts.serialnum ));
      memcpy( vptr->subject->opts.serialnum, ptr, vptr->subject->opts.serialnum_length =
                                            ak_min( len, sizeof( vptr->subject->opts.serialnum )));
    }

 /* 3. Получаем алгоритм подписи (oid секретного ключа) */
  ak_asn1_next( sequence );
  if(( error = ak_tlv_get_algorithm_identifier( sequence->current,
                                                            &algoid, &paroid )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect reading of signature algorithm identifier" );
    goto lab1;
  }

 /* если разбирается сертификат с неподдерживаемым алгоритмом,
    то в данном месте возникнет ошибка, но выполнение функции продолжится */
  if( algoid->engine != sign_function ) {
    ak_error_message( error = ak_error_oid_engine, __func__,
                   "the certificate has incorrect or unsupported signature algorithm identifier" );
  }

 /* 4. Получаем имя эмитента (лица подписавшего сертификат)
       и сравниваем с тем, что у нас есть (если сертификат был создан ранее)
       иначе просто присваиваем имя в контекст */
  ak_asn1_next( sequence );
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__,
                    "unexpected tag value for generalized name of certificate's issuer (tag: %x)",
                                                                          sequence->current->tag );
    goto lab1;
  }
  if( vptr->issuer != NULL ) { /* в функцию передан созданный ранее открытый ключ проверки подписи,
                                  поэтому мы должны проверить совпадение имен, т.е. то,
                                  что переданный ключ совпадает с тем, что был использован
                                                                           при подписи сертификата */
    if( ak_tlv_compare_global_names( sequence->current,
                                                   vptr->issuer->opts.subject ) != ak_error_ok ) {
      error = ak_error_certificate_verify_names;
      goto lab1;
    }
  }
  vptr->subject->opts.issuer = ak_tlv_duplicate_global_name( sequence->current );

 /* 5. Получаем интервал времени действия */
  ak_asn1_next( sequence );
  if(( yaerror = ak_tlv_get_validity( sequence->current,
                                         &not_before, &not_after )) != ak_error_ok ) {
    ak_error_message( error = yaerror, __func__,
                                          "incorrect reading a validity value from asn1 context" );
    goto lab1;
  }

 /* 6. Получаем имя владельца импортируемого ключа */
  ak_asn1_next( sequence );
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__,
                   "unexpected tag value for generalized name of certificate's subject (tag: %x)",
                                                                          sequence->current->tag );
    goto lab1;
  }
  subject_name = ak_tlv_duplicate_global_name( sequence->current );

 /* ожидаем наличие поля, содержащего значение открытого ключа */
  if( ak_asn1_next( sequence ) != ak_true ) {
    ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                                                   "unexpected end of asn1 tree" );
    goto lab1;
  }

 /* если мы добрались, значит формат верный и мы, скорее всего, разбираем именно сертификат
    установленный код ошибки говорит о том, что мы разбираем сертификат с
    неподдерживаемыми алгортмами, такой ключ создается только для хранения считанных данных */
  if( error != ak_error_ok ) {
    if( ak_verifykey_create_streebog256( &vptr->subject->vkey ) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect creation of public key context" );
      goto lab1;
    }
   /* изменяем значения, которые будут использованы при выводе сертификата */
    vptr->subject->vkey.oid = algoid;
    vptr->subject->vkey.wc = NULL;
  }
   else { /* только здесь мы считываем значение открытого ключа и помещаем его в контекст */
    /* проверяем наличие последовательности верхнего уровня */
     if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
        ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE )) {
        ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                      "the element of root asn1 tree must be a sequence with object identifiers" );
        goto lab1;
     }
     if(( error = ak_verifykey_import_from_asn1_value( &vptr->subject->vkey,
                                         sequence->current->data.constructed )) != ak_error_ok ) {
       ak_error_message( error, __func__, "incorrect import of public key value" );
       goto lab1;
     }
  }

 /* присваиваем значения полей */
  vptr->subject->opts.subject = subject_name;
  vptr->subject->opts.time.not_after = not_after;
  vptr->subject->opts.time.not_before = not_before;
  vptr->subject->opts.created = ak_true;

  lab1:
    if( !vptr->subject->opts.created ) {
      if( vptr->subject != NULL ) ak_tlv_delete( subject_name );
    }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_import_from_asn1_extension( ak_certificate_ptr vptr, ak_asn1 sequence )
{
  size_t size = 0;
  ak_oid oid = NULL;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                              "incorrect asn1 tree for certificate's extensions" );
    else ak_asn1_first( sequence = sequence->current->data.constructed ); /* все расширения здесь */
  if( sequence->count == 0 ) goto lab1;

 /* -- часть кода, отвечающая за разбор расширений сертификата */
  do{
    ak_asn1 ext = NULL, vasn = NULL;
    if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
                                   ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE )) continue;

    ak_asn1_first( ext = sequence->current->data.constructed ); /* текущее расширение */
    if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
                          ( TAG_NUMBER( ext->current->tag ) != TOBJECT_IDENTIFIER )) continue;
    if( ak_tlv_get_oid( ext->current, &ptr ) != ak_error_ok ) continue;
    if(( oid = ak_oid_find_by_id( ptr )) == NULL ) continue;
    ak_asn1_last( ext ); /* перемещаемся к данным */

   /* теперь мы разбираем поступившие расширения */
   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "1.2.643.2.52.1.98.1" ) == 0 ) {
                 /* это SecretKeyNumber, т.е. номер секретного ключа, соотвествующего открытому */
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
                          ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;
      vptr->subject->opts.ext_secret_key_number.is_present = ak_true;

     /* декодируем номер ключа */
      ak_tlv_get_octet_string( ext->current, &ptr, &size );
      memcpy( vptr->subject->opts.ext_secret_key_number.number, ((ak_uint8 *)ptr)+2,
                    ak_min( size-2, sizeof( vptr->subject->opts.ext_secret_key_number.number )));
    }

   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "2.5.29.14" ) == 0 ) { /* это subjectKeyIdentifier,
                                                        т.е. номер считываемого открытого ключа */
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
                          ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;
      vptr->subject->opts.ext_subjkey.is_present = ak_true;

     /* декодируем номер ключа */
      ak_tlv_get_octet_string( ext->current, &ptr, &size );
      memcpy( vptr->subject->vkey.number, ((ak_uint8 *)ptr)+2,
       vptr->subject->vkey.number_length = ak_min( size-2, sizeof( vptr->subject->vkey.number )));
    }

   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "2.5.29.19" ) == 0 ) { /* это basicConstraints
                                                        т.е. принадлежность центрам сертификации */
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
                          ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;
      vptr->subject->opts.ext_ca.is_present = ak_true;
      ak_tlv_get_octet_string( ext->current, &ptr, &size );

     /* теперь разбираем поля */
      if( ak_asn1_decode( vasn = ak_asn1_new(), ptr, size, ak_false ) == ak_error_ok ) {

        if(( DATA_STRUCTURE( vasn->current->tag ) == CONSTRUCTED ) ||
           ( TAG_NUMBER( vasn->current->tag ) != TSEQUENCE )) {
           ak_asn1 vasn2 = vasn->current->data.constructed;

           if( vasn2->current != NULL ) {
             ak_asn1_first( vasn2 );
             if(( DATA_STRUCTURE( vasn2->current->tag ) == PRIMITIVE ) &&
                ( TAG_NUMBER( vasn2->current->tag ) == TBOOLEAN )) {
                  ak_tlv_get_bool( vasn2->current, &vptr->subject->opts.ext_ca.value );
             }
             ak_asn1_last( vasn2 );
             if(( DATA_STRUCTURE( vasn2->current->tag ) == PRIMITIVE ) &&
                ( TAG_NUMBER( vasn2->current->tag ) == TINTEGER )) {
                ak_tlv_get_uint32( vasn2->current, &vptr->subject->opts.ext_ca.pathlenConstraint );
             }
           }
        }
      }
      if( vasn ) ak_asn1_delete( vasn );
    }

   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "2.5.29.15" ) == 0 ) { /* это keyUsage
                                                        т.е. область применения сертификата */
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
         ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;
      vptr->subject->opts.ext_key_usage.is_present = ak_true;

     /* декодируем битовую последовательность */
      ak_tlv_get_octet_string( ext->current, &ptr, &size );
      if( ak_asn1_decode( vasn = ak_asn1_new(), ptr, size, ak_false ) == ak_error_ok ) {
        if(( DATA_STRUCTURE( vasn->current->tag ) == PRIMITIVE ) &&
           ( TAG_NUMBER( vasn->current->tag ) == TBIT_STRING )) {

          struct bit_string bs;
          ak_tlv_get_bit_string( vasn->current, &bs );
          vptr->subject->opts.ext_key_usage.bits = bs.value[0]; /* TODO: это фрагмент необходимо оттестировать */
          vptr->subject->opts.ext_key_usage.bits <<= 1;
          if( bs.len > 1 ) {
            vptr->subject->opts.ext_key_usage.bits <<= 8-bs.unused;
            vptr->subject->opts.ext_key_usage.bits ^= bs.value[1];
          }
        }
      }
       else vptr->subject->opts.ext_key_usage.bits = 0;
      if( vasn ) ak_asn1_delete( vasn );
    }

   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "2.5.29.35" ) == 0 ) { /* это authorityKeyIdentifier
                                                                  т.е. номера ключа проверки */
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
         ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;
      ak_tlv_get_octet_string( ext->current, &ptr, &size );
      if( ak_asn1_decode( vasn = ak_asn1_new(), ptr, size, ak_false ) == ak_error_ok ) {

     /* здесь мы должны иметь последовательность, примерно, такого вида

        └SEQUENCE┐
                 ├[0] 8b983b891851e8ef9c0278b8eac8d420b255c95d
                 ├[1]┐
                 │   └[4]┐
                 │       └SEQUENCE┐
                 │                ├SET┐
                 │                │   └SEQUENCE┐
                 │                │            ├OBJECT IDENTIFIER 1.2.840.113549.1.9.1 (email-address)
                 │                │            └IA5 STRING dit@minsvyaz.ru
                 └[2] 34681e40cb41ef33a9a0b7c876929a29

        где
          - [0] - номер открытого ключа, используемого для проверки подписи
                  (в openssl для самоподписанных сертификатов совпадает с SubjectKeyIdentifer)
                  (у нас это vkey->number)
          - [1] - расширенное имя владельца
          - [2] - номер сертификата открытого ключа, используемого для проверки подписи

        может быть конечно не у всех, например, у корневого сертификата ГУЦ нет этого расширения
        (для CA это допускается в RFC)                                                           */

        ak_asn1 lasn = NULL;
        if(( DATA_STRUCTURE( vasn->current->tag ) != CONSTRUCTED ) ||
           ( TAG_NUMBER( vasn->current->tag ) != TSEQUENCE )) {
           ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                    "incorrect asn1 tree for authorithyKeyIdentifier extension" );
           goto labstop;
        }

        lasn = vasn->current->data.constructed;
        vptr->subject->opts.ext_authoritykey.is_present = ak_true;

        ak_asn1_first( lasn );
        do{
         if(( DATA_STRUCTURE( lasn->current->tag ) == CONSTRUCTED ) ||
            (( DATA_CLASS( lasn->current->tag )) == CONTEXT_SPECIFIC )) {
            switch( TAG_NUMBER( lasn->current->tag )) {
              case 0x00:
               /* сохраняем номер ключа эмитента */
                vptr->subject->opts.issuer_number_length = ak_min( lasn->current->len ,
                                                      sizeof( vptr->subject->opts.issuer_number ));
                memcpy( vptr->subject->opts.issuer_number, lasn->current->data.primitive,
                                                        vptr->subject->opts.issuer_number_length );
                if( vptr->issuer == NULL ) {
               /* в данной ситуации ключ проверки подписи не известен.
                  поскольку мы можем считывать из файла и искать в хранилище только ключи по серийным номерам,
                  то использовать данный номер мы можем только для проверки того, что сертификат
                  является самоподписанным  т.е. subject_key.number =?  lasn->current->data.primitive */
                 if( memcmp( lasn->current->data.primitive, vptr->subject->vkey.number,
                                               vptr->subject->opts.issuer_number_length ) == 0 ) {
                   vptr->issuer = vptr->subject; /* ключ проверки совпадает с ключом в сертификате */
                 }
                 /* поиск, на всякий "пожарный" случай
                   ak_verifykey_import_from_repository( issuer_vkey,
                                               lasn->current->data.primitive, lasn->current->len ); */
                }
                break;

              case 0x01:
                break;

              case 0x02: /* поиск сертификата по его серийному номеру */
               /* сохраняем серийный номер ключа эмитента */
                vptr->subject->opts.issuer_serialnum_length = ak_min( lasn->current->len ,
                                                   sizeof( vptr->subject->opts.issuer_serialnum ));
                memcpy( vptr->subject->opts.issuer_serialnum, lasn->current->data.primitive,
                                                     vptr->subject->opts.issuer_serialnum_length );
               /* пытаемся считать ключ проверки из хранилища сертификатов */
                if( vptr->issuer == NULL ) {
                  char fileca[FILENAME_MAX];

                  ak_snprintf( fileca, sizeof( fileca ), "%s/%s.cer", ca_repository_path,
                    ak_ptr_to_hexstr( vptr->subject->opts.issuer_serialnum,
                                 vptr->subject->opts.issuer_serialnum_length, ak_false ), ".cer" );

                  ak_certificate_opts_create( &vptr->real_issuer.opts );
                  if( ak_certificate_import_from_file( &vptr->real_issuer,
                                                                 NULL, fileca ) != ak_error_ok ) {
                    ak_certificate_destroy( &vptr->real_issuer );
                  }
                   else { /* нам сопутствовала удача и сертификат успешно считан */
                     vptr->issuer = &vptr->real_issuer;
                   }
                }
                break;

              default:
                break;
            }
         }
        } while( ak_asn1_next( lasn ));
        labstop:;

      }
      if( vasn ) ak_asn1_delete( vasn );
    }

   /* ----------------------------------------------------------------------------------------- */
   } while( ak_asn1_next( sequence )); /* конец цикла перебора расширений */

  /* для самоподписанных сертификатов может быть не установлено расширение 2.5.29.35,
     в этом случае, все-равно необходимо попробовать проверить подпись. */
  if(( vptr->issuer == NULL ) && ( vptr->subject->opts.created )) {
    if( vptr->subject->opts.ext_ca.is_present ) /* считанный сертификат является CA,
          следовательно он может подписывать сертификаты и, в частности, самого себя  */
      vptr->issuer = vptr->subject; /* теперь ключ проверки совпадает с ключом в сертификате */
  }

 lab1:
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*            Фукции для работы с репозиторием (хранилищем) доверенных сертификатов                */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Устанавливаемый каталог используется функциями импорта сертификатов для поиска
    доверенных сертификатов.
    \param path Существующий каталог
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_set_repository( const char *path )
{
  char str[FILENAME_MAX];

  if( path == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to CA repository's path" );
 /* обрабатываем символ ~ в начале строки */
  if( strchr( path, '~' ) == path ) {
    char home[FILENAME_MAX];
    ak_homepath( home, sizeof( home ));
    ak_snprintf( str, sizeof( str ), "%s%s", home, ++path );
  }
   else memcpy( str, path, strlen( path ));

 /* проверяем существование заказанного каталога */
  if( ak_file_or_directory( str ) != DT_DIR )
    return ak_error_message_fmt( ak_error_not_directory,
                                                       __func__,  "directory %s not exists", str );
  memset( ca_repository_path, 0, sizeof( ca_repository_path ));
  strncpy( ca_repository_path, str, sizeof( ca_repository_path ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \return Возвращается указатель на константную область памяти.                                  */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_certificate_get_repository( void )
{
  return ca_repository_path;
}

/* ----------------------------------------------------------------------------------------------- */
                        /* Функции проверки содержимого asn1 дерева */
/* ----------------------------------------------------------------------------------------------- */
/*! Поскольку формат запроса не предусматривает наличие
    какого-либо фиксированого идентификатора, то проверяется, что поданное на вход дерево
    состоит из одного элемента sequence, содержащего в точности три элемента.

    \param root asn1 дерево, содержащее запрос на сертификат
    \return В случае успешного выполнения всех проверок, возвращается истина.                      */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_is_request( ak_asn1 root )
{
  ak_tlv tlv = NULL;
  ak_asn1 asn = NULL;

  if( root == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 context" );
    return ak_false;
  }

 /* проверяем, что данные содержат хоть какое-то значение */
  if(( root->count != 1 ) || ( root->current == NULL )) {
    ak_error_message_fmt( ak_error_invalid_value, __func__, "asn1 context does not contain data" );
    return ak_false;
  }

 /* здесь мы считали asn1, декодировали и должны убедиться, что это то самое дерево */
  ak_asn1_first( root );
  tlv = root->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) || ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                             "unexpected tag (%u) instead of sequence", tlv->tag );
    return ak_false;
  }

 /* проверяем количество узлов */
  if(( asn = tlv->data.constructed )->count != 3 ) {
    ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                          "root asn1 context contains incorrect count of leaves" );
    return ak_false;
  }

 /* проверяем, что первый узел sequence */
  ak_asn1_first( asn );
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) || ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                             "unexpected tag (%u) instead of sequence", tlv->tag );
    return ak_false;
  }

  if( tlv->data.constructed->count == 0 ) {
    ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                "subsecuence of asn1 context contains incorrect count of leaves" );
    return ak_false;
  }

  ak_asn1_first( tlv->data.constructed ); /* различие, межу запросом и сертификатом, */
  tlv = tlv->data.constructed->current;   /*                проявляется только здесь */
  if(( DATA_STRUCTURE( tlv->tag ) != PRIMITIVE ) || ( TAG_NUMBER( tlv->tag ) != TINTEGER )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                             "unexpected tag (%u) instead of sequence", tlv->tag );
    return ak_false;
  }

 /* проверяем, что последний узел - строка бит */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                  "unexpected tag (%u) instead of bit string", asn->current->tag );
    return ak_false;
  }

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Поскольку формат сертификата не предусматривает наличие
    какого-либо фиксированого идентификатора, то проверяется, что поданное на вход дерево
    состоит из одного элемента sequence, содержащего в точности три элемента.

    \param root asn1 дерево, содержащее запрос на сертификат
    \return В случае успешного выполнения всех проверок, возвращается истина.                      */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_is_certificate( ak_asn1 root )
{
  ak_tlv tlv = NULL;
  ak_asn1 asn = NULL;

  if( root == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 context" );
    return ak_false;
  }

 /* проверяем, что данные содержат хоть какое-то значение */
  if(( root->count != 1 ) || ( root->current == NULL )) {
    ak_error_message_fmt( ak_error_invalid_value, __func__, "asn1 context does not contain data" );
    return ak_false;
  }

 /* здесь мы считали asn1, декодировали и должны убедиться, что это то самое дерево */
  ak_asn1_first( root );
  tlv = root->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) || ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                             "unexpected tag (%u) instead of sequence", tlv->tag );
    return ak_false;
  }

 /* проверяем количество узлов */
  if(( asn = tlv->data.constructed )->count != 3 ) {
    ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                          "root asn1 context contains incorrect count of leaves" );
    return ak_false;
  }

 /* проверяем, что первый узел sequence */
  ak_asn1_first( asn );
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) || ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                             "unexpected tag (%u) instead of sequence", tlv->tag );
    return ak_false;
  }

  if( tlv->data.constructed->count == 0 ) {
    ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                "subsecuence of asn1 context contains incorrect count of leaves" );
    return ak_false;
  }

  ak_asn1_first( tlv->data.constructed ); /* различие, межу запросом и сертификатом, */
  tlv = tlv->data.constructed->current;   /*                проявляется только здесь */
 /* проверяем поле [0] */
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) ||
     (( DATA_CLASS( tlv->tag )) != CONTEXT_SPECIFIC ) ||
     ( TAG_NUMBER( tlv->tag ) != 0x00 )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                             "incorrect tag value for certificate tbs field (tag: %x)", tlv->tag );
    return ak_false;
  }

 /* проверяем, что последний узел - строка бит */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                  "unexpected tag (%u) instead of bit string", asn->current->tag );
    return ak_false;
  }

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция понимает частный случай формата CMS, а именно структуру,
    хранящую список сертификатов согласно RFC 5652.
    Поданное на вход функции дерево должно иметь следующую структуру.

\code
┌SEQUENCE┐
         ├OBJECT IDENTIFIER 1.2.840.113549.1.7.2 (cms-signed-data-content-type)
         └[0]┐
             └SEQUENCE┐
                      ├INTEGER 0x1
                      ├SET┐
                      │    (null)
                      ├SEQUENCE┐
                      │        └OBJECT IDENTIFIER 1.2.840.113549.1.7.1 (cms-data-content-type)
                      ├[0]┐

\endcode
    После [0] должна идти последовательность сертификатов (как элементов одного уровня asn1 дерева).

    \param root asn1 дерево, содержащее p7b контейнер сертификатов
    \return В случае успешного выполнения всех проверок, возвращается истина.                      */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_is_p7b_container( ak_asn1 root )
{
  if( root == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 context" );
    return ak_false;
  }

  if( ak_certificate_get_sequence_from_p7b_asn1( root ) != NULL ) return ak_true;

 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                Функции доступа к p7b контейнерам                                */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция выполняет "грязную" работу и проверяет поля p7b контейнера.
    Поданное на вход функции дерево должно иметь следующую структуру.

\code
┌SEQUENCE┐
         ├OBJECT IDENTIFIER 1.2.840.113549.1.7.2 (cms-signed-data-content-type)
         └[0]┐
             └SEQUENCE┐
                      ├INTEGER 0x1
                      ├SET┐
                      │    (null)
                      ├SEQUENCE┐
                      │        └OBJECT IDENTIFIER 1.2.840.113549.1.7.1 (cms-data-content-type)
                      ├[0]┐

\endcode
    После [0] должна идти последовательность сертификатов (как элементов одного уровня asn1 дерева).

    \param root asn1 дерево, содержащее p7b-контейнер
    \return В случае успешной проверки, функция возвращается указатель на уровень asn1 дерева,
    содержащий последовательность сертификатов.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_asn1 ak_certificate_get_sequence_from_p7b_asn1( ak_asn1 root )
{
  ak_uint32 value;
  ak_oid oid = NULL;
  ak_tlv tlv = NULL;
  ak_asn1 asn = NULL;
  ak_pointer ptr = NULL;

  if( root == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to p7b asn1 tree" );
    return NULL;
  }

 /* проверяем, что данные содержат хоть какое-то значение */
  if(( root->count != 1 ) || ( root->current == NULL )) {
    ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                                       "root asn1 context does not contain data" );
    return NULL;
  }

 /* здесь мы считали asn1, декодировали и должны убедиться, что это то самое дерево */
  ak_asn1_first( root );
  tlv = root->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) || ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                             "unexpected tag (%u) instead of sequence", tlv->tag );
    return NULL;
  }

  asn = tlv->data.constructed;
  if(( asn->count != 2 ) || ( asn->current == NULL )) {
    ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                              "asn1 context does not contain two fixed elements" );
    return NULL;
  }

 /* получаем идентификатор cms контейнера */
  ak_asn1_first( asn );
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( tlv->tag ) != TOBJECT_IDENTIFIER )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                    "unexpected tag (%u) instead of object identifier", tlv->tag );
    return NULL;
  }
  ak_tlv_get_oid( tlv, &ptr );
  if(( oid = ak_oid_find_by_id( ptr )) == NULL ) {
    ak_error_message_fmt( ak_error_null_pointer, __func__,
                                                   "using unsupported object identifier %s", ptr );
    return NULL;
  }
  if( strncmp( oid->id[0], "1.2.840.113549.1.7.2", strlen( oid->id[0] )) != 0 ) {
    ak_error_message( ak_error_oid_id, __func__, "using wrong object identifier" );
    return NULL;
  }

 /* проверяем поле [0] */
  ak_asn1_next( asn );
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) ||
     (( DATA_CLASS( tlv->tag )) != CONTEXT_SPECIFIC ) ||
     ( TAG_NUMBER( tlv->tag ) != 0x00 )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                              "incorrect tag value for p7b container header (tag: %x)", tlv->tag );
    return NULL;
  }

 /* спускаемся ниже */
  asn = tlv->data.constructed;
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) || ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                             "unexpected tag (%u) instead of sequence", tlv->tag );
    return NULL;
  }
  asn = tlv->data.constructed;

 /* теперь мы внизу и имеем такое дерево

  ├INTEGER 0x1
  ├SET┐
  │    (null)
  ├SEQUENCE┐
  │        └OBJECT IDENTIFIER 1.2.840.113549.1.7.1 (cms-data-content-type)
  ├[0]┐

  где после [0] идет последовательность сертификатов */

  ak_asn1_first( asn );
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != PRIMITIVE ) || ( TAG_NUMBER( tlv->tag ) != TINTEGER )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                              "unexpected tag (%u) instead of integer", tlv->tag );
    return NULL;
  }
  ak_tlv_get_uint32( tlv, &value );
  if( value != 1 ) {
    ak_error_message_fmt( ak_error_invalid_asn1_content, __func__,
                                                           "unexpected version of p7b container" );
    return NULL;
  }

 /* 2 */
  ak_asn1_next( asn );
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) || ( TAG_NUMBER( tlv->tag ) != TSET )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                                  "unexpected tag (%u) instead of set", tlv->tag );
    return NULL;
  }

 /* 3 */
  ak_asn1_next( asn );
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) || ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                    "unexpected tag (%u) instead of object identifier", tlv->tag );
    return NULL;
  }
  if( tlv->data.constructed != NULL ) {
    tlv = ( tlv->data.constructed )->current;

    if(( DATA_STRUCTURE( tlv->tag ) != PRIMITIVE ) ||
       ( TAG_NUMBER( tlv->tag ) != TOBJECT_IDENTIFIER )) {
      ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                    "unexpected tag (%u) instead of object identifier", tlv->tag );
      return NULL;
    }
    ak_tlv_get_oid( tlv, &ptr );
    if(( oid = ak_oid_find_by_id( ptr )) == NULL ) {
      ak_error_message_fmt( ak_error_oid_id, __func__,
                                                   "using unsupported object identifier %s", ptr );
      return NULL;
    }
    if( strncmp( oid->id[0], "1.2.840.113549.1.7.1", strlen( oid->id[0] )) != 0 ) {
      ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );
      return NULL;
    }
  } else {
      ak_error_message( ak_error_null_pointer, __func__, "null pointer to internal sequence" );
      return NULL;
    }

 /* 4 */
  ak_asn1_next( asn );
  tlv = asn->current;
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) ||
     (( DATA_CLASS( tlv->tag )) != CONTEXT_SPECIFIC ) ||
     ( TAG_NUMBER( tlv->tag ) != 0x00 )) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                "incorrect tag value for p7b container data (tag: %x)", tlv->tag );
    return NULL;
  }

 return tlv->data.constructed;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_asn1 ak_certificate_get_sequence_from_p7b_container( const char *filename )
{
  int error = ak_error_ok;
  ak_asn1 root = NULL, seq = NULL;

  if( filename == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );
    return NULL;
  }

 /* считываем ключ и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_import_from_file( root = ak_asn1_new(), filename, NULL )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
    goto lab1;
  }

 /* получаем asn1 последовательность сертификатов */
  if(( seq = ak_certificate_get_sequence_from_p7b_asn1( root )) == NULL ) {
    ak_error_message( error, __func__,
                                 "given asn1 context has not a correct sequence of certificates" );
    goto lab1;
  }

 lab1:
  if( root != NULL ) ak_asn1_delete( root );

 return seq;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param sequence указатель, в который помещается ссылка нас прелполагаемый список сертификатов
    \return В случае успеха возвращается указатель на вершину созданного asn1 дерева.              */
/* ----------------------------------------------------------------------------------------------- */
 ak_asn1 ak_certificate_new_p7b_skeleton( ak_asn1 *sequence )
{
  ak_tlv tlv = NULL;
  int error = ak_error_ok;
  ak_asn1 root = ak_asn1_new(), asn = NULL;

   if(( error = ak_asn1_add_tlv( root, tlv = ak_tlv_new_sequence( ))) != ak_error_ok ) goto labex;
   asn = tlv->data.constructed;

   if(( error = ak_asn1_add_oid( asn, "1.2.840.113549.1.7.2" )) != ak_error_ok ) goto labex;
   if(( error = ak_asn1_add_asn1( asn, CONTEXT_SPECIFIC^0x00,
                                                      ak_asn1_new( ))) != ak_error_ok ) goto labex;
   asn = asn->current->data.constructed;

   if(( error = ak_asn1_add_tlv( asn, tlv = ak_tlv_new_sequence( ))) != ak_error_ok ) goto labex;
   asn = tlv->data.constructed;

   if(( error = ak_asn1_add_uint32( asn, 1 )) != ak_error_ok ) goto labex;
   if(( error = ak_asn1_add_tlv( asn, ak_tlv_new_constructed( TSET,
                                                     ak_asn1_new( )))) != ak_error_ok ) goto labex;
   if(( error = ak_asn1_add_tlv( asn, tlv = ak_tlv_new_sequence( ))) != ak_error_ok ) goto labex;
   if(( error = ak_asn1_add_oid( tlv->data.constructed,
                                             "1.2.840.113549.1.7.1" )) != ak_error_ok ) goto labex;
   if(( error = ak_asn1_add_asn1( asn, CONTEXT_SPECIFIC^0x00,
                                                     ak_asn1_new( ))) != ak_error_ok ) goto labex;
   if( sequence != NULL ) *sequence = asn->current->data.constructed;

   error = ak_asn1_add_tlv( asn, ak_tlv_new_constructed( TSET, ak_asn1_new( )));

   labex:
     if( error != ak_error_ok ) root = ak_asn1_delete( root );
 return root;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_cert.c  */
/* ----------------------------------------------------------------------------------------------- */
