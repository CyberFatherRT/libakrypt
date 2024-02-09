/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_asn1_keys.c                                                                            */
/*  - содержит реализацию функций, предназначенных для экспорта/импорта секретной                  */
/*    ключевой информации                                                                          */
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
/* устанавливаем начальные значения для глобавальных переменных */
 ak_function_password_read *ak_function_default_password_read = ak_password_read_from_terminal;
 char *ak_default_password_prompt = "password: ";
 password_t ak_default_password_interpretation = symbolic_pass;

/* ----------------------------------------------------------------------------------------------- */
/*! \note Функция экспортируется.
    \param function Обработчик операции чтения пароля.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_password_read_function( ak_function_password_read *function )
{
  if( function == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to password read function" );
  ak_function_default_password_read = function;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \note Функция экспортируется.
    \param prompt Константная строка, которая выводит перед запросом пароля
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_password_read_prompt( const char *prompt )
{
  if( prompt == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to password prompt value" );
  ak_default_password_prompt = (char *) prompt;
 return ak_error_ok;

}

/* ----------------------------------------------------------------------------------------------- */
/*! \note Функция экспортируется.
    \param method Элемент перечисления, указывающий способ интерпретации вводимых данных.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_password_read_method( password_t method )
{
  ak_default_password_interpretation = method;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция расширяет возможности функции ak_password_read() следующим образом:

    - функция выводит приглашение для ввода пароля,
    - функция позволяет вводить данные в шестнадцатеричном формате.

    \param prompt Приглашение, печатаемое перед вводом пароля
    \param password Указатель на область памяти, в которую помещается пароль.
    Если даные вводятся в символьном формате (hex = ak_false), то последний введенный символ
    полагается равным нулю, так что позднее, размер введенного пароля также может быть определен
    с помощью функции strlen().

    \param pass_size Размер массива, для хранения введенных данных.
    \param hex Флаг того, вводятся ли даные в символьном (hex = ak_false) или
    шестнадцатеричном формате (hex = ak_true ).

    @return В случае успеха функция возвращает количество считанных символов.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_password_read_from_terminal( const char *prompt, char *password,
                                                           const size_t pass_size, password_t hex )
{
   char buffer[256];
   struct random generator;
   ssize_t error = ak_error_ok;

   fprintf( stdout, "%s", prompt ); fflush( stdout );
   if( hex == hexademal_pass ) {
     size_t length = ak_password_read( buffer, sizeof( buffer )); /* мы считали максимум 255 символов
                                                                            + замыкающий ноль */
     if(( length > 0 ) && ( strlen( buffer ) == (size_t)length )) { /* ошибки нет,
                                                                        можно преобразовывать */
       if(( error = ak_hexstr_to_ptr( buffer, password, pass_size, ak_false )) == ak_error_ok ) {
        /* получаем длину преобразованных данных */
         if( length&1 ) length++;
         error = ( length >>= 1 );
        /* здесь мы, фактически, хотим почистить стек процесса */
         ak_random_create_lcg( &generator );
         ak_ptr_wipe( buffer, sizeof( buffer ), &generator );
         ak_random_destroy( &generator );
       }
     }
      else error = length;
   }
    else error = ak_password_read( password, pass_size );
  fprintf( stdout, "\n" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                  /* Функции выработки и сохранения производных ключей */
/* ----------------------------------------------------------------------------------------------- */
/*! Для выработки ключей `eKey` и `iKey` используется алгоритм PBKDF2, реализуемый при
    помощи функции хеширования Стрибог512 (см. Р 50.1.111-2016), т.е.
    \code
     eKey || iKey = PBKDF2( password, salt, iter, 64 )
    \endcode

    \param ekey контекст создаваемого ключа шифрования
    \param ikey контекст создаваемого ключа имитозащиты
    \param oid идентификатор алгоритма блочного шифрования, для которого создается ключевая пара
    \param password пароль
    \param pass_size длина пароля (в октетах)
    \param salt последовательность случайных чисел
    \param salt_size длина последовательности случайных чисел (в октетах)
    \param iter количество итераций алгоритма pbkdf2
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create_key_pair_from_password( ak_bckey ekey, ak_bckey ikey, ak_oid oid,
                                      const char *password, const size_t pass_size,
                                        ak_uint8 *salt, const size_t salt_size, const size_t iter )
{
  int error = ak_error_ok;
  ak_uint8 derived_key[64]; /* вырабатываемый из пароля ключевой материал,
                               из которого формируются производные ключи шифрования и имитозащиты */

  if( salt == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null pointer to salt value");
  if( !salt_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                             "using zero length for salt buffer" );

  /* 1. вырабатываем случайное значение и производный ключевой материал */
   if(( error = ak_hmac_pbkdf2_streebog512(
                (ak_pointer) password,                      /* пароль */
                 pass_size,                          /* размер пароля */
                 salt,                    /* инициализационный вектор */
                 sizeof( salt ), /* размер инициализационного вектора */
                 iter,               /* количество итераций алгоритма */
                 64,                  /* размер вырабатываемого ключа */
                 derived_key            /* массив для хранения данных */
     )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect creation of derived key" );

 /* 2. инициализируем контексты ключа шифрования контента и ключа имитозащиты */
   if(( error = ak_bckey_create_oid( ekey, oid )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of encryption cipher key" );
   if(( error = ak_bckey_set_key( ekey, derived_key, 32 )) != ak_error_ok ) {
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to encryption key" );
   }
   if(( error = ak_bckey_create_oid( ikey, oid )) != ak_error_ok ) {
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect creation of integrity key" );
   }
   if(( error = ak_bckey_set_key( ikey, derived_key+32, 32 )) != ak_error_ok ) {
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to integrity key" );
   }
  /* очищаем использованную память */
   ak_ptr_wipe( derived_key, sizeof( derived_key ), &ikey->key.generator );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вырабатывает производные ключи шифрования и имитозащиты контента из пароля и
    экспортирует в ASN.1 дерево параметры ключа, необходимые для восстановления.
    \details Функция вычисляет последовательность октетов `basicKey` длиной 64 октета
    в соответствии со следующим равенством

\code
    basicKey = PBKDF2( password, salt, count, 64 )
\endcode

в котором

 - величина `salt` принимает случайное значение,
 - `count` это значение опции `pbkdf2_iteration_count`,
 - константа 64 означает длину вырабатываемого ключа в октетах

 Далее, функция определяет производные ключи шифрования и имитозащиты равенствами

\code
    KEK = Lsb( 256, BasicKey ) = BasicKey[0..31],
    KIM = Msb( 256, BasicKey ) = BasicKey[32..63].
\endcode

После этого функция присоединяет к заданному уровню `root` следующую ASN.1 структуру.

\code
    BasicKeyMetaData ::= SEQUENCE {
      method OBJECT IDENTIFIER,  -- метод генерации производных ключей
                                 -- для выработки производных ключей из пароля
                                    используется значение 1.2.643.2.52.1.127.2.1
      basicKey PBKDF2BasicKey  OPTIONAL,
                                 -- данные, необходимые для выработки и использования
                                    производных ключей.
    }
\endcode

Структура `PBKDF2BasicKey` определяется следующим образом.

\code
    PBKDF2BasicKey ::= SEQUENCE {
      algorithm OBJECT IDENTIFIER -- алгоритм блочного шифрования,
                                     для которого предназначены производные ключи
      parameters PBKDF2Parameters -- параметры алгоритма генерации производных ключей
    }
\endcode

Структура `PBKDF2Parameters` определяется следующим образом

\code
    PBKDF2Parameters ::= SEQUENCE {
      algorithmID OBJECT IDENTIFIER,   -- идентификатор алгоритма, лежащего в основе PBKDF2
                                       -- по умолчанию, это hmac-streebog512 (1.2.643.7.1.1.4.2)
      salt OCTET STRING,               -- инициализационный вектор для алгоритма PBKDF2,
      iterationCount INTEGER (0..65535),  -- число итераций алгоритма PBKDF2
    }
\endcode

 \param root уровень ASN.1 дерева, к которому добавляется структура BasicKeyMetaData
 \param oid идентификатор алгоритма блочного шифрования,
 для которого вырабатываются производные ключи шифрования и имитозащиты
 \param ekey контекст производного ключа шифрования
 \param ikey контекст производного ключа имитозащиты
 \param password пароль, используемый для генерации ключей шифрования и имитозащиты контента
 \param pass_size длина пароля (в октетах)

 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_add_derived_keys_from_password( ak_asn1 root, ak_bckey ekey, ak_bckey ikey,
                                        ak_oid oid, const char *password, const size_t pass_size )
{
  ak_uint8 salt[32]; /* случайное значение для генерации ключа шифрования контента */
  struct random generator; /* генератор ПДСЧ */
  int error = ak_error_ok;
  ak_asn1 asn1 = NULL, asn2 = NULL, asn3 = NULL;

  if(( error = ak_random_create_lcg(  &generator )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of random generator");

  memset( salt, 0, sizeof( salt ));
  ak_random_ptr( &generator, salt, sizeof( salt ));

  if(( error = ak_bckey_create_key_pair_from_password( ekey, ikey, oid, password, pass_size,
      salt, sizeof( salt ), (size_t) ak_libakrypt_get_option_by_name( "pbkdf2_iteration_count" )))
                                                                                  != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of derived key pairs");

 /* собираем ASN.1 дерево - снизу вверх */
   if(( ak_asn1_create( asn3 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__,
                                         "incorrect creation of PBKDF2Parameters asn1 structure" );
   }
   ak_asn1_add_oid( asn3, ak_oid_find_by_name( "hmac-streebog512" )->id[0] );
   ak_asn1_add_octet_string( asn3, salt, sizeof( salt ));
   ak_asn1_add_uint32( asn3,
                         ( ak_uint32 )ak_libakrypt_get_option_by_name( "pbkdf2_iteration_count" ));

   if(( ak_asn1_create( asn2 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     ak_asn1_delete( asn3 );
     return ak_error_message( error, __func__,
                                           "incorrect creation of PBKDF2BasicKey asn1 structure" );
   }
   ak_asn1_add_oid( asn2, oid->id[0] );
   ak_asn1_add_asn1( asn2, TSEQUENCE, asn3 );

   if(( ak_asn1_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     ak_asn1_delete( asn2 );
     return ak_error_message( error, __func__,
                                         "incorrect creation of BasicKeyMetaData asn1 structure" );
   }
   ak_asn1_add_oid( asn1, ak_oid_find_by_name( "pbkdf2-basic-key" )->id[0] );
   ak_asn1_add_asn1( asn1, TSEQUENCE, asn2 );

  /* помещаем в основное ASN.1 дерево структуру BasicKeyMetaData */
 return ak_asn1_add_asn1( root, TSEQUENCE, asn1 );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_add_derived_keys_unencrypted( ak_asn1 root, ak_bckey ekey, ak_bckey ikey )
{
  struct hash ctx;
  ak_uint8 salt[64];
  ak_asn1 asn1 = NULL;
  int error = ak_error_ok;

    /* формируем необходимую информацию */
     ak_hash_create_streebog512( &ctx );
     ak_hash_ptr( &ctx, "libakrypt-container", 19, salt, 64 );
     ak_hash_destroy( &ctx );

    /* вырабатываем ключи */
     salt[40] = 0;
     if(( error = ak_bckey_create_key_pair_from_password( ekey, ikey,
                     ak_oid_find_by_name( "kuznechik" ), (const char *)salt, 40,
                                                          salt +42, 16, 2000 )) != ak_error_ok ) {
       return ak_error_message( error, __func__, "incorrect creation of derived key pairs");
     }

    /* помещаем в основное ASN.1 дерево структуру BasicKeyMetaData */
     ak_asn1_add_oid( asn1 = ak_asn1_new(), ak_oid_find_by_name( "no-basic-key" )->id[0] );

 return ak_asn1_add_asn1( root, TSEQUENCE, asn1 );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_get_derived_keys_unencrypted( ak_asn1 akey, ak_bckey ekey, ak_bckey ikey )
{
   struct hash ctx;
   ak_uint8 salt[64];
   ak_oid oid = NULL;
   ak_pointer ptr = NULL;
   int error = ak_error_ok;

  /* проверяем параметры */
   if(( DATA_STRUCTURE( akey->current->tag ) != PRIMITIVE ) ||
      ( TAG_NUMBER( akey->current->tag ) != TOBJECT_IDENTIFIER ))
     return ak_error_message( ak_error_invalid_asn1_tag, __func__, "odject identifier not found" );
   ak_tlv_get_oid( akey->current, &ptr );

   oid = ak_oid_find_by_name( "no-basic-key" );
   if( strncmp( oid->id[0], ptr, strlen( oid->id[0] )) != 0 )
     return ak_error_message( ak_error_invalid_asn1_content, __func__,
                                                         "unexpected value of odject identifier" );
  /* формируем необходимую информацию */
   ak_hash_create_streebog512( &ctx );
   ak_hash_ptr( &ctx, "libakrypt-container", 19, salt, 64 );
   ak_hash_destroy( &ctx );

  /* вырабатываем ключи */
   salt[40] = 0;
   if(( error = ak_bckey_create_key_pair_from_password( ekey, ikey,
                     ak_oid_find_by_name( "kuznechik" ), (const char *)salt, 40,
                                                          salt +42, 16, 2000 )) != ak_error_ok ) {
     return ak_error_message( error, __func__, "incorrect creation of derived key pairs");
   }

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для ввода пароля используется функция, на которую указывает ak_function_defaut_password_read.
    Если этот указатель не установлен (то есть равен NULL), то выполняется чтение пароля
    из терминала, владеющего текущим процессом, с помощью функции ak_password_read().

    Формат ASN.1 структуры, хранящей параметры восстановления производных ключей,
    содержится в документации к функции ak_asn1_add_derived_keys_from_password().

 \param akey контекст ASN.1 дерева, содержащий информацию о ключе (структура `BasicKeyMetaData`)
 \param ekey контекст ключа шифрования
 \param ikey контекст ключа имитозащиты
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_get_derived_keys( ak_asn1 akey, ak_bckey ekey, ak_bckey ikey )
{
  size_t size = 0;
  ak_uint32 u32 = 0;
  ak_asn1 asn = NULL;
  char password[256];
  ssize_t passlen = 0;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  ak_oid eoid = NULL, oid = NULL;

 /* получаем структуру с параметрами, необходимыми для восстановления ключа */
  ak_asn1_first( akey );
  if( akey->count == 1 ) return ak_asn1_get_derived_keys_unencrypted( akey, ekey, ikey );
  if( akey->count != 2 ) return ak_error_invalid_asn1_count;

 /* проверяем параметры */
  if(( DATA_STRUCTURE( akey->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( akey->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  ak_tlv_get_oid( akey->current, &ptr );
  oid = ak_oid_find_by_name( "pbkdf2-basic-key" );
  if( strncmp( oid->id[0], ptr, strlen( oid->id[0] )) != 0 )
    return ak_error_invalid_asn1_content;
   /* в дальнейшем, здесь вместо if должен появиться switch,
      который разделяет все три возможных способа генерации производных ключей
      сейчас поддерживается только способ генерации из пароля */

  ak_asn1_next( akey );
  if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = akey->current->data.constructed;

 /* получаем информацию о ключе и параметрах его выработки */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;

  ak_tlv_get_oid( asn->current, &ptr );
  eoid = ak_oid_find_by_id( ptr ); /* идентификатор ключа блочного шифрования */
  if(( eoid->engine != block_cipher ) || ( eoid->mode != algorithm ))
    return ak_error_invalid_asn1_tag;

 /* получаем доступ к параметрам алгоритма генерации производных ключей */
  ak_asn1_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = asn->current->data.constructed;

 /* получаем из ASN.1 дерева параметры, которые будут передаватьсяв функцию pbkdf2 */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  ak_tlv_get_oid( asn->current, &ptr );
  oid = ak_oid_find_by_name( "hmac-streebog512" );
  if( strncmp( oid->id[0], ptr, strlen( oid->id[0] )) != 0 )
    return ak_error_invalid_asn1_content;

  ak_asn1_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
  ak_tlv_get_octet_string( asn->current, &ptr, &size ); /* инициализационный вектор */

  ak_asn1_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
  ak_tlv_get_uint32( asn->current, &u32 ); /* число циклов */

 /* вырабатываем производную ключевую информацию */
  if(( passlen = ak_function_default_password_read( ak_default_password_prompt,
               password, sizeof( password ), ak_default_password_interpretation )) < ak_error_ok )
    return ak_error_message( error, __func__, "incorrect password reading" );

 /* 1. получаем пользовательский пароль и вырабатываем производную ключевую информацию */
   if(( error = ak_bckey_create_key_pair_from_password( ekey, ikey, eoid,
                                             password, passlen, ptr, size, u32 )) == ak_error_ok )
     ak_ptr_wipe( password, sizeof( password ), &ikey->key.generator );
    else memset( password, 0, sizeof( password ));

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                         /* Функции экспорта ключевой информации */
/* ----------------------------------------------------------------------------------------------- */
/*!  - если `fsize` равен нулю, а указатель `filename` отличен от `NULL`, то функция
       предполагает, что `filename` уже содержит имя файла и ничего не вырабатывает.
     - если `fsize` отличен от нуля, а указатель `filename` отличен от `NULL`, то функция
       предполагает, что `filename` является указателем на область памяти, в которую будем
       помещено имя файла. Размер этой памяти определеяется значением переменной `size`.

    В качестве имени файла выбирается номер ключа, содержащийся в `buffer`,
    к которому приписывается расширение, зависящее от запрашиваемого пользователем формата.

    \param buffer Указатель на номер ключа
    \param bufsize Размер номера ключа в октетах
    \param filename Указатель на область памяти для имени файл;
    указатель должен быть отличен от `NULL`
    \param fsize Размер области памяти (в октетах )
    \param format Формат, в котором сохраняются данные.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_generate_file_name_from_buffer( ak_uint8 *buffer, const size_t bufsize,
                                       char *filename, const size_t fsize, export_format_t format )
{
  const char *file_extensions[] = { /* имена параметризуются значениями типа export_format_t */
    "key",
    "pem"
  };

  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to filename buffer" );
 /* формируем имя, только если длина отлична от нуля */
  if( fsize ) {
    if( fsize < 6 ) return ak_error_message( ak_error_out_of_memory, __func__,
                                               "insufficent buffer size for secret key filename" );
     memset( filename, 0, fsize );
     ak_snprintf( filename, fsize, "%s.%s",
      ak_ptr_to_hexstr( buffer, ak_min( bufsize, fsize-5 ), ak_false ), file_extensions[format] );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует ASN.1 структуру, содержащую зашифрованное значение секретного ключа.

 Формируеммая структура определяется следующим образом.

 \code
   EncryptedContent ::= SEQUENCE {
      dataStorage DataStorage,  -- метка наличия ключа
      compability OpenSSLCompability, -- флаг формата данных,
                                         совместимого с форматом библиотеки OpenSSL
      encryptedKey OCTET STRING -- собственно ключ, в защифрованном виде
   }
 \endcode

где

 \code
   DataStorage ::= INTEGER {
        data_not_present_storage(0), -- данные не содержатся
        data_present_storage(1), -- данные в наличии
        external_file_storage(2) -- данные находятся во внешнем файле или носителе
  }

  OpenSSLCompability ::= INTEGER {
        non_compatibly (0), -- данные не совместимы
        compatibly (1)      -- данные совместимы
  }
 \endcode

  Для шифрования ключевой информации используется алгоритм KExp15,
  описанный в рекомендациях Р 1323565.1.017-2018. Данный формат описывается следующей диаграммой

 \code
     iv || key + mask  ||                imito
   |__________________| --> ak_bckey_cmac -^
          |____________________________________|
                        ak_bckey_ctr
 \endcode

 На вход данного преобразования подаются два ключа алгоритма блочного шифрования "Кузнечик",
 после чего

  - вырабатывается случайный вектор `iv`, длина которого равна половине длины блока
    алгоритма "Кузнечик", т.е. 8 байт,
  - от вектора `iv || key + mask` с использованием ключа имитозащиты вычисляется имитовставка `imito`,
    используется алгоритм выработки имитовставки ГОСТ Р 34.12-2015,
  - с использованием ключа шифрования вектор `key+mask || imito` зашифровывается в режие гаммирования
    согласно ГОСТ Р 34.12-2015.

 \param root ASN.1 структура, к которой добавляется новая структура
 \param skey секретный ключ, содержащий зашифровываемые данные
 \param ekey производный ключ шифрования
 \param ikey производный ключ имитозащиты
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_add_skey_content( ak_asn1 root, ak_skey skey, ak_bckey ekey, ak_bckey ikey )
{
  ak_asn1 content = NULL;
  int error = ak_error_ok;
  size_t ivsize  = ekey->bsize >> 1,
         keysize = 2*skey->key_size;
  size_t len = ivsize + keysize + ikey->bsize;
             /* необходимый объем памяти:
                синхропосылка (половина блока) + ( ключ+маска ) + имитовставка (блок) */

  if(( content = ak_asn1_new( )) == NULL ) return ak_error_message( ak_error_get_value(),
                                                  __func__, "incorrect creation of asn1 context" );
  if(( error = ak_asn1_add_uint32( content, data_present_storage )) != ak_error_ok ) {
    ak_asn1_delete( content );
    return ak_error_message( error, __func__, "incorrect adding data storage identifier" );
  }
  if(( error = ak_asn1_add_uint32( content,
        ( ak_uint32 )ak_libakrypt_get_option_by_name( "openssl_compability" ))) != ak_error_ok ) {
    ak_asn1_delete( content );
    return ak_error_message( error, __func__, "incorrect adding data storage identifier" );
  }

 /* добавляем ключ: реализуем КЕexp15 для ключа и маски */
  if(( error = ak_asn1_add_octet_string( content, &len, len )) == ak_error_ok ) {
    ak_uint8 *ptr = content->current->data.primitive;

   /* формируем iv */
    memset( ptr, 0, len );
    ak_random_ptr( &ekey->key.generator, ptr, ivsize );
   /* меняем маску секретного ключа */
    skey->set_mask( skey );
   /* копируем данные:
      сохраняем их как большое целое число в big-endian кодировке */
    ak_mpzn_to_little_endian(( ak_uint64 *)skey->key,
                                             (skey->key_size >> 2), ptr+ivsize, keysize, ak_true );
   /* меняем маску секретного ключа */
    skey->set_mask( skey );
   /* вычисляем имитовставку */
    if(( error = ak_bckey_cmac( ikey, ptr, ivsize+keysize,
                                            ptr+(ivsize+keysize), ikey->bsize )) != ak_error_ok ) {
      ak_asn1_delete( content );
      return ak_error_message( error, __func__, "incorrect evaluation of cmac" );
    }
   /* шифруем данные */
    if(( error = ak_bckey_ctr( ekey, ptr+ivsize, ptr+ivsize, keysize+ikey->bsize,
                                                                  ptr, ivsize )) != ak_error_ok ) {
      ak_asn1_delete( content );
      return ak_error_message( error, __func__, "incorrect encryption of skey" );
    }
  } else {
           ak_asn1_delete( content );
           return ak_error_message( error, __func__, "incorrect adding a secret key" );
    }

 /* вставляем изготовленную последовательность и выходим */
 return ak_asn1_add_asn1( root, TSEQUENCE, content );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Экспорт секретного ключа симметричного алгоритма в ASN.1 дерево.

   Функция создает ASN.1 структуру `Content`, определяемую следующим образом
\code
    Content ::= SEQUENCE {
       type OBJECT IDENTIFIER, -- уникальный тип контента
                               -- для симметричных ключей это значение равно 1.2.643.2.52.1.127.3.1
       symkey SymmetricKeyContent -- собственно контент ключа
    }
\endcode

Структура `SymmetricKeyContent` определяется следующим образом.

\code
    SymmetricKeyContent ::= SEQUENCE {
       algorithm OBJECT IDENTIFIER,   -- идентификатор алгоритма, для которого предназначен ключ
       number OCTET STRING,           -- уникальный номер ключа
       keyLabel             CHOICE {
                              UTF8 STRING,
                              NULL    -- человекочитаемое имя (описание или метка) ключа,
                                         если имя не определено, то помещается NULL
                            }
       params KeyParameters,          -- параметры секретного ключа, такие как ресурс использований и
                                         временной интервал
       content EncryptedContent       -- собственно ключ, зашифрованный с помощью преобразования KExp15
    }
\endcode

Формат структуры `KeyParameters` определяется следующим образом.
\code
    KeyParameters ::= SEQUENCE {
       resourceType INTEGER, -- тип ресурса секретного ключа
       resource INTEGER,     -- значение ресурса
       validity Validity     -- временной интервал использования ключа
    }
\endcode

Структура `Validity` содержит в себе временной интервал действия ключа и
определяется стандартным для x509 образом.

\code
    Validity ::= SEQUENCE {
      notBefore Time,
      notAfter Time
    }

    Time ::= CHOICE {
      utcTime UTCTime,
      generalTime generalizedTime
    }
\endcode

 \param root уровень ASN.1 дерева, к которому добавляется структура `Content`
 \param skey контекст секретного ключа
 \param ekey контекст производного ключа шифрования
 \param ikey контекст производного ключа имитозащиты
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_add_symmetric_key_content( ak_asn1 root, ak_skey skey,
                                                                     ak_bckey ekey, ak_bckey ikey )
{
  ak_asn1 symkey = NULL;
  int error = ak_error_ok;

 /* 1. помечаем контейнер */
   if(( error = ak_asn1_add_oid( root,
                         ak_oid_find_by_name( "symmetric-key-content" )->id[0] )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect adding contents identifier" );

 /* 2. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_add_asn1( root, TSEQUENCE, symkey = ak_asn1_new( ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );

  /* 3. создаем пять встроенных полей (данный набор специфичен только для SymmetricKeyContent
     - 3.1. - идентификатор ключа */
   if(( error = ak_asn1_add_oid( symkey, skey->oid->id[0] )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's identifier" );
   }

  /* - 3.2. - номер ключа ключа */
   if(( error = ak_asn1_add_octet_string( symkey,
                                         skey->number, sizeof( skey->number ))) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's number" );
   }

  /* - 3.3. - имя/описание ключа */
   if(( error = ak_asn1_add_utf8_string( symkey, skey->label )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's label" );
     goto labexit;
   }

  /* - 3.4. - ресурс ключа */
   if(( error = ak_asn1_add_resource( symkey, &skey->resource )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
     goto labexit;
   }

  /* - 3.5. - собственно зашифрованный ключ */
   if(( error = ak_asn1_add_skey_content( symkey, skey, ekey, ikey )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
   }

  labexit: return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Экспорт секретного ключа асимметричного криптошрафического преобразования в ASN.1 дерево.

   Функция создает ASN.1 структуру `Content`, определяемую следующим образом
\code
    Content ::= SEQUENCE {
       type OBJECT IDENTIFIER, -- уникальный тип контента
                               -- для симметричных ключей это значение равно 1.2.643.2.52.1.127.3.2
       symkey SecretKeyContent -- собственно контент ключа
    }
\endcode

Структура `SecretKeyContent` определяется следующим образом.

\code
    SecretKeyContent ::= SEQUENCE {
       algorithm OBJECT IDENTIFIER,   -- идентификатор алгоритма, для которого предназначен ключ
       number OCTET STRING,           -- уникальный номер ключа
       keyLabel             CHOICE {
                              UTF8 STRING,
                              NULL    -- человекочитаемое имя (описание или метка) ключа,
                                         если имя не определено, то помещается NULL
                            }
       params KeyParameters,          -- параметры секретного ключа, такие как ресурс использований и
                                         временной интервал
       curveOID OBJECT IDENTIFIER     -- идентификатор эллиптической кривой, на которой выполняются
                                         криптографические преобразования
       subjectKeyIdentifier CHOICE {
                                OBJECT IDENTIFIER
                                NULL
                            }         -- идентификатор открытого ключа, связанного с данным
                                         секретным ключом, если идентификатор не определен,
                                         то помещается NULL
       subjectName          CHOICE {
                                Name
                                NULL  -- обощенное имя владельца ключа (как в открытом ключе), если
                            }            имя не определено, то помещается NULL
       content EncryptedContent       -- собственно данные, зашифрованные с помощью преобразования KExp15
    }
\endcode

Формат структуры `KeyParameters` определяется следующим образом.
\code
    KeyParameters ::= SEQUENCE {
       resourceType INTEGER, -- тип ресурса секретного ключа
       resource INTEGER,     -- значение ресурса
       validity Validity     -- временной интервал использования ключа
    }
\endcode

Структура `Validity` содержит в себе временной интервал действия ключа и определяется стандартным для x509 образом.
\code
    Validity ::= SEQUENCE {
      notBefore Time,
      notAfter Time
    }

    Time ::= CHOICE {
      utcTime UTCTime,
      generalTime generalizedTime
    }
\endcode

 \param root уровень ASN.1 дерева, к которому добавляется структура `Content`
 \param skey контекст секретного ключа
 \param ekey контекст производного ключа шифрования
 \param ikey контекст производного ключа имитозащиты
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_add_signature_key_content( ak_asn1 root, ak_signkey skey,
                                                                      ak_bckey ekey, ak_bckey ikey )
{
  ak_oid eoid = NULL;
  ak_uint8 pnumber[32];
  ak_asn1 symkey = NULL;
  int error = ak_error_ok;

 /* 1. помечаем контейнер */
   if(( error = ak_asn1_add_oid( root,
                 ak_oid_find_by_name( "secret-key-content" )->id[0] )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect adding contents identifier" );

 /* 2. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_add_asn1( root, TSEQUENCE, symkey = ak_asn1_new( ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );

  /* 3. создаем восемь встроенных полей (данный набор специфичен только для SecretKeyContent

     - 3.1. - идентификатор ключа */
   if(( error = ak_asn1_add_oid( symkey, skey->key.oid->id[0] )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's identifier" );
   }

  /* - 3.2. - номер ключа ключа */
   if(( error = ak_asn1_add_octet_string( symkey,
                                skey->key.number, sizeof( skey->key.number ))) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's number" );
   }

  /* - 3.3. - имя/описание ключа */
   if(( error = ak_asn1_add_utf8_string( symkey, skey->key.label )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's description" );
     goto labexit;
   }

  /* - 3.4. - ресурс ключа */
   if(( error = ak_asn1_add_resource( symkey, &skey->key.resource )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
     goto labexit;
   }

  /* - 3.5. - сохраняеми идентификатор эллиптической кривой,
              поскольку мы имеем только указатель на данные, надо найти oid по заданному адресу */

     eoid = ak_oid_find_by_mode( wcurve_params );
     while( eoid != NULL ) {
       if( eoid->data == skey->key.data ) {
           if(( error = ak_asn1_add_oid( symkey, eoid->id[0] )) != ak_error_ok )
             return ak_error_message( error, __func__,
                                                    "incorrect adding elliptic curve identifier" );
           break;
       }
       eoid = ak_oid_findnext_by_mode( eoid, wcurve_params );
     }

  /* - 3.6. идентификатор открытого ключа */
   memset( pnumber, 0, sizeof( pnumber ));
   if( memcmp( pnumber, skey->verifykey_number, sizeof( skey->verifykey_number )) == 0 )
     ak_asn1_add_utf8_string( symkey, NULL );
    else ak_asn1_add_octet_string( symkey,
                                         skey->verifykey_number, sizeof( skey->verifykey_number ));

  /* - 3.7. - собственно зашифрованный ключ */
   if(( error = ak_asn1_add_skey_content( symkey, &skey->key, ekey, ikey )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
   }

  labexit: return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция экспортирует секретный ключ криптографического преобразования в ASN.1 дерево
   с использованием пользовательского пароля.

   Функция формирует ASN.1 структуру следующего формата.
\code
    Container ::= SEQUENCE {
       id OBJECT IDENTIFIER, -- идентификатор контейнера,
                             -- по умоланию, используется значение 1.2.643.2.52.1.127.1.1
       basicKey BasicKeyMetaData, -- структура, необходимая для восстановления хранимой информации
       content Content       -- собственно содержимое
    }
\endcode

 Формат структуры метаданных `BasicKeyMetaData`, используемой для восстановления ключа,
 зависит от способа генерации ключей шифрования секретного ключа.
 Описание формата при использовании пароля
 содержится в документации к функции ak_asn1_add_derived_keys_from_password().

 Формат структуры `Content` зависит от типа помещаемых данных:

 -  для симметричных ключей (ключей алгоритмов блочного шифрования, алгоритмов выработки имитовставки и т.п.)
    описание формата структуры `Content` содержится в документации к функции
    ak_asn1_add_symmetric_key_content().

 -  для секретных ключей асимметричных алгоритмов, в частности, электронной подписи
    описание формата структуры `Content` содержится в документации к функции
    ak_asn1_add_signature_key_content().

 \param key секретный ключ криптографического преобразования
 \param root  уровень ASN.1 дерева, в который помещаются экспортируемые данные
 \param password пароль пользователя, может быть NULL
 \param pass_size длина пользовательского пароля в октетах, может равняться нулю

 \note Если пароль не определен или длина пароля равна нулю,
 то данные помещаются в контейнер незашифрованными, а точнее, зашифрованными на константном пароле.

 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_export_to_asn1_with_password( ak_pointer key,
                                       ak_asn1 root, const char *password, const size_t pass_size )
{
  int error = ak_error_ok;
  struct bckey ekey, ikey; /* производные ключи шифрования и имитозащиты */
  ak_asn1 asn = NULL, content = NULL;

  /* выполняем проверки */
   if( key == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to block cipher context" );
   if( root == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to root asn1 context" );
 /* 1. помечаем контейнер */
   if(( error = ak_asn1_add_oid( asn = ak_asn1_new(),
                           ak_oid_find_by_name( "libakrypt-container" )->id[0] )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );

 /* 2. Проверяем, что пароль определен.
       В противном случае, сохраняем ключ в незашифрованном виде, а более точно,
       защифровываем на константном пароле. */
   if(( password == NULL ) || ( !pass_size )) {
      error = ak_asn1_add_derived_keys_unencrypted( asn, &ekey, &ikey );
   }
    else { /* полноценное шифрование данных */
      error = ak_asn1_add_derived_keys_from_password( asn, &ekey, &ikey,
                                         ak_oid_find_by_name( "kuznechik" ), password, pass_size );
    }
  if( error != ak_error_ok ) {
    ak_asn1_delete( asn );
    return ak_error_message( error, __func__, "incorrect creation of derived secret keys" );
  }

 /* 3. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_add_asn1( asn, TSEQUENCE, content = ak_asn1_new( ))) != ak_error_ok ) {
     ak_asn1_delete( asn );
     ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );
     goto labexit;
   }

  /* 4. экспортируем данные в asn1 дерево,
        перед экспортом выполняем фильтр криптографического механизма еще раз */
   switch( ((ak_skey)key)->oid->engine ) {
    /* формируем ASN.1 дерево для симметричного секретного ключа */
     case block_cipher:
     case hmac_function:
           if(( error = ak_asn1_add_symmetric_key_content( content, (ak_skey)key,
                                                                &ekey, &ikey )) != ak_error_ok ) {
              ak_asn1_delete( asn );
              ak_error_message( error, __func__, "incorrect creation of symmetric key content" );
              goto labexit;
           }
           break;

     case sign_function:
           if(( error = ak_asn1_add_signature_key_content( content, (ak_signkey)key,
                                                                &ekey, &ikey )) != ak_error_ok ) {
              ak_asn1_delete( asn );
              ak_error_message( error, __func__, "incorrect creation of symmetric key content" );
              goto labexit;
           }
          break;

     default:
           ak_asn1_delete( asn );
           ak_error_message( error = ak_error_oid_engine, __func__,
                                                         "using usupported engine of secret key" );
           goto labexit;
  }

   error = ak_asn1_add_asn1( root, TSEQUENCE, asn );
   labexit:
     ak_bckey_destroy( &ekey );
     ak_bckey_destroy( &ikey );
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! В текущей версии библиотеки допускается экспорт следующих секретных ключей

     - ключа алгоритма блочного шифрования (указатель на struct \ref skey),
     - ключа алгоритма выработки имитовставки `HMAC` (указатель на struct \ref hmac),
     - секретного ключа асимметричного алгоритма (указатель на struct \ref signkey).

    В процессе экспорта функция создает ASN.1 дерево, содержащее экспортное ( зашифрованное )
    представление секретного ключа, после чего функция кодирует дерево в виде der-последовательности
    и сохряняет данную последовательность в заданный файл.

    Для шифрования ключа используются производные ключи, вырабатываемые
    из заданного пользователем пароля. Использование пароля нулевой длины или `NULL`
    указателя `password` не допускается.

    Если длина имени файла `filename_size` отлична от нуля, то функция предполагает, что имя файла
    пользователем не указано. В этом случае функция формирует имя файла (в качестве имени берется номер ключа)
    и помещает сформированную строку в переменную, на которую указывает `filename`.

    Формат ASN.1 дерева, в котором хранится
    экспортируемый ключ описывается в документации к функции ak_skey_export_to_asn1_with_password().
    В зависимости от значения параметра `format` закодированное ASN.1 дерево сохраняется
    либо в формате `der` (двоичные данные), либо в формате `pem` (текстовые данные, полученные
    путем base64-кодирования двоичных данных формате `der`)

    Пример вызова функции.
    \code
      // сохранение ключа в файле, имя которого возвращается в переменной filename
       char filemane[256];
       ak_skey_export_to_file_with_password( key,
             "password", 8, filename, sizeof( filename ), asn1_der_format );

      // сохранение ключа в файле с заданным именем
       ak_skey_export_to_file_with_password( key,
                            "password", 8, "name.key", 0, asn1_pem_format );
    \endcode

    \param key контекст экспортируемого секретного ключа криптографического преобразования;
    контекст должен быть инициализирован ключевым значением, а поле oid должно содержать
    идентификатор алгоритма, для которого предназначен ключ.
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `fsize` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param fsize  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \param format формат, в котором зашифрованные данные сохраняются в файл.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_export_to_file_with_password( ak_pointer key, const char *password,
               const size_t pass_size, char *filename, const size_t fsize, export_format_t format )
{
   ak_oid oid = NULL;
   ak_asn1 asn = NULL;
   int error = ak_error_ok;
   ak_skey skey = (ak_skey)key;
   crypto_content_t content = undefined_content;

  /* необходимые проверки */
   if( key == NULL )
     return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
   if( ak_oid_check( oid = skey->oid ) != ak_true )
     return ak_error_message( ak_error_invalid_value, __func__,
                                                 "using incorrect pointer to secret key context" );
   switch( oid->engine ) { /* перечисляем все поддерживаемые типы секретных ключей */
     case block_cipher:
     case hmac_function:
       content = symmetric_key_content;
       break;

     case sign_function:
       content = secret_key_content;
       break;

     default: return ak_error_message_fmt( ak_error_oid_engine, __func__,
          "using object with unsupported engine: %s", ak_libakrypt_get_engine_name( oid->engine ));
   }
   if( oid->mode != algorithm ) return ak_error_message_fmt( ak_error_oid_mode, __func__,
                "using object with unsupported mode: %s", ak_libakrypt_get_mode_name( oid->mode ));

   if(( error = ak_skey_generate_file_name_from_buffer( skey->number, sizeof( skey->number ),
                                                       filename, fsize, format )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of secret key filename" );

 /* преобразуем ключ в asn1 дерево */
  if(( error = ak_skey_export_to_asn1_with_password( key,
                                    asn = ak_asn1_new(), password, pass_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect export of secret key to asn1 context");
    goto lab1;
  }

 /* сохраняем созданное asn1 дерево в файле */
  if(( error = ak_asn1_export_to_file( asn, filename, format, content )) != ak_error_ok )
    ak_error_message_fmt( error, __func__, "incorrect export of asn1 context" );

  lab1: if( asn != NULL ) ak_asn1_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_export_to_file_unencrypted( ak_pointer key,
                                       char *filename, const size_t fsize, export_format_t format )
{
  return ak_skey_export_to_file_with_password( key, NULL, 0, filename, fsize, format );
}

/* ----------------------------------------------------------------------------------------------- */
                    /* Функции импорта секретной ключевой информации */
/* ----------------------------------------------------------------------------------------------- */
/*! В случае успешной проверки, функция присваивает двум своим аргументам ссылки на поддеревья,
    содержащие информацию о процедуре выработки производных ключей (basicKey) и собственно
    зашифрованных данных (content).

    Использование узла tlv позволяет вызывать эту функцию в цикле, т.е.
    реализовывать следующую схему

  \code
    ak_asn1_first( asn );
    do {
      if( ak_tlv_check_libakrypt_container( asn->current, ... )) {
        ...
      }
    } while( ak_asn1_next( asn ));
  \endcode

    \param tlv узел ASN.1 дерева.
    \param basicKey указатель, в который помещается ссылка на дерево секретного ключа
    \param content указатель, в который помещается ссылка на дерево с данными
    \return Функция возвращает истину, если количество ключей в контейнере отлично от нуля.
    В противном случае возвращается ложь.                                                          */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_tlv_check_libakrypt_container( ak_tlv tlv, ak_asn1 *basicKey, ak_asn1 *content )
{
  ak_asn1 asn = NULL;
  ak_pointer str = NULL;
  const char *id = ak_oid_find_by_name( "libakrypt-container" )->id[0];

  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) return ak_false;
  asn = tlv->data.constructed;

 /* проверяем количество узлов */
  if( asn->count != 3 ) return ak_false;

 /* проверяем наличие фиксированного id */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
        ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_false;

 /* проверяем совпадение идентификаторов */
  ak_tlv_get_oid( asn->current, &str );
  if( strncmp( str, id, strlen( id )) != 0 ) return ak_false;

 /* получаем доступ к структурам */
  ak_asn1_next( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) return ak_false;
   else *basicKey = asn->current->data.constructed;

  ak_asn1_next( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) return ak_false;
   else *content = asn->current->data.constructed;

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализирует секретный ключ значениями, расположенными в ASN.1 контейнере. */
/*! \param akey контекст ASN.1 дерева, содержащий информацию о ключе
    \param skey контекст ключа, значение которого считывается из ASN.1 дерева
    \param ekey контекст ключа шифрования
    \param ikey контекст ключа имитозащиты
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_get_skey_content( ak_asn1 akey, ak_skey skey, ak_bckey ekey, ak_bckey ikey )
{
  size_t size = 0;
  size_t ivsize  = ekey->bsize >> 1,
         keysize = 2*skey->key_size;
  ak_uint8 out[64];
  ak_asn1 asn = NULL;
  ak_uint8 *ptr = NULL;
  int error = ak_error_ok;
  ak_uint32 oc = 0, u32 = 0;

  /* проверяем наличие памяти (64 байта это 512 бит) */
   if( ikey->bsize > 64 )
     return ak_error_message( ak_error_wrong_length, __func__, "large size for integrity code" );

  /* получаем доступ к поддереву, содержащему зашифрованное значение ключа */
   ak_asn1_last( akey );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = akey->current->data.constructed;

   ak_asn1_last( asn );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = asn->current->data.constructed;

  /* теперь мы на уровне дерева, который содержит
     последовательность ключевых данных */

  /* проверяем значения полей дерева */
   ak_asn1_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_get_uint32( asn->current, &u32 );
   if( u32 != data_present_storage ) return ak_error_invalid_asn1_content;

   ak_asn1_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_get_uint32( asn->current, &u32 );  /* теперь u32 содержит флаг совместимости с openssl */
   if( u32 !=  (oc = ( ak_uint32 )ak_libakrypt_get_option_by_name( "openssl_compability" ))) /* текущее значение */
     ak_libakrypt_set_openssl_compability( u32 );

  /* расшифровываем и проверяем имитовставку */
   ak_asn1_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
   ak_tlv_get_octet_string( asn->current, (ak_pointer *)&ptr, &size );
   if( size != ( ivsize + keysize + ikey->bsize )) /* длина ожидаемых данных */
     return ak_error_invalid_asn1_content;

  /* расшифровываем */
   if(( error = ak_bckey_ctr( ekey, ptr+ivsize, ptr+ivsize, keysize+ikey->bsize,
                                                                  ptr, ivsize )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect decryption of skey" );
     goto labexit;
   }

  /* вычисляем имитовставку */
   memset(out, 0, sizeof( out ));
   if(( error = ak_bckey_cmac( ikey, ptr, ivsize+keysize,
                                                     out, ikey->bsize )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect evaluation of cmac" );
     goto labexit;
   }
  /* теперь сверяем значения */
   if( !ak_ptr_is_equal( out, ptr+(ivsize+keysize), ikey->bsize )) {
     ak_error_message( error = ak_error_not_equal_data, __func__,
                                                             "incorrect value of integrity code" );
     goto labexit;
   }

  /* теперь копируем данные,
     поскольку мы полностью уверенны, что данные, хранящиеся в ASN.1 дереве содержат значение ключа */
   ak_mpzn_set_little_endian( (ak_uint64 *)(skey->key),
                                              (skey->key_size >>2), ptr+ivsize, keysize, ak_true );
  /* меняем значение флага */
   skey->flags |= key_flag_set_mask;

  /* вычисляем контрольную сумму */
   if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );
  /* маскируем ключ */
   if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );
  /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
   skey->flags |= key_flag_set_key;

  /* для ключей блочного шифрования выполняем развертку раундовых ключей */
   if( skey->oid->engine == block_cipher ) {
     if( ((ak_bckey)skey)->schedule_keys != NULL ) {
       if(( error = ((ak_bckey)skey)->schedule_keys( skey )) != ak_error_ok )
         ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );
     }
   }

  /* восстанавливаем изначальный режим совместимости и выходим */
   labexit: if( u32 != oc ) ak_libakrypt_set_openssl_compability( oc );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция считывает информацию о секретном ключе из заданного файла, созданного
    при помощи функции ak_skey_export_to_file().

   Эта очень длинная функция позволяет инициализировать статически созданные ключи,
   а также динамически создавать ключи в оперативной памяти. За это отвечает параметр `engine`:

   - если значение `engine` равно `undefined engine`, то сначала мы выделяем память под
     объект с помощью функции, указанной в его `oid`, а потом инициализируем объект значениями из файла;
   - если значение `engine` содержит осознанное значение, то мы считаем, что объект уже
     размещен в памяти и его тип определен значением `engine`; если содержащийся в файле тип
     криптографического преобразования совпадает с запрашиваемым, то ключ инициалищируется.

   Функция также позволяет выбирать: надо ли считывать и устанавливать ключевую информацию
   или не нужно. За это отвечает параметр `basicKey`:

   - если значение `basicKey` отлично от `NULL`, то производится считывание и
     помещение ключевой информации в контекст секретного ключа; информация о ключе доступа находится
     в asn1 дереве `basicKey`.
   - если значение `basicKey` равно NULL, то считывание не производится.


   \param key Указатель на контекст секретного ключа
   \param engine Тип ожидаемого криптографического механизма
   \param basicKey Указатель на ASN.1 структуру с информацией для восстановления ключа
    шифрования контента
   \param content Указатель на ASN.1 структуру, соержащую данные
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_create_form_asn1_content( ak_pointer *key, oid_engines_t engine,
                                                                ak_asn1 basicKey, ak_asn1 content )
{
  size_t len = 0;
  ak_oid oid = NULL;
  ak_asn1 asn = NULL;
  ak_pointer ptr = NULL;
  struct bckey ekey, ikey;
  int error = ak_error_ok;
  crypto_content_t content_type = undefined_content;

 /* получаем структуру с параметрами, необходимыми для восстановления ключа */
  ak_asn1_first( content );
  if(( DATA_STRUCTURE( content->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( content->current->tag ) != TOBJECT_IDENTIFIER )) return undefined_content;

 /* получаем oid контента и проверяем, что он нам подходит */
  if(( error = ak_tlv_get_oid( content->current, &ptr )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect asn1 structure of content" );
    return undefined_content;
  }
  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message( ak_error_undefined_value, __func__, "incorrect content type" );
  if(( oid->engine != identifier ) || ( oid->mode != parameter ))
    return ak_error_message( ak_error_wrong_oid, __func__,
                                                         "incorrect value of content identifier" );
 /* определяем тип контента ( нас интересует только хранение секретных ключей ) */
  switch(( content_type = ((ak_uint64) oid->data )&0xFF )) {
    case symmetric_key_content:
    case secret_key_content:
      break;
    default: return ak_error_message( ak_error_invalid_asn1_content, __func__,
                                                    "unsupported content type for this function" );
  }

 /* получаем указатель на дерево, содержащее параметры ключа и его зашифрованное значение */
  ak_asn1_next( content );
  if(( asn = content->current->data.constructed ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__,
                                                      "unexpected null pointer to asn1 sequence" );
 /* получаем идентификатор ключа */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER ))
     return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                          "context has'nt object identifer for crypto algorithm" );

  ak_tlv_get_oid( asn->current, &ptr );
  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message( ak_error_invalid_asn1_content, __func__,
                                           "object identifier for crypto algorithm is not valid" );
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__, "wrong mode for object identifier" );

 /* теперь мы реализуем действия, зависящие от значения engine . */
  if( engine == undefined_engine ) { /* мы создаем новый объект  */
    if(( *key = ak_oid_new_object( oid )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of new secret key context" );
  } else { /* проверяем, что считанный тип совпадает с ожидаемым */
      if( oid->engine != engine )
        return ak_error_message_fmt( error = ak_error_oid_engine, __func__,
           "unexpected engine (%s) of object identifier (must be: %s)",
              ak_libakrypt_get_engine_name( oid->engine ), ak_libakrypt_get_engine_name( engine ));
      if(( error = oid->func.first.create( *key )) != ak_error_ok )
        return ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of new secret key context" );
    }

 /* в текущий момент объект создан и мы
     1. можем присваивать значения его полям
     2. экстренный выход из функции должен обеспечивать очистку созданного контекста

    мы начинаем с полей, общих как для symmetric_key_content, так и для secret_key_content */

  /* - 3.2. получаем номер ключа */
   ak_asn1_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) {
      ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                      "context has incorrect asn1 type for symmetric key number" );
      goto lab1;
   }
   if(( error = ak_tlv_get_octet_string( asn->current, &ptr, &len )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect reading of symmetric key number");
     goto lab1;
   }
   if(( error = ak_skey_set_number( *key, ptr, len )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assigning a key number");
     goto lab1;
   }

  /* - 3.3. получаем имя/название/метку ключа */
   ak_asn1_next( asn );
   if( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) {
     ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                        "context has incorrect asn1 type for symmetric key name" );
     goto lab1;
   }
   switch( TAG_NUMBER( asn->current->tag )) {
     case TNULL: /* параметр опционален, может быть null */
              ptr = NULL;
              break;
     case TUTF8_STRING:
              ak_tlv_get_utf8_string( asn->current, &ptr );
              ak_skey_set_label( (ak_skey)*key, ptr, 0 );
              break;
     default: ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                        "context has incorrect asn1 type for symmetric key name" );
              goto lab1;
   }

  /* - 3.4. получаем ресурс ключа */
   ak_asn1_next( asn );
   if(( error = ak_tlv_get_resource( asn->current, &((ak_skey)*key)->resource )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect reading of secret key resource" );
     goto lab1;
   }

 /* для секретных ключей асимметричных алгоритмов надо считать дополнительные данные */
  if( content_type == secret_key_content ) {
    ak_oid curvoid = NULL;

    /* - 3.5  получаем идентификатор кривой */
     ak_asn1_next( asn );
     ak_tlv_get_oid( asn->current, &ptr );
     if(( curvoid = ak_oid_find_by_id( ptr )) == NULL ) {
       ak_error_message( error = ak_error_invalid_asn1_content, __func__,
                                             "object identifier for elliptic curve is not valid" );
       goto lab1;
     }
     if(( error = ak_signkey_set_curve( *key, (ak_wcurve)curvoid->data )) != ak_error_ok ) {
       ak_error_message( error, __func__, "using unapplicabale elliptic curve" );
       goto lab1;
     }

    /* - 3.5 получаем идентификатор открытого ключа */
     ak_asn1_next( asn );
     if( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) {
       ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                   "context has constructed context for subject key identifier" );
       goto lab1;
     }

     memset( ((ak_signkey)*key)->verifykey_number, 0, 32 );
     if( TAG_NUMBER( asn->current->tag ) != TNULL ) {
       if( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING ) {
         ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                    "context has incorrect asn1 type for subject key identifier" );
         goto lab1;
       }
       if(( error = ak_tlv_get_octet_string( asn->current, &ptr, &len )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect reading of symmetric key number");
         goto lab1;
       }
       memcpy( ((ak_signkey)*key)->verifykey_number, ptr, ak_min( 32, len ));
     }

  } /* конец  if(  content_type == secret_key_content ) */

 /* в завершение всех дел, можно считать значение секретного ключа,
    это происходит только в том случае, когда указатель basicKey отличен от NULL */
  if( basicKey != NULL ) {

   /* получаем производные ключи шифрования и имитозащиты */
    if(( error = ak_asn1_get_derived_keys( basicKey, &ekey, &ikey )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect creation of derived keys" );            
      goto lab1;
    }

    if(( error = ak_asn1_get_skey_content( content, *key, &ekey, &ikey )) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect assigning a seсret key value");

    ak_bckey_destroy( &ekey );
    ak_bckey_destroy( &ikey );
  }

 /* удаляем память, если нужно и выходим */
  lab1:
   if( error != ak_error_ok ) {
     oid = ((ak_skey)*key)->oid;

    /* удаляем объект */
     if( engine == undefined_engine ) ak_oid_delete_object( oid, *key );
      else oid->func.first.destroy( *key );
     *key = NULL; /* это значение возвращается наверх и служит признаком ошибки
                                           исполнения функции, так же как и код  */
   }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно выполняет следующие действия
     - создает объект (аналог действия `new`)
     - инициализирует контекст (аналог действия `create`)
     - присваивает ключевое значение (аналог действия `set_key`)

    \param filename Имя файла в котором хранятся данные
    \return Функция возвращает указатель на созданный контекст ключа. В случае ошибки возвращается
    а `NULL`, а код ошибки может быть получен с помощью вызова функции ak_error_get_value().       */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_load_from_file( const char *filename )
{
  ak_pointer key = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = NULL, basicKey = NULL, content = NULL;

   if( filename == NULL ) {
     ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );
     return NULL;
   }
  /* считываем ключ и преобразуем его в ASN.1 дерево */
   if(( error = ak_asn1_import_from_file( asn = ak_asn1_new(), filename, NULL )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
     goto lab1;
   }
  /* проверяем контейнер на формат хранящихся данных */
   ak_asn1_first( asn );
   if( !ak_tlv_check_libakrypt_container( asn->current, &basicKey, &content )) {
     ak_error_message( ak_error_invalid_asn1_content, __func__,
                                                      "incorrect format of secret key container" );
     goto lab1;
   }
  /* создаем ключ и считываем его значение */
   if(( error = ak_skey_create_form_asn1_content(
                   &key,     /* указатель на создаваемый объект */
                             /* проверку ожидаемого типа механизма не проводим */
                   undefined_engine,  /* и создаем объект в оперативной памяти */
                   basicKey, /* после создания будем присваивать ключ */
                   content   /* указатель на ключевые данные */
       )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of a new secret key");
     goto lab1;
   }

   lab1: if( asn != NULL ) ak_asn1_delete( asn );
 return key;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно выполняет следующие действия
     - создает объект (аналог действия `new`)
     - инициализирует контекст (аналог действия `create`)

    \note Значение ключа в созданный контекст не перемещается.

    \param filename Имя файла в котором хранятся данные
    \return Функция возвращает указатель на созданный контекст ключа. В случае ошибки возвращается
    а `NULL`, а код ошибки может быть получен с помощью вызова функции ak_error_get_value().       */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_new_from_file( const char *filename )
{
  ak_pointer key = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = NULL, basicKey = NULL, content = NULL;

   if( filename == NULL ) {
     ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );
     return NULL;
   }
  /* считываем ключ и преобразуем его в ASN.1 дерево */
   if(( error = ak_asn1_import_from_file( asn = ak_asn1_new(), filename, NULL )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
     goto lab1;
   }
  /* проверяем контейнер на формат хранящихся данных */
   ak_asn1_first( asn );
   if( !ak_tlv_check_libakrypt_container( asn->current, &basicKey, &content )) {
     ak_error_message( error = ak_error_invalid_asn1_content, __func__,
                                                      "incorrect format of secret key container" );
     goto lab1;
   }
  /* создаем ключ и считываем его значение */
   if(( error = ak_skey_create_form_asn1_content(
                   &key,     /* указатель на создаваемый объект */
                             /* проверку ожидаемого типа механизма не проводим */
                   undefined_engine,  /* и создаем объект в оперативной памяти */
                   NULL,     /* после создания ключ присваивать не будем */
                   content   /* указатель на ключевые данные */
       )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of a new secret key");
     goto lab1;
   }

   lab1: if( asn != NULL ) ak_asn1_delete( asn );
 return key;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно выполняет следующие действия
     - инициализирует контекст (аналог действия `create`)
     - присваивает ключевое значение (аналог действия `set_key`)

    \param ctx Контекст секретного ключа, должен быть не инициализирован до вызова функции
    \param engine Тип криптографического алгоритма, для которого создается контекст.
    Если это значение отлично от типа, хранящегося в ключевом контейнере, то возбуждается ошибка
    \param filename Имя файла в котором хранятся данные
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_import_from_file( ak_pointer ctx, oid_engines_t engine, const char *filename )
{
  int error = ak_error_ok;
  ak_asn1 asn = NULL, basicKey = NULL, content = NULL;

   if( filename == NULL )
     return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );

  /* считываем ключ и преобразуем его в ASN.1 дерево */
   if(( error = ak_asn1_import_from_file( asn = ak_asn1_new(), filename, NULL )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
     goto lab1;
   }

  /* проверяем контейнер на формат хранящихся данных */
   ak_asn1_first( asn );
   if( !ak_tlv_check_libakrypt_container( asn->current, &basicKey, &content )) {
     ak_error_message( error = ak_error_invalid_asn1_content, __func__,
                                                      "incorrect format of secret key container" );
     goto lab1;
   }

  /* создаем ключ и считываем его значение */
   if(( error = ak_skey_create_form_asn1_content(
                   &ctx,     /* указатель на инициализируемый объект */
                   engine,   /* ожидаем объект заданного типа */
                   basicKey, /* после инициализации будем присваивать ключ */
                             /* указатель на ключевые данные */
                   content )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of a new secret key");
     goto lab1;
   }

   lab1: if( asn != NULL ) ak_asn1_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_delete( ak_pointer ctx )
{
   ak_oid oid = NULL;
   int error = ak_error_ok;

   if( ctx == NULL )
     return ak_error_message( ak_error_null_pointer, __func__, "deleting null pointer" );

  /* пользуемся тем, что ключ содержит oid, а тот, в свою очередь, ссылку на деструктор */
   oid = (( ak_skey )ctx)->oid;
   if( !ak_oid_check( oid ))
     return ak_error_message( ak_error_wrong_oid, __func__,
                                   "deleting incorrect pointer with undefined object identifier" );
   error = oid->func.first.destroy( ctx );
   free( ctx );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example aktool_key.c                                                                          */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_keys.c  */
/* ----------------------------------------------------------------------------------------------- */
