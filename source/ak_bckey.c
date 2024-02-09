/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                            by kirlit26                                                          */
/*  Файл ak_bckey.c                                                                                */
/*  - содержит реализацию общих функций для алгоритмов блочного шифрования.                        */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает параметры алгоритма блочного шифрования, передаваемые в качестве
    аргументов. После инициализации остаются неопределенными следующие поля и методы,
    зависящие от конкретной реализации алгоритма блочного шифрования:

    - bkey.encrypt -- алгоритм зашифрования одного блока
    - bkey.decrypt -- алгоритм расшифрования одного блока
    - bkey.shedule_keys -- алгоритм развертки ключа и генерации раундовых ключей
    - bkey.delete_keys -- функция удаления раундовых ключей

    Следующие поля принимают значения по-умолчанию
    - bkey.key.data -- указатель на служебную область памяти
    - bkey.key.resource.value.counter -- максимально возможное число обрабатываемых блоков информации
    - bkey.key.oid -- идентификатор алгоритма шифрования
    - bkey.key.set_mask -- функция установки или смены маски ключа
    - bkey.key.unmask -- функция снятия маски с ключа
    - bkey.key.set_icode -- функция вычисления кода целостности
    - bkey.key.check_icode -- функция проверки кода целостности

    Перечисленные методы могут переопределяться в производящих функциях,
    создающих объекты конкретных алгоритмов блочного шифрования.

    @param bkey контекст ключа алгоритма блочного шифрованния
    @param keysize длина ключа в байтах
    @param blocksize длина блока обрабатываемых данных в байтах
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create( ak_bckey bkey, size_t keysize, size_t blocksize )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using a null pointer to block cipher context" );
  if( !keysize ) return ak_error_message( ak_error_zero_length, __func__,
                                                        "using block cipher key with zero length" );
  if( !blocksize ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using cipher with zero block length" );
 /* инициализируем ключевые данные */
  if(( error = ak_skey_create( &bkey->key, keysize )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of secret key" );

  memset( bkey->ivector, 0, sizeof( bkey->ivector ));
  bkey->bsize =         blocksize;
  bkey->ivector_size =  0;
  bkey->encrypt =       NULL;
  bkey->decrypt =       NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =   NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey контекст ключа алгоритма блочного шифрованния
    @return В случае успеха функция возввращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_destroy( ak_bckey bkey )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using a null pointer to block cipher context" );
  if( bkey->delete_keys != NULL ) {
    if(( error = bkey->delete_keys( &bkey->key )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong deleting of round keys" );
    }
  }
 /* изменяем значение вектора синхропосылок перед уничтожением */
  if(( error =  ak_ptr_wipe( bkey->ivector, sizeof( bkey->ivector ),
                                                          &bkey->key.generator )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect wiping of internal buffer" );
  bkey->ivector_size = 0;

 /* уничтожаем секретный ключ */
  if(( error = ak_skey_destroy( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroying a secret key" );

  bkey->bsize =            0;
  bkey->encrypt =       NULL;
  bkey->decrypt =       NULL;
  bkey->schedule_keys = NULL;
  bkey->delete_keys =   NULL;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey контекст ключа алгоритма блочного шифрованния
    @param oid Идентификатор алгоритма HMAC - ключевой функции хеширования.
    @return В случае успешного завершения функция возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create_oid( ak_bckey bkey, ak_oid oid )
{
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using a null pointer to block cipher context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using a null pointer to oid context" );
 /* проверяем, что OID от правильного алгоритма выработки */
  if( oid->engine != block_cipher )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );
 /* проверяем, что производящая функция определена */
  if( oid->func.first.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                             "using block cipher oid with undefined constructor" );
 /* инициализируем контекст */
  if(( error = (( ak_function_bckey_create *)oid->func.first.create )( bkey )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                                     "invalid creation of %s block cipher context", oid->name[0] );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция присваивает контексту ключа алгоритма блочного шифрования заданное значение,
    содержащееся в области памяти, на которую указывает аргумент функции keyptr.
    При инициализации значение ключа \b копируется в контекст ключа.

    Перед присвоением ключа контекст должен быть инициализирован.
    После присвоения ключа производится его маскирование и выработка контрольной суммы.

    Предпалагается, что основное использование функции ak_bckey_context_set_key()
    заключается в тестировании алгоритма блочного шифрования на заданных (тестовых)
    значениях ключей. Другое использование функции - присвоение значений, выработанных в ходе
    выполнения алгоритмов выработки ключевой информации.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param keyptr Указатель на область памяти, содержащую значение ключа.
    @param size Размер области памяти, содержащей значение ключа.

    @return Функция возвращает код ошибки. В случае успеха возвращается \ref ak_error_ok (ноль).   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_set_key( ak_bckey bkey, const ak_pointer keyptr, const size_t size )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( keyptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                "using null pointer to key data" );
  if( size != bkey->key.key_size ) return ak_error_message( ak_error_wrong_length, __func__,
                                       "using a constant value for secret key with wrong length" );

 /* дополнительный переворот ключа для алгоритма Магма (в режиме совместимости с openssl) */
  if(( ak_libakrypt_get_option_by_name( "openssl_compability" ) == 1 ) &&
                                         ( strncmp( bkey->key.oid->name[0], "magma", 5 ) == 0 )) {
    int i = 0;
    ak_uint8 revkey[32];

    for( i = 0; i < 32; i++ ) revkey[i] = ((ak_uint8 *)keyptr)[31-i];
    error = ak_skey_set_key( &bkey->key, revkey, sizeof( revkey ));
    ak_ptr_wipe( revkey, sizeof( revkey ), &bkey->key.generator );
    if( error != ak_error_ok )
      return ak_error_message( error, __func__ , "incorrect assigning of reversed key data" );

  } else {
      /* обычное присвоение ключевого буффера */
       if(( error = ak_skey_set_key( &bkey->key, keyptr, size )) != ak_error_ok )
       return ak_error_message( error, __func__ , "incorrect assigning of fixed key data" );
   }

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) {
    if(( error = bkey->schedule_keys( &bkey->key )) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );
  }
 /* устанавливаем ресурс использования секретного ключа */
  switch( bkey->bsize ) {
    case  8: if(( error = ak_skey_set_resource_values( &bkey->key,
                      block_counter_resource, "magma_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__, "incorrect assigning \"magma_cipher_resource\" option" );
      break;

    case 16: if(( error = ak_skey_set_resource_values( &bkey->key,
                     block_counter_resource, "kuznechik_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__,
                                      "incorrect assigning \"kuznechik_cipher_resource\" option" );
      break;
    default:  ak_error_message( error = ak_error_wrong_block_cipher_length, __func__,
                                                        "incorrect value of block cipher length" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает контексту ключа алгоритма блочного шифрования случайное (псевдослучайное)
    значение, вырабатываемое заданным генератором случайных (псевдослучайных) чисел.

    Перед присвоением ключа контекст должен быть инициализирован.

    После присвоения значения ключа производится его маскирование и выработка контрольной суммы.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param generator Контекст генератора случайных (псевдослучайных) чисел.

    @return Функция возвращает код ошибки. В случае успеха возвращается \ref ak_error_ok.          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_set_key_random( ak_bckey bkey, ak_random generator )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to secret key context" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                          "using null pointer to random generator" );
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_set_key_random( &bkey->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of random key data" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) error = bkey->schedule_keys( &bkey->key );
  if( error != ak_error_ok )
    ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );

 /* устанавливаем ресурс использования секретного ключа */
  switch( bkey->bsize ) {
    case  8: if(( error = ak_skey_set_resource_values( &bkey->key,
                      block_counter_resource, "magma_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__, "incorrect assigning \"magma_cipher_resource\" option" );
      break;

    case 16: if(( error = ak_skey_set_resource_values( &bkey->key,
                     block_counter_resource, "kuznechik_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__,
                                      "incorrect assigning \"kuznechik_cipher_resource\" option" );
      break;
    default:  ak_error_message( error = ak_error_wrong_block_cipher_length, __func__,
                                                        "incorrect value of block cipher length" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает контексту ключа блочного шифрования значение, выработанное из заданного
    пароля при помощи алгоритма PBKDF2, описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    Количество итераций алгоритма PBKDF2 определяется опцией библиотеки `pbkdf2_iteration_count`,
    значение которой может быть опредедено с помощью вызова функции ak_libakrypt_get_option().

    Перед присвоением ключа контекст должен быть инициализирован.

    После присвоения значения ключа производится его маскирование и выработка контрольной суммы.

    @param bkey Контекст ключа блочного алгоритма шифрования.
    @param pass Пароль, представленный в виде строки символов.
    @param pass_size Длина пароля в байтах
    @param salt Случайный вектор, представленный в виде строки символов.
    @param salt_size Длина случайного вектора в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_set_key_from_password( ak_bckey bkey, const ak_pointer pass,
                             const size_t pass_size, const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;

 /* проверяем входные данные */
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to secret key context" );
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_set_key_from_password( &bkey->key,
                                                pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning for given password" );

 /* выполняем развертку раундовых ключей */
  if( bkey->schedule_keys != NULL ) error = bkey->schedule_keys( &bkey->key );
  if( error != ak_error_ok )
    ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );

 /* устанавливаем ресурс использования секретного ключа */
  switch( bkey->bsize ) {
    case  8: if(( error = ak_skey_set_resource_values( &bkey->key,
                      block_counter_resource, "magma_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__, "incorrect assigning \"magma_cipher_resource\" option" );
      break;

    case 16: if(( error = ak_skey_set_resource_values( &bkey->key,
                     block_counter_resource, "kuznechik_cipher_resource", 0, 0 )) != ak_error_ok )
       ak_error_message( error, __func__,
                                      "incorrect assigning \"kuznechik_cipher_resource\" option" );
      break;
    default:  ak_error_message( error = ak_error_wrong_block_cipher_length, __func__,
                                                        "incorrect value of block cipher length" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Контекст создаваемого ключа.
    @param rkey Контекст ключа, значение которого дублируется.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create_and_set_bckey( ak_bckey bkey, ak_bckey rkey )
{
  ak_oid oid = NULL;
  int error = ak_error_ok;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to left block cipher context" );
  if( rkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to right block cipher context" );
  if(( oid = rkey->key.oid ) == NULL )
    return ak_error_message( ak_error_wrong_oid, __func__,
                             "using null pointer to internal oid in right block cipher context" );
  if( oid->func.first.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__,
                          "using null pointer to create function in right block cipher context" );
 /* создаем объект */
  if(( error = ((ak_function_bckey_create *)oid->func.first.create)( bkey )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of left block cipher context" );

 /* присваиваем ключ */
  if(( error = rkey->key.unmask( &rkey->key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect unmasking block cipher context" );
    goto  labex;
  }
  if(( error = ak_bckey_set_key( bkey, rkey->key.key, rkey->key.key_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning a new key value" );
  }
  rkey->key.set_mask( &rkey->key );

 return error;

  labex:
   ak_bckey_destroy( bkey );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             теперь реализация режимов шифрования                                */
/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Контекст ключа алгоритма блочного шифрования.
    @param in Указатель на область памяти, где хранятся входные (зашифровываемые) данные
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с in)
    @param size Размер зашировываемых данных (в байтах). Для режима простой замены
    длина зашифровываемых данных должна быть кратна длине блока.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_ecb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size )
{
  size_t blocks = 0;
  int error = ak_error_ok;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* выполняем проверку размера входных данных */
  if( size%bkey->bsize != 0 )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  blocks = size/bkey->bsize;
  if( bkey->key.resource.value.counter < (ssize_t)blocks )
    return ak_error_message( ak_error_low_key_resource,
                                                   __func__ , "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= blocks;

 /* теперь приступаем к зашифрованию данных */
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита */
      do {
        bkey->encrypt( &bkey->key, inptr++, outptr++ );
      } while( --blocks > 0 );
    break;

    case 16: /* шифр с длиной блока 128 бит */
      do {
        bkey->encrypt( &bkey->key, inptr, outptr );
        inptr+=2; outptr+=2;
      } while( --blocks > 0 );
    break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
  }
 /* перемаскируем ключ */
  if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param bkey Контекст ключа алгоритма блочного шифрования.
    @param in Указатель на область памяти, где хранятся входные (расшифровываемые) данные.
    @param out Указатель на область памяти, куда помещаются расшифрованные данные
    (этот указатель может совпадать с in).
    @param size Размер расшировываемых данных (в байтах). Для режима простой замены
    длина расшифровываемых данных должна быть кратна длине блока.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_ecb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size )
{
  size_t blocks = 0;
  int error = ak_error_ok;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;

 /* выполняем проверку размера входных данных */
  if( size%bkey->bsize != 0 )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  blocks = size/bkey->bsize;
  if( bkey->key.resource.value.counter < (ssize_t) blocks )
    return ak_error_message( ak_error_low_key_resource,
                                                   __func__ , "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= blocks;

 /* теперь приступаем к расшифрованию данных */
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита */
      do {
        bkey->decrypt( &bkey->key, inptr++, outptr++ );
      } while( --blocks > 0 );
    break;

    case 16: /* шифр с длиной блока 128 бит */
      do {
        bkey->decrypt( &bkey->key, inptr, outptr );
        inptr+=2; outptr+=2;
      } while( --blocks > 0 );
    break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
  }
 /* перемаскируем ключ */
  if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Поскольку в режиме гаммирования операцией шифрования является сложение открытого текста по
    модулю два с последовательностью, вырабатываемой блочным шифром из заданной синхропосылки,
    то для зашифрования и расшифрования информациии используется одна и та же функция.

    Значение синхропосылки `iv` копируется в контекст секретного ключа (область памяти, на которую
    указывает `iv` не изменяется) и преобразуется в ходе реализации режима гаммирования.
    Преобразованное значение сохраняется в контексте секретного ключа в буффере `skey.ivector`.
    Данное значение может быть использовано при повторном вызове функции ak_bckey_ctr().
    Следующий пример иллюстрирует сказанное.


\code
 // bkey - ключ алгоритма "Магма"
 // шифрование буффера с данными одним фрагментом
  ak_bckey_ctr( bkey, in, out, size, iv, 4 );

 // тот же результат может быть получен за три последовательных вызова
  ak_bckey_ctr( bkey, in, out, 16, iv, 4 );
  ak_bckey_ctr( bkey, in+16, out+16, 16, NULL, 0 );
  ak_bckey_ctr( bkey, in+32, out+32, size-32, NULL, 0 );
 //   для того, чтобы использовать внутреннее значение синхропосылки,
 //                мы передаем нулевые значения последних параметров
 //        использовать данную возможность можно только в том случае,
 // когда длина переданных в функцию ранее данных кратна длине блока
\endcode


 В приведенном выше фрагменте исходный буффер сначала зашифровывается за один вызов функции,
 а потом фрагментами, длина которых кратна длине блока используемого алгоритма блочного шифрования.
 Результаты зашифрования должны совпадать в обоих случаях. Указанное поведение функции позволяет
 зашифровывать данные в случае, когда они поступают фрагментами, например из сети, или когда хранение
 данных полностью в оперативной памяти нецелесообразно (например, шифрование больших файлов).

    @param bkey Контекст ключа алгоритма блочного шифрования, на котором происходит
    зашифрование или расшифрование информации.
    @param in Указатель на область памяти, где хранятся входные (открытые) данные.
    @param out Указатель на область памяти, куда помещаются зашифрованные данные
    (этот указатель может совпадать с `in`).
    @param size Размер зашировываемых данных (в байтах).
    @param iv Указатель на произвольную область памяти - синхропосылку. Область памяти, на
    которую указывает `iv` не изменяется.
    @param iv_size Длина синхропосылки в байтах. Согласно  стандарту ГОСТ Р 34.13-2015 длина
    синхропосылки должна быть ровно в два раза меньше, чем длина блока, то есть 4 байта для Магмы
    и 8 байт для Кузнечика. Значение `iv_size`, отличное от указанных, может привести к
    возникновению ошибки.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается \ref ak_error_ok (ноль)                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_ctr( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                                     ak_pointer iv, size_t iv_size )
{
  ak_int64 blocks = (ak_int64)( size/bkey->bsize ),
             tail = (ak_int64)( size%bkey->bsize );
  ak_uint64 x, yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
  int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

  if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                "wrong value for \"openssl_compability\" option" );

 /* проверяем, установлен ли ключ */
  if(( bkey->key.flags&key_flag_set_key ) == 0 ) return ak_error_message( ak_error_key_value,
                                    __func__, "using secret key context with undefined key value" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                   "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.value.counter < ( blocks + ( tail > 0 )))
    return ak_error_message( ak_error_low_key_resource,
                                                    __func__ , "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= ( blocks + ( tail > 0 ));

 /* выбираем, как вычислять синхропосылку проверяем флаг
    флаг поднимается при вызове функции с заданным значением синхропосылки и
    всегда опускается при обработке данных, не кратных длина блока */
  if(( iv == NULL ) || ( iv_size == 0 )) { /* запрос на использование внутреннего значения */

    if( bkey->key.flags&key_flag_not_ctr )
      return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                           "function call with undefined value of initial vector" );
  } else {
    /* данное значение определяет в точности половину блока */
     size_t halfsize = bkey->bsize >> 1 ;

    /* проверяем длину синхропосылки (если меньше половины блока, то плохо)
        если больше, то нормально - лишнее простое не используется */
     if( iv_size < halfsize )
       return ak_error_message( ak_error_wrong_iv_length, __func__,
                                                              "incorrect length of initial value" );
    /* помещаем во внутренний буффер значение синхропосылки */
     memset( bkey->ivector, 0, ( bkey->ivector_size = bkey->bsize ));
    /* слишком большое значение iv_size может привести к выходу за границы памяти,
                                                       выделенной под переменную ivector */
     memcpy( bkey->ivector + halfsize*((unsigned int)(1-oc)), iv, ak_min( halfsize, iv_size ));

    /* поднимаем значение флага: синхропосылка установлена */
     bkey->key.flags = ( bkey->key.flags&( ~key_flag_not_ctr ));
    }

 /* обработка основного массива данных (кратного длине блока) */
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита (Магма) */
      while( blocks > 0 ) {
        #ifndef AK_LITTLE_ENDIAN
          x = oc ? ((ak_uint64 *)bkey->ivector)[0] : bswap_64( ((ak_uint64 *)bkey->ivector)[0] );
        #else
          x = oc ? bswap_64( ((ak_uint64 *)bkey->ivector)[0] ) : ((ak_uint64 *)bkey->ivector)[0];
        #endif
          bkey->encrypt( &bkey->key, bkey->ivector, yaout );
          *outptr = *inptr ^ yaout[0];
          outptr++; inptr++;

        #ifndef AK_LITTLE_ENDIAN
          ((ak_uint64 *)bkey->ivector)[0] = oc ? ++x : bswap_64( ++x );
        #else
          ((ak_uint64 *)bkey->ivector)[0] = oc ? bswap_64( ++x ) : ++x;
        #endif
        --blocks;
      }
    break;

    case 16: /* шифр с длиной блока 128 бит (Кузнечик) */
     #ifndef AK_LITTLE_ENDIAN
      x = bswap_64( ((ak_uint64 *)bkey->ivector)[oc] );
     #else
      x = ((ak_uint64 *)bkey->ivector)[oc];
     #endif

      while( blocks > 0 ) {
          bkey->encrypt( &bkey->key, bkey->ivector, yaout );
          *outptr = *inptr ^ yaout[0]; outptr++; inptr++;
          *outptr = *inptr ^ yaout[1]; outptr++; inptr++;

       /* за элементарное сложение с единицей приходится платить одним разворотом */
        #ifdef AK_LITTLE_ENDIAN
         ((ak_uint64 *)bkey->ivector)[oc] = oc ? bswap_64(++x) : ++x;
        #else
          ((ak_uint64 *)bkey->ivector)[oc] = oc ? ++x : bswap_64( ++x );
        #endif                    /* здесь мы не учитываем знак переноса
                                     потому что объем данных на одном ключе не должен
                                     превышать 2^64 блоков (контролируется через ресурс ключа) */
        --blocks;
      }
    break;

    default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
  }

 /* обрабатываем хвост сообщения */
  if( tail ) {
    int i;
    bkey->encrypt( &bkey->key, bkey->ivector, yaout );
    for( i = 0; i < tail; i++ ) /* теперь мы гаммируем tail байт, используя для этого
                                   старшие байты (most significant bytes) зашифрованного счетчика */
       if( oc ) {
        /* для блочного шифра Магма этот код выдает результат отличный от того, что вырабатывает openssl
           для блочного шифра Кузнечик результат совпадает

           поиск того, почему Магма реализована по другому - задача за гранью добра и зла */
         ( (ak_uint8*)outptr )[i] = ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[i];

       } else ( (ak_uint8*)outptr )[i] =
           ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[bkey->bsize - (size_t)(tail-i)];

   /* запрещаем дальнейшее использование функции на данном значении синхропосылки,
                                           поскольку обрабатываемые данные не кратны длине блока. */
    memset( bkey->ivector, 0, sizeof( bkey->ivector ));
    bkey->key.flags = bkey->key.flags&( ~key_flag_not_ctr );
  }

 /* перемаскируем ключ */
  if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of secret key" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_cbc( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                                    ak_pointer iv, size_t iv_size )
 {
   ak_int64 blocks = 0;
   ak_uint64 yaout[2], z = iv_size / bkey->bsize;
   ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out, *ivector = (ak_uint64 *)bkey->ivector;
   int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

   if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                 "wrong value for \"openssl_compability\" option" );

  /* выполняем проверку размера входных данных */
   if( size%bkey->bsize != 0 )
     return ak_error_message( ak_error_wrong_block_cipher_length,
                             __func__ , "the length of input data is not divided by block length" );

  /* проверяем целостность ключа */
   if( bkey->key.check_icode( &bkey->key ) != ak_true )
     return ak_error_message( ak_error_wrong_key_icode,
                                         __func__, "incorrect integrity code of secret key value" );
  /* уменьшаем значение ресурса ключа */
   blocks = ( ak_int64 ) (size/bkey->bsize);
   if( bkey->key.resource.value.counter < blocks )
     return ak_error_message( ak_error_low_key_resource,
                                                    __func__ , "low resource of block cipher key" );
    else bkey->key.resource.value.counter -= blocks;

  /* проверяем длину синхропосылки */
   if(( iv_size < bkey->bsize ) ||                              /* если меньше  блока */
      ( iv_size%bkey->bsize != 0 ) ||             /* если длина не кратна длине блока */
      ( iv_size > sizeof( bkey->ivector ))) /* если длина больше, чем выделено памяти */
     return ak_error_message( ak_error_wrong_iv_length, __func__,
                                                              "incorrect length of initial value" );
   memcpy( bkey->ivector, iv, iv_size );

  /* теперь приступаем к зашифрованию данных */
   switch( bkey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
           if( z == 0 ) {
             ivector = (ak_uint64 *)out;
           }
           yaout[0] = *inptr ^ *ivector; inptr++; ivector++;
           bkey->encrypt( &bkey->key, yaout, outptr );
           outptr++;
           --blocks;
           --z;
       }
     break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
           if( z == 0 ) {
               ivector = (ak_uint64 *)out;
           }
           yaout[0] = *inptr ^ *ivector; inptr++; ivector++;
           yaout[1] = *inptr ^ *ivector; inptr++; ivector++;
           bkey->encrypt( &bkey->key, yaout, outptr );
           outptr+=2;
           --blocks;
           --z;
       }
     break;
     default: return ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
   }
  /* перемаскируем ключ */
   if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
     ak_error_message( error, __func__ , "wrong remasking of secret key" );

  return ak_error_ok;
 }

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_cbc( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                                    ak_pointer iv, size_t iv_size )
 {
  ak_int64 blocks = 0;
  ak_uint64 yaout[2], z = iv_size / bkey->bsize;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out, *ivector = (ak_uint64 *)bkey->ivector;
  int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

  if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                "wrong value for \"openssl_compability\" option" );

 /* выполняем проверку размера входных данных */
  if( size%bkey->bsize != 0 )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode,
                                        __func__, "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  blocks = (ak_int64 ) (size/bkey->bsize);
  if( bkey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                                   __func__ , "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= blocks;

 /* проверяем длину синхропосылки */
  if(( iv_size < bkey->bsize ) ||                              /* если меньше  блока */
     ( iv_size%bkey->bsize != 0 ) ||             /* если длина не кратна длине блока */
     ( iv_size > sizeof( bkey->ivector ))) /* если длина больше, чем выделено памяти */
    return ak_error_message( ak_error_wrong_iv_length, __func__,
                                                             "incorrect length of initial value" );
   memcpy(bkey->ivector, iv, iv_size);

 /* теперь приступаем к расшифрованию данных */
  switch( bkey->bsize ) {
    case  8: /* шифр с длиной блока 64 бита */
      while( blocks > 0 ) {
          bkey->decrypt( &bkey->key, inptr, yaout );
          if( z == 0 ) {
              ivector = (ak_uint64 *)in;
          }
          *outptr = yaout[0] ^ *ivector; outptr++; ivector++;
          inptr++;
          --blocks;
          --z;
      }
    break;

    case 16: /* шифр с длиной блока 128 бит */
      while( blocks > 0 ) {
          bkey->decrypt( &bkey->key, inptr, yaout );
          if( z == 0 ) {
              ivector = (ak_uint64 *)in;
          }
          *outptr = yaout[0] ^ *ivector; outptr++; ivector++;
          *outptr = yaout[1] ^ *ivector; outptr++; ivector++;
          inptr+=2;
          --blocks;
          --z;
      }

    break;
    default: return ak_error_message( ak_error_wrong_block_cipher,
                                          __func__ , "incorrect block size of block cipher key" );
  }
 /* перемаскируем ключ */
  if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of secret key" );

 return ak_error_ok;
 }

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_ofb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                                     ak_pointer iv, size_t iv_size )
{
  ak_uint8 *vecptr = NULL;
  ak_int64 blocks = (ak_int64)( size/bkey->bsize ),
             tail = (ak_int64)( size%bkey->bsize );
  ak_uint64 yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
  int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );
  unsigned long counter = 0, z = iv_size / bkey->bsize; /* во сколько раз синхрпосылка длиннее блока */

  if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                               "wrong value for \"openssl_compability\" option" );
 /* проверяем целостность ключа */
  if( bkey->key.check_icode( &bkey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                   "incorrect integrity code of secret key value" );
 /* уменьшаем значение ресурса ключа */
  if( bkey->key.resource.value.counter < ( blocks + ( tail > 0 )))
    return ak_error_message( ak_error_low_key_resource,
                                                     __func__ , "low resource of block cipher key" );
   else bkey->key.resource.value.counter -= ( blocks + ( tail > 0 ));

  /* проверяем длину синхропосылки */
  if(( iv == NULL ) || ( iv_size == 0 )) { /* запрос на использование внутреннего значения */

    if( bkey->key.flags&key_flag_not_ctr )
      return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                           "function call with undefined value of initial vector" );
  }
  /* Если длина синхропосылки больше 64 байт (размер буфера ivector
   * ИЛИ не кратна размеру блока данных шифра (т.к. по ГОСТу m=n*z, z - целое),
   * завершить работу */
  if(( iv_size > 64 ) || ( iv_size % bkey->bsize) )
      return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                               "function call with wrong value of initial vector" );

  /* помещаем во внутренний буффер значение синхропосылки */
   if( iv != NULL ) memcpy( bkey->ivector, iv, iv_size);
  /* поднимаем значение флага: синхропосылка установлена */
   bkey->key.flags = ( bkey->key.flags&( ~key_flag_not_ctr ))^key_flag_not_ctr;

   /* обработка основного массива данных (кратного длине блока) */
    switch( bkey->bsize ) {
        case 8: /* шифр с длиной блока 64 бита */
            while( blocks > 0 ) {
                bkey->encrypt( &bkey->key, &bkey->ivector[counter * bkey->bsize], yaout );
                *outptr = *inptr ^ yaout[0];
                outptr++; inptr++;
                /* Помещаем в текущий блок синхрпосылки выход encrypt и сдвигаем указатель синхропосылки */
                ((ak_uint64 *)bkey->ivector)[counter] = yaout[0];
                if (++counter == z) counter = 0;

                --blocks;
            }
        break;

        case 16: /* шифр с длиной блока 128 бит */
            while( blocks > 0 ) {
                vecptr = ( bkey->ivector + counter*bkey->bsize );
                bkey->encrypt( &bkey->key, vecptr, yaout );
                *outptr = *inptr ^ yaout[0]; outptr++; inptr++;
                *outptr = *inptr ^ yaout[1]; outptr++; inptr++;
                /* Помещаем в текущий блок синхрпосылки выход encrypt и сдвигаем указатель синхропосылки */
                ((ak_uint64 *)vecptr)[0] = yaout[0];
                ((ak_uint64 *)vecptr)[1] = yaout[1];
                if (++counter == z) counter = 0;

                --blocks;
            }

          break;

          default: return ak_error_message( ak_error_wrong_block_cipher,
                                                __func__ , "incorrect block size of block cipher key" );
    }

    /* обрабатываем хвост сообщения */
    if( tail ) {
      int i;
      bkey->encrypt( &bkey->key, bkey->ivector, yaout );
      for( i = 0; i < tail; i++ )
          ( (ak_uint8*)outptr)[i] =
              ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[i];

    /* запрещаем дальнейшее использование функции на данном значении синхропосылки,
                                            поскольку обрабатываемые данные не кратны длине блока. */
     memset( bkey->ivector, 0, sizeof( bkey->ivector ));
     bkey->key.flags = bkey->key.flags&( ~key_flag_not_ctr );
   }

  /* перемаскируем ключ */
   if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
     ak_error_message( error, __func__ , "wrong remasking of secret key" );

  return error;
 }

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_cfb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                                      ak_pointer iv, size_t iv_size )
 {
   ak_int64 blocks = (ak_int64)( size/bkey->bsize ),
              tail = (ak_int64)( size%bkey->bsize );
   ak_uint8 *vecptr = NULL;
   ak_uint64 yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
   int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );
   unsigned long i = 0, z = iv_size / bkey->bsize; // во сколько раз синхрпосылка длиннее блока

   if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                 "wrong value for \"openssl_compability\" option" );
  /* проверяем целостность ключа */
   if( bkey->key.check_icode( &bkey->key ) != ak_true )
     return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                    "incorrect integrity code of secret key value" );
  /* уменьшаем значение ресурса ключа */
   if( bkey->key.resource.value.counter < ( blocks + ( tail > 0 )))
     return ak_error_message( ak_error_low_key_resource,
                                                     __func__ , "low resource of block cipher key" );
    else bkey->key.resource.value.counter -= ( blocks + ( tail > 0 ));

  /* выбираем, как вычислять синхропосылку проверяем флаг
     флаг поднимается при вызове функции с заданным значением синхропосылки и
     всегда опускается при обработке данных, не кратных длине блока */
   if(( iv == NULL ) || ( iv_size == 0 )) { /* запрос на использование внутреннего значения */

     if( bkey->key.flags&key_flag_not_ctr )
       return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                            "function call with undefined value of initial vector" );
   } else {

     /* проверяем длину синхропосылки (если меньше длины блока, то плохо)
         если больше, то нормально - лишнее просто не используется */
      if( (iv_size % bkey->bsize) || (iv_size > 64) )
        return ak_error_message( ak_error_wrong_iv_length, __func__,
                                                               "incorrect length of initial value" );
     /* помещаем во внутренний буффер значение синхропосылки */
      memcpy(bkey->ivector, iv, iv_size);

     /* поднимаем значение флага: синхропосылка установлена */
      bkey->key.flags = ( bkey->key.flags&( ~key_flag_not_ctr ))^key_flag_not_ctr;
     }

  /* обработка основного массива данных (кратного длине блока) */
   switch( bkey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
           vecptr = (bkey->ivector + i*bkey->bsize);
           bkey->encrypt( &bkey->key, vecptr, yaout );
           *outptr = *inptr ^ yaout[0];
           ((ak_uint64 *)vecptr)[0] = *outptr;
           outptr++; inptr++;
           if (++i == z) i = 0;
           --blocks;
       }
     break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
           vecptr = (bkey->ivector + i*bkey->bsize );
           bkey->encrypt( &bkey->key, vecptr, yaout );
           *outptr = *inptr ^ yaout[0];
           ((ak_uint64 *)vecptr)[0] = *outptr; ++outptr; ++inptr;
           *outptr = *inptr ^ yaout[1];
           ((ak_uint64 *)vecptr)[1] = *outptr; ++outptr; ++inptr;
           if (++i == z) i = 0;
           --blocks;
       }
     break;

     default: return ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
   }

  /* обрабатываем хвост сообщения */
   if( tail ) {
     vecptr = (bkey->ivector + bkey->bsize * (i % (int)(iv_size / bkey->bsize)));
     bkey->encrypt( &bkey->key, vecptr, yaout );
     for( i = 0; i < (unsigned long)tail; i++ )
        ( (ak_uint8*)outptr)[i] = ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[i];

     /* запрещаем дальнейшее использование функции на данном значении синхропосылки,
                                               поскольку обрабатываемые данные не кратны длине блока. */
     memset( bkey->ivector, 0, sizeof( bkey->ivector ));
     bkey->key.flags = bkey->key.flags&( ~key_flag_not_ctr );
     /* перемаскируем ключ */
     if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
        ak_error_message( error, __func__ , "wrong remasking of secret key" );
   }
   return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_cfb( ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size,
                                                                      ak_pointer iv, size_t iv_size )
 {
   ak_int64 blocks = (ak_int64)( size/bkey->bsize ),
              tail = (ak_int64)( size%bkey->bsize );
   ak_uint8 *vecptr = NULL;
   ak_uint64 yaout[2], *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
   int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );
   unsigned long i = 0, z = iv_size / bkey->bsize; // во сколько раз синхрпосылка длиннее блока

   if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                 "wrong value for \"openssl_compability\" option" );
  /* проверяем целостность ключа */
   if( bkey->key.check_icode( &bkey->key ) != ak_true )
     return ak_error_message( ak_error_wrong_key_icode, __func__,
                                                    "incorrect integrity code of secret key value" );
  /* уменьшаем значение ресурса ключа */
   if( bkey->key.resource.value.counter < ( blocks + ( tail > 0 )))
     return ak_error_message( ak_error_low_key_resource,
                                                     __func__ , "low resource of block cipher key" );
    else bkey->key.resource.value.counter -= ( blocks + ( tail > 0 ));

  /* выбираем, как вычислять синхропосылку проверяем флаг
     флаг поднимается при вызове функции с заданным значением синхропосылки и
     всегда опускается при обработке данных, не кратных длине блока */
   if(( iv == NULL ) || ( iv_size == 0 )) { /* запрос на использование внутреннего значения */

     if( bkey->key.flags&key_flag_not_ctr )
       return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                            "function call with undefined value of initial vector" );
   } else {

     /* проверяем длину синхропосылки (если меньше длины блока, то плохо)
         если больше, то нормально - лишнее просто не используется */
      if( (iv_size % bkey->bsize) || (iv_size > 64) )
        return ak_error_message( ak_error_wrong_iv_length, __func__,
                                                               "incorrect length of initial value" );
     /* помещаем во внутренний буффер значение синхропосылки */
      memcpy(bkey->ivector, iv, iv_size);

     /* поднимаем значение флага: синхропосылка установлена */
      bkey->key.flags = ( bkey->key.flags&( ~key_flag_not_ctr ))^key_flag_not_ctr;
     }

  /* обработка основного массива данных (кратного длине блока) */
   switch( bkey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
           vecptr = (bkey->ivector + i*bkey->bsize);
           bkey->encrypt( &bkey->key, vecptr, yaout );
           *outptr = *inptr ^ yaout[0];
           ((ak_uint64 *)vecptr)[0] = *inptr;
           outptr++; inptr++;
           if (++i == z) i = 0;
           --blocks;
       }
     break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
           vecptr = (bkey->ivector + i*bkey->bsize );
           bkey->encrypt( &bkey->key, vecptr, yaout );
           *outptr = *inptr ^ yaout[0];
           ((ak_uint64 *)vecptr)[0] = *inptr; ++outptr; ++inptr;
           *outptr = *inptr ^ yaout[1];
           ((ak_uint64 *)vecptr)[1] = *inptr; ++outptr; ++inptr;
           if (++i == z) i = 0;
           --blocks;
       }
     break;

     default: return ak_error_message( ak_error_wrong_block_cipher,
                                           __func__ , "incorrect block size of block cipher key" );
   }

  /* обрабатываем хвост сообщения */
   if( tail ) {
     vecptr = (bkey->ivector + bkey->bsize * (i % (int)(iv_size / bkey->bsize)));
     bkey->encrypt( &bkey->key, vecptr, yaout );
     for( i = 0; i < (unsigned long)tail; i++ )
        ( (ak_uint8*)outptr)[i] = ( (ak_uint8*)inptr )[i]^( (ak_uint8 *)yaout)[i];

     /* запрещаем дальнейшее использование функции на данном значении синхропосылки,
                                               поскольку обрабатываемые данные не кратны длине блока. */
     memset( bkey->ivector, 0, sizeof( bkey->ivector ));
     bkey->key.flags = bkey->key.flags&( ~key_flag_not_ctr );
     /* перемаскируем ключ */
     if(( error = bkey->key.set_mask( &bkey->key )) != ak_error_ok )
        ak_error_message( error, __func__ , "wrong remasking of secret key" );
   }
   return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует последовательную комбинацию алгоритма выработки имитовставки HMAC и
    режима гаммирования данных, согласно ГОСТ Р 34.12-2015. В начале
    вычисляется имитовставка от объединения ассоцииированных данных и
    данных, подлежащих зашифрования. При этом предполагается, что ассоциированные данные
    расположены вначале. После этого, данные зашифровываются.

    Режим `ctr-hmac` \b должен использовать для шифрования и выработки имитовставки два
    различных ключа -- ключ алгоритма шифрования и ключ алгоритма hmac.

    Если указатель на ключ шифрования равен `NULL`, то шифрование данных не производится и указатель на
    зашифровываемые (plain data) и зашифрованные (cipher data) данные \b должен быть равен `NULL`;
    длина данных (size) также \b должна принимать нулевое значение.
    В этом случае результат работы функции должен быть эквивалентен результату работы
    функции ak_hmac_ptr().

    Если указатель на ключ выработки имитовставки равен `NULL`, то аутентификация данных не производится.
    В этом случае указатель на ассоциированные данные (associated data) \b должен быть равен `NULL`,
    указатель на имитовставку (icode) \b должен быть равен `NULL`, длина дополнительных данных \b должна
    равняться нулю.
    В этом случае результат работы функции должен быть эквивалентен результату работы
    функции ak_bckey_ctr().

    Ситуация, при которой оба указателя на ключ принимают значение `NULL` воспринимается как ошибка.

    @param encryptionKey ключ шифрования (указатель на struct bckey), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки)
           (указатель на struct hmac), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на зашифровываеме данные;
    @param out указатель на зашифрованные данные;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, куда будет помещено значение имитовставки;
           память должна быть выделена заранее; указатель может принимать значение NULL.
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;
           если значение icode_size меньше, чем длина блока, то возвращается запрашиваемое количество
           старших байт результата вычислений.

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_ctr_hmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  int error = ak_error_ok;

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                               "using null pointers both to encryption and authentication keys" );

 /* тестируем типы ключей */
  if(( encryptionKey != NULL ) && ((ak_bckey)encryptionKey)->key.oid->engine != block_cipher )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using non block cipher key for data encryption" );
  if(( authenticationKey != NULL ) &&
                                  ((ak_hmac)authenticationKey)->key.oid->engine != hmac_function )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "using non hmac key for checkin data integrity" );
 /* вычисляем имитовставку */
  if( authenticationKey != NULL ) {
    if(( error = ak_hmac_clean( authenticationKey )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect cleaning of hmac secret key context" );
    if(( error = ak_hmac_update( authenticationKey, adata, adata_size )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect updating of associated data" );
    if(( error = ak_hmac_finalize( authenticationKey, in, size, icode, icode_size )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect finalizing of integrity code" );
  }
 /* зашифровываем даные */
  if( encryptionKey != NULL ) {
    if(( error = ak_bckey_ctr( encryptionKey, in, out, size, iv, iv_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect data encryption" );
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных. Требования к передаваемым параметрам
    аналогичны требованиям, предъявляемым к параметрам функции ak_bckey_encrypt_ctr_hmac().

    @param encryptionKey ключ шифрования (указатель на struct bckey), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки)
           (указатель на struct hmac), должен быть инициализирован
           перед вызовом функции; может принимать значение `NULL`;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на расшифровываемые данные;
    @param out указатель на область памяти, куда будут помещены расшифрованные данные;
           данный указатель может совпадать с указателем in;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, в которой хранится значение имитовставки;
    @param icode_size размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;

    @return Функция возвращает \ref ak_error_ok, если значение имитовтсавки совпало с
            вычисленным в ходе выполнения функции значением; если значения не совпадают,
            или в ходе выполнения функции возникла ошибка, то возвращается код ошибки.             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_ctr_hmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  int error = ak_error_ok;

 /* проверки ключей */
  if(( encryptionKey == NULL ) && ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,
                               "using null pointers both to encryption and authentication keys" );

 /* тестируем типы ключей */
  if(( encryptionKey != NULL ) && ((ak_bckey)encryptionKey)->key.oid->engine != block_cipher )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using non block cipher key for data encryption" );
  if(( authenticationKey != NULL ) &&
                                  ((ak_hmac)authenticationKey)->key.oid->engine != hmac_function )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "using non hmac key for checkin data integrity" );
 /* расшифровываем даные */
  if( encryptionKey != NULL ) {
    if(( error = ak_bckey_ctr( encryptionKey, in, out, size, iv, iv_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect data decryption" );
  }
 /* вычисляем имитовставку */
  if( authenticationKey != NULL ) {
    ak_uint8 icode2[128];
    memset( icode2, 0, sizeof( icode2 ));

    if( ak_hmac_get_tag_size( authenticationKey ) > sizeof( icode2 ))
      return ak_error_message( ak_error_wrong_length, __func__,
                                                       "using hmac key with very huge tag size" );
    if(( error = ak_hmac_clean( authenticationKey )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect cleaning of hmac secret key context" );
    if(( error = ak_hmac_update( authenticationKey, adata, adata_size )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect updating of associated data" );
    if(( error = ak_hmac_finalize( authenticationKey, out, size, icode2, icode_size )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect finalizing of integrity code" );
    if( ak_ptr_is_equal_with_log( icode, icode2, icode_size )) error = ak_error_ok;
       else error = ak_error_not_equal_data;
  }

 return error;
}
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_bckey.c  */
/* ----------------------------------------------------------------------------------------------- */
