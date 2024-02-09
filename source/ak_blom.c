/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_blom.с                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey-blom-doc Реализация схемы Блома распределения ключевой информации
 *  @{
   Схема Блома представляет собой механизм выработки секретных симметричных ключей парной связи,
   предоставляющий действенную альтернативу инфрастуктуре открытых ключей.
   Ключевая система, построенная на схеме Блома, рекомендована к использованию
   в рекомендациях по стандартизации Р 1323565.1.018-2018, Р 1323565.1.019-2018 и Р 1323565.1.028–2019.

   Пусть заданы конечное поле \f$ GF(2^n)\f$, где \f$ n \in \{ 256, 512 \} \f$
   и параметр безопасности \f$ m \f$.
   Основным ключевым элементом схемы Блома является мастер-ключ, представленный в виде
   секретной симметричной матрицы

   \f\[ A = (a_{i,j})_{i,j = 0}^{m-1} =
           \left( \begin{array}{c}
           a_{0,0\ }a_{0,1}\dots \ a_{0,m-1} \\
           a_{1,0}\ a_{1,1}\dots \ a_{1,m-1} \\
           \dots \  \\
           a_{m,0\ }a_{m,1}\dots \ a_{m-1,m-1} \end{array}
           \right),
   \f\]
  где \f$ a_{i,j} = a_{j,i},\: 0 \le i < m,\: 0 \le j < m \f$ и \f$ a_{i,j} \in GF(2^n)\f$.
  Указаная матрица может быть создана с помощью функции ak_blomkey_create_matrix().

  С матрицей может быть связан многочлен
  \f\[ f(x,y)= \sum_{i=0}^{m-1} \sum_{j=0}^{m-1} a_{i,j}x^i y^j,\quad f(x,y) \in GF(2^{n})[x,y], \f\]
  удволетворяющий равенству \f$ f(x,y) = f(y,x) \f$.

  Пусть абоненты `a` и `b` имеют идентификаторы IDa и IDb, тогда ключ парной связи между
  указанными абонентами определяется равенством

  \f\[ Kab = f( \texttt{Streebog}_n(IDa), \texttt{Streebog}_n(IDb) ). \f\]

  Для возможности вступать в связь с несколькими абонентами,
  каждый абонент `a` может выработать из мастер-ключа свой уникальный ключ, представляющий собой
  вектор

  \f\[ Ka = (b_0, b_1, \ldots, b_{m-1}),  \f\]

  в котором координаты \f$ b_i \in GF(2^n), \: 0 \le i < m \f$, определены равенствами

  \f[ b_i = \sum_{j=0}^{m-1} a_{i,j} \big( \texttt{Streebog}_n(IDa) \big)^j \f]

  и могут быть связаны с многочленом

  \f\[ f_a(x) = f\left(x, \texttt{Streebog}_n(IDa)\right) = \sum_{i=0}^{m-1} b_ix^i,
   \quad f_a(x) \in GF(2^{n})[x]. \f\]

  Тогда для связи с любым абонентом, имеющим идентификатор IDb,
  абоненту `a` достаточно вычислить ключ парной связи, определяемый равенством
  \f\[ Kab = f_a\left( \texttt{Streebog}_n(IDb) \right). \f\]

  Создание ключа абонента \f$ Ka \f$ выполняется с помощью функции ak_blomkey_create_abonent_key().

  Создание ключа парной связи \f$ Kab \f$ - с помощью функции ak_blomkey_create_pairwise_key_as_ptr().

  Удаление созданных ключей выполняется с помощью функции ak_blomkey_destroy().

  Экспорт и импорт абонентских ключей и мастер-ключа из файловых контейнеров осуществляется
  с помощью функций
 
  - ak_blomkey_export_to_file_with_password(),
  - ak_blomkey_import_from_file_with_password().

  Отметим, что неприводимые многочлены, используемые для реализации элементарных операций
  в конечном поле \f$ GF(2^n)\f$, определены в файле ak_gf2n.c                                  @} */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_blomkey_check_icode( ak_blomkey bkey )
{
  ak_uint8 value[32];

  if( bkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to blom key context" );
    return ak_false;
  }
  if( bkey->data == NULL ) {
    ak_error_message( ak_error_undefined_value, __func__, "checking the null pointer memory" );
    return ak_false;
  }

 /* вычисляем контрольную сумму и сравниваем */
  memset( value, 0, sizeof( value ));
  ak_hash_ptr( &bkey->ctx, bkey->data,
                    bkey->type == blom_matrix_key ? (bkey->size)*(bkey->size)*bkey->count :
                                                             (bkey->size)*bkey->count, value, 32 );
  if( ak_ptr_is_equal( value, bkey->icode, 32 ) == ak_false ) {
    ak_error_message( ak_error_not_equal_data, __func__, "integrity code is wrong" );
    return ak_false;
  }
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! В ходе своего выполнения функция вырабатывает симметричную матрицу,
    состоящую из (`size`)x(`size`) элементов конечного поля \f$ GF(2^n)\f$, где `n` это количество
    бит (задается параметром `count`). Например, для поля \f$ GF(2^{256})\f$ величина `count` должна
    принимать значение 32.

    \param bkey указатель на контекст мастер-ключа
    \param size размер матриц
    \param count количество октетов (!), определяющих размер конечного поля;
    допустимыми значениями являются \ref ak_galois256_size = 32 и \ref ak_galois512_size = 64.
    \param generator указатель на контекст генератора случайных значений.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_create_matrix( ak_blomkey bkey, const ak_uint32 size,
                                                      const ak_uint32 count, ak_random generator )
{
  int error = ak_error_ok;
  ak_uint32 column = 0, row = 0;
  size_t memsize = size*size*count;

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( size > 4096 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                        "using very huge size for secret matrix" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__, "using zero field size" );
  if(( count != ak_galois256_size ) && ( count != ak_galois512_size ))
   return ak_error_message_fmt( ak_error_undefined_value, __func__,
            "this function accepts only 32 or 64 octets galois fields, but requested: %u", count );
  bkey->type = blom_matrix_key;
  bkey->count = count;
  bkey->size = size;
  if(( bkey->data = malloc( memsize + 16 )) == NULL ) /* 16 это размер имитовставки */
    return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );

  memset( bkey->data, 0, memsize + 16 );
  for( column = 0; column < size; column++ ) {
    /* копируем созданное ранее */
     for( row = 0; row < column; row++ ) memcpy( bkey->data + column*count*size+row*count,
                                     ak_blomkey_get_element_by_index( bkey, row, column ), count );
    /* создаем новое */
     ak_random_ptr( generator, bkey->data+column*count*(size+1),( size - column )*count );
  }
  
  switch( bkey->count ) {
    case ak_galois256_size: error = ak_hash_create_streebog256( &bkey->ctx );
                            break;
    case ak_galois512_size: error = ak_hash_create_streebog512( &bkey->ctx );
                            break;
    default: ak_error_message( error = ak_error_undefined_value, __func__,
                                       "this function accepts only 256 or 512 bit galois fields" );
  }
  if( error != ak_error_ok ) {
    ak_blomkey_destroy( bkey );
    return ak_error_message( error, __func__, "incorrect creation of hash function context" );
  }
  if(( error = ak_hash_ptr( &bkey->ctx, bkey->data, memsize,
                                    bkey->icode, 32 )) != ak_error_ok ) ak_blomkey_destroy( bkey );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Вырабатываемый ключ предназначается для конкретного абонента и
    однозначно зависит от его идентификатора и мастер-ключа.
    \param bkey указатель на контекст создаваемого ключа абонента
    \param matrix указатель на контекст мастер-ключа
    \param id указатель на идентификатор абонента
    \param size длина идентификатора (в октетах)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_create_abonent_key( ak_blomkey bkey, ak_blomkey matrix,
                                                               ak_pointer id, const size_t idsize )
{
  ak_uint8 value[64];
  size_t memsize = 0;
  ak_int32 column = 0;
  ak_uint32 i, row = 0;
  int error = ak_error_ok;

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to abonent's key" );
  if( matrix == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to blom master key" );
  if( matrix->type != blom_matrix_key ) return ak_error_message( ak_error_wrong_key_type,
                                                   __func__, "incorrect type of blom secret key" );
  if(( id == NULL ) || ( !idsize )) return ak_error_message( ak_error_undefined_value, __func__,
                                                          "using undefined abonent's identifier" );
  if( !ak_blomkey_check_icode( matrix ))
    return ak_error_message( ak_error_get_value(), __func__, "using wrong blom master key" );

  memset( bkey, 0, sizeof( struct blomkey ));
  bkey->count = matrix->count;
  bkey->size = matrix->size;
  bkey->type = blom_abonent_key;

 /* создаем контекст хеш-функции */
  if(( error = ak_hash_create_oid( &bkey->ctx, matrix->ctx.oid )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of hash function context" );
 /* формируем хэш от идентификатора */
  if(( error = ak_hash_ptr( &bkey->ctx, id, idsize, value, bkey->count )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect evauation of initial hash value" );

 /* формируем ключевые данные */
  if(( bkey->data = malloc( ( memsize = bkey->size*matrix->count ) + 16 )) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );

  memset( bkey->data, 0, memsize + 16 );
  for( row = 0; row < bkey->size; row++ ) { /* схема Горнера для вычисления значений многочлена */
     ak_uint8 *sum = bkey->data + row*bkey->count;
     memset( sum, 0, bkey->count );
     for( column = bkey->size - 1; column >= 0; column-- ) {
        ak_uint8 *key = ak_blomkey_get_element_by_index( matrix, row, column );
        if( bkey->count == ak_galois256_size ) ak_gf256_mul( sum, sum, value );
         else ak_gf512_mul( sum, sum, value );
        for( i = 0; i < ( bkey->count >> 3 ); i++ ) ((ak_uint64 *)sum)[i] ^= ((ak_uint64 *)key)[i];
     }
  }

  if(( error = ak_hash_ptr( &bkey->ctx, bkey->data, memsize,
                                    bkey->icode, 32 )) != ak_error_ok ) ak_blomkey_destroy( bkey );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает общий для двух абонентов секретный вектор и
    помещает его в контекст секретного ключа парной связи с заданным oid
    (функция релизует действия `new` и `set_key`).

    \param bkey указатель на контекст ключа абонента
    \param id указатель на идентификатор абонента, с которым вырабатывается ключ парной связи
    \param idsize длина идентификатора (в октетах)
    \param oid идентификатор алгоритма, для которого предназначен ключ парной связи
    (в настоящее время поддерживаются только секретные ключи блочных алгоритмов шифрования
     и ключи алгоритмов HMAC).
    \return Функция возвращает указатель на созданный контекст секретного ключа.
    В случае возникновения ошибки возвращается `NULL`. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_blomkey_new_pairwise_key( ak_blomkey bkey,
                                                   ak_pointer id, const size_t idsize, ak_oid oid )
{
  ak_uint8 sum[64];
  ak_pointer key = NULL;
  struct random generator;
  int error = ak_error_ok;

 /* проверяем, что заданый oid корректно определяет секретный ключ */
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to pairwise key identifier" );
    return NULL;
  }
  if( oid->mode != algorithm ) {
    ak_error_message( ak_error_oid_mode, __func__, "using wrong mode to pairwise key identifier" );
    return  NULL;
  }
  if(( oid->engine != block_cipher ) && ( oid->engine != hmac_function )) {
    ak_error_message( ak_error_oid_engine, __func__,
                                                 "using wrong engine to pairwise key identifier" );
  }
  if(( error = ak_blomkey_create_pairwise_key_as_ptr( bkey, id,
                                                   idsize, sum, sizeof( sum ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong generation of pairwise key" );
    return NULL;
  }

 /* формируем ключ парной связи для заданного пользователем алгоритма */
  if(( key = ak_oid_new_object( oid )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong generation of pairwise key" );
    return NULL;
  }
  if(( error = oid->func.first.set_key( key, sum,
                              ak_min( bkey->count, ((ak_skey)key)->key_size ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of pairwise key value" );
    ak_oid_delete_object( oid, key );
    key = NULL;
  }

  if( ak_random_create_lcg( &generator ) == ak_error_ok ) {
    ak_ptr_wipe( sum, 64, &generator );
    ak_random_destroy( &generator );
  }

 return key;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает общий для двух абонентов секретный вектор и
    помещает его в заданную область памяти.

    \param bkey указатель на контекст ключа абонента
    \param id указатель на идентификатор абонента, с которым вырабатывается ключ парной связи
    \param size длина идентификатора (в октетах)
    \param key указатель на область памяти, в которую помещается ключ парной связи
    \param keysize размер доступной области памяти (в октетах); данное значение должно быть
     не менее, чем размер ключа парной связи (см. поле `bkey->count`)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_create_pairwise_key_as_ptr( ak_blomkey bkey,
                               ak_pointer id, const size_t idsize, ak_pointer key, size_t keysize )
{
  ak_uint32 i = 0;
  ak_int32 row = 0;
  ak_uint8 value[64];
  int error = ak_error_ok;

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to abonent's key" );
  if(( id == NULL ) || ( !idsize )) return ak_error_message( ak_error_undefined_value, __func__,
                                                          "using undefined abonent's identifier" );
  if( bkey->type != blom_abonent_key ) return ak_error_message( ak_error_wrong_key_type,
                                                   __func__, "incorrect type of blom secret key" );
  if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to pairwise key" );
  if( keysize < bkey->count ) return ak_error_message( ak_error_null_pointer, __func__,
                                           "insufficient memory size for storing a pairwise key" );
  if( !ak_blomkey_check_icode( bkey ))
    return ak_error_message( ak_error_get_value(), __func__, "using wrong blom master key" );

 /* формируем хэш от идентификатора */
  if(( error = ak_hash_ptr( &bkey->ctx, id, idsize, value, bkey->count )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect evauation of initial hash value" );

  memset( key, 0, bkey->count );
  for( row = bkey->size - 1; row >= 0; row-- ) {
     ak_uint8 *element = ak_blomkey_get_element_by_index( bkey, row, 0 );
     if( bkey->count == ak_galois256_size ) ak_gf256_mul( key, key, value );
       else ak_gf512_mul( key, key, value );
     for( i = 0; i < ( bkey->count >> 3 ); i++ ) ((ak_uint64 *)key)[i] ^= ((ak_uint64 *)element)[i];
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param bkey указатель на контекст мастер-ключа или ключа абонента
    \param row номер строки
    \param column номер столбца; для ключей абонентов данное значение не учитывается.
    \return В случае успеха, функция возвращает указатель на область памяти, содержащей
    зазанный элемент. В случае возникновения ошибки возвращается `NULL`.                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_blomkey_get_element_by_index( ak_blomkey bkey, const ak_uint32 row,
                                                                          const ak_uint32 column )
{
  if( bkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to blom matrix " );
    return NULL;
  }
  if(( row >= bkey->size ) || ( column >= bkey->size )) {
    ak_error_message( ak_error_wrong_index, __func__, "parameter is very large" );
    return NULL;
  }
  switch( bkey->type ) {
   case blom_matrix_key: return bkey->data + (bkey->size*row + column)*bkey->count;
   case blom_abonent_key: return bkey->data + row*bkey->count;
   default:
     ak_error_message_fmt( ak_error_undefined_value, __func__ ,
                                                "incorrect type of blom matrix (%u)", bkey->type );
  }
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param bkey указатель на контекст мастер-ключа или ключа абонента
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_destroy( ak_blomkey bkey )
{
  struct random generator;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "destroying null pointer to blom context" );
  ak_hash_destroy( &bkey->ctx );
  if( bkey->data != NULL ) {
    ak_random_create_lcg( &generator );
    ak_ptr_wipe( bkey->data, /* очищаем либо матрицу, либо строку */
       bkey->type == blom_matrix_key ?
                (bkey->size)*(bkey->size)*(bkey->count) : (bkey->size)*(bkey->count), &generator );
    ak_random_destroy( &generator );
    free( bkey->data );
  }
  memset( bkey, 0, sizeof( struct blomkey ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для сохранения ключа используется преобразование KExp15, регламентируемое
    рекомендациями по стадартизации Р 1323565.1.017-2018.

    Формат хранения данных определяется следующим образом.

   \code
      IV || CTR( eKey, Key || CMAC( iKey, IV || Key ))
   \endcode

    Ключи шифрования `eKey` и имитозащиты `iKey` вырабатываются из пароля
    с помощью преобразования pbkdf2, см. функцию ak_bckey_create_key_pair_from_password().

    Вектор IV формируется следующим образом:

    - первые 8 октетов - значение синхропосылки для режима гаммирования,
    - два октета - значение числа итераций в алгоритме pbkdf2,
    - один октет - тип ключа (bkey->type),
    - один октет - размер элемента поля (bkey->count),
    - четыре октета - размерность матрицы (bkey->size).

    Если имя файла для сохранения ключа не определено,
    то функция формирует его самостоятельно.

    \param bkey указатель на контекст мастер-ключа или ключа-абонента
    \param password пароль, из которого вырабатывается ключ шифрования ключа
    \param pass_size длина пароля (в октетах)
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `fsize` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param fsize  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_export_to_file_with_password( ak_blomkey bkey, const char *password,
                                      const size_t pass_size, char *filename, const size_t fsize )
{
  struct file fs;
  int error = ak_error_ok;
  struct random generator;
  size_t memsize, iter = ak_libakrypt_get_option_by_name( "pbkdf2_iteration_count" );
  struct bckey ekey, ikey;
  size_t i, j, blocks, lblocks, ltail;
  ak_uint8 iv[16], buffer[1024], *ptr = NULL;

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
 /* определяем заголовок:
    - первые 8 октетов - значение синхропосылки для режима гаммирования
    - два октета - значение числа итераций в алгоритме pbkdf
    - один октет - тип ключа (bkey->type)
    - один октет - размер элемента поля (bkey->count)
    - четыре октета - размерность матрицы (bkey->size) */

  if(( error = ak_random_create_lcg( &generator )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of random number generator");
  ak_random_ptr( &generator, iv, sizeof( iv ));
  iv[8]  = (iter >> 8)&0xFF;
  iv[9]  = iter&0xFF; /* помещаем число итераций в big-endian формате */
  iv[10] = (ak_uint8) bkey->type;    /* сохраняем тип ключа */
  iv[11] = bkey->count; /* количество октетов в одном элементе */
  iv[12] = ( bkey->size >> 24)&0xFF; /* сохраняем значение size */
  iv[13] = ( bkey->size >> 16)&0xFF;
  iv[14] = ( bkey->size >>  8)&0xFF;
  iv[15] = bkey->size&0xFF;
  ak_random_destroy( &generator );

 /* вычисляем размер ключевых данных */
  if( bkey->type == blom_matrix_key ) memsize = (bkey->size)*(bkey->size)*(bkey->count);
   else memsize = (bkey->size)*(bkey->count);
  if( memsize%16 != 0 ) return ak_error_message( ak_error_wrong_key_length, __func__,
                                                               "unexpected length of secret key" );
  if(( blocks = memsize/16 ) == 0 )
    return ak_error_message( ak_error_wrong_key_length, __func__, "using short secret key" );

 /* создаем ключи */
  if(( error = ak_bckey_create_key_pair_from_password( &ekey, &ikey,
       ak_oid_find_by_name( "kuznechik" ), password, pass_size, iv, 16, iter )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of key pair" );

 /* вычисляем контрольную сумму, которая будет сохранена в файл */
  ikey.key.resource.value.counter = blocks + 1;
  ak_bckey_cmac_clean( &ikey );
  ak_bckey_cmac_update( &ikey, iv, 16 );
  if( blocks > 1 ) ak_bckey_cmac_update( &ikey, bkey->data, memsize - 16 );
  ak_bckey_cmac_finalize( &ikey, bkey->data + memsize - 16, 16, bkey->data + memsize, 16 );

 /* создаем имя файла и сохраняем данные */
  if(( error = ak_skey_generate_file_name_from_buffer( iv, 8,
                                            filename, fsize, asn1_der_format )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of secret key filename" );
    goto labex;
  }

 /* открытие и запись */
  if(( error = ak_file_create_to_write( &fs, filename )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect file creation" );
    goto labex;
  }
  if( ak_file_write( &fs, iv, 16 ) < 0 ) {
    ak_error_message( error, __func__, "incorrect writing a file header" );
    goto labex2;
  }

 /* сохраняем данные в оптимальном виде */
  ekey.key.resource.value.counter = blocks + 1;
  switch( bkey->type ) {
   case blom_matrix_key:                   /* сохраняем только существенные данные, т.е. */
    /* фактически, мы сохраняем верхнетреугольную матрицу, отбрасывая симметричную часть */
     for( i = 0; i < bkey->size; i++ ) {
        memsize = ( bkey->size - i )*bkey->count;
        if( i == ( bkey->size - 1 )) memsize += 16; /* добавляем контрольную сумму */

        ltail = ( memsize )%sizeof( buffer );
        lblocks = ( memsize - ltail )/sizeof( buffer );
        ptr = bkey->data + i*bkey->count*(bkey->size + 1);

        for( j = 0; j < lblocks; j++ ) {
           ak_bckey_ctr( &ekey, ptr, buffer, sizeof( buffer ), j == 0 ? iv : NULL, 8 );
           ptr += sizeof( buffer );
           if( ak_file_write( &fs, buffer, sizeof( buffer )) < 0 ) {
             ak_error_message( error = ak_error_write_data, __func__,
                                                              "incorrect writing encrypted data" );
             goto labex2;
           }
        }
        if( ltail ) {
          ak_bckey_ctr( &ekey, ptr, buffer, ltail, NULL, 0 );
          if( ak_file_write( &fs, buffer, ltail ) < 0 ) {
            ak_error_message( error = ak_error_write_data, __func__,
                                                              "incorrect writing encrypted tail" );
            goto labex2;
          }
        }
     }
     break;

   case blom_abonent_key: /* в этом случае сохраняем все данные, без выбросов */
     ptr = bkey->data;
     ltail = ( memsize + 16 )%sizeof( buffer );
     lblocks = ( memsize + 16 - ltail )/sizeof( buffer );

     for( i = 0; i < lblocks; i++ ) {
        ak_bckey_ctr( &ekey, ptr, buffer, sizeof( buffer ), i == 0 ? iv : NULL, 8 );
        ptr += sizeof( buffer );
        if( ak_file_write( &fs, buffer, sizeof( buffer )) < 0 ) {
          ak_error_message( error = ak_error_write_data, __func__,
                                                              "incorrect writing encrypted data" );
          goto labex2;
        }
     }
     if( ltail ) {
       ak_bckey_ctr( &ekey, ptr, buffer, ltail, NULL, 0 );
       if( ak_file_write( &fs, buffer, ltail ) < 0 ) {
         ak_error_message( error = ak_error_write_data, __func__,
                                                              "incorrect writing encrypted tail" );
         goto labex2;
       }
     }
     break;

   default: ak_error_message( error = ak_error_wrong_key_type, __func__,
                                                          "using secret key with incorrect type" );
     goto labex;
  }

  labex2:
    ak_file_close( &fs );
  labex:
   ak_bckey_destroy( &ekey );
   ak_bckey_destroy( &ikey );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно реализует действия `create` и `set_key`, считывая данные, сохраненные
    ранее функцией ak_blomkey_export_to_file_with_password()

    \param bkey указатель на контекст создаваемого мастер-ключа или ключа-абонента
    \param password пароль, из которого вырабатывается ключ шифрования ключа
    \param pass_size длина пароля (в октетах)
    \param filename указатель на строку, содержащую имя файла с ключевой информацией
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_import_from_file_with_password( ak_blomkey bkey,
                                    const char *password, const size_t pass_size, char *filename )
{
  struct file fs;
  ssize_t len = 0;
  int error = ak_error_ok;
  struct bckey ekey, ikey;
  ak_uint8 iv[16], buffer[1024], *ptr = NULL;
  size_t i, j, blocks, memsize, iter, lblocks, ltail;

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null pointer to file name" );

  if(( error = ak_file_open_to_read( &fs, filename )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__, "incorrect opening a file \"%s\"", filename );

  if( ak_file_read( &fs, iv, 16 ) != 16 ) {
    ak_error_message( error = ak_error_read_data, __func__, "incorrect reading a file header" );
    goto labex;
  }

  memset( bkey, 0, sizeof( struct blomkey ));
  bkey->size = iv[12];
  bkey->size = ( bkey-> size << 8 ) + iv[13];
  bkey->size = ( bkey-> size << 8 ) + iv[14];
  bkey->size = ( bkey-> size << 8 ) + iv[15];
  if( bkey->size > 4096 ) {
    ak_error_message( error = ak_error_wrong_length, __func__,
                                                          "using very huge size for blom matrix" );
    goto labex;
  }
  if( !bkey->size ) {
    ak_error_message( error = ak_error_zero_length, __func__, "using zero field size" );
    goto labex;
  }
  bkey->count = iv[11];
  if(( bkey->count != ak_galois256_size ) && ( bkey->count != ak_galois512_size )) {
    ak_error_message( error = ak_error_undefined_value, __func__,
                                       "this function accepts only 256 or 512 bit galois fields" );
    goto labex;
  }
  bkey->type = iv[10];
  if(( bkey->type != blom_matrix_key ) && ( bkey->type != blom_abonent_key )) {
    ak_error_message( error = ak_error_wrong_key_type, __func__, "incorrect type of secret key" );
    goto labex;
  }

 /* вычисляем размер ключевых данных */
  if( bkey->type == blom_matrix_key ) memsize = (bkey->size)*(bkey->size)*(bkey->count);
   else memsize = (bkey->size)*(bkey->count);
  if( memsize%16 != 0 ) {
    ak_error_message( error = ak_error_wrong_key_length, __func__,
                                                               "unexpected length of secret key" );
    goto labex;
  }
  if(( blocks = memsize/16 ) == 0 ) {
    ak_error_message( error = ak_error_wrong_key_length, __func__, "using short secret key" );
    goto labex;
  }
  if(( bkey->data = malloc( memsize + 16 )) == NULL ) { /* 16 это размер имитовставки */
    ak_error_message( error = ak_error_out_of_memory, __func__, "incorrect memory allocation" );
    goto labex;
  }
  memset( bkey->data, 0, memsize + 16 );

 /* вычисляем ключи */
  iter = ( iv[8] << 8 ) + iv[9];
  if(( error = ak_bckey_create_key_pair_from_password( &ekey, &ikey,
        ak_oid_find_by_name( "kuznechik" ), password, pass_size, iv, 16, iter )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of key pair" );
    goto labex;
  }

 /* считываем данные */
  ekey.key.resource.value.counter = blocks + 1;
  switch( bkey->type ) {
   case blom_matrix_key: /* считываем верхнетреугольную матрицу и разворачиваем ее */
     for( i = 0; i < bkey->size; i++ ) {
       /* копируем созданное ранее */
        for( j = 0; j < i; j++ ) memcpy( bkey->data + i*bkey->count*bkey->size+j*bkey->count,
                                      ak_blomkey_get_element_by_index( bkey, j, i ), bkey->count );
       /* создаем новое */
        iter = ( bkey->size - i )*bkey->count;
        if( i == ( bkey->size - 1 )) iter += 16; /* добавляем контрольную сумму */

        ptr = bkey->data + i*bkey->count*(bkey->size + 1);
        ltail = iter%sizeof( buffer );
        lblocks = ( iter - ltail )/sizeof( buffer );

        for( j = 0; j < lblocks; j++ ) {
           if(( len = ak_file_read( &fs, buffer, sizeof( buffer ))) != sizeof( buffer )) {
             ak_error_message( error = ak_error_read_data, __func__,
                                                              "incorrect reading encrypted data" );
             goto labex1;
           }
           ak_bckey_ctr( &ekey, buffer, ptr, sizeof( buffer ), j == 0 ? iv : NULL, 8 );
           ptr += sizeof( buffer );
        }
        if( ltail ) {
          if(( len = ak_file_read( &fs, buffer, ltail )) != (ssize_t)ltail ) {
            ak_error_message( error = ak_error_read_data, __func__,
                                                              "incorrect reading encrypted tail" );
            goto labex1;
          }
          ak_bckey_ctr( &ekey, buffer, ptr, ltail, NULL, 8 );
        }
     }
     break;

   case blom_abonent_key: /* считываем ключевой массив без каких либо изменений */
     ptr = bkey->data;
     ltail = ( memsize + 16 )%sizeof( buffer );
     lblocks = ( memsize + 16 - ltail )/sizeof( buffer );

     for( i = 0; i < lblocks; i++ ) {
        if(( len = ak_file_read( &fs, buffer, sizeof( buffer ))) != sizeof( buffer )) {
          ak_error_message( error = ak_error_read_data, __func__,
                                                              "incorrect reading encrypted data" );
          goto labex1;
        }
        ak_bckey_ctr( &ekey, buffer, ptr, sizeof( buffer ), i == 0 ? iv : NULL, 8 );
        ptr += sizeof( buffer );
     }
     if( ltail ) {
       if(( len = ak_file_read( &fs, buffer, ltail )) != (ssize_t)ltail ) {
          ak_error_message( error = ak_error_read_data, __func__,
                                                              "incorrect reading encrypted tail" );
          goto labex1;
        }
        ak_bckey_ctr( &ekey, buffer, ptr, ltail, NULL, 8 );
     }
     break;

   default: ak_error_message( error = ak_error_wrong_key_type, __func__,
                                                          "using secret key with incorrect type" );
     goto labex;
  }

 /* вычисляем и проверяем значение имитовставки  */
  ikey.key.resource.value.counter = blocks + 1;
  ak_bckey_cmac_clean( &ikey );
  ak_bckey_cmac_update( &ikey, iv, 16 );
  if( blocks > 1 ) ak_bckey_cmac_update( &ikey, bkey->data, memsize - 16 );
  ak_bckey_cmac_finalize( &ikey, bkey->data + memsize - 16, 16, iv, 16 );

  if( !ak_ptr_is_equal( bkey->data + memsize, iv, 16 )) {
    ak_error_message( error = ak_error_not_equal_data, __func__,
                                    "incorrect value of control sum, may be wrong password ... " );
    goto labex1;
  }

 /* данные корректно считаны, завершаем создание контекста и
                    определяем бесключевую контрольную сумму */
  switch( bkey->count ) {
    case ak_galois256_size: error = ak_hash_create_streebog256( &bkey->ctx );
                            break;
    case ak_galois512_size: error = ak_hash_create_streebog512( &bkey->ctx );
                            break;
    default: ak_error_message( error = ak_error_undefined_value, __func__,
                                       "this function accepts only 256 or 512 bit galois fields" );
  }
  if( error != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of hash function context" );
    goto labex1;
  }
  if(( error = ak_hash_ptr( &bkey->ctx, bkey->data, memsize, bkey->icode, 32 )) != ak_error_ok ) {
    ak_error_message( error,  __func__ , "incorrect calculation of control sum" );
    ak_hash_destroy( &bkey->ctx );
  }

  labex1:
    ak_bckey_destroy( &ekey );
    ak_bckey_destroy( &ikey );

  labex:
    ak_file_close( &fs );
    if( error != ak_error_ok ) {
      if( bkey->data != NULL ) free( bkey->data );
    }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-blom-keys.c                                                                      */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_blom.c  */
/* ----------------------------------------------------------------------------------------------- */
