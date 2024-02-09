/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_random.с                                                                               */
/*  - содержит реализацию генераторов псевдо-случайных чисел                                       */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif
#ifdef AK_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef AK_HAVE_FCNTL_H
 #include <fcntl.h>
#endif
#ifdef AK_HAVE_STDLIB_H
 #include <stdlib.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация генератора псевдо-случайных чисел.
    Функция используется для устанавки значение полей структуры struct random в
    значения по-умолчанию. Созданный таким образом генератор не является работоспособным.

    @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_create( ak_random rnd )
{
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  rnd->oid = NULL;
  rnd->next = NULL;
  rnd->randomize_ptr = NULL;
  rnd->random = NULL;
  rnd->free = NULL;
  memset( &rnd->data, 0, sizeof( rnd->data ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на структуру struct random
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_destroy( ak_random rnd )
{
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( rnd->free != NULL ) rnd->free( rnd );
  rnd->oid = NULL;
  rnd->next = NULL;
  rnd->randomize_ptr = NULL;
  rnd->random = NULL;
  memset( &rnd->data, 0, sizeof( rnd->data ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает все внутренние поля, уничтожает генератор псевдо-случайных чисел
    (структуру struct random) и присваивает указателю значение NULL.

    @param rnd указатель на структуру struct random.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_random_delete( ak_pointer rnd )
{
  if( rnd != NULL ) {
   ak_random_destroy(( ak_random ) rnd );
   free( rnd );
  } else ak_error_message( ak_error_null_pointer, __func__ ,
                                            "use a null pointer to a random generator" );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Установка происходит путем вызова функции-члена класса random,
    которая и реализует механизм инициализации.

    @param rnd контекст генератора псевдо-случайных чисел.
    @param in указатель на данные, с помощью которых инициализируется генератор.
    @param size размер данных, в байтах.

    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_randomize( ak_random rnd, const ak_pointer in, const ssize_t size )
{
 if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "use a null pointer to random generator" );
 if( in == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "use a null pointer to initializator" );
 if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                              "using a buffer with wrong length" );
 if( rnd->randomize_ptr == NULL ) return ak_error_message( ak_error_undefined_function, __func__,
                                           "randomize() function not defined for this generator" );
 return rnd->randomize_ptr( rnd, in, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Выработка последовательности псведо-случайных данных происходит путем
    вызова функции-члена класса random.

    @param rnd контекст генератора псевдо-случайных чисел.
    @param out указатель на область памяти, в которую помещаются псевдо-случайные данные.
    @param size размер помещаемых данных, в байтах.

    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_ptr( ak_random rnd, const ak_pointer out, const ssize_t size )
{
 if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "use a null pointer to random generator" );
 if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "use a null pointer to output data" );
 if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                              "using a buffer with wrong length" );
 if( rnd->random == NULL ) return ak_error_message( ak_error_undefined_function, __func__,
                                                "this generator has undefined random() function" );
 return rnd->random( rnd, out, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd указатель на контекст генератора псевдо-случайных чисел
    @param oid OID генератора.

    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_oid( ak_random rnd, ak_oid oid )
{
  int error = ak_error_ok;

 /* выполняем проверку */
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to random generator context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to random generator OID" );
 /* проверяем, что OID от того, что нужно */
  if( oid->engine != random_generator )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от каких-то там параметров  */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );
 /* проверяем, что производящая функция определена */
  if( oid->func.first.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                                       "using oid with undefined constructor" );
 /* инициализируем контекст */
  if(( error = (( ak_function_random * )oid->func.first.create )( rnd )) != ak_error_ok )
      return ak_error_message( error, __func__, "invalid creation of random generator context");

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
  static ak_uint64 shift_value = 0; // Внутренняя статическая переменная (счетчик вызовов)

/* ----------------------------------------------------------------------------------------------- */
/*! Функция использует для генерации случайного значения текущее время, номер процесса и
    номер пользователя.
    Несмотря на кажущуюся случайность вырабатываемого значения, функция не должна использоваться для
    генерации значений, для которых требуется криптографическая случайность. Это связано с
    достаточно прогнозируемым изменением значений функции при многократных повторных вызовах.

    Основная задача данной функции - инициализация программного генератора
    каким-либо значением, в случае, когда пользователь не инициализирует программный генератор
    самостоятельно.

   \return Функция возвращает случайное число размером 8 байт (64 бита).                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 ak_random_value( void )
{
  ak_uint64 vtme = 17, clk = 23, value = 1;
#ifndef _WIN32
  ak_uint64 pval = ( ak_uint64 ) getpid();
  ak_uint64 uval = ( ak_uint64 ) getuid();
#else
  ak_uint64 pval = _getpid();
  ak_uint64 uval = 67;
#endif

#ifdef AK_HAVE_TIME_H
  vtme = ( ak_uint64) time( NULL );
  clk = ( ak_uint64 ) clock();
#endif

  value = ( shift_value += 11 )*125643267795740073ULL + pval;
  value = ( value * 506098983240188723ULL ) + 71331*uval + vtme;
 return value ^ clk;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_lcg                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_next( ak_random rnd )
{
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  rnd->data.val *= 125643267795740073ULL;
  rnd->data.val += 506098983240188723ULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_randomize_ptr( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  ssize_t idx = 0;
  ak_uint8 *value = ptr;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                          "use a null pointer to initial vector" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                          "use initial vector with wrong length" );
 /* сначала начальное значение, потом цикл по всем элементам массива */
  rnd->data.val = value[idx];
  do {
        rnd->next( rnd );
        rnd->data.val += value[idx];
  } while( ++idx < size );

 return rnd->next( rnd );
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_lcg_random( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  ssize_t idx = 0;
  ak_uint8 *value = ptr;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                           "use a data vector with wrong length" );
  lab_start:
    value[idx] = (ak_uint8) ( rnd->data.val >> 16 );
    rnd->next( rnd );
    if( ++idx < size ) goto lab_start;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Генератор вырабатывает последовательность внутренних состояний, удовлетворяющую
    линейному сравнению \f$ x_{n+1} \equiv a\cdot x_n + c \pmod{2^{64}}, \f$
    в котором константы a и c удовлетворяют равенствам
    \f$ a = 125643267795740073 \f$ и \f$ b = 506098983240188723. \f$

    Далее, последовательность внутренних состояний преобразуется в последовательность
    байт по следующему правилу
    \f$ \gamma_n = \displaystyle\frac{x_n - \hat x_n}{2^{24}} \pmod{256}, \f$
    где \f$\hat x_n \equiv x_n \pmod{2^{24}}. \f$

    @param generator Контекст создаваемого генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_lcg( ak_random generator )
{
  int error = ak_error_ok;
  ak_uint64 qword = ak_random_value(); /* вырабатываем случайное число */

  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  generator->oid = ak_oid_find_by_name("lcg");
  generator->next = ak_random_lcg_next;
  generator->randomize_ptr = ak_random_lcg_randomize_ptr;
  generator->random = ak_random_lcg_random;

 /* для корректной работы присваиваем какое-то случайное начальное значение */
  ak_random_lcg_randomize_ptr( generator, &qword, sizeof( ak_uint64 ));
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_file                                      */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_file_ptr( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  ak_uint8 *value = ptr;
  ssize_t result = 0, count = size;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                                 "use a data with wrong length" );
  /* считываем несколько байт */
  slabel: result = read( rnd->data.fd, value,
  #ifdef _MSC_VER
    (unsigned int)
  #else
    (size_t)
  #endif
    count );

  /* если конец файла, то переходим в начало */
  if( result == 0 ) {
    lseek( rnd->data.fd, 0, SEEK_SET );
    goto slabel;
  }
  /* если мы считали меньше, чем надо */
  if( result < count ) {
    value += result;
    count -= result;
    goto slabel;
  }
  /* если ошибка чтения, то возбуждаем ошибку */
  if( result == -1 ) return ak_error_message( ak_error_read_data, __func__ ,
                                                                 "wrong reading data from file" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_random_file_free( ak_random rnd )
{
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if( close( rnd->data.fd ) == -1 )
    ak_error_message( ak_error_close_file, __func__ , "wrong closing a file with random data" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Данный генератор связывается с заданным файлом и возвращает содержащиеся в нем значения
    в качестве случайных чисел. Если данные в файле заканчиваются, то считывание начинается
    с начала файла.

    Основное назначение данного генератора - считывание данных из файловых устройств,
    таких как /dev/randon или /dev/urandom.

    @param generator Контекст создаваемого генератора.
    @param filename Имя файла.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_file( ak_random rnd, const char *filename )
{
  int error = ak_error_ok;
  if(( error = ak_random_create( rnd )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

 /* теперь мы открываем заданный пользователем файл */
  if(( rnd->data.fd = open( filename, O_RDONLY | O_BINARY )) == -1 ) {
    ak_error_message_fmt( ak_error_open_file, __func__ ,
                                  "wrong opening a file \"%s\" with random data", filename );
    ak_random_destroy( rnd );
    return ak_error_open_file;
  }

  // для данного генератора oid не определен
  rnd->next = NULL;
  rnd->randomize_ptr = NULL;
  rnd->random = ak_random_file_ptr;
  rnd->free = ak_random_file_free;

 return error;
}

#if defined(__unix__) || defined(__APPLE__)
/* ----------------------------------------------------------------------------------------------- */
/*! @param generator Контекст создаваемого генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_random( ak_random generator )
{
 int result = ak_random_create_file( generator, "/dev/random" );
  if( result == ak_error_ok ) generator->oid = ak_oid_find_by_name("dev-random");
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param generator Контекст создаваемого генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_urandom( ak_random generator )
{
 int result = ak_random_create_file( generator, "/dev/urandom" );
  if( result == ak_error_ok ) generator->oid = ak_oid_find_by_name("dev-urandom");
 return result;
}
#endif


/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация класса rng_winrtl                                    */
/* ----------------------------------------------------------------------------------------------- */
#ifdef _WIN32
 static int ak_random_winrtl_random( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                           "use a data vector with wrong length" );

  if( !CryptGenRandom( rnd->data.handle, (DWORD) size, ptr ))
    return ak_error_message( ak_error_undefined_value, __func__,
                                                    "wrong generation of pseudo random sequence" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_winrtl_free( ak_random rnd )
{
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                "freeing a null pointer to data" );
  if( !CryptReleaseContext( rnd->data.handle, 0 )) {
    return ak_error_message_fmt( ak_error_close_file,
            __func__ , "wrong closing a system crypto provider with error: %x", GetLastError( ));
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_random_create_winrtl( ak_random generator )
{
  HCRYPTPROV handle = 0;

  int error = ak_error_ok;
  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  /* теперь мы открываем криптопровайдер для доступа к генерации случайных значений
     в начале мы пытаемся создать новый ключ */
  if( !CryptAcquireContext( &handle, NULL, NULL,
                                         PROV_RSA_FULL, CRYPT_NEWKEYSET )) {
    /* здесь нам не удалось создать ключ, поэтому мы пытаемся его открыть */
    if( GetLastError() == NTE_EXISTS ) {
      if( !CryptAcquireContext( &handle, NULL, NULL,
                                            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT )) {
        ak_error_message_fmt( error = ak_error_open_file, __func__,
              "wrong open default key for system crypto provider with error: %x", GetLastError( ));
       ak_random_destroy( generator );
       return error;
      }
    } else {
       ak_error_message_fmt( error = ak_error_access_file, __func__,
                    "wrong creation of default key for system crypto provider with error: %x",
                                                                                  GetLastError( ));
       ak_random_destroy( generator );
       return error;
     }
  }

  generator->data.handle = handle;
  generator->oid = ak_oid_find_by_name("winrtl");
  generator->next = NULL;
  generator->randomize_ptr = NULL;
  generator->random = ak_random_winrtl_random;

 /* эта функция должна закрыть открытый ранее криптопровайдер */
  generator->free = ak_random_winrtl_free;
 return error;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция заполняет заданную область памяти случайными данными, выработанными заданным
    генератором псевдослучайных чисел. Генератор должен быть предварительно корректно
    инициализирован с помощью функции вида `ak_random_create_...()`.

    @param ptr Область данных, которая заполняется случайным мусором.
    @param size Размер заполняемой области в байтах.
    @param generator Генератор псевдо-случайных чисел, используемый для генерации случайного мусора.
    @param readflag Булева переменная, отвечающая за обязательное чтение сгенерированных данных.
    В большинстве случаев должна принимать истинное значение.
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успешного уничтожения данных.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ptr_wipe( ak_pointer ptr, size_t size, ak_random rnd )
{
  size_t idx = 0;
  int error = ak_error_ok;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using null pointer to random generator context" );
  if( rnd->random == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using uninitialized random generator context" );
  if( size > (((size_t)-1) >> 1 )) return ak_error_message( ak_error_wrong_length, __func__,
                                                                   "using very large size value" );
  if(( ptr == NULL ) || ( size == 0 )) return ak_error_ok;

  if( rnd->random( rnd, ptr, (ssize_t) size ) != ak_error_ok ) {
    memset( ptr, 0, size );
    ak_error_message( error = ak_error_write_data, __func__, "incorrect memory wiping" );
  }
 /* запись в память при чтении => необходим вызов функции чтения данных из ptr */
  for( idx = 0; idx < size; idx++ ) ((ak_uint8 *)ptr)[idx] += ((ak_uint8 *)ptr)[size - 1 - idx];
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_delete( const char *file, ak_random rnd )
{
  if( file == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null pointer to file name" );
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using null pointer to random generator context" );
  if( rnd->random == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using uninitialized random generator context" );
 /* пропущен фрагмент с очищением кармы */
  #ifdef AK_HAVE_UNISTD_H
   unlink( file );
  #else
   remove( file );
  #endif

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                           реализация одиночного nlfsr генератора                                */
/* ----------------------------------------------------------------------------------------------- */
/** @brief Класс с параметрами для NLFSR генератора с квадратичной обратной связью */
 typedef struct nlfsr_register{
     /** @brief Внутреннее состояние генератора. */
     ak_uint32 state;
     /** @brief Цифровой код линейной функции обратной связи. */
     ak_uint32 linear_part;
     /** @brief Представление нелинейной функции обратной связи специального вида. */
     ak_uint32 nonlinear_part;
     /** @brief Длина регистра в данном генераторе. n<=32. */
     size_t n;
 } nlfsr_register;

/* ----------------------------------------------------------------------------------------------- */
/**
 * @brief Инициализирует цифровое представление нелинейной функции обратной связи для NLFSR генератора специального
 * вида.
 * @param rnd NLFSR генератор.
 */
 static void initialize_nonlinear_part(ak_random rnd)
{
    unsigned non_linear = 1;
    for (size_t i = 0; i < ((nlfsr_register*)(rnd->data.ctx))->n - 3; i++)
        non_linear = (non_linear << 1) ^ non_linear;

    ((nlfsr_register*)(rnd->data.ctx))->nonlinear_part = non_linear;
}

/* ----------------------------------------------------------------------------------------------- */
 /**
  * @brief  Инициализирует NLFSR генератор специального вида переданными параметрами.
  *
  * @param rnd NLFSR генератор.
  * @param ptr Указатель на данные для инициализации NLFSR генератора.
  * @param size Количество параметров для инициализации.
  * @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
  */
 static int ak_random_nlfsr_randomize_ptr( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  nlfsr_register *ctx = NULL;
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                          "use a null pointer to initial vector" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                          "use initial vector with wrong length" );

 /* текущая реализация ограничена 32-мя битами, поэтому больше 4х октетов не копируем */
  ctx = rnd->data.ctx;
  ctx->state = ((ak_uint8 *)ptr)[0];
  if( size > 1 ) { ctx->state <<= 8; ctx->state += ((ak_uint8 *)ptr)[1]; }
  if( size > 2 ) { ctx->state <<= 8; ctx->state += ((ak_uint8 *)ptr)[2]; }
  if( size > 3 ) { ctx->state <<= 8; ctx->state += ((ak_uint8 *)ptr)[3]; }

  ((nlfsr_register*)(rnd->data.ctx))->state <<= 64-((nlfsr_register*)(rnd->data.ctx))->n;
  ((nlfsr_register*)(rnd->data.ctx))->state >>= 64-((nlfsr_register*)(rnd->data.ctx))->n;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @brief Функция вычисления веса Хэмминга
 *
 * @param number Число для рассчёта веса.
 * @return size_t Как бы вес.
 */
 static inline size_t hamming_weight( ak_uint32 number )
{
    number = number - ((number >> 1) & 0x55555555);
    number = (number & 0x33333333) + ((number >> 2) & 0x33333333);
    number = (number + (number >> 4)) & 0x0F0F0F0F;
    return (( number * 0x01010101 ) >> 24 ) &1;
}

/* ----------------------------------------------------------------------------------------------- */
 #define ak_random_nlfsr_next_bit2 do{ \
    state = ctx->state >> 1; \
    linear = ctx->linear_part & state; \
    non_linear = linear^( ctx->nonlinear_part & ( state ) & ( state >> 1 )); \
    hweight = hamming_weight( non_linear ); \
    new_bit = lsb ^ hweight; \
    moved = new_bit << n1; \
    ctx->state = state ^ moved; \
    lsb = ctx->state & 1; \
  } while( 0 );

/* ----------------------------------------------------------------------------------------------- */
/**
 * @brief Генерирует новый байт с помощью NLFSR генератора специального вида.
 * @param rnd NLFSR генератор.
 * @return char Новый байт.
 */
 static inline ak_uint8 ak_random_nlfsr_next_byte( ak_random rnd )
{
  ak_uint8 byte;
  nlfsr_register *ctx = rnd->data.ctx;
  ak_uint32 lsb = ctx->state & 1;
  ak_uint32 n1 = ctx->n -1;
  ak_uint32 state, linear, non_linear, hweight, new_bit, moved;

  ak_random_nlfsr_next_bit2; byte = lsb;

  byte <<= 1; ak_random_nlfsr_next_bit2; byte |= lsb;
  byte <<= 1; ak_random_nlfsr_next_bit2; byte |= lsb;
  byte <<= 1; ak_random_nlfsr_next_bit2; byte |= lsb;
  byte <<= 1; ak_random_nlfsr_next_bit2; byte |= lsb;
  byte <<= 1; ak_random_nlfsr_next_bit2; byte |= lsb;
  byte <<= 1; ak_random_nlfsr_next_bit2; byte |= lsb;
  byte <<= 1; ak_random_nlfsr_next_bit2; byte |= lsb;

  return byte;
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @brief Функция выработки последователности псевдо-случайных байт NLFSR генератором.
 *
 * @param rnd NLFSR генератор.
 * @param buffer Указатель на вырабатываемую последовательность.
 * @param size Размер после5довательности в байтах.
 * @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
 */
 static int ak_random_nlfsr_random( ak_random rnd, const ak_pointer buffer, ssize_t size )
{
  ak_uint8 *value = buffer;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( buffer == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                           "use a data vector with wrong length" );
  while( size-- > 0 )
     *value++ = ak_random_nlfsr_next_byte( rnd );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @brief Функция освобождения внутреннего состояния NLFSR генератора.
 *
 * @param rnd Контекст создаваемого генератора.
 * @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
 */
 static int ak_random_nlfsr_free( ak_random rnd )
{
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if( rnd->data.ctx != NULL)
    free(rnd->data.ctx);

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @param generator NLFSR генератор
   @param size размер нелинейного регистра, не должен быть более 32-х
   @param linear_part код линейной части обратной связи
   @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                              */
 int ak_random_create_nlfsr_with_params( ak_random generator, size_t size, ak_uint64 linear_part )
{
  int error = ak_error_ok;

  if(( error = ak_random_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  generator->oid = ak_oid_find_by_name("nlfsr");
  generator->next = NULL; // внутреннее состояние изменяется в функции ak_random_nlfsr_next_bit
  generator->randomize_ptr = ak_random_nlfsr_randomize_ptr;
  generator->random = ak_random_nlfsr_random;
  generator->free = ak_random_nlfsr_free;

  generator->data.ctx = ( struct nlfsr_generator* ) malloc(sizeof( nlfsr_register ));
  ((nlfsr_register*)(generator->data.ctx))->n = size;
  ((nlfsr_register*)(generator->data.ctx))->state = ak_random_value();
  ((nlfsr_register*)(generator->data.ctx))->state <<= 64-size;
  ((nlfsr_register*)(generator->data.ctx))->state >>= 64-size;
  ((nlfsr_register*)(generator->data.ctx))->linear_part = linear_part;
  initialize_nonlinear_part(generator);

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @param generator NLFSR генератор.
 * @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
 */
 int ak_random_create_nlfsr( ak_random generator )
{
  /*  для последовательностей с которотким циклом
   *  можно использовать следующие параметры инициализации генератора
   *    return ak_random_create_nlfsr_with_params( generator, 21, 849314 ); */
 return ak_random_create_nlfsr_with_params( generator, 32, 183599831 );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                   реализация класса hrng                                        */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний генератора hrng */
 typedef struct random_hrng {
  /*! \brief структура используемой бесключевой функции хеширования */
   struct hash hctx;
  /*! \brief текущее внутреннее состояние генератора, включая счетчик обработанных блоков */
   ak_mpzn512 counter;
  /*! \brief массив выработанных значений */
   ak_uint8 buffer[64];
  /*! \brief текущее количество доступных для выдачи октетов */
   size_t capacity;
 } *ak_random_hrng;

/* ----------------------------------------------------------------------------------------------- */
/**
 * @brief Функция вычисляет новое значение внутреннего состояния генератора
 *
 * @param rnd Контекст создаваемого генератора.
 * @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
 */
 static int ak_random_hrng_next( ak_random rnd )
{
  int error = ak_error_ok;
  ak_random_hrng hrng = NULL;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if(( hrng = (ak_random_hrng) rnd->data.ctx ) == NULL )
   return ak_error_message( ak_error_undefined_value, __func__, "using non initialized context" );

  hrng->counter[7]++;
  hrng->capacity = 64;
  if(( error = ak_hash_ptr( &hrng->hctx, hrng->counter, 64, hrng->buffer, 64 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect hashing of internal state" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @param rnd контекст генератора псевдослучайных чисел
 * @param ptr указатель на область памяти, где располагаются данные,
 *            которыми инициализируется генератор псевдослучайных чисел
 * @param size размер данных (в байтах)
   @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
 */
 static int ak_random_hrng_randomize_ptr( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  int error = ak_error_ok;
  ak_random_hrng hrng = NULL;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if(( hrng = (ak_random_hrng) rnd->data.ctx ) == NULL )
   return ak_error_message( ak_error_undefined_value, __func__, "using non initialized context" );

 /* формируем внутреннее состояние */
  if(( error = ak_hash_ptr( &hrng->hctx, ptr, size, hrng->counter, 64 )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect hashing of input data");
 /* вычисляем новое состояние промежуточного буфера */
 return rnd->next( rnd );
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @param rnd контекст генератора псевдослучайных чисел
 * @param ptr указатель на область памяти, куда помещаются случайные данные
 * @param size размер данных (в байтах)
   @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
 */
 static int ak_random_hrng_random( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  ssize_t cursize = size;
  ak_uint8 *outbuf = ptr;
  ak_random_hrng hrng = NULL;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if(( hrng = (ak_random_hrng) rnd->data.ctx ) == NULL )
   return ak_error_message( ak_error_undefined_value, __func__, "using non initialized context" );

  while( hrng->capacity < cursize ) {
     memcpy( outbuf, hrng->buffer + (64 - hrng->capacity), hrng->capacity );
     cursize -= hrng->capacity;
     outbuf += hrng->capacity;
     rnd->next( rnd );
  }

  memcpy( outbuf, hrng->buffer + (64 - hrng->capacity), cursize );
  hrng->capacity -= cursize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @param rnd контекст генератора псевдослучайных чисел
   @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
 */
 static int ak_random_hrng_free( ak_random rnd )
{
  ak_random_hrng hrng = NULL;
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if(( hrng = (ak_random_hrng) rnd->data.ctx ) != NULL ) {
    ak_hash_destroy( &hrng->hctx );
    memset( hrng, 0, sizeof( struct random_hrng ));
    free( hrng );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/**
 * @param rnd контекст генератора псевдослучайных чисел
   @return int В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.
 */
 int ak_random_create_hrng( ak_random rnd )
{
  int error = ak_error_ok;
  ak_random_hrng hrng = NULL;
  ak_uint64 value = ak_random_value();

  if(( error = ak_random_create( rnd )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

 /* выделяем память под внутренний контекст генератора */
  if(( rnd->data.ctx = calloc( 1, sizeof( struct random_hrng ))) == NULL ) {
    ak_random_destroy( rnd );
    return ak_error_message( ak_error_null_pointer, __func__, "incorrect memory allocation ");
  }

 /* создаем контекст функции хеширования */
  hrng = (ak_random_hrng) rnd->data.ctx;
  if(( error =
          ak_hash_create_streebog512( &hrng->hctx )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect creation of hash function context" );

 /* устанавливаем обработчики событий */
  rnd->oid = ak_oid_find_by_name("hrng");
  rnd->next = ak_random_hrng_next;
  rnd->randomize_ptr = ak_random_hrng_randomize_ptr;
  rnd->random = ak_random_hrng_random;
  rnd->free = ak_random_hrng_free;

 /* инициализируем начальное состояние */
  if(( error = rnd->randomize_ptr( rnd, &value, sizeof( value ))) != ak_error_ok )
   ak_error_message( error, __func__, "incorrect initialization of internal state" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_random.c  */
/* ----------------------------------------------------------------------------------------------- */
