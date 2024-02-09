/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_libakrypt.с                                                                            */
/*  - содержит реализацию функций инициализации и тестирования библиотеки.                         */
/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_PTHREAD_H
 #include <pthread.h>
#endif
#ifdef AK_HAVE_BUILTIN_XOR_SI128
 #include <emmintrin.h>
#endif
#ifdef AK_HAVE_WINDOWS_H
 #include <windows.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность определения базовых типов данных
    \return В случе успешного тестирования возвращает \ref ak_true (истина).
    В противном случае возвращается ak_false.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_libakrypt_test_types( void )
{
  union {
    ak_uint8 x[4];
    ak_uint32 z;
  } val;

  if( sizeof( ak_int8 ) != 1 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int8 type" );
    return ak_false;
  }
  if( sizeof( ak_uint8 ) != 1 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint8 type" );
    return ak_false;
  }
  if( sizeof( ak_int32 ) != 4 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int32 type" );
    return ak_false;
  }
  if( sizeof( ak_uint32 ) != 4 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint32 type" );
    return ak_false;
  }
  if( sizeof( ak_int64 ) != 8 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_int64 type" );
    return ak_false;
  }
  if( sizeof( ak_uint64 ) != 8 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong size of ak_uint64 type" );
    return ak_false;
  }

  if( ak_log_get_level() > ak_log_standard )
    ak_error_message_fmt( ak_error_ok, __func__, "size of pointer is %d", sizeof( ak_pointer ));

 /* определяем тип платформы: little-endian или big-endian */
  val.x[0] = 0; val.x[1] = 1; val.x[2] = 2; val.x[3] = 3;

  #ifdef AK_LITTLE_ENDIAN
   if( val.z != 50462976 ) {
     ak_error_message( ak_error_wrong_endian, __func__,
      "incorrect endian: library runs on big endian, but compiled for little endian platform");
     return ak_false;
   } else
      if( ak_log_get_level() > ak_log_standard ) {
        ak_error_message( ak_error_ok, __func__ , "library runs on little endian platform" );
      }
  #else
   if( val.z != 66051 ) {
     ak_error_message( ak_error_wrong_endian, __func__,
      "incorrect endian: library runs on little endian, but compiled for big endian platform");
     return ak_false;
   } else
      if( ak_log_get_level() > ak_log_standard ) {
        ak_error_message( ak_error_ok, __func__ , "library runs on big endian platform" );
      }
  #endif

  #ifdef AK_HAVE_BUILTIN_XOR_SI128
   if( ak_log_get_level() > ak_log_standard ) {
     ak_error_message( ak_error_ok, __func__ , "library applies __m128i base type" );
   }
  #endif
  #ifdef AK_HAVE_BUILTIN_CLMULEPI64
   if( ak_log_get_level() > ak_log_standard ) {
     ak_error_message( ak_error_ok, __func__ , "library applies clmulepi64 instruction" );
   }
  #endif
  #ifdef AK_HAVE_BUILTIN_MULQ_GCC
   if( ak_log_get_level() > ak_log_standard ) {
     ak_error_message( ak_error_ok, __func__ , "library applies assembler code for mulq command" );
   }
  #endif
  #ifdef AK_HAVE_PTHREAD_H
   if( ak_log_get_level() > ak_log_standard ) {
     ak_error_message( ak_error_ok, __func__ , "library runs with pthreads support" );
   }
  #endif
  #ifdef AK_HAVE_GMP_H
   if( ak_log_get_level() > ak_log_standard ) {
     ak_error_message( ak_error_ok, __func__ , "library runs with gmp support" );
   }
  #endif

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param flag булева переменная; истинное значение устанавливает режим совместимости,
    ложное -- снимает.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_openssl_compability( bool_t flag )
{
  if( ak_libakrypt_set_option( "openssl_compability", flag ) != ak_error_ok )
    return ak_error_message( ak_error_get_value(), __func__, "using an incorrect option name" );
  ak_bckey_kuznechik_init_gost_tables();

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки может быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_hash_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing hash functions started" );

 /* тестируем функцию Стрибог256 */
  if( ak_libakrypt_test_streebog256() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect streebog256 testing" );
    return ak_false;
  }

 /* тестируем функцию Стрибог512 */
  if( ak_libakrypt_test_streebog512() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect streebog512 testing" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing hash functions ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки может быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_block_ciphers( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing block ciphers started" );

 /* тестируем корректность реализации блочного шифра Магма */
  if( ak_libakrypt_test_magma()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of magma block cipher" );
    return ak_false;
  }

 /* тестируем корректность реализации блочного шифра Кузнечик */
  if( ak_libakrypt_test_kuznechik()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                                   "incorrect testing of kuznechik block cipher" );
    return ak_false;
  }

 /* тестируем дополнительные режимы работы */
  if( ak_libakrypt_test_acpkm()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                  "incorrect testing of acpkm encryption mode for block ciphers" );
    return ak_false;
  }
  if( ak_libakrypt_test_mgm()  != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                               "incorrect testing of mgm mode for block ciphers" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing block ciphers ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет корректность реализации алгоритмов итерационного сжатия
    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки может быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_mac_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing mac algorithms started" );

 /* тестирование механизмов hmac и pbkdf2 */
  if( ak_libakrypt_test_hmac_streebog() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect testing of hmac functions" );
    return ak_false;
  }
  if( ak_libakrypt_test_pbkdf2() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect testing of pbkdf2 function" );
    return ak_false;
  }
 /* тестирование функций выработки производных ключей */
  if( ak_libakrypt_test_kdf256() != ak_true ) {
    ak_error_message( ak_error_get_value(),
                                __func__, "incorrect testing a kdf26 key derivaion function" );
    return ak_false;
  }
  if( ak_libakrypt_test_tlstree() != ak_true ) {
    ak_error_message( ak_error_get_value(),
                      __func__, "incorrect testing a set of tlstree key derivaion functions" );
    return ak_false;
  }

 /* тестирование различых реализаци cmac на совпадение */
  if( ak_libakrypt_test_cmac() != ak_true ) {
    ak_error_message( ak_error_get_value(),
                                       __func__, "incorrect testing different kinds of cmac" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing mac algorithms ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return Возвращает ak_true в случае успешного тестирования. В случае возникновения ошибки
    функция возвращает ak_false. Код ошибки можеть быть получен с помощью
    вызова ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_asymmetric_functions( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "testing asymmetric mechanisms started" );

 /* тестируем корректность реализации операций с эллиптическими кривыми в форме Вейерштрасса */
  if( ak_libakrypt_test_wcurves() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of Weierstrass curves" );
    return ak_false;
  }

 /* тестируем корректность реализации алгоритмов электронной подписи */
  if( ak_libakrypt_test_sign() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of digital signatures" );
    return ak_false;
  }

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing asymmetric mechanisms ended successfully" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция проверяет корректность работы всех криптографических механизмов библиотеки
    с использованием как значений, содержащихся в нормативных документах и стандартах,
    так и с использованием случайных значений, вырабатываемых в ходе тестирования.                 */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_dynamic_control_test( void )
{
  int audit = ak_log_get_level();
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ , "testing started" );

 /* тестируем арифметические операции в конечных полях */
  if( ak_libakrypt_test_gfn_multiplication() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                          "incorrect testing of multiplication in Galois fields" );
    return ak_false;
  }

 /* проверяем корректность реализации алгоритмов бесключевого хеширования */
  if( ak_libakrypt_test_hash_functions( ) != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of hash functions" );
    return ak_false;
  }

 /* тестируем работу алгоритмов блочного шифрования */
  if( ak_libakrypt_test_block_ciphers() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ , "error while testing block ciphers" );
    return ak_false;
  }

 /* проверяем корректность реализации алгоритмов итерационного сжатия */
   if( ak_libakrypt_test_mac_functions( ) != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "incorrect testing of mac algorithms" );
     return ak_false;
   }

 /* тестируем работу алгоритмов выработки и проверки электронной подписи */
  if( ak_libakrypt_test_asymmetric_functions() != ak_true ) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                        "error while testing digital signature mechanisms" );
    return ak_false;
  }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ , "testing is Ok" );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция должна вызываться перед использованием любых криптографических механизмов библиотеки.

   Пример использования функции.

   \code
    int main( void )
   {
     if( ak_libakrypt_create( NULL ) != ak_true ) {
       // инициализация выполнена не успешна => выход из программы
       return ak_libakrypt_destroy();
     }

     // ... здесь код программы ...

    return ak_libakrypt_destroy();
   }
   \endcode

   \param logger Указатель на функцию аудита. Может быть равен NULL.
   \return Функция возвращает \ref ak_true (истина) в случае успешной инициализации и тестирования
   библиотеки. В противном случае, возвращается \ref ak_false. Код ошибки может быть получен
   с помощью вызова функции ak_error_get_value()                                                   */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_create( ak_function_log *logger )
{
 int error;

#ifdef AK_HAVE_WINDOWS_H
  #ifdef LIBAKRYPT_NETWORK
      WORD wVersionRequested;
      WSADATA wsaData;
  #endif
#endif

 /* перед стартом все должно быть хорошо */
   ak_error_set_value( ak_error_ok );

 /* инициализируем систему аудита (вывод сообщений) */
   if(( error = ak_log_set_function( logger )) != ak_error_ok ) {
     ak_error_message( error, __func__ , "audit mechanism not started" );
     return ak_false;
   }

 /* выводим версию библиотеки */
   if( ak_log_get_level() > ak_log_standard )
     ak_error_message_fmt( ak_error_ok, __func__, "libakrypt version %s", ak_libakrypt_version( ));

 /* считываем настройки криптографических алгоритмов */
   if( ak_libakrypt_load_options() != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ ,
                                        "unsuccessful load options from libakrypt.conf file" );
     return ak_false;
   }

#ifdef _WIN32
 /* использование цвета в стандартной консоли Windows бессмысленно
                            поэтому мы его принудительно запрещаем */
   ak_error_set_color_output( ak_false );
#endif
 /* выводим значения установленных параметров библиотеки */
   if( ak_log_get_level() > ak_log_standard ) ak_libakrypt_log_options();

 /* проверяем длины фиксированных типов данных */
   if( ak_libakrypt_test_types() != ak_true ) {
     ak_error_message( ak_error_get_value(), __func__ , "sizes of predefined types is wrong" );
     return ak_false;
   }

 /* инициализируем константные таблицы для алгоритма Кузнечик */
   if(( error = ak_bckey_kuznechik_init_gost_tables()) != ak_error_ok ) {
    ak_error_message( error, __func__, "initialization of context manager is wrong" );
     return ak_false;
   }

 /* в случае, когда компилируются сетевые функции, инициализируем работу с сокетами */
#ifdef AK_HAVE_WINDOWS_H
  #ifdef LIBAKRYPT_NETWORK
      wVersionRequested = MAKEWORD(2, 0);  // Запрос WinSock v2.0
      if( WSAStartup(wVersionRequested, &wsaData) != 0 ) {  // Загрузка WinSock DLL

      #ifdef _MSC_VER
        char str[128];
        strerror_s( str, sizeof( str ), WSAGetLastError( ));
        ak_error_message_fmt( ak_error_open_file, __func__, "unable to load WinSock DLL [%s]", str );
      #else
        ak_error_message_fmt( ak_error_wrong_setsockopt, __func__,
                                             "unable to load WinSock DLL [%s]", strerror( errno ));
      #endif
        return ak_false;
      }
  #endif
#endif

 /* процедура полного тестирования всех криптографических алгоритмов
    занимает крайне много времени, особенно на встраиваемых платформах,
    поэтому ее запуск должен производиться в соответствии с неким (внешним) регламентом ....

    if( !ak_libakrypt_dynamic_control_test( )) {
      ak_error_message( error, __func__, "incorrect dynamic control test" );
      return ak_false;
    }

    поскольку функция динамического контроля экспортируется,
    то она может быть запущена пользователем самостоятельно. */

 if( ak_log_get_level() > ak_log_none )
   ak_error_message( ak_error_ok, __func__ , "creation of libakrypt is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_destroy( void )
{
  int error = ak_error_get_value();
  if( error != ak_error_ok )
    ak_error_message( error, __func__ , "before destroing library holds an error(s)" );

#ifdef AK_HAVE_WINDOWS_H
  #ifdef LIBAKRYPT_NETWORK
    if( WSACleanup() != 0 )
      ak_error_message( ak_error_close_file, __func__, "WSACleanup() failed" );
  #endif
#endif

  if( ak_log_get_level() != ak_log_none )
    ak_error_message( ak_error_ok, __func__ , "all crypto mechanisms successfully destroyed" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
