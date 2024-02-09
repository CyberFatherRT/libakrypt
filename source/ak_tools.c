/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2022 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_tools.с                                                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_SYSLOG_H
 #include <syslog.h>
#endif
#ifdef AK_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef AK_HAVE_TERMIOS_H
 #include <termios.h>
#endif
#ifdef AK_HAVE_PTHREAD_H
 #include <pthread.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*!  Переменная, содержащая в себе код последней ошибки                                            */
 static int ak_errno = ak_error_ok;
 static int ak_log_level = ak_log_standard;

/* ----------------------------------------------------------------------------------------------- */
/*! Внутренний указатель на функцию аудита                                                         */
 static ak_function_log *ak_function_log_default =
  #ifdef AK_HAVE_SYSLOG_H
    ak_function_log_syslog;
  #else
    ak_function_log_stderr;
  #endif

#ifdef AK_HAVE_PTHREAD_H
 static pthread_mutex_t ak_function_log_default_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Cтатическая переменная для вывода сообщений. */
 static char ak_static_buffer[1024];

/* ----------------------------------------------------------------------------------------------- */
 #define AK_START_RED_STRING ("\x1b[31m")
 #define AK_END_RED_STRING ("\x1b[0m")

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Cтатическая переменные для окрашивания кодов и выводимых сообщений. */
 static char *ak_error_code_start_string = "";
 static char *ak_error_code_end_string = "";
#ifndef _WIN32
 static char *ak_error_code_start_red_string = AK_START_RED_STRING;
 static char *ak_error_code_end_red_string = AK_END_RED_STRING;
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \mainpage Краткая аннотация
 *
 *  \image html http://libakrypt.ru/_static/logo.png width=100mm
 *
 *  Целью библиотеки **libakrypt** является разработка свободно распространяемого программного модуля,
 *  предназначенного для использования в средствах защиты информации,
 *  удовлетворяющих рекомендациям по стандартизации P1323565.1.012-2017.
 *
 *  Библиотека разрабатывается на языке Си и распространяется под лицензией **MIT**.
 *
 *  Домашняя страница проекта **http://libakrypt.ru**
 *  */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup log
 @{
    Все сообщения библиотеки могут быть разделены на три уровня.

    \li Первый уровень аудита определяется константой \ref ak_log_none. На этом уровне выводятся
    только сообщения об ошибках.

    \li Второй уровень аудита определяется константой \ref ak_log_standard. На этом уровене
    выводятся сообщения об ошибках, а также сообщения, регламентируемые существующей
    нормативной базой.

    \li Третий (максимальный) уровень аудита определяется константой \ref ak_log_maximum.
    На этом уровне выводятся все сообщения, доступные на первых двух уровнях, а также
    сообщения отладочного характера, позволяющие проследить логику работы функций библиотеки.

    Для вывода сообщений об ошибке необходимо использовать функции ak_error_message()
    и ak_error_message_fmt(), которые формируют строку с сообщением специального вида и
    выводят данную строку в установленное устройство аудита (консоль, демон syslog и т.п.).

    Низкоуровневая функция вывода строк в устройство аудита может быть установлена
    с помощью ak_log_set_function(). Примерами устанавливаемых функций являются:

    - ak_function_log_stderr(), реализующая вывод в стандартный поток вывода ошибок,
    - ak_function_log_syslog(), реализующая вывод в демон аудита syslog.
 @} */

/* ----------------------------------------------------------------------------------------------- */
/*! \param level Уровень аудита, может принимать значения \ref ak_log_none,
    \ref ak_log_standard и \ref ak_log_maximum

    \note Допускается передавать в функцию любое целое число, не превосходящее 16.
    Однако для всех значений от \ref ak_log_maximum  до 16 поведение функции аудита
    будет одинаковым. Дополнительный диапазон предназначен для приложений библиотеки.

    \return Функция возвращает новое значение уровня аудита.                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_level( int level )
{
   if( level < 0 ) return ( ak_log_level = ak_log_none );
   if( level > 16 ) return ( ak_log_level = 16 );
 return ( ak_log_level = level );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_log_get_level( void )
{
 return ak_log_level;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.
    \param value Код ошибки, который будет установлен. В случае, если значение value положительно,
    то код ошибки полагается равным величине \ref ak_error_ok (ноль).
    \return Функция возвращает устанавливаемое значение.                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_set_value( const int value )
{
  return ( ak_errno = value );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \return Функция возвращает текущее значение кода ошибки. Данное значение не является
    защищенным от возможности изменения различными потоками выполнения программы.                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_get_value( void )
{
  return ak_errno;
}

#ifdef AK_HAVE_SYSLOG_H
/* ----------------------------------------------------------------------------------------------- */
/*! \param message Выводимое сообщение.
    \return В случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_function_log_syslog( const char *message )
{
 #ifdef __linux__
   int priority = LOG_AUTHPRIV | LOG_NOTICE;
 #else
   int priority = LOG_USER;
 #endif
  if( message != NULL ) syslog( priority, "%s", message );
 return ak_error_ok;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \param message Выводимое сообщение
    \return В случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_function_log_stderr( const char *message )
{
  if( message != NULL ) {
   #ifdef AK_HAVE_WINDOWS_H
     fprintf( stderr, "%s\n", message );
   #else
    #ifdef AK_HAVE_FILE
      struct file file = { 2, 0, 0 };
      ak_file_printf( &file, "%s\n", message );
    #else
      fprintf( stderr, "%s\n", message );
    #endif
   #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает в качестве основного обработчика
    вывода сообщений функцию, задаваемую указателем function. Если аргумент function равен NULL,
    то используется функция по-умолчанию.
    Выбор того, какая именно функция будет установлена по-умолчанию, не фискирован.
    В текущей версии библиотеки он зависит от используемой операционной системы, например,
    под ОС Linux это вывод с использованием демона syslogd.

    \param function Указатель на функцию вывода сообщений.
    \return Функция всегда возвращает ak_error_ok (ноль).                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_function( ak_function_log *function )
{
#ifdef AK_HAVE_PTHREAD_H
  pthread_mutex_lock( &ak_function_log_default_mutex );
#endif
  if( function != NULL ) {
    ak_function_log_default = function;
    if( function == ak_function_log_stderr ) { /* раскрашиваем вывод кодов ошибок */
      #ifndef _WIN32
        ak_error_code_start_string = ak_error_code_start_red_string;
        ak_error_code_end_string = ak_error_code_end_red_string;
      #endif
    } else { /* в остальных случаях, убираем раскраску вывода */
             ak_error_code_start_string = "";
             ak_error_code_end_string = "";
           }
  }
   else {
    #ifdef AK_HAVE_SYSLOG_H
      ak_function_log_default = ak_function_log_syslog;
    #else
      ak_function_log_default = ak_function_log_stderr;
    #endif
   }
#ifdef AK_HAVE_PTHREAD_H
  pthread_mutex_unlock( &ak_function_log_default_mutex );
#endif
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция использует установленную ранее функцию-обработчик сообщений. Если сообщение,
    или обработчик не определены (равны NULL) возвращается код ошибки.

    \param message выводимое сообщение
    \return в случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_message( const char *message )
{
  int result = ak_error_ok;
  if( ak_function_log_default == NULL ) return ak_error_set_value( ak_error_undefined_function );
  if( message == NULL ) {
    return ak_error_message( ak_error_null_pointer, __func__ , "use a null string for message" );
  } else {
          #ifdef AK_HAVE_PTHREAD_H
           pthread_mutex_lock( &ak_function_log_default_mutex );
          #endif
           result = ak_function_log_default( message );
          #ifdef AK_HAVE_PTHREAD_H
           pthread_mutex_unlock( &ak_function_log_default_mutex );
          #endif
      return result;
    }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param str Строка, в которую помещается результат (сообщение)
    \param size Максимальный размер помещаемого в строку str сообщения
    \param format Форматная строка, в соответствии с которой формируется сообщение

    \return Функция возвращает значение, которое вернул вызов системной (библиотечной) функции
    форматирования строки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_snprintf( char *str, size_t size, const char *format, ... )
{
  int result = 0;
  va_list args;
  va_start( args, format );

 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    result = _vsnprintf_s( str, size, size, format, args );
  #else
    result = _vsnprintf( str, size, format, args );
  #endif
 #else
  result = vsnprintf( str, size, format, args );
 #endif
  va_end( args );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param function Функция, которая используется для вывода сообщения.
    \param format Форматная строка, в соответствии с которой формируется сообщение

    \note Функция содержит внутреннее ограничение на длину выводимой строки символов.
    Сейчас это ограничение равно 1022 символа.

    \return Функция возвращает значение, которое вернул вызов системной (библиотечной) функции
    форматирования строки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_printf( ak_function_log *function, const char *format, ... )
{
  int result = 0;
  va_list args;
  char str[1024];

  va_start( args, format );

 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    result = _vsnprintf_s( str, sizeof( str ) -1, sizeof( str ) -1, format, args );
  #else
    result = _vsnprintf( str, sizeof( str ) -1, format, args );
  #endif
 #else
  result = vsnprintf( str, sizeof( str ) -1, format, args );
 #endif
  va_end( args );

  function( str );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param flag Если значение истинно, то цветовое выделение используется

    \return В случае удачного установления значения опции возввращается \ref ak_error_ok.
     Если имя опции указано неверно, то возвращается ошибка \ref ak_error_wrong_option.            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_set_color_output( bool_t flag )
{
  if( flag ) { /* устанавливаем цветной вывод */
 #ifndef _WIN32
    ak_error_code_start_red_string = AK_START_RED_STRING;
    ak_error_code_end_red_string = AK_END_RED_STRING;
 #endif
  } else {
 #ifndef _WIN32
    ak_error_code_start_string = ak_error_code_start_red_string = "";
    ak_error_code_end_string = ak_error_code_end_red_string = "";
 #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_error_get_start_string( void )
{
#ifndef _WIN32
  return ak_error_code_start_red_string;
#else
  return "";
#endif
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_error_get_end_string( void )
{
#ifndef _WIN32
  return ak_error_code_end_red_string;
#else
  return "";
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает текущее значение кода ошибки, формирует строку специального вида и
    выводит сформированную строку в логгер с помомощью функции ak_log_set_message().

    \param code Код ошибки
    \param message Читаемое (понятное для пользователя) сообщение
    \param function Имя функции, вызвавшей ошибку

    \hidecallgraph
    \hidecallergraph
    \return Функция возвращает установленный код ошибки.                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_message( const int code, const char *function, const char *message )
{
 /* здесь мы выводим в логгер строку вида [pid] function: message (code: n)                        */
  char error_event_string[1024];
  const char *br0 = "", *br1 = "():", *br = NULL;

  memset( error_event_string, 0, 1024 );
  if(( function == NULL ) || strcmp( function, "" ) == 0 ) br = br0;
    else br = br1;

#ifdef AK_HAVE_UNISTD_H
  if( code < 0 ) ak_snprintf( error_event_string, 1023, "[%d] %s%s %s (%scode: %d%s)",
                              getpid(), function, br, message,
                                    ak_error_code_start_string, code, ak_error_code_end_string );
   else ak_snprintf( error_event_string, 1023, "[%d] %s%s %s", getpid(), function, br, message );
#else
 #ifdef _MSC_VER
  if( code < 0 ) ak_snprintf( error_event_string, 1023, "[%d] %s%s %s (code: %d)",
                                             GetCurrentProcessId(), function, br, message, code );
   else ak_snprintf( error_event_string, 1023, "[%d] %s%s %s",
                                                   GetCurrentProcessId(), function, br, message );
 #else
   #error Unsupported path to compile, sorry ...
 #endif
#endif
  ak_log_set_message( error_event_string );
 return ak_error_set_value( code );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param code Код ошибки
    \param function Имя функции, вызвавшей ошибку
    \param format Форматная строка, в соответствии с которой формируется сообщение
    \hidecallgraph
    \hidecallergraph
    \return Функция возвращает установленный код ошибки.                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_message_fmt( const int code, const char *function, const char *format, ... )
{
  va_list args;
  char ak_static_buffer_fmt[512];

  va_start( args, format );
  memset( ak_static_buffer_fmt, 0, sizeof( ak_static_buffer_fmt ));

 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    _vsnprintf_s( ak_static_buffer_fmt,
                  sizeof( ak_static_buffer_fmt ), sizeof( ak_static_buffer_fmt ), format, args );
  #else
    _vsnprintf( ak_static_buffer_fmt, sizeof( ak_static_buffer_fmt ), format, args );
  #endif
 #else
   vsnprintf( ak_static_buffer_fmt, sizeof( ak_static_buffer_fmt ), format, args );
 #endif
   va_end( args );

 return ak_error_message( code, function, ak_static_buffer_fmt );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает область памяти, на которую указывает указатель ptr, как массив
    последовательно записанных байт фиксированной длины, и
    последовательно выводит в статический буффер значения, хранящиеся в заданной области памяти.
    Значения выводятся в шестнадцатеричной системе счисления.

    Пример использования.
  \code
    ak_uint8 data[5] = { 1, 2, 3, 4, 5 };
    ak_uint8 *str = ak_ptr_to_hexstr( data, 5, ak_false );
    if( str != NULL ) printf("%s\n", str );
  \endcode

    @param ptr Указатель на область памяти
    @param ptr_size Размер области памяти (в байтах)
    @param reverse Последовательность вывода байт в строку. Если reverse равно \ref ak_false,
    то байты выводятся начиная с младшего к старшему.  Если reverse равно \ref ak_true, то байты
    выводятся начиная от старшего к младшему (такой способ вывода принят при стандартном выводе
    чисел: сначала старшие разряды, потом младшие).

    @return Функция возвращает указатель на статическую строку. В случае ошибки конвертации,
    либо в случае нехватки статической памяти, возвращается NULL.
    Код ошибки может быть получен с помощью вызова функции ak_error_get_value().                   */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_ptr_to_hexstr( ak_const_pointer ptr, const size_t ptr_size, const bool_t reverse )
{
  size_t len = 1 + (ptr_size << 1);
  ak_uint8 *data = ( ak_uint8 * ) ptr;
  size_t idx = 0, js = 0, start = 0, offset = 2;

  memset( ak_static_buffer, 0, sizeof( ak_static_buffer ));

  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to data" );
    return NULL;
  }
  if( ptr_size <= 0 ) {
    ak_error_message( ak_error_zero_length, __func__ , "using data with zero or negative length" );
    return NULL;
  }
 /* если возвращаемое значение функции обрабатывается, то вывод предупреждения об ошибке излишен */
  if( sizeof( ak_static_buffer ) < len ) return NULL;

  if( reverse ) { // движение в обратную сторону - от старшего байта к младшему
    start = len-3; offset = -2;
  }
  for( idx = 0, js = start; idx < ptr_size; idx++, js += offset ) {
     char str[4];
     ak_snprintf( str, 3, "%02x", data[idx] );
     memcpy( ak_static_buffer+js, str, 2 );
  }

 return ak_static_buffer;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает область памяти, на которую указывает указатель ptr, как массив
    последовательно записанных байт фиксированной длины. Функция выделяет в оперативной памяти
    массив необходимого размера и последовательно выводит в него значения,
    хранящиеся в заданной области памяти. Значения выводятся в шестнадцатеричной системе счисления.

    Выделенная область памяти должна быть позднее удалена с помощью вызова функции free().

    Пример использования.
  \code
    ak_uint8 data[1000] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    ak_uint8 *str = ak_ptr_to_hexstr_alloc( data, sizeof( data ), ak_false );
    if( str != NULL ) printf("%s\n", str );
    free( str );
  \endcode

    @param ptr Указатель на область памяти
    @param ptr_size Размер области памяти (в байтах)
    @param reverse Последовательность вывода байт в строку. Если reverse равно \ref ak_false,
    то байты выводятся начиная с младшего к старшему.  Если reverse равно \ref ak_true, то байты
    выводятся начиная от старшего к младшему (такой способ вывода принят при стандартном выводе
    чисел: сначала старшие разряды, потом младшие).

    @return Функция возвращает указатель на статическую строку.
    В случае ошибки конвертации возвращается NULL.
    Код ошибки может быть получен с помощью вызова функции ak_error_get_value().                   */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_ptr_to_hexstr_alloc( ak_const_pointer ptr, const size_t ptr_size, const bool_t reverse )
{
  char *result = NULL;
  size_t len = 1 + (ptr_size << 1);
  ak_uint8 *data = ( ak_uint8 * ) ptr;
  size_t idx = 0, js = 0, start = 0, offset = 2;

  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to data" );
    return NULL;
  }
  if( ptr_size <= 0 ) {
    ak_error_message( ak_error_zero_length, __func__ , "using data with zero or negative length" );
    return NULL;
  }
  if(( result = malloc( len )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "incorrect memory allocation" );
    return NULL;
  }

  memset( result, 0, len );
  if( reverse ) { // движение в обратную сторону - от старшего байта к младшему
    start = len-3; offset = -2;
  }
  for( idx = 0, js = start; idx < ptr_size; idx++, js += offset ) {
     char str[4];
     ak_snprintf( str, 3, "%02x", data[idx] );
     memcpy( result+js, str, 2 );
  }

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Конвертация символа в целочисленное значение                                            */
/* ----------------------------------------------------------------------------------------------- */
 inline static ak_uint32 ak_xconvert( const char c )
{
    switch( c )
   {
      case 'a' :
      case 'A' : return 10;
      case 'b' :
      case 'B' : return 11;
      case 'c' :
      case 'C' : return 12;
      case 'd' :
      case 'D' : return 13;
      case 'e' :
      case 'E' : return 14;
      case 'f' :
      case 'F' : return 15;
      case '0' : return 0;
      case '1' : return 1;
      case '2' : return 2;
      case '3' : return 3;
      case '4' : return 4;
      case '5' : return 5;
      case '6' : return 6;
      case '7' : return 7;
      case '8' : return 8;
      case '9' : return 9;
      default : ak_error_set_value( ak_error_undefined_value ); return 0;
 }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразует строку символов, содержащую последовательность шестнадцатеричных цифр,
    в массив данных. Строка символов должна быть строкой, оканчивающейся нулем (NULL string).

    @param hexstr Строка символов.
    @param ptr Указатель на область памяти (массив), в которую будут размещаться данные.
    @param size Максимальный размер памяти (в байтах), которая может быть помещена в массив.
    Если исходная строка требует больший размер, то возбуждается ошибка.
    @param reverse Последовательность считывания байт в память. Если reverse равно \ref ak_false
    то первые байты строки (с младшими индексами) помещаются в младшие адреса, а старшие байты -
    в старшие адреса памяти. Если reverse равно \ref ak_true, то производится разворот,
    то есть обратное преобразование при котором элементы строки со старшими номерами помещаются
    в младшие разряды памяти (такое представление используется при считывании больших целых чисел).

    @return В случае успеха возвращается ноль. В противном случае, в частности,
                      когда длина строки превышает размер массива, возвращается код ошибки.        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hexstr_to_ptr( const char *hexstr, ak_pointer ptr, const size_t size, const bool_t reverse )
{
  int i = 0;
  ak_uint8 *bdata = ptr;
  size_t len = 0;

  if( hexstr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using null pointer to a hex string" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                 "using null pointer to a buffer" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                          "using zero value for length of buffer" );
  len = strlen( hexstr );
  if( len&1 ) len++;
  len >>= 1;
  if( size < len ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                               "using a buffer with small length" );

  memset( ptr, 0, size ); // перед конвертацией мы обнуляем исходные данные
  ak_error_set_value( ak_error_ok );
  if( reverse ) {
    for( i = strlen( hexstr )-2, len = 0; i >= 0 ; i -= 2, len++ ) {
       bdata[len] = (ak_xconvert( hexstr[i] ) << 4) + ak_xconvert( hexstr[i+1] );
    }
    if( i == -1 ) bdata[len] = ak_xconvert( hexstr[0] );
  } else {
        for( i = 0, len = 0; i < (int) strlen( hexstr ); i += 2, len++ ) {
           bdata[len] = (ak_xconvert( hexstr[i] ) << 4);
           if( i < (int) strlen( hexstr )-1 ) bdata[len] += ak_xconvert( hexstr[i+1] );
        }
    }
 return ak_error_get_value();
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция используется для определения размера буффера, который может сохранить данные,
 *  записанные в виде шестнадцатеричной строки. Может использоваться совместно с функцией
 *  ak_hexstr_to_ptr().
 *  Строка символов должна быть строкой, оканчивающейся нулем (NULL string). При этом проверка того,
 *  что строка действительно содержит только шестнадцатеричные символы, не проводится.

    @param hexstr Строка символов.
    @return В случае успеха возвращается длина буффера. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_hexstr_size( const char *hexstr )
{
  ssize_t len = 0;
  if( hexstr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using null pointer to a hex string" );
  len = ( ssize_t ) strlen( hexstr );
  if( len&1 ) len++;
  len >>= 1;

 return len;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция сравнивает две области памяти одного размера, на которые указывают аргументы функции.

    Пример использования функции (результат выполнения функции должен быть \ref ak_false).
  \code
    ak_uint8 data_left[5] = { 1, 2, 3, 4, 5 };
    ak_uint8 data_right[5] = { 1, 2, 3, 4, 6 };

    if( ak_ptr_is_equal( data_left, data_right, 5 )) printf("Is equal");
     else printf("Not equal");
  \endcode

    @param left Указатель на область памяти, участвующей в сравнении слева.
    @param right Указатель на область пямяти, участвующей в сравнении справа.
    @param size Размер области, для которой производяится сравнение.
    @return Если данные идентичны, то возвращается \ref ak_true.
    В противном случае, а также в случае возникновения ошибки, возвращается \ref ak_false.
    Код ошибки может быть получен с помощью выщова функции ak_error_get_value().                   */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_ptr_is_equal( ak_const_pointer left, ak_const_pointer right, const size_t size )
{
  size_t i = 0;
  bool_t result = ak_true;
  const ak_uint8 *lp = left, *rp = right;

  if(( left == NULL ) || ( right == NULL )) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer" );
    return ak_false;
  }

  for( i = 0; i < size; i++ )
     if( lp[i] != rp[i] ) result = ak_false;

  return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция сравнивает две области памяти одного размера, на которые указывают аргументы функции.
 *
    @param left Указатель на область памяти, участвующей в сравнении слева.
    Это, как правило, данные, которые вычислены в ходе выполнения программы.
    @param right Указатель на область пямяти, участвующей в сравнении справа.
    Это константные данные, с которыми производится сравнение.
    @param size Размер области, для которой производяится сравнение.
    @return Если данные идентичны, то возвращается \ref ak_true.
    В противном случае, а также в случае возникновения ошибки, возвращается \ref ak_false.
    Код ошибки может быть получен с помощью выщова функции ak_error_get_value().                   */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_ptr_is_equal_with_log( ak_const_pointer left, ak_const_pointer right, const size_t size )
{
  size_t i = 0;
  bool_t result = ak_true;
  const ak_uint8 *lp = left, *rp = right;
  char buffer[1024];

  if(( left == NULL ) || ( right == NULL )) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer" );
    return ak_false;
  }

  for( i = 0; i < size; i++ ) {
     if( lp[i] != rp[i] ) {
       result = ak_false;
       if( i < ( sizeof( buffer ) >> 1 )) { buffer[2*i] = buffer[2*i+1] = '^'; }
      } else {
         if( i < ( sizeof( buffer ) >> 1 )) { buffer[2*i] = buffer[2*i+1] = ' '; }
        }
  }
  buffer[ ak_min( size << 1, 1022 ) ] = 0;

  if( result == ak_false ) {
    ak_error_message( ak_error_ok, "", "" ); /* пустая строка */
    ak_error_message_fmt( ak_error_ok, "", "%s (calculated data)",
                                                         ak_ptr_to_hexstr( left, size, ak_false ));
    ak_error_message_fmt( ak_error_ok, "", "%s (const value)",
                                                        ak_ptr_to_hexstr( right, size, ak_false ));
    ak_error_message_fmt( ak_error_ok, "", "%s", buffer );
  }

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция пытается считать данные из файла в буффер, на который указывает `buf`.
    Если выделенной памяти не достаточно, то функция выделяет память с помощью вызова
    функции malloc() и помещает считанные данные в новую память.

 \note Функция экспортируется.
 \param buf указатель на массив, в который будут считаны данные;
 память может быть выделена заранее, если память не выделена, то указатель должен принимать
 значение NULL.
 \param size размер выделенной заранее памяти в байтах;
 в случае выделения новой памяти, в переменную `size` помещается размер выделенной памяти.
 \param filename файл, из которого будет производиться чтение.

 \return Функция возвращает указатель на буффер, в который помещены данные.
 Если произошла ошибка, то функция возвращает NULL; код ошибки может быть получен с помощью
 вызова функции ak_error_get_value().                                                              */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_ptr_load_from_file( ak_pointer buf, size_t *size, const char *filename )
{
  struct file sfp;
  ak_uint8 *ptr = NULL;
  int error = ak_error_ok;

  if(( error = ak_file_open_to_read( &sfp, filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "wrong opening the %s", filename );
    return NULL;
  }
  if(( buf == NULL ) || ((size_t)sfp.size > *size )) {
    if(( ptr = malloc( (size_t)sfp.size )) == NULL ) {
      ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
      ak_file_close( &sfp );
      return NULL;
    }
  } else { ptr = buf; }

 /* сохраняем размер считываемых данных */
  *size = (size_t)sfp.size;

 /* теперь считываем данные */
  if(( ak_file_read( &sfp, ptr, ( size_t )sfp.size )) != sfp.size ) {
    ak_error_message_fmt( ak_error_get_value(), __func__,
                                                      "incorrect reading data from %s", filename );
  }
  ak_file_close( &sfp );
 return ptr;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pass Строка, в которую будет помещен пароль. Память под данную строку должна быть
    выделена заранее. Если в данной памяти хранились какие-либо данные, то они будут полностью
    уничтожены.
    @param psize Максимально возможная длина пароля. При этом величина psize-1 задает
    максимально возможную длину пароля, поскольку пароль всегда завершается нулевым символом.
    После чтения пароля, его длина может быть получена с помощью функции strlen().

    \b Внимание. В случае ввода пароля нулевой длины функция возвращает ошибку с кодом
    \ref ak_error_terminal.

    @return В случае успеха функция возвращает количество считанных символов.
    В случае возникновения ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_password_read( char *pass, const size_t psize )
{
   ssize_t len = 0;

 #ifndef AK_HAVE_TERMIOS_H
  #ifdef _WIN32
   char c = 0;
   DWORD mode, count;
   HANDLE ih = GetStdHandle( STD_INPUT_HANDLE  );

   if( !GetConsoleMode( ih, &mode )) {
     return ak_error_message( ak_error_terminal, __func__, "process can not connect to console" );
   }
   SetConsoleMode( ih, mode & ~( ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT ));

   memset( pass, 0, psize );
   while( ReadConsoleA( ih, &c, 1, &count, NULL) && (c != '\r') && (c != '\n') && (len < psize-1) ) {
     pass[len]=c;
     len++;
   }
   pass[len]=0;

   /* восстанавливаем настройки консоли */
   SetConsoleMode( ih, mode );
   if(( len = strlen( pass )) < 2 )
     return ak_error_message( ak_error_zero_length, __func__ , "input a very short password");
   return len-1;

  #endif

  ak_error_message( ak_error_undefined_function, __func__, "this compile branch is unsupported" );
  return ak_error_undefined_function;

 #else
   int error = ak_error_ok;

  /* обрабатываем терминал */
   struct termios ts, ots;

   tcgetattr( STDIN_FILENO, &ts);   /* получаем настройки терминала */
   ots = ts;
   ts.c_cc[ VTIME ] = 0;
   ts.c_cc[ VMIN  ] = 1;
   ts.c_iflag &= ~( BRKINT | INLCR | ISTRIP | IXOFF ); // ICRNL | IUTF8
   ts.c_iflag |=    IGNBRK;
   ts.c_oflag &= ~( OPOST );
   ts.c_cflag &= ~( CSIZE | PARENB);
   ts.c_cflag |=    CS8;
   ts.c_lflag &= ~( ECHO | ICANON | IEXTEN | ISIG );
   tcsetattr( STDIN_FILENO, TCSAFLUSH, &ts );
   tcgetattr( STDIN_FILENO, &ts ); /* проверяем, что все установилось */
   if( ts.c_lflag & ECHO ) {
        ak_error_message( error = ak_error_terminal, __func__, "failed to turn off echo" );
        goto lab_exit;
   }

   memset( pass, 0, psize );
   if( fgets( pass, psize, stdin ) == NULL ) {
     ak_error_message( error = ak_error_null_pointer, __func__ , "input a null password");
     goto lab_exit;
   }
   pass[psize-1] = 0;
   if(( len = strlen( pass )) < 2 ) {
     ak_error_message( error = ak_error_zero_length, __func__ , "input a very short password");
     goto lab_exit;
   }
   if( len > 0 ) pass[len-1] = 0;
    else pass[0] = 0;

  /* убираем за собой и восстанавливаем настройки */
   lab_exit: tcsetattr( STDIN_FILENO, TCSANOW, &ots );
   if( error == ak_error_ok ) return len-1;
    else return error;
 #endif

 /* некорректный путь компиляции исходного текста функции */
 return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выводит предложение `message` в консоль, а после пытается считать строку и поместить
    ее в заданную область памяти, на которую указывает строка `string`.
    Размер памяти, доступный для записи, передается в значении переменной `size`.

    Если при вызове функции строка `string` содержит некоторое значение, имеющее ненулевую длину,
    то данное значение рассматривается как значение по умолчанию. В этом случае, ввод пустой строки
    приведет к принятию значения по-умолчанию.

    \param message предложение, которое печатается перед вводом строки
    \param string буффер, в который помещается введенное значение
    \param size переменная, в которой возвращается размер введенной строки.
    Перед вызовом функции переменная должна содержать доступный объем памяти.

    \return В случае успеха функция возвращает значение \ref ak_error_ok. В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_string_read( const char *message, char *string, size_t *size )
{
  char c = 0;
  size_t len = 0;
  bool_t sp = ak_true;

  if( *size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                           "using buffer with zero length value" );
 /* выводим приглашение */
  printf("%s", message);
  if( strlen( string ) != 0 ) printf(" [%s]: ", string );
   else printf(": ");
  fflush( stdout );

 /* считываем данные из консоли */
  while( (( c = fgetc( stdin )) != '\r') && (c != '\n') && ( len < *size-1 )) {
   string[len]=c;
   len++;
  }
 /* если len равен нулю, то мы сохраняем старое значение */
  if( len > 0 ) string[(*size = len)] = 0;
    else *size = strlen( string );

 /* теперь расправляемся со строками из одних пробелов (редко, но бывают и такие) */
  for( len = 0; len < *size; len++ ) if( string[len] != ' ' ) sp = ak_false;
  if( sp ) {
    memset( string, 0, *size );
    *size = 0;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Используется модифицированный алгоритм,
    заменяющий обычное модульное сложение на операцию порязрядного сложения по модулю 2.
    Такая замена не только не изменяет статистические свойства алгоритма, но и позволяет
    вычислять контрольную сумму от ключевой информации в не зависимотси от значения используемой маски.

    \param data Указатель на область пямяти, для которой вычисляется контрольная сумма.
    \param size Размер области (в октетах).
    \param out Область памяти куда помещается результат.
    Память (32 бита) должна быть выделена заранее.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успешного вычисления результата.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ptr_fletcher32_xor( ak_const_pointer data, const size_t size, ak_uint32 *out )
{
  ak_uint32 sB = 0;
  size_t idx = 0, cnt = size ^( size&0x1 );
  const ak_uint8 *ptr = data;

  if( data == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to input data" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                                        "using zero length data" );
  if( out == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to output buffer" );
 /* основной цикл по четному числу байт  */
  *out = 0;
  while( idx < cnt ) {
    *out ^= ( ptr[idx] | (ak_uint32)(ptr[idx+1] << 8));
    sB = (( sB ^= *out )&0x8000) ? (sB << 1)^0x8BB7 : (sB << 1);
    idx+= 2;
  }

 /* дополняем последний (нечетный) байт */
  if( idx != size ) {
    *out ^= ptr[idx];
    sB = (( sB ^= *out )&0x8000) ? (sB << 1)^0x8BB7 : (sB << 1);
  }
  *out ^= ( sB << 16 );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует алгоритм Флетчера с измененным модулем простого числа
    подробное описание см. [здесь]( https://en.wikipedia.org/wiki/Fletcher%27s_checksum#Fletcher-32).

    \param data Указатель на область пямяти, для которой вычисляется контрольная сумма.
    \param size Размер области (в октетах).
    \param out Область памяти куда помещается результат.
    Память (32 бита) должна быть выделена заранее.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успешного вычисления результата.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ptr_fletcher32( ak_const_pointer data, const size_t size, ak_uint32 *out )
{
 ak_uint32 c0 = 0, c1 = 0;
 const ak_uint32 *ptr = ( const ak_uint32 *) data;
 size_t i, len = size >> 2, tail = size - ( len << 2 );

  if( data == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to input data" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                                        "using zero length data" );
  if( out == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to output buffer" );
 /* основной цикл обработки 32-х битных слов */
  for( i = 0; i < len; i++ ) {
    c0 += ptr[i];
    c1 += c0;
  }

 /* обрабатываем хвост */
  if( tail ) {
    ak_uint32 idx = 0, c2 = 0;
    while( tail-- ) {
        c2 <<= 8;
        c2 += (( const ak_uint8 * )data)[(len << 2)+(idx++)];
    }
    c0 += c2;
    c1 += c0;
  }

 *out = ( c1&0xffff ) << 16 | ( c0&0xffff );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! эта реализация востребована только при сборке mingw и gcc под Windows                          */
/* ----------------------------------------------------------------------------------------------- */
#ifdef _WIN32
 #ifndef _MSC_VER
 unsigned long long __cdecl _byteswap_uint64( unsigned long long _Int64 )
{
#if defined(_AMD64_) || defined(__x86_64__)
  unsigned long long retval;
  __asm__ __volatile__ ("bswapq %[retval]" : [retval] "=rm" (retval) : "[retval]" (_Int64));
  return retval;
#elif defined(_X86_) || defined(__i386__)
  union {
    long long int64part;
    struct {
      unsigned long lowpart;
      unsigned long hipart;
    } parts;
  } retval;
  retval.int64part = _Int64;
  __asm__ __volatile__ ("bswapl %[lowpart]\n"
    "bswapl %[hipart]\n"
    : [lowpart] "=rm" (retval.parts.hipart), [hipart] "=rm" (retval.parts.lowpart)  : "[lowpart]" (retval.parts.lowpart), "[hipart]" (retval.parts.hipart));
  return retval.int64part;
#else
  unsigned char *b = (unsigned char *)&_Int64;
  unsigned char tmp;
  tmp = b[0];
  b[0] = b[7];
  b[7] = tmp;
  tmp = b[1];
  b[1] = b[6];
  b[6] = tmp;
  tmp = b[2];
  b[2] = b[5];
  b[5] = tmp;
  tmp = b[3];
  b[3] = b[4];
  b[4] = tmp;
  return _Int64;
#endif
}
 #endif
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Если это возможно, то функция возвращает память, выравненную по границе 16 байт.
    @param size Размер выделяемой памяти в байтах.
    @return Указатель на выделенную память.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_aligned_malloc( size_t size )
{
 return
#ifndef __MINGW32__
 #ifdef AK_HAVE_STDALIGN_H
  #ifdef AK_HAVE_WINDOWS_H
   _aligned_malloc( size, 16 );
  #else
   aligned_alloc( 16, size );
  #endif
 #else
  malloc( size );
 #endif
#else
 malloc( size );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция освобождает память, выделенную функцией ak_aligned_malloc
    @param size Размер выделяемой памяти в байтах.
    @return Указатель на выделенную память.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_aligned_free( ak_pointer ptr )
{
#ifndef __MINGW32__
 #ifdef AK_HAVE_STDALIGN_H
  #ifdef AK_HAVE_WINDOWS_H
   _aligned_free( ptr );
  #else
   free( ptr );
  #endif
 #else
  free( ptr );
 #endif
#else
 free( ptr );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_tools.c  */
/* ----------------------------------------------------------------------------------------------- */
