/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_options.с                                                                              */
/*  - содержит реализацию функций для работы с опциями библиотеки                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef AK_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип данных для хранения одной опции библиотеки */
 typedef struct option {
  /*! \brief Человекочитаемое имя опции, используется для поиска и установки значения */
   char *name;
  /*! \brief Численное значение опции (31 значащий бит + знак) */
   ak_int64 value;
  /*! \brief Минимально возможное значение */
   ak_int64 min;
  /*! \brief Максимально возможное значение */
   ak_int64 max;
 } *ak_option;

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения опций (значения по-умолчанию) */
 static struct option options[] = {
     { "log_level", ak_log_standard, 0, 2 },
     { "pbkdf2_iteration_count", 2000, 1000, 65536 },
     { "hmac_key_count_resource", 1048576, 1024, 2147483648 },
     { "digital_signature_count_resource", 65536, 1024, 2147483648 },

  /* значение константы задает максимальный объем зашифрованной информации на одном ключе в 256 MБ:
                                       33554432 блока x 8 байт на блок = 268.435.456 байт = 256 MБ */
     { "magma_cipher_resource", 33554432, 1024, 2147483648 },

  /* значение константы задает максимальный объем зашифрованной информации на одном ключе в 4ГБ:
                               268435456 блоков x 16 байт на блок = 4.294.967.296 байт = 4096 MБ  */
     { "kuznechik_cipher_resource", 268435456, 8196, 2147483648 },
     { "acpkm_message_count", 4096, 128, 65536 },
     { "acpkm_section_magma_block_count", 128, 128, 16777216 },
     { "acpkm_section_kuznechik_block_count", 512, 512, 16777216 },

  /* при значении равным единицы, формат шифрования данных соответствует варианту OpenSSL */
     { "openssl_compability", 0, 0, 1 },
  /* флаг использования цвета при выводе сообщений библиотеки */
     { "use_color_output", 1, 0, 1 },
     { NULL, 0, 0, 0 } /* завершающая константа, должна всегда принимать нулевые значения */
 };

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_version( void )
{
#ifdef LIBAKRYPT_VERSION
  return LIBAKRYPT_VERSION;
#else
  return "0.9";
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \return Общее количество опций библиотеки.                                                     */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_libakrypt_options_count( void )
{
  return ( sizeof( options )/( sizeof( struct option ))-1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param index Индекс опции, должен быть от нуля до значения,
    возвращаемого функцией ak_libakrypt_options_count().

    \return Строка симовлов, содержащая имя функции, в случае правильно определенного индекса.
    В противном случае, возвращается NULL.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_libakrypt_get_option_name( const size_t index )
{
 if( index >= ak_libakrypt_options_count() ) return ak_null_string;
  else return options[index].name;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param name Имя опции
    \return Значение опции с заданным именем. Если имя указано неверно, то возвращается
    ошибка \ref ak_error_wrong_option.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_int64 ak_libakrypt_get_option_by_name( const char *name )
{
  size_t i = 0;
  ak_int64 result = ak_error_wrong_option;
  for( i = 0; i < ak_libakrypt_options_count(); i++ ) {
     if( strncmp( name, options[i].name, strlen( options[i].name )) == 0 ) result = options[i].value;
  }
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param index Индекс опции, должен быть от нуля до значения,
    возвращаемого функцией ak_libakrypt_options_count().

    \return Значение опции с заданным именем. Если имя указано неверно, то возвращается
    ошибка \ref ak_error_wrong_option.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_int64 ak_libakrypt_get_option_by_index( const size_t index )
{
  if( index >= ak_libakrypt_options_count() ) return ak_error_wrong_option;
 return options[index].value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \note Функция не проверяет и не интерпретирует значение устанавливааемой опции.

    \param name Имя опции
    \param value Значение опции

    \return В случае удачного установления значения опции возввращается \ref ak_error_ok.
     Если имя опции указано неверно, то возвращается ошибка \ref ak_error_wrong_option.            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_option( const char *name, const ak_int64 value )
{
  size_t i = 0;
  int result = ak_error_wrong_option;
  for( i = 0; i < ak_libakrypt_options_count(); i++ ) {
     if( strncmp( name, options[i].name, strlen( options[i].name )) == 0 ) {
       options[i].value = value;
       result = ak_error_ok;
     }
  }
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! При выводе используется текущая функция аудита.                                                */
/* ----------------------------------------------------------------------------------------------- */
 void ak_libakrypt_log_options( void )
{
    size_t i = 0;

   /* выводим сообщение об установленных параметрах библиотеки */
   /* мы пропускаем вывод информации об архитектуре,
      поскольку она будет далее тестироваться отдельно         */
    for( i = 1; i < ak_libakrypt_options_count(); i++ ) {
       switch( options[i].value ) {

         case  0:  ak_error_message_fmt( ak_error_ok, __func__,
                                  "option %s is %ld (false)", options[i].name, options[i].value );
                   break;

         case  1:  ak_error_message_fmt( ak_error_ok, __func__,
                                   "option %s is %ld (true)", options[i].name, options[i].value );
                   break;

         default:  ak_error_message_fmt( ak_error_ok, __func__,
                                          "option %s is %ld", options[i].name, options[i].value );
       }
    }
 /* выводим сообщение об установленных каталогах доступа к криптографическим ключам */
   ak_error_message_fmt( ak_error_ok, __func__,
                          "certificate's repository path: %s", ak_certificate_get_repository( ));
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param filename Массив, куда помещается имя файла. Память под массив
           должна быть быделена заранее.
    @param size Размер выделенной памяти.
    @param lastname Собственно короткое имя файла, заданное в виде null-строки.
    @param where Указатель на то, в каком каталоге будет расположен файл с настройками.
           Значение 0 - домашний каталог, значение 1 - общесистемный каталог
   @return В случае возникновения ошибки возвращается ее код. В случае успеха
           возвращается \ref ak_error_ok.                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create_home_filename( char *filename,
                                              const size_t size, char *lastname, const int where  )
{
 int error = ak_error_ok;
 char hpath[FILENAME_MAX];

  memset( (void *)filename, 0, size );
  memset( (void *)hpath, 0, FILENAME_MAX );

  switch( where )
 {
   case 0  : /* имя файла помещается в домашний каталог пользователя */
             if(( error = ak_homepath( hpath, FILENAME_MAX )) != ak_error_ok )
               return ak_error_message_fmt( error, __func__, "wrong %s name creation", lastname );
             #ifdef _WIN32
              ak_snprintf( filename, size, "%s\\.config\\libakrypt\\%s", hpath, lastname );
             #else
              ak_snprintf( filename, size, "%s/.config/libakrypt/%s", hpath, lastname );
             #endif
             break;

   case 1  : { /* имя файла помещается в общесистемный каталог */
               size_t len = 0;
               if(( len = strlen( LIBAKRYPT_OPTIONS_PATH )) > FILENAME_MAX-16 ) {
                 return ak_error_message( ak_error_wrong_length, __func__ ,
                                                           "wrong length of predefined filepath" );
               }
               memcpy( hpath, LIBAKRYPT_OPTIONS_PATH, len );
             }
             #ifdef _WIN32
              ak_snprintf( filename, size, "%s\\%s", hpath, lastname );
             #else
              ak_snprintf( filename, size, "%s/%s", hpath, lastname );
             #endif
             break;
   default : return ak_error_message( ak_error_undefined_value, __func__,
                                                       "unexpected value of \"where\" parameter ");
 }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_libakrypt_write_options( void )
{
  size_t i;
  struct file fd;
  int error = ak_error_ok;
  char hpath[FILENAME_MAX], filename[FILENAME_MAX];

  memset( hpath, 0, FILENAME_MAX );
  memset( filename, 9, FILENAME_MAX );

 /* начинаем последовательно создавать подкаталоги */
  if(( error = ak_homepath( hpath, FILENAME_MAX )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong libakrypt.conf name creation" );

 /* создаем .config */
 #ifdef _WIN32
  ak_snprintf( filename, FILENAME_MAX, "%s\\.config", hpath );
  #ifdef _MSC_VER
   if( _mkdir( filename ) < 0 ) {
  #else
   if( mkdir( filename ) < 0 ) {
  #endif
 #else
  ak_snprintf( filename, FILENAME_MAX, "%s/.config", hpath );
  if( mkdir( filename, S_IRWXU ) < 0 ) {
 #endif
    if( errno != EEXIST ) {
     #ifdef _MSC_VER
       strerror_s( hpath, FILENAME_MAX, errno ); /* помещаем сообщение об ошибке в ненужный буффер */
       return ak_error_message_fmt( ak_error_access_file, __func__,
                                         "wrong creation of %s directory [%s]", filename, hpath );
     #else
      return ak_error_message_fmt( ak_error_access_file, __func__,
                              "wrong creation of %s directory [%s]", filename, strerror( errno ));
     #endif
    }
  }

 /* создаем libakrypt */
 #ifdef _WIN32
  ak_snprintf( hpath, FILENAME_MAX, "%s\\libakrypt", filename );
  #ifdef _MSC_VER
   if( _mkdir( hpath ) < 0 ) {
  #else
   if( mkdir( hpath ) < 0 ) {
  #endif
 #else
  ak_snprintf( hpath, FILENAME_MAX, "%s/libakrypt", filename );
  if( mkdir( hpath, S_IRWXU ) < 0 ) {
 #endif
    if( errno != EEXIST ) {
     #ifdef _MSC_VER
       strerror_s( hpath, FILENAME_MAX, errno ); /* помещаем сообщение об ошибке в ненужный буффер */
       return ak_error_message_fmt( ak_error_access_file, __func__,
                                        "wrong creation of %s directory [%s]", filename, hpath );
     #else
      return ak_error_message_fmt( ak_error_access_file, __func__,
                             "wrong creation of %s directory [%s]", filename, strerror( errno ));
     #endif
    }
  }

 /* теперь начинаем манипуляции с файлом */
 #ifdef _WIN32
  ak_snprintf( filename, FILENAME_MAX, "%s\\libakrypt.conf", hpath );
 #else
  ak_snprintf( filename, FILENAME_MAX, "%s/libakrypt.conf", hpath );
 #endif

  if(( error = ak_file_create_to_write( &fd, filename )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of libakrypt.conf file");

 /* сперва записываем заголовок секции */
  ak_snprintf( hpath, FILENAME_MAX - 1, "[libakrypt]\n" );
  if( ak_file_write( &fd, hpath, strlen( hpath )) < 1 ) {
   #ifdef _MSC_VER
    strerror_s( hpath, FILENAME_MAX, errno ); /* помещаем сообщение об ошибке в ненужный буффер */
    ak_error_message_fmt( error = ak_error_write_data, __func__,
                                                "section's header stored with error [%s]", hpath );
   #else
    ak_error_message_fmt( error = ak_error_write_data, __func__,
                                     "section's header stored with error [%s]", strerror( errno ));
   #endif
  }

 /* потом сохраняем текущие значения всех опций */
  for( i = 0; i < ak_libakrypt_options_count(); i++ ) {
    memset( hpath, 0, ak_min( 1024, FILENAME_MAX ));
    ak_snprintf( hpath, FILENAME_MAX - 1, "  %s = %d\n", options[i].name, options[i].value );
    if( ak_file_write( &fd, hpath, strlen( hpath )) < 1 ) {
     #ifdef _MSC_VER
      strerror_s( hpath, FILENAME_MAX, errno ); /* помещаем сообщение об ошибке в ненужный буффер */
      ak_error_message_fmt( error = ak_error_write_data, __func__,
                                 "option %s stored with error [%s]", options[i].name, hpath );
     #else
      ak_error_message_fmt( error = ak_error_write_data, __func__,
                      "option %s stored with error [%s]", options[i].name, strerror( errno ));
     #endif
    }
  }

  /* сохраняем каталог для хранения доверенных сертификатов открытых ключей */
  ak_snprintf( hpath, sizeof( hpath )-1, "  %s = %s\n", "certificate_repository", ak_certificate_get_repository());
  ak_file_write( &fd, hpath, strlen( hpath ));

  ak_file_close( &fd );
  if( error == ak_error_ok )
    ak_error_message_fmt( ak_error_ok, __func__, "all options stored in %s file", filename );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 #define opt_check( str, a, b )  do{ \
  if( strncmp( name, str, strlen( str )) == 0 ) {\
    if( value < a ) value = a;\
    if( value > b ) value = b;\
    ak_libakrypt_set_option( str, value );\
    return 1;\
  }\
 }while(0);\

/* ----------------------------------------------------------------------------------------------- */
 static int ak_libakrypt_load_option_from_file( void *user ,
                                      const char *section , const char *name , const char *valstr )
{
  size_t idx = 0;
  char message[256], *endptr = NULL;
  ak_int64 value = strtoll( valstr, &endptr, 10 );

 /* проверки */
  if( user != NULL ) return 0;
  if( strncmp( section, "libakrypt", 9 ) != 0 ) return 0;
  if( strncmp( name, "certificate_repository", 25 ) == 0 ) {
    if( ak_certificate_set_repository( valstr ) != ak_error_ok ) ak_error_set_value( ak_error_ok );
   /* если каталог с доверенными сертификатами не существует,
      мы выдаём сообщение об ошибке и продолжаем работу программы */
    return 1;
  }

 /* теперь детальный разбор каждой опции */
  while( options[idx].name != NULL ) {
   opt_check( options[idx].name, options[idx].min, options[idx].max );
   ++idx;
  }

 /* если ничего не нашли, выводим красивое сообщение */
  ak_error_message( ak_error_undefined_value, __func__, "found unexpected following option" );
  memset( message, 0, sizeof( message ));
  ak_snprintf( message, sizeof( message )-1, " [%s]\n  %s = %s", section, name, valstr );
  ak_log_set_message( message );
  ak_error_set_value( ak_error_ok );

 /* нулевое значение - неуспешное завершение обработчика */
 return 1;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно ищет файл `libakrypt.conf` сначала в домашнем каталоге пользователя,
    потом в каталоге, указанном при сборке библиотеки с помощью флага `LIBAKRYPT_OPTIONS_PATH`.
    В случае, если ни в одном из указанных мест файл не найден, то функция создает
    файл `libakrypt.conf` в домашнем каталоге пользователя со значениями по-умолчанию.             */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_load_options( void )
{
 struct file fd;
 int error = ak_error_ok;
 char name[FILENAME_MAX];

/* создаем имя файла, расположенного в домашнем каталоге */
 if(( error = ak_libakrypt_create_home_filename( name, FILENAME_MAX,
                                                          "libakrypt.conf", 0 )) != ak_error_ok ) {
   ak_error_message( error, __func__, "incorrect name generation for options file");
   return ak_false;
 }
/* пытаемся считать данные из указанного файла */
 if( ak_file_open_to_read( &fd, name ) == ak_error_ok ) {
   ak_file_close( &fd );
   if(( error = ak_ini_parse( name, ak_libakrypt_load_option_from_file, NULL )) == ak_error_ok ) {
     if( ak_log_get_level() > ak_log_standard ) ak_error_message_fmt( ak_error_ok, __func__,
                                            "all options have been read from the %s file", name );
     return ak_true;
   } else {
       ak_error_message_fmt( ak_error_wrong_option, __func__,
                           "file %s exists, but contains invalid data in line: %d", name, error );
       return ak_false;
     }
 }

/* создаем имя файла, расположенного в системном каталоге */
 if(( error = ak_libakrypt_create_home_filename( name, FILENAME_MAX,
                                                          "libakrypt.conf", 1 )) != ak_error_ok ) {
   ak_error_message( error, __func__, "incorrect name generation for options file");
   return ak_false;
 }
/* пытаемся считать данные из указанного файла */
 if( ak_file_open_to_read( &fd, name ) == ak_error_ok ) {
   ak_file_close( &fd );
   if(( error = ak_ini_parse( name, ak_libakrypt_load_option_from_file, NULL )) == ak_error_ok ) {
     if( ak_log_get_level() > ak_log_standard ) ak_error_message_fmt( ak_error_ok, __func__,
                                             "all options have been read from the %s file", name );
     return ak_true;
   } else {
       ak_error_message_fmt( ak_error_wrong_option, __func__,
                           "file %s exists, but contains invalid data in line: %d", name, error );
       return ak_false;
     }
 } else ak_error_message( ak_error_access_file, __func__,
                         "file libakrypt.conf not found either in home or system directories");

 /* формируем дерево подкаталогов и записываем файл с настройками */
  if(( error = ak_libakrypt_write_options( )) != ak_error_ok )
    ak_error_message_fmt( error, __func__, "wrong creation a libakrypt.conf file" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_options.c  */
/* ----------------------------------------------------------------------------------------------- */
