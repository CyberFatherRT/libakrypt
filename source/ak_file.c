/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2004 - 2020, 2022 - 2023 by Axel Kenzo, axelkenzo@mail.ru                        */
/*                                                                                                 */
/*  Файл ak_file.с                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif
#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef AK_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef AK_HAVE_FCNTL_H
 #include <fcntl.h>
#endif
#ifdef AK_HAVE_DIRENT_H
 #include <dirent.h>
#endif
#ifdef AK_HAVE_FNMATCH_H
 #include <fnmatch.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \param filename Имя, для которого проводится проверка
    \return Функция возвращает одну из констант \ref DT_REG или \ref DT_DIR в случае успеха.
    В случае, если имя ошибочно, то возвращается \ref ak_error_access_file.                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_file_or_directory( const tchar *filename )
{
 struct stat st;

  if(( !filename ) || ( stat( filename, &st )))  return ak_error_access_file;
  if( S_ISREG( st.st_mode )) return DT_REG;
  if( S_ISDIR( st.st_mode )) return DT_DIR;

 return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param root Имя каталога, в котором проводится поиск файлов
    \param mask Маска разыскиваемых файлов
    \param function Пользовательская функция, которой передается управление при нахождении файла
    \param ptr Указатель на данные, которые передаются пользовательской функции
    \param tree Флаг, который указывает нужно ли обходить каталоги рекурсивно
    (искать файлы во вложенных каталогах)
    \return В случае успеха возвращается \ref ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_file_find( const char *root , const char *mask,
                                          ak_function_find *function, ak_pointer ptr, bool_t tree )
{
  int ev, error = ak_error_ok;

#ifdef _WIN32
  WIN32_FIND_DATA ffd;
  TCHAR szDir[MAX_PATH];
  char filename[MAX_PATH];
  HANDLE hFind = INVALID_HANDLE_VALUE;
  size_t rlen = 0, mlen = 0;

 #ifdef _MSC_VER
  if( FAILED( StringCchLength( root, MAX_PATH-1, &rlen )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                             "incorrect length for root variable" );
  if( FAILED( StringCchLength( mask, MAX_PATH-1, &mlen )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect length for mask variable" );
 #else
  rlen = strlen( root ); mlen = strlen( mask );
 #endif

  if( rlen > (MAX_PATH - ( mlen + 2 )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ , "directory path too long" );

 #ifdef _MSC_VER
  if( FAILED( StringCchCopy( szDir, MAX_PATH-1, root )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect copying of root variable" );
  if( FAILED( StringCchCat( szDir, MAX_PATH-1, TEXT( "\\" ))))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                      "incorrect copying of directory separator" );
  if( FAILED( StringCchCat( szDir, MAX_PATH-1, mask )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect copying of mask variable" );
 #else
  ak_snprintf( szDir, MAX_PATH-1, "%s\\%s", root, mask );
 #endif

 /* начинаем поиск */
  if(( hFind = FindFirstFile( szDir, &ffd )) == INVALID_HANDLE_VALUE )
    return ak_error_message_fmt( ak_error_access_file, __func__ , "given mask search error" );

  do {
       if( ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) {

         if( !strcmp( ffd.cFileName, "." )) continue;  // пропускаем себя и каталог верхнего уровня
         if( !strcmp( ffd.cFileName, ".." )) continue;

         if( tree ) { // выполняем рекурсию для вложенных каталогов
           memset( szDir, 0, MAX_PATH );
          #ifdef _MSC_VER
           if( FAILED( StringCchCopy( szDir, MAX_PATH-1, root )))
             return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect copying of root variable" );
           if( FAILED( StringCchCat( szDir, MAX_PATH-1, TEXT( "\\" ))))
             return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                      "incorrect copying of directory separator" );
           if( FAILED( StringCchCat( szDir, MAX_PATH-1,  ffd.cFileName )))
             return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                                "incorrect copying of file name" );
          #else
           ak_snprintf( szDir, MAX_PATH-1, "%s\\%s", root,  ffd.cFileName );
          #endif

           if(( ev = ak_file_find( szDir, mask, function, ptr, tree )) != ak_error_ok )
             ak_error_message_fmt( error = ev,
                                         __func__, "access to \"%s\" directory denied", filename );
         }
       } else {
               if( ffd.dwFileAttributes &FILE_ATTRIBUTE_SYSTEM ) continue;
                 memset( filename, 0, FILENAME_MAX );
                #ifdef _MSC_VER
                 if( FAILED( StringCchCopy( filename, MAX_PATH-1, root )))
                   return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect copying of root variable" );
                 if( FAILED( StringCchCat( filename, MAX_PATH-1, TEXT( "\\" ))))
                   return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                      "incorrect copying of directory separator" );
                 if( FAILED( StringCchCat( filename, MAX_PATH-1,  ffd.cFileName )))
                   return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                               "incorrect copying of file namme" );
                #else
                 ak_snprintf( filename, MAX_PATH-1, "%s\\%s", root,  ffd.cFileName );
                #endif
                 if(( ev = function( filename, ptr )) != ak_error_ok ) error = ev;
              }

  } while( FindNextFile( hFind, &ffd ) != 0);
  FindClose(hFind);

// далее используем механизм функций open/readdir + fnmatch
#else
  DIR *dp = NULL;
  struct dirent *ent = NULL;
  char filename[FILENAME_MAX];

 /* открываем каталог */
  errno = 0;
  if(( dp = opendir( root )) == NULL ) {
    if( errno == EACCES ) return ak_error_message_fmt( ak_error_access_file,
                                          __func__ , "access to \"%s\" directory denied", root );
    if( errno > -1 ) return ak_error_message_fmt( ak_error_open_file,
                                                                __func__ , "%s", strerror( errno ));
  }

 /* перебираем все файлы и каталоги */
  while(( ent = readdir( dp )) != NULL ) {
    if( ent->d_type == DT_DIR ) {
      if( !strcmp( ent->d_name, "." )) continue;  // пропускаем себя и каталог верхнего уровня
      if( !strcmp( ent->d_name, ".." )) continue;

      if( tree ) { // выполняем рекурсию для вложенных каталогов
        memset( filename, 0, FILENAME_MAX );
        ak_snprintf( filename, FILENAME_MAX, "%s/%s", root, ent->d_name );
        if(( ev = ak_file_find( filename, mask, function, ptr, tree )) != ak_error_ok ) {
          ak_error_message_fmt( error = ev, __func__, "access to \"%s\" directory denied", filename );
        }
      }
    } else
       if( ent->d_type == DT_REG ) { // обрабатываем только обычные файлы
          if( !fnmatch( mask, ent->d_name, FNM_PATHNAME )) {
            memset( filename, 0, FILENAME_MAX );
            ak_snprintf( filename, FILENAME_MAX, "%s/%s", root, ent->d_name );
            if(( ev = function( filename, ptr )) != ak_error_ok ) error = ev;
          }
       }
  }
  if( closedir( dp )) return ak_error_message_fmt( ak_error_close_file,
                                                                __func__ , "%s", strerror( errno ));
#endif
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param filename Имя файла из которого считываются строки
    \param function Пользовательская функция, которая производит обработку считанной строки
    \param ptr Указатель на данные, передаваемые в пользовательскую функцию
    \return В случае успеха возвращается \ref ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_file_read_by_lines( const tchar *filename, ak_file_read_function *function , ak_pointer ptr )
{
  #define buffer_length ( FILENAME_MAX + 160 )

  struct stat st;
  size_t idx = 0, off = 0;
  int fd = 0, error = ak_error_ok;
  char ch, localbuffer[buffer_length];

 /* проверяем наличие файла и прав доступа к нему */
  if(( fd = open( filename, O_RDONLY | O_BINARY )) < 0 )
    return ak_error_message_fmt( ak_error_open_file,
                             __func__, "wrong open file \"%s\" - %s", filename, strerror( errno ));
  if( fstat( fd, &st ) ) {
    close( fd );
    return ak_error_message_fmt( ak_error_access_file, __func__ ,
                              "wrong stat file \"%s\" with error %s", filename, strerror( errno ));
  }

 /* нарезаем входные на строки длиной не более чем buffer_length - 2 символа */
  memset( localbuffer, 0, buffer_length );
  for( idx = 0; idx < (size_t) st.st_size; idx++ ) {
     if( read( fd, &ch, 1 ) != 1 ) {
       close(fd);
       return ak_error_message_fmt( ak_error_read_data, __func__ ,
                                                                "unexpected end of %s", filename );
     }
     if( off > buffer_length - 2 ) {
       close( fd );
       return ak_error_message_fmt( ak_error_read_data, __func__ ,
                          "%s has a line with more than %d symbols", filename, buffer_length - 2 );
     }
    if( ch == '\n' ) {
      #ifdef _WIN32
       if( off ) localbuffer[off-1] = 0;  /* удаляем второй символ перехода на новую строку */
      #endif
      error = function( localbuffer, ptr );
     /* далее мы очищаем строку независимо от ее содержимого */
      off = 0;
      memset( localbuffer, 0, buffer_length );
    } else localbuffer[off++] = ch;
   /* выходим из цикла если процедура проверки нарушена */
    if( error != ak_error_ok ) return error;
  }

  close( fd );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_open_to_read( ak_file file, const char *filename )
{
#ifdef _WIN32
  struct _stat st;
  if( _stat( filename, &st ) < 0 ) {
#else
  struct stat st;
  if( stat( filename, &st ) < 0 ) {
#endif
    switch( errno ) {
      case EACCES:
        if( ak_log_get_level() >= ak_log_maximum )
          ak_error_message_fmt( ak_error_access_file, __func__,
                                 "incorrect access to file %s [%s]", filename, strerror( errno ));
        return ak_error_access_file;
      default:
        if( ak_log_get_level() >= ak_log_maximum )
          ak_error_message_fmt( ak_error_open_file, __func__ ,
                                     "wrong opening a file %s [%s]", filename, strerror( errno ));
        return ak_error_open_file;
    }
  }

 /* заполняем данные */
  file->size = ( ak_int64 )st.st_size;
 #ifdef AK_HAVE_WINDOWS_H
  if(( file->hFile = CreateFile( filename,   /* name of the write */
                     GENERIC_READ,           /* open for reading */
                     0,                      /* do not share */
                     NULL,                   /* default security */
                     OPEN_EXISTING,          /* open only existing file */
                     FILE_ATTRIBUTE_NORMAL,  /* normal file */
                     NULL )                  /* no attr. template */
      ) == INVALID_HANDLE_VALUE ) {
      if( ak_log_get_level() >= ak_log_maximum )
        ak_error_message_fmt( ak_error_open_file, __func__,
                                     "wrong opening a file %s [%s]", filename, strerror( errno ));
      return ak_error_open_file;
  }
  file->blksize = 4096;
 #else
  if(( file->fd = open( filename, O_SYNC|O_RDONLY )) < 0 ) {
    if( ak_log_get_level() >= ak_log_maximum )
      ak_error_message_fmt( ak_error_open_file, __func__ ,
                                     "wrong opening a file %s [%s]", filename, strerror( errno ));
    return ak_error_open_file;
  }
  file->blksize = ( ak_int64 )st.st_blksize;
 #endif

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_create_to_write( ak_file file, const char *filename )
{
 #ifndef AK_HAVE_WINDOWS_H
  struct stat st;
 #endif

 /* необходимые проверки */
  if(( file == NULL ) || ( filename == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer" );

  file->size = 0;
 #ifdef AK_HAVE_WINDOWS_H
  if(( file->hFile = CreateFile( filename,   /* name of the write */
                     GENERIC_WRITE,          /* open for writing */
                     0,                      /* do not share */
                     NULL,                   /* default security */
                     CREATE_ALWAYS,          /* create new file only */
                     FILE_ATTRIBUTE_NORMAL,  /* normal file */
                     NULL )                  /* no attr. template */
     ) == INVALID_HANDLE_VALUE )
      return ak_error_message_fmt( ak_error_create_file, __func__,
                                    "wrong creation a file %s [%s]", filename, strerror( errno ));
   file->blksize = 4096;

 #else  /* мы устанавливаем минимальные права: чтение и запись только для владельца */
  if(( file->fd = creat( filename, S_IRUSR | S_IWUSR )) < 0 )
    return ak_error_message_fmt( ak_error_create_file, __func__,
                                   "wrong creation a file %s [%s]", filename, strerror( errno ));
  if( fstat( file->fd, &st )) {
    close( file->fd );
    return ak_error_message_fmt( ak_error_access_file,  __func__,
                                "incorrect access to file %s [%s]", filename, strerror( errno ));
  } else file->blksize = ( ak_int64 )st.st_blksize;
 #endif

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_close( ak_file file )
{
   file->size = 0;
   file->blksize = 0;
  #ifdef AK_HAVE_WINDOWS_H
   CloseHandle( file->hFile);
  #else
   if( close( file->fd ) != 0 ) return ak_error_message_fmt( ak_error_close_file, __func__ ,
                                                 "wrong closing a file [%s]", strerror( errno ));
  #endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_file_read( ak_file file, ak_pointer buffer, size_t size )
{
 #ifdef AK_HAVE_WINDOWS_H
  DWORD dwBytesReaden = 0;
  BOOL bErrorFlag = ReadFile( file->hFile, buffer, ( DWORD )size,  &dwBytesReaden, NULL );
  if( bErrorFlag == FALSE ) {
    ak_error_message( ak_error_read_data, __func__, "unable to read from file");
    return -1;
  } else return ( ssize_t ) dwBytesReaden;
 #else
  return read( file->fd, buffer, size );
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_file_write( ak_file file, ak_const_pointer buffer, size_t size )
{
 #ifdef AK_HAVE_WINDOWS_H
  DWORD dwBytesWritten = 0;
  BOOL bErrorFlag = WriteFile( file->hFile, buffer, ( DWORD )size,  &dwBytesWritten, NULL );
  if( bErrorFlag == FALSE ) {
    ak_error_message( ak_error_write_data, __func__, "unable to write to file");
    return -1;
  } else return ( ssize_t ) dwBytesWritten;
 #else
   ssize_t wb = write( file->fd, buffer, size );
   if( wb == -1 ) ak_error_message_fmt( ak_error_write_data, __func__,
                                                "unable to write to file (%s)", strerror( errno ));
  return wb;
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_file_printf( ak_file outfile, const char *format, ... )
{
  va_list args;
  ssize_t result = 0;
  char static_buffer[1024];
  va_start( args, format );

 /* формируем строку (дублируем код функции ak_snprintf) */
 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    _vsnprintf_s( static_buffer,
                  sizeof( static_buffer ),
                  sizeof( static_buffer ), format, args );
  #else
    _vsnprintf( static_buffer,
                sizeof( static_buffer ), format, args );
  #endif
 #else
  vsnprintf( static_buffer, sizeof( static_buffer ), format, args );
 #endif
  va_end( args );

 /* выводим ее в файл как последовательность байт */
  result = ak_file_write( outfile, static_buffer, strlen( static_buffer ));
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
                   /* Отображение файлов в память (обертка вокруг mmap) */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_file_mmap( ak_file file,
                                    void *addr, size_t length, int prot, int flags, size_t offset )
{
 #ifdef AK_HAVE_SYSMMAN_H
  if(( file->addr = mmap( addr, file->mmaped_size = length,
                                                prot, flags, file->fd, offset )) == MAP_FAILED ) {
    ak_error_message_fmt( ak_error_mmap_file, __func__, "mmap error (%s)", strerror( errno ));
  }
  return file->addr;
 #else
 /* в ситуациях, когда mmap не определена, сразу выходим */
  ak_error_message( ak_error_undefined_function, __func__, "this function is'nt well developed" );
  return NULL;
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_unmap( ak_file file )
{
 #ifdef AK_HAVE_SYSMMAN_H
  if( munmap( file->addr, file->mmaped_size ) < 0 ) {
    return ak_error_message_fmt( ak_error_unmap_file, __func__,
                                                           "munmap error (%s)", strerror( errno ));
  }
  return ak_error_ok;
 #else
 /* в ситуациях, когда mmap не определена, сразу выходим */
  return ak_error_message( ak_error_undefined_function, __func__,
                                                            "this function is'nt well developed" );
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция обрабатывает только префикс файла.
    В случае появления внутри строки символов вида .. их обработка не производится.

    @param path null-строка, в которой содержится короткое имя файла;
    @param resolved_path преобразованное имя файла, оканчивается нулем.
    @param maxsize размер массива, выделенного под преобразованное имя.
    @return В случае успеха возвращается \ref ak_error_ok, в противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_realpath( const char *path, char *resolved_path, size_t maxsize )
{
    tchar prefix[FILENAME_MAX];

    if( path == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to input data" );
    if( resolved_path == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to output data" );
    if( !maxsize) return ak_error_message( ak_error_zero_length, __func__,
                                                          "using output buffer with zero length" );
    if( getcwd( prefix, FILENAME_MAX -1 ) == NULL )
      return ak_error_message( ak_error_getcwd, __func__,
                                                     "incorrect generation of current directory" );
   /* если начинается с / */
    if( path[0] == '/' ) {
      ak_snprintf( resolved_path, maxsize, "%s", path );
      goto exlab;
    }
   /* если начинается с . */
    if( path[0] == '.' ) {
      if( strlen( path ) == 1 )
        return ak_error_message( ak_error_undefined_file, __func__, "unsupported name of file");
      if( path[1] == '/' ) {
        ak_snprintf( resolved_path, maxsize, "%s%s%s", prefix,
          #ifdef WIN32
            "\\"
          #else
            "/"
          #endif
          , path +2 );
        goto exlab;
      }
      if( path[1] == '.' ) {
        if( strlen( path ) == 2 )
          return ak_error_message( ak_error_undefined_file, __func__, "unsupported name of file");
        if( path[2] == '/' ) {
          /* имеем файл вида "../имя файла" */
          char *ptr = strrchr( prefix,
            #ifdef WIN32
              '\\'
            #else
              '/'
            #endif
           );
          if( ptr == NULL )
            return ak_error_message( ak_error_undefined_file, __func__, "unsupported prefix");
          if( ptr == prefix )
            return ak_error_message( ak_error_undefined_file, __func__, "unsupported prefix");
          *ptr = 0;
          ak_snprintf( resolved_path, maxsize, "%s%s%s", prefix,
            #ifdef WIN32
              "\\"
            #else
              "/"
            #endif
           , path +3 );
          goto exlab;
        }
      }
    }
    if( path[0] == '~' ) {
      ak_homepath( prefix, FILENAME_MAX -1 );
      ak_snprintf( resolved_path, maxsize, "%s%s", prefix, path +1 );
      goto exlab;
    }
   /* иначе */
    ak_snprintf( resolved_path, maxsize, "%s%s%s",
       prefix,
     #ifdef WIN32
      "\\"
     #else
      "/"
     #endif
       , path );

   exlab:
    resolved_path[maxsize -1] = 0;
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hpath Буффер в который будет помещено имя домашнего каталога пользователя.
    @param size Размер буффера в байтах.

    @return В случае возникновения ошибки возвращается ее код. В случае успеха
    возвращается \ref ak_error_ok.                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_homepath( char *hpath, const size_t size )
{
 if( hpath == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to filename buffer" );
 if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                               "using a buffer with zero length" );
 memset( hpath, 0, size );

 #ifdef _WIN32
  /* в начале определяем, находимся ли мы в консоли MSys */
   GetEnvironmentVariableA( "HOME", hpath, ( DWORD )size );
  /* если мы находимся не в консоли, то строка hpath должна быть пустой */
   if( strlen( hpath ) == 0 ) {
     GetEnvironmentVariableA( "USERPROFILE", hpath, ( DWORD )size );
   }
 #else
   ak_snprintf( hpath, size, "%s", getenv( "HOME" ));
 #endif

 if( strlen( hpath ) == 0 ) return ak_error_message( ak_error_undefined_value, __func__,
                                                                           "wrong user home path");
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-file.c                                                                        */
/*! \example example-mmap.c                                                                        */
/*! \example example-realpath.c                                                                    */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_file.c  */
/* ----------------------------------------------------------------------------------------------- */
