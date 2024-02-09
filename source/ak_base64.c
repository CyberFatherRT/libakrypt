/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 - 2023 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Portions Copyright (c) 1996-1999 by Internet Software Consortium.                              */
/*  Portions Copyright (c) 1995 by International Business Machines, Inc.                           */
/*                                                                                                 */
/*  Файл ak_base64.с                                                                               */
/*  - содержит реализацию функций для кодирования/декодирования данных в формате BASE64            */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Используемый для кодирования алфавит, согласно RFC1113 */
 static const char base64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* ----------------------------------------------------------------------------------------------- */
/*! Буфер, который хранит строку максимально возможной длины */
 char localbuffer[FILENAME_MAX];

/* ----------------------------------------------------------------------------------------------- */
/*! \param in  указатель на кодируемые данные,
    \param out указатель на данные, куда помещается результат
    \param len количество кодируемых октетов (от одного до трех)                                   */
/* ----------------------------------------------------------------------------------------------- */
 void ak_base64_encodeblock( ak_uint8 *in, ak_uint8 *out, int len )
{
     switch ( len )
    {
     case 1:
        out[0] = (ak_uint8) base64[ (int)(in[0] >> 2) ];
        out[1] = (ak_uint8) base64[ (int)((in[0] & 0x03) << 4) ];
        out[2] = '=';
        out[3] = '=';
       break;

     case 2:
        out[0] = (ak_uint8) base64[ (int)(in[0] >> 2) ];
        out[1] = (ak_uint8) base64[ (int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)) ];
        out[2] = (ak_uint8) base64[ (int)((in[1] & 0x0f) << 2) ];
        out[3] = '=';
       break;

     case 3:
        out[0] = (ak_uint8) base64[ (int)(in[0] >> 2) ];
        out[1] = (ak_uint8) base64[ (int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)) ];
        out[2] = (ak_uint8) base64[ (int)(((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)) ];
        out[3] = (ak_uint8) base64[ (int)(in[2] & 0x3f) ];
       break;

     default:
        ak_error_message( ak_error_undefined_value, __func__, "unexpected value of length" );
       break;
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция пытается считать данные из файла в буффер, на который указывает `buf`.
    Данные в файле должны быть сохранены в формате base64. Все строки файлов,
    содержащие последовательность символов "-----",
    а также ограничители '#', ':', игнорируются.

    В оставшихся строках символы, не входящие в base64, игнорируются.

 \note Функция экспортируется.
 \param buf указатель на массив, в который будут считаны данные;
        память может быть выделена заранее, если память не выделена,
        то указатель должен принимать значение NULL. Если выделенной памяти недостаточно,
        то выделяется новая область памяти, которая должна быть позднее удалена с помощью функции free().
 \param size размер выделенной заранее памяти в байтах;
        в случае выделения новой памяти, в переменную `size` помещается размер выделенной памяти.
 \param filename файл, из которого будет производиться чтение.

 \return Функция возвращает указатель на буффер, в который помещены данные.
        Если произошла ошибка, то функция возвращает NULL; код ошибки может быть получен с помощью
        вызова функции ak_error_get_value().                                                       */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_ptr_load_from_base64_file( ak_pointer buf, size_t *size, const char *filename )
{
  char ch;
  struct file sfp;
  ak_uint64 idx = 0;
  size_t ptrlen = 0, len = 0;
  ak_uint8 *ptr = NULL;
  int error = ak_error_ok, off = 0;

 /* открываемся */
  if(( error = ak_file_open_to_read( &sfp, filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "wrong opening the %s", filename );
    return NULL;
  }

  /* надо бы определиться с размером буфера:
     величины 1 + sfp.size*3/4 должно хватить, даже без лишних символов. */
  if( sfp.size < 5 ) {
    ak_error_message( ak_error_zero_length, __func__, "loading from file with zero length" );
    ak_file_close( &sfp );
    return NULL;
  } else ptrlen = 1 + (( 3*sfp.size ) >> 2);

 /* проверяем наличие доступной памяти */
  if(( buf == NULL ) || ( ptrlen > *size )) {
    if(( ptr = malloc( ptrlen )) == NULL ) {
      ak_error_message( error = ak_error_out_of_memory, __func__, "incorrect memory allocation" );
      goto exlab;
    }
  } else {
      ptr = buf;
      ptrlen = *size;
    }

 /* нарезаем входные данные на строки длиной не более чем 1022 символа */
  memset( ptr, 0, ptrlen );
  memset( localbuffer, 0, sizeof( localbuffer ));
  for( idx = 0; idx < (size_t) sfp.size; idx++ ) {
     if( ak_file_read( &sfp, &ch, 1 ) != 1 ) {
       ak_error_message_fmt( error = ak_error_read_data, __func__ ,
                                                               "unexpected end of %s", filename );
       goto exlab;
     }
     if( off > (int)( sizeof( localbuffer )-2 )) {
       ak_error_message_fmt( error = ak_error_read_data, __func__ ,
                   "%s has a line with more than %u symbols", filename, sizeof( localbuffer )-2 );
       goto exlab;
     }
    if( ch == '\n' ) {
      int state = 0;
      char *pos = 0;
      size_t i = 0, slen = strlen( localbuffer );

     /* обрабатываем конец строки для файлов, созданных в Windows */
      if((slen > 0) && (localbuffer[slen-1] == 0x0d )) { localbuffer[slen-1] = 0; slen--; }

     /* проверяем корректность строки с данными */
      if(( slen != 0 ) &&              /* строка не пустая */
         ( strchr( localbuffer, '#' ) == 0 ) &&        /* строка не содержит символ # */
         ( strchr( localbuffer, ':' ) == 0 ) &&        /* строка не содержит символ : */
         ( strstr( localbuffer, "-----" ) == NULL )) { /* строка не содержит ----- */

        /* теперь последовательно декодируем одну строку */
         while(( ch = localbuffer[i++]) != 0 ) {
           if( ch == ' ' ) continue; /* пробелы пропускаем */
           if( ch == '=' ) break;    /* достигли конца данных */
           if(( pos = strchr( base64, ch )) == NULL ) { /* встречен некорректный символ,
                                                                      мы его игнорируем */
           }
           if( len + 1 >= ptrlen ) { /* достаточно места для хранения данных */
             ak_error_message( error = ak_error_wrong_index, __func__ ,
                                                                   "current index is too large" );
             goto exlab;
           }
           switch( state ) {
             case 0:
               ptr[len] = (pos - base64) << 2;
               state = 1;
             break;

             case 1:
               ptr[len] |= (pos - base64) >> 4;
               ptr[len+1] = ((pos - base64) & 0x0f) << 4;
               len++;
               state = 2;
             break;

             case 2:
               ptr[len] |= (pos - base64) >> 2;
               ptr[len+1] = ((pos - base64) & 0x03) << 6;
               len++;
               state = 3;
             break;

             case 3:
               ptr[len] |= (pos - base64);
               len++;
               state = 0;
             break;
             default: break;
           }
         }

        /* обработка конца данных */
         if( ch == '=' ) {
           if(( state == 0 ) || ( state == 1 )) {
             ak_error_message( error = ak_error_wrong_length, __func__ ,
                                                     "incorrect last symbol(s) of encoded data" );
             goto exlab;
           }
         }

      } /* далее мы очищаем строку независимо от ее содержимого */
      off = 0;
      memset( localbuffer, 0, sizeof( localbuffer ));
    } else localbuffer[off++] = ch;
  }

 /* получили нулевой вектор => ошибка */
  if( len == 0 ) ak_error_message_fmt( error = ak_error_zero_length, __func__,
                                       "%s not contain a correct base64 encoded data", filename );
 exlab:
  *size = len;
  ak_file_close( &sfp );
  if( error != ak_error_ok ) {
    if(( ptr != NULL ) && (ptr != buf )) free(ptr);
    ptr = NULL;
  }

 return ptr;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param size размер двоичных данных (в байтах)
 *  @param format формат строки для вывода
 *  @return В случае успеха, функция возвращает количество байт в строке, в случае ошибки,
 *  возвращается ноль. */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_ptr_to_base64_size( const size_t size, const base64_format_t format )
{
    size_t blocks = size/3;
    size_t tail = size - 3*blocks;
    size_t result = 0;

    if( size == 0 ) {
      ak_error_message( ak_error_zero_length, __func__, "using input data with zero length" );
      return 0;
    }
    if( tail > 0 ) blocks++;

    switch( format ) {
     /* режим без добавления пробелов */
      case plain_base64_format:
         result = ( 1 + 4*blocks ); /* количество блоков по четыре символа + завершающий ноль */
         break;

      case grouped_base64_format:
         result = 1 + 4*blocks + ( blocks -1 );
         break;
        /* количество блоков по четыре символа + количество пробелов + завершающий ноль */
    }

 /* мы выравниваем по длине в 8 байт с обязательным(!) запасом, даже с учетом завершающего нуля */
  return ( 1+ ( result>>3 ))<<3;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param in двоичные данные, которые преобразуются в base64
 *  @param size размер двоичных данных (в байтах)
 *  @param format формат строки для вывода
 *  @return В случае успеха, функция возвращает указатель на статическую строку с преобразованной
 *  последовательностью символов. В случае ошибки, возвращается NULL. */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_ptr_to_base64( ak_const_pointer in, const size_t size, const base64_format_t format )
{
    ak_uint8 *inptr = (ak_uint8 *) in;
    ak_uint8 *outptr = (ak_uint8 *) localbuffer;
    size_t bs, locsize = size, len = ak_ptr_to_base64_size( size, format );

    if( in == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__, "using null pointer to input data" );
      return NULL;
    }
    if( len == 0 ) {
      ak_error_message( ak_error_zero_length, __func__, "using input data with zero length" );
      return NULL;
    }
    if( len > sizeof( localbuffer )) {
      ak_error_message( ak_error_wrong_length, __func__,
                            "input data is too long, use ak_ptr_to_base64_alloc() function" );
      return NULL;

    }

   /* теперь все хорошо, и мы начинаем конвертацию */
    memset( localbuffer, 0, len );

    while( locsize > 0 ) {
      ak_base64_encodeblock( inptr, outptr, bs = ak_min( locsize, 3 ));
      outptr += 4;

      if( format == grouped_base64_format ) *outptr++ = ' ';

      locsize -= bs;
      inptr += bs;
    }

  return localbuffer;
}

/* ----------------------------------------------------------------------------------------------- */
/*! В процессе своей работы функция выделяет область в оперативной памяти процесса и возвращает
 *  указатель на эту область. После использования, память должна быть удалена с помощью вызова
 *  функции free().
 *
 *  @param in двоичные данные, которые преобразуются в base64
 *  @param size размер двоичных данных (в байтах)
 *  @param format формат строки для вывода
 *  @return В случае успеха, функция возвращает указатель на статическую строку с преобразованной
 *  последовательностью символов. В случае ошибки, возвращается NULL. */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_ptr_to_base64_alloc( ak_const_pointer in, const size_t size, const base64_format_t format )
{
    ak_uint8 *retptr, *outptr = NULL, *inptr = (ak_uint8 *) in;
    size_t bs, locsize = size, len = ak_ptr_to_base64_size( size, format );

    if( in == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__, "using null pointer to input data" );
      return NULL;
    }
    if( len == 0 ) {
      ak_error_message( ak_error_zero_length, __func__, "using input data with zero length" );
      return NULL;
    }
    if(( retptr = outptr = (ak_uint8 *) calloc( 1, len )) == NULL ) {
      ak_error_message( ak_error_out_of_memory, __func__, "memory allocation error" );
      return NULL;
    }

   /* теперь все хорошо, и мы начинаем конвертацию */
    while( locsize > 0 ) {
      ak_base64_encodeblock( inptr, outptr, bs = ak_min( locsize, 3 ));
      outptr += 4;

      if( format == grouped_base64_format ) *outptr++ = ' ';

      inptr += bs;
      locsize -= bs;
    }

  return (char *)retptr;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразует строку символов, содержащую последовательность символов в кодировке base64
 *  в массив данных. Строка символов должна быть строкой, оканчивающейся нулем (NULL string).

    @param b64 Строка символов.
    @param buffer Указатель на область памяти (массив), в которую будут размещаться данные.
           память может быть выделена заранее, если память не выделена,
           то указатель должен принимать значение NULL. Если выделенной памяти недостаточно,
           то выделяется новая область памяти, которая должна быть позднее удалена с помощью
           функции free().
    @param size размер выделенной заранее памяти в байтах;
           в случае выделения новой памяти, в переменную `size` помещается размер выделенной памяти.

    @return Функция возвращает указатель на буффер, в который помещены данные.
           Если произошла ошибка, то функция возвращает NULL; код ошибки может быть получен
           с помощью вызова функции ak_error_get_value().                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_base64_to_ptr( const char *b64, ak_pointer buffer, size_t *size )
{
    char ch, *pos = 0;
    ak_uint8 *ptr = buffer;
    size_t i = 0, j = 0, len = 0;
    int state = 0, error = ak_error_ok;

   /* негоже вычислять strlen на null-указателе */
    if( b64 == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__, "using null pointer to input string" );
      return NULL;
    }
     else len = 3*((( strlen( b64 )&0x3 ) != 0 ) + ( strlen( b64 ) >> 2 ));
                     /* длина строки без нуля даст почти точное количество байт (оцениваем сверху) */

//    printf("size: %u, len: %u\n", *size, len );

    if(( *size < len ) || ( buffer == NULL )) {
      if(( ptr = (ak_uint8 *)calloc( 1, len )) == NULL ) {
        ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
        return NULL;
      }
    }

   /* теперь последовательно декодируем входную строку */
    while(( ch = b64[i++]) != 0 ) {
      if( ch == ' ' ) continue; /* пробелы пропускаем */
      if( ch == '=' ) break;    /* достигли конца данных */
      if(( pos = strchr( base64, ch )) == NULL ) { /* встречен некорректный символ,
                                                                 мы его игнорируем */
      }
      if( j + 1 > len ) {
        ak_error_message( error = ak_error_wrong_index, __func__ , "current index is too large" );
        goto exlab;
      }

     /* основная перекодировка */
           switch( state ) {
             case 0:
               ptr[j] = (pos - base64) << 2;
               state = 1;
             break;

             case 1:
               ptr[j] |= (pos - base64) >> 4;
               ptr[j+1] = ((pos - base64) & 0x0f) << 4;
               j++;
               state = 2;
             break;

             case 2:
               ptr[j] |= (pos - base64) >> 2;
               ptr[j+1] = ((pos - base64) & 0x03) << 6;
               j++;
               state = 3;
             break;

             case 3:
               ptr[j] |= (pos - base64);
               j++;
               state = 0;
             break;
             default: break;
           }
    }

   exlab:
    *size = j;
    if( error != ak_error_ok ) {
      if(( ptr != NULL ) && ( ptr != buffer )) free(ptr);
      ptr = NULL;
    }
  return ptr;
}

/* ----------------------------------------------------------------------------------------------- */
/* ak_base64.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
