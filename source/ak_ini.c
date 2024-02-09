/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2009-2020, Ben Hoyt, https://github.com/benhoyt/inih                             */
/*                                                                                                 */
/*  adopted by Axel Kenzo, axelkenzo@mail.ru                                                       */
/*                                                                                                 */
/*  Файл ak_ini.c                                                                                  */
/*  - содержит реализацию функций чтения данных из ini файлов                                      */
/* ----------------------------------------------------------------------------------------------- */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/*! \brief Прототип функции чтения строк (fgets-style). */
 typedef char* (*ak_function_ini_reader)( char * , int , void * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Множество символов с которых могут начинаться строки-комментарии. */
 #define ini_start_comment_prefixes ";#"
/*! \brief Флаг разрешает использование комментариев, расположенных внутри строк с данными. */
 #define ini_allow_inline_comments 1
/*! \brief Множество символов с которых могут начинаться комментарии, расположенные внутри строк с данными. */
 #define ini_inline_comment_prefixes ";#"
/*! \brief Флаг остановки парсинга ini-файла после возникновения первой ошибки. */
 #define ini_stop_on_first_error 1
/*! \brief Флаг разрешает/запрещает использование полей без параметров. */
 #define ini_allow_no_value 0

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Максимальное количество символов в одной строке (включая '\r', '\n', and '\0'). */
 #define ini_max_line 1024
/*! \brief Максимальный размер строки для имени секции. */
 #define ini_max_section 256
/*! \brief Максимальный размер строки для имени. */
 #define ini_max_name 256

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, используемая ini_parse_string() для хранения текущего состояния. */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct {
    const char* ptr;
    size_t num_left;
} ini_parse_string_ctx;

/* ----------------------------------------------------------------------------------------------- */
/*! Strip whitespace chars off end of given string, in place. Return s. */
/* ----------------------------------------------------------------------------------------------- */
 static char* rstrip(char* s)
{
    char* p = s + strlen(s);
    while (p > s && isspace((unsigned char)(*--p)))
        *p = '\0';
    return s;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Return pointer to first non-whitespace char in given string. */
/* ----------------------------------------------------------------------------------------------- */
 static char* lskip(const char* s)
{
    while (*s && isspace((unsigned char)(*s)))
        s++;
    return (char*)s;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Return pointer to first char (of chars) or inline comment in given string,
   or pointer to null at end of string if neither found. Inline comment must
   be prefixed by a whitespace character to register as a comment. */
/* ----------------------------------------------------------------------------------------------- */
 static char* find_chars_or_comment(const char* s, const char* chars)
{
#if ini_allow_inline_comments
    int was_space = 0;
    while (*s && (!chars || !strchr(chars, *s)) &&
           !(was_space && strchr(ini_inline_comment_prefixes, *s))) {
        was_space = isspace((unsigned char)(*s));
        s++;
    }
#else
    while (*s && (!chars || !strchr(chars, *s))) {
        s++;
    }
#endif
    return (char*)s;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Version of strncpy that ensures dest (size bytes) is null-terminated. */
/* ----------------------------------------------------------------------------------------------- */
 static char* strncpy0( char* dest, const char* src, size_t size )
{
  size_t len = 0;

 /* используем медленное побайтное копирование с проверкой длины
    операция может привести к обрезанию исходной строки */
  memset( dest, 0, size );

  while(( len < size-1 ) && ( *src != 0 )) {
   dest[len] = src[len];
   ++len;
  }

 return dest;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Same as ini_parse(), but takes an ini_reader function pointer instead of
   filename. Used for implementing custom or string-based I/O (see also
   ini_parse_string). */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_ini_parse_stream( ak_function_ini_reader reader, void* stream,
				                      ak_function_ini_handler handler, void* user )
{
    char line[ini_max_line];
    int max_line = ini_max_line;
    char section[ini_max_section] = "";
    char prev_name[ini_max_section] = "";

    char* start;
    char* end;
    char* name;
    char* value;
    int lineno = 0;
    int error = 0;

    /* Scan through stream line by line */
    while (reader(line, (int)max_line, stream) != NULL) {
        lineno++;

        start = line;
        start = lskip(rstrip(start));

        if (strchr(ini_start_comment_prefixes, *start)) {
            /* Start-of-line comment */
        }
        else if (*start == '[') {
            /* A "[section]" line */
            end = find_chars_or_comment(start + 1, "]");
            if (*end == ']') {
                *end = '\0';
                strncpy0(section, start + 1, sizeof(section));
                *prev_name = '\0';
            }
            else if (!error) {
                /* No ']' found on section line */
                error = lineno;
            }
        }
        else if (*start) {
            /* Not a comment, must be a name[=:]value pair */
            end = find_chars_or_comment(start, "=:");
            if (*end == '=' || *end == ':') {
                *end = '\0';
                name = rstrip(start);
                value = end + 1;
#if ini_allow_inline_comments
                end = find_chars_or_comment(value, NULL);
                if (*end)
                    *end = '\0';
#endif
                value = lskip(value);
                rstrip(value);

                /* Valid name[=:]value pair found, call handler */
                strncpy0( prev_name, name, sizeof( prev_name ));
                if( !handler(user, section, name, value) && !error)
                    error = lineno;
            }
            else if (!error) {
                /* No '=' or ':' found on name[=:]value line */
#if ini_allow_no_value
                *end = '\0';
                name = rstrip(start);
                if (!handler(user, section, name, NULL) && !error)
                    error = lineno;
#else
                error = lineno;
#endif
            }
        }

#if ini_stop_on_first_error
        if( error ) break;
#endif
    }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Same as ini_parse(), but takes a FILE* instead of filename. This doesn't
    close the file when it's finished -- the caller must do that.

  \param file файловый дескриптор ini-файла
  \param handler функция-обработчик найденных значений
  \param user указатель на пользовательские данные
  \return В случае возникновения ошибки возвращается ее код. В случае успеха
   возвращается \ref ak_error_ok (ноль).                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ini_parse_file( FILE* file, ak_function_ini_handler handler, void* user )
{
    return ak_ini_parse_stream( (ak_function_ini_reader)fgets, file, handler, user );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Обрабатываемый ini-файл с именем filename может содержать секции,
    обозначаемые словами в квадратных скобках, пары имя=значение (пробелы справа и слева от знака
    равно - опускаются), а также символы комментариев "#", ";".
    Если имя секции не определено, то пара имя=значение отправляется в секцию "".
    Также, для совместимости с Питоном, поддерживаются пары имя:значение.

    Например
    \code
     [Section]
       code = AU
       number = 162344-xa
       time: 14.15
    \endcode

    Все пары имя=значение обрабатываются последовательно.
    Для каждой пары вызывается обработчик handler, которому передаются строки,
    содержащие секцию, имя, значение имени, а также указатель на данные user.
    Отметим, что время хранения строковых данных ограничено
    временем работы обработчика, а дакнные должны быть скопированы/сохранены для
    дальнейшего использования.

    Обработчик должен возвращать ненулевое значение в случае успеха и ноль, в случае
    возникновения ошибки.

  \param filename имя ini-файла
  \param handler функция-обработчик найденных значений
  \param user указатель на пользовательские данные
  \return В случае возникновения ошибки возвращается ее код. В случае успеха
   возвращается \ref ak_error_ok (ноль).                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ini_parse( const char* filename, ak_function_ini_handler handler, void* user )
{
  FILE *file = NULL;
  int error = ak_error_ok;

  if(( file = fopen(filename, "r")) == NULL ) return ak_error_message_fmt( ak_error_open_file,
                                                   __func__, "wrong opening a %s file", filename );
  error = ak_ini_parse_file( file, handler, user );
  fclose( file );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! An ini_reader function to read the next line from a string buffer. This
   is the fgets() equivalent used by ini_parse_string(). */
/* ----------------------------------------------------------------------------------------------- */
 static char* ini_reader_string( char* str, int num, void* stream )
{
    ini_parse_string_ctx* ctx = (ini_parse_string_ctx*)stream;
    const char* ctx_ptr = ctx->ptr;
    size_t ctx_num_left = ctx->num_left;
    char* strp = str;
    char c;

    if (ctx_num_left == 0 || num < 2)
        return NULL;

    while (num > 1 && ctx_num_left != 0) {
        c = *ctx_ptr++;
        ctx_num_left--;
        *strp++ = c;
        if (c == '\n')
            break;
        num--;
    }

    *strp = '\0';
    ctx->ptr = ctx_ptr;
    ctx->num_left = ctx_num_left;
    return str;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Same as ini_parse(), but takes a zero-terminated string with the INI data
    instead of a file. Useful for parsing INI data from a network socket or
    already in memory.

  \param строка, содержащая данные в формате ini-файла
  \param handler функция-обработчик найденных значений
  \param user указатель на пользовательские данные
  \return В случае возникновения ошибки возвращается ее код. В случае успеха
   возвращается \ref ak_error_ok (ноль).                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ini_parse_string( const char* string, ak_function_ini_handler handler, void* user )
{
  ini_parse_string_ctx ctx;

  ctx.ptr = string;
  ctx.num_left = strlen(string);
 return ak_ini_parse_stream( (ak_function_ini_reader)ini_reader_string, &ctx, handler, user );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-ini.c                                                                         */
/*! \example example-ini-file.c                                                                    */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_ini.c  */
/* ----------------------------------------------------------------------------------------------- */
