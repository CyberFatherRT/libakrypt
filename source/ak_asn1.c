/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 by Anton Sakharov                                                           */
/*  Copyright (c) 2020 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_asn1.c                                                                                 */
/*  - содержит реализацию функций,                                                                 */
/*    используемых для базового кодирования/декодированя ASN.1 структур                            */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef AK_HAVE_CTYPE_H
 #include <ctype.h>
#endif
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_WINDOWS_H
 #define HOR_LINE    "─"  /* "\xC4" неиспользуемые коды для 866 страницы */
 #define VER_LINE    "│"  /* "\xB3" */
 #define LT_CORNER   "┌"  /* "\xDA" */
 #define RT_CORNER   "┐"  /* "\xBF" */
 #define LB_CORNER   "└"  /* "\xC0" */
 #define RB_CORNER   "┘"  /* "\xD9" */
 #define LTB_CORNERS "├"  /* "\xC3" */
 #define RTB_CORNERS "┤"  /* "\xB4" */

#else
/*! \brief Символ '─' в кодировке юникод */
 #define HOR_LINE    "\u2500"
/*! \brief Символ '│' в кодировке юникод */
 #define VER_LINE    "\u2502"
/*! \brief Символ '┌' в кодировке юникод */
 #define LT_CORNER   "\u250C"
/*! \brief Символ '┐' в кодировке юникод */
 #define RT_CORNER   "\u2510"
/*! \brief Символ '└' в кодировке юникод */
 #define LB_CORNER   "\u2514"
/*! \brief Символ '┘' в кодировке юникод */
 #define RB_CORNER   "\u2518"
/*! \brief Символ '├' в кодировке юникод */
 #define LTB_CORNERS "\u251C"
/*! \brief Символ '┤' в кодировке юникод */
 #define RTB_CORNERS "\u2524"

#endif

/* ----------------------------------------------------------------------------------------------- */
                                /* глобальные переменные модуля */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Массив, содержащий символьное представление тега. */
 static char tag_description[32] = "\0";
/*! \brief Массив, содержащий префикс в выводимой строке с типом данных. */
 static char prefix[1024] = "";
/*! \brief Массив, содержащий информацию для вывода в консоль. */
 static char output_buffer[1024] = "";

/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_print_to_stdout( const char *message )
{
  if( message ) printf( "%s", message );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static ak_function_log *asn1_print_function = ak_asn1_print_to_stdout;

/* ----------------------------------------------------------------------------------------------- */
                                      /*  служебные функции */
/* ----------------------------------------------------------------------------------------------- */
/*! \param new_function Функция, используемая для вывода сообщений                                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_set_print_function( ak_function_log *new_function )
{
  if( new_function == NULL )
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to new function" );

  asn1_print_function = new_function;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_unset_print_function( void )
{
  asn1_print_function = ak_asn1_print_to_stdout;
 return ak_error_ok; 
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param len длина данных
    @return Кол-во байтов, необходимое для хранения закодированной длины.                          */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_asn1_get_length_size( const size_t len )
{
    if (len < 0x80u)
        return 1;
    if (len <= 0xFFu)
        return 2;
    if (len <= 0xFFFFu)
        return 3;
    if (len <= 0xFFFFFFu)
        return 4;
    if (len <= 0xFFFFFFFFu)
        return 5;
    else
        return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param oid строка, содержая идентификатор объекта в виде чисел, разделенных точками
    \return Количество байт, необходимое для хранения закодированного идентификатора.              */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_asn1_get_length_oid( const char *oid )
{
   char * p_end = NULL;
   size_t num, byte_cnt = 0;

   if( !oid ) return 0;
   byte_cnt = 1;

  /* Пропускаем 2 первых идентификатора */
   strtoul( oid, &p_end, 10 );
   oid = ++p_end;
   strtol( oid, &p_end, 10);

   while( *p_end != '\0' ) {
        oid = ++p_end;
        num = (size_t) strtol((char *) oid, &p_end, 10);
        if (num <= 0x7Fu)             /*                               0111 1111 -  7 бит */
            byte_cnt += 1;
        else if (num <= 0x3FFFu)      /*                     0011 1111 1111 1111 - 14 бит */
            byte_cnt += 2;
        else if (num <= 0x1FFFFFu)    /*           0001 1111 1111 1111 1111 1111 - 21 бит */
            byte_cnt += 3;
        else if (num <= 0x0FFFFFFFu)  /* 0000 1111 1111 1111 1111 1111 1111 1111 - 28 бит */
            byte_cnt += 4;
        else
            return 0;
   }
 return byte_cnt;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент разбираюся только теги, представленные одним байтом.
    Указатель на данные сдвигается на длину тега (1 октет).

    @param pp_data указатель на тег
    @param p_tag указатель на переменную, содержащую тег
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_get_tag_from_der( ak_uint8** pp_data, ak_uint8 *p_tag )
{
  if ( !pp_data || !p_tag ) return ak_error_null_pointer;

 /* записываем тег */
  *p_tag = **pp_data;
 /* смещаем указатель на данные */
  (*pp_data)++;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент определяется длинна, представленная не более, чем в 4 байтах.

    @param pp_data указатель на длину данных
    @param p_len указатель переменную, содержащую длинну блока данных
    @param p_len_byte_cnt указатель переменную, содержащую кол-во памяти (в байтах),
           необходимое для хранения длины блока данных в DER последовательности
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_asn1_get_length_from_der( ak_uint8** pp_data, size_t *p_len )
{
    ak_uint8 len_byte_cnt; /* Кол-во байтов, которыми представлена длина */
    ak_uint8 i; /* Индекс */

    if (!pp_data || !p_len) return ak_error_null_pointer;

    *p_len = 0;

    if (**pp_data & 0x80u)
    {
        len_byte_cnt = (ak_uint8) ((**pp_data) & 0x7Fu);
        (*pp_data)++;

        if (len_byte_cnt > 4) {
            return ak_error_wrong_length;
        }

        for (i = 0; i < len_byte_cnt; i++)
        {
            *p_len = (*p_len << 8u) | (**pp_data);
            (*pp_data)++;
        }
    }
    else
    {
        *p_len = **pp_data;
        (*pp_data)++;
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tag тег данных
    \return Строка с символьным представлением тега                                                */
/* ----------------------------------------------------------------------------------------------- */
 const char* ak_asn1_get_tag_description( ak_uint8 tag )
{
    /* используется tag_description - статическая переменная */

    if( DATA_CLASS( tag ) == UNIVERSAL ) {
      switch( tag & 0x1F )
     {
      case TEOC :              ak_snprintf( tag_description, sizeof(tag_description), "EOC" ); break;
      case TBOOLEAN:           ak_snprintf( tag_description, sizeof(tag_description), "BOOLEAN" ); break;
      case TINTEGER:           ak_snprintf( tag_description, sizeof(tag_description), "INTEGER" ); break;
      case TBIT_STRING:        ak_snprintf( tag_description, sizeof(tag_description), "BIT STRING"); break;
      case TOCTET_STRING:      ak_snprintf( tag_description, sizeof(tag_description), "OCTET STRING"); break;
      case TNULL:              ak_snprintf( tag_description, sizeof(tag_description), "NULL"); break;
      case TOBJECT_IDENTIFIER: ak_snprintf( tag_description, sizeof(tag_description), "OBJECT IDENTIFIER"); break;
      case TOBJECT_DESCRIPTOR: ak_snprintf( tag_description, sizeof(tag_description), "OBJECT DESCRIPTOR"); break;
      case TEXTERNAL:          ak_snprintf( tag_description, sizeof(tag_description), "EXTERNAL"); break;
      case TREAL:              ak_snprintf( tag_description, sizeof(tag_description), "REAL"); break;
      case TENUMERATED:        ak_snprintf( tag_description, sizeof(tag_description), "ENUMERATED"); break;
      case TUTF8_STRING:       ak_snprintf( tag_description, sizeof(tag_description), "UTF8 STRING"); break;
      case TSEQUENCE:          ak_snprintf( tag_description, sizeof(tag_description), "SEQUENCE"); break;
      case TSET:               ak_snprintf( tag_description, sizeof(tag_description), "SET"); break;
      case TNUMERIC_STRING:    ak_snprintf( tag_description, sizeof(tag_description), "NUMERIC STRING"); break;
      case TPRINTABLE_STRING:  ak_snprintf( tag_description, sizeof(tag_description), "PRINTABLE STRING"); break;
      case TT61_STRING:        ak_snprintf( tag_description, sizeof(tag_description), "T61 STRING"); break;
      case TVIDEOTEX_STRING:   ak_snprintf( tag_description, sizeof(tag_description), "VIDEOTEX STRING"); break;
      case TIA5_STRING:        ak_snprintf( tag_description, sizeof(tag_description), "IA5 STRING"); break;
      case TUTCTIME:           ak_snprintf( tag_description, sizeof(tag_description), "UTC TIME"); break;
      case TGENERALIZED_TIME:  ak_snprintf( tag_description, sizeof(tag_description), "GENERALIZED TIME"); break;
      case TGRAPHIC_STRING:    ak_snprintf( tag_description, sizeof(tag_description), "GRAPHIC STRING"); break;
      case TVISIBLE_STRING:    ak_snprintf( tag_description, sizeof(tag_description), "VISIBLE STRING"); break;
      case TGENERAL_STRING:    ak_snprintf( tag_description, sizeof(tag_description), "GENERAL STRING"); break;
      case TUNIVERSAL_STRING:  ak_snprintf( tag_description, sizeof(tag_description), "UNIVERSAL STRING"); break;
      case TCHARACTER_STRING:  ak_snprintf( tag_description, sizeof(tag_description), "CHARACTER STRING"); break;
      case TBMP_STRING:        ak_snprintf( tag_description, sizeof(tag_description), "BMP STRING"); break;
      default:                 ak_snprintf( tag_description, sizeof(tag_description), "UNKNOWN TYPE"); break;
     }
    return  tag_description;
    }
     else
      if( DATA_CLASS( tag ) == CONTEXT_SPECIFIC )
    {
        /* Добавляем номер тега (младшие 5 бит) */
        ak_snprintf( tag_description, sizeof( tag_description ), "[%u]", tag & 0x1F);
        return tag_description;
    }
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет, что переданный ей массив октетов содержит только
    символы английского алфавита, расположенные на печатной машинке.
    \param str массив октетов
    @param len длина массива
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_asn1_check_prntbl_string( ak_uint8 *string, ak_uint32 len )
{
    char c;
    ak_uint32 i;

    for( i = 0; i < len; i++ )
    {
        c = (char) string[i];
        if( !(
                ( c >= 'A' && c <= 'Z' ) ||
                ( c >= '0' && c <= '9' ) ||
                        (c >= 'a' && c <= 'z') ||
                        (c == ' ')             ||
                        (c == '\'')            ||
                        (c == '(')             ||
                        (c == ')')             ||
                        (c == '+')             ||
                        (c == ',')             ||
                        (c == '-')             ||
                        (c == '.')             ||
                        (c == '/')             ||
                        (c == ':')             ||
                        (c == '=')             ||
                        (c == '?')                  )) {
             if( ak_log_get_level() >= ak_log_maximum )
               ak_error_message_fmt( 0, __func__, "unexpected symbol: %c (code: %d)", c, (int)c );
             return ak_false;
            }
    }
  return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
                       /*  функции для разбора/создания узлов ASN1 дерева */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует поля структуры примитивного узла ASN1 дерева заданными значениями.

    \param tlv указатель на структуру узла, память под tlv структуру должна быть выделена заранее.
    \param tag тип размещаемого элемента
    \param len длина кодированного представления элемента
    \param data собственно кодированные данные
    \param free флаг, определяющий, нужно ли выделять память под кодированные данные
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_create_primitive( ak_tlv tlv, ak_uint8 tag, size_t len, ak_pointer data, bool_t free )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if( DATA_STRUCTURE( tag ) != PRIMITIVE )
    return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                            "data must be primitive, but tag has value: %u", tag );
 /* Добавляем тег и длину */
  tlv->tag = tag;
  tlv->len = (ak_uint32) len;

  if( len == 0 ) tlv->data.primitive = NULL;
   else { /* добавляем данные */

    if( free ) {
      if(( tlv->data.primitive = malloc( len )) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
      if( data != NULL ) memcpy( tlv->data.primitive, data, len );
        else memset( tlv->data.primitive, 0, len ); /* обнуляем выделенную память */

    } else tlv->data.primitive = data;
   }

  tlv->free = free;
  tlv->prev = tlv->next = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выделяет память и инициализирует поля структуры примитивного узла ASN1 дерева
    заданными значениями.

    \param tag тип размещаемого элемента
    \param len длина кодированного представления элемента
    \param data собственно кодированные данные
    \param flag флаг, определяющий, нужно ли выделять память под кодированные данные
    \return Функция возвращает указатель на структуру узла. Данная структура должна
    быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
    удаления дерева, в который данный узел будет входить.
    В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_primitive( ak_uint8 tag, size_t len, ak_pointer data, bool_t flag )
{
  ak_tlv tlv = NULL;
  int error = ak_error_ok;

  if( DATA_STRUCTURE( tag ) != PRIMITIVE ) {
    ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                            "data must be primitive, but tag has value: %u", tag );
    return NULL;
  }
  if(( tlv = malloc( sizeof( struct tlv ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__, "allocation memory error" );
    return NULL;
  }
  if(( error = ak_tlv_create_primitive( tlv, tag, len, data, flag )) != ak_error_ok ) {
    if( tlv != NULL ) free( tlv );
    tlv = NULL;
    ak_error_message( error, __func__, "incorrect creation of primitive tlv context");
  }

 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует поля структуры составного узла ASN1 дерева заданным деревом
   низлежащего уровня.

    \param tlv указатель на структуру узла, память под tlv структуру должна быть выделена заранее.
    \param tag тип размещаемого элемента
    \param asn1 размещаемое дерево нижнего уровня.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_create_constructed( ak_tlv tlv, ak_uint8 tag, ak_asn1 asn1 )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if( DATA_STRUCTURE( tag ) != CONSTRUCTED )
    return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                          "data must be constructed, but tag has value: %u", tag );
  tlv->tag = tag;
  tlv->len = 0;
  tlv->data.constructed = asn1;
  tlv->free = ak_false;
  tlv->prev = tlv->next = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выделяет память и инициализирует поля структуры составного узла ASN1 дерева заданным
   деревом низлежащего уровня.

    \param tag тип размещаемого элемента
    \param asn1 размещаемое дерево нижнего уровня.
    \return Функция возвращает указатель на структуру узла. Данная структура должна
    быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
    удаления дерева, в который данный узел будет входить.
    В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_constructed( ak_uint8 tag, ak_asn1 asn1 )
{
  ak_tlv tlv = NULL;
  int error = ak_error_ok;

  if( DATA_STRUCTURE( tag ) != CONSTRUCTED ) {
    switch( TAG_NUMBER( tag )) { /* подправляем тип, если пользователь забыл сделать это сам */
      case TSET:
      case TSEQUENCE:
        tag ^= CONSTRUCTED;
        break;

      default:
        ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                          "data must be constructed, but tag has value: %u", tag );
        return NULL;
    }
  }
  if(( tlv = malloc( sizeof( struct tlv ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__, "allocation memory error" );
    return NULL;
  }
  if(( error = ak_tlv_create_constructed( tlv, tag, asn1 )) != ak_error_ok ) {
    if( tlv != NULL ) free( tlv );
    tlv = NULL;
    ak_error_message( error, __func__, "incorrect creation of primitive tlv context");
  }
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает составной узел дерева следующего вида.

   \code
     ┌SEQUENCE┐
              └ (null)
   \endcode
   \return Функция возвращает указатель на структуру узла. Данная структура должна
   быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
   удаления дерева, в который данный узел будет входить.
   В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
   функции ak_error_get_value().                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_sequence( void )
{
  ak_asn1 asn = NULL;
  ak_tlv tlv = ak_tlv_new_constructed( TSEQUENCE, asn = ak_asn1_new( ));
  if( asn == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__,
                                                   "incorrect creation of internal asn1 context" );
    if( tlv != NULL ) free( tlv ); /* удаляем, если создано */
    tlv = NULL;
  }
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_destroy( ak_tlv tlv )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  switch( DATA_STRUCTURE( tlv->tag )) {
    case PRIMITIVE: /* уничтожаем примитивный узел */
      if(( tlv->free ) && ( tlv->data.primitive != NULL )) free( tlv->data.primitive );
     break;

    case CONSTRUCTED: /* уничтожаем составной узел */
      if( tlv->data.constructed != NULL )
        tlv->data.constructed = ak_asn1_delete( tlv->data.constructed );
     break;

    default: ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                                   "destroying tlv context with wrong tag value" );
  }
  tlv->tag = TEOC;
  tlv->len = 0;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_tlv_delete( ak_pointer tlv )
{
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "deleting null pointer to tlv element" );
    return NULL;
  }
  ak_tlv_destroy( (ak_tlv) tlv );
  free( tlv );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для вывода используется функция fprintf( stdout, ... )
    (может быть изменена с помощью вызова ak_asn1_set_print_function() )

    \param tlv указатель на структуру узла ASN1 дерева.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_print( ak_tlv tlv )
{
  const char *dp = NULL;
  char tmp[ sizeof(prefix) ];
  size_t plen = strlen( prefix );

  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
 /* выводим информацию об узле */
  dp = ak_asn1_get_tag_description( tlv->tag );

  if( DATA_STRUCTURE( tlv->tag ) == CONSTRUCTED) {
    const char *corner = LTB_CORNERS;

   /* вычисляем уголочек */
    if( tlv->next == NULL ) corner = LB_CORNER;
    if(( plen == 0 ) && ( tlv->prev == NULL )) corner = LT_CORNER;

   /* выводим префикс и тег */
    ak_printf( asn1_print_function, "%s%s%s%s\n", prefix, corner, dp, RT_CORNER );

    memset( tmp, 0, sizeof( tmp ));
    memcpy( tmp, prefix, ak_min( sizeof(tmp)-1, strlen( prefix )));
    if( tlv->next == NULL )
      ak_snprintf( prefix, sizeof( prefix ), "%s%s%*s", tmp, " ", strlen(dp), " " );
     else ak_snprintf( prefix, sizeof( prefix ), "%s%s%*s", tmp, VER_LINE, strlen(dp), " " );

    ak_asn1_print( tlv->data.constructed );
    prefix[plen] = 0;
  }
   else {
        /* выводим префикс и тег */
         if( tlv->next == NULL ) ak_printf( asn1_print_function, "%s%s%s ", prefix, LB_CORNER, dp );
          else ak_printf( asn1_print_function, "%s%s%s ", prefix, LTB_CORNERS, dp );

        /* теперь собственно данные */
         if( DATA_CLASS( tlv->tag ) == UNIVERSAL )
           ak_tlv_print_primitive( tlv );
          else {
            if( DATA_CLASS( tlv->tag ) == CONTEXT_SPECIFIC ) {
              if( tlv->data.primitive != NULL )
                ak_printf( asn1_print_function, "%s\n",
                                      ak_ptr_to_hexstr( tlv->data.primitive, tlv->len, ak_false ));
               else ak_printf( asn1_print_function, "%s(null)%s",
                                           ak_error_get_start_string(), ak_error_get_end_string());
            }
             else ak_printf( asn1_print_function, "%sUnknown data%s\n",
                                           ak_error_get_start_string(), ak_error_get_end_string());
          } /* конец else UNIVERSAL */
   }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_print_primitive( ak_tlv tlv )
{
  size_t len = 0;
  ak_uint32 u32 = 0;
  ak_oid oid = NULL;
  struct bit_string bs;
  bool_t dp = ak_false;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  switch( TAG_NUMBER( tlv->tag )) {

    case TNULL:
      ak_printf( asn1_print_function, "\n" );
      break;

    case TBOOLEAN:
      if( *tlv->data.primitive == 0x00 ) ak_printf( asn1_print_function, "FALSE\n" );
        else ak_printf( asn1_print_function, "TRUE\n");
      break;

    case TINTEGER:
      if(( error = ak_tlv_get_uint32( tlv, &u32 )) == ak_error_ok )
        ak_printf( asn1_print_function, "0x%x\n", (unsigned int)u32 );
       else { /* обрабатываем большие целые числа */
         switch( error ) {
           case ak_error_invalid_asn1_length:
             /* неожиданно получено отрицательное число */
             if( tlv->data.primitive[0] > 127 ) dp = ak_true;
              else {
                 if( tlv->data.primitive[0] == 0 )
                   ak_printf( asn1_print_function, "0x%s [%u bits]\n",
                         ak_ptr_to_hexstr( tlv->data.primitive+1, tlv->len-1, ak_false ),
                                                                  (unsigned int)( 8*(tlv->len-1)));
                  else ak_printf( asn1_print_function, "0x%s [%u bits]\n",
                         ak_ptr_to_hexstr( tlv->data.primitive, tlv->len, ak_false ),
                                                                      (unsigned int)(8*tlv->len ));
              }
             break;
             case ak_error_invalid_asn1_significance: /* здесь нужно чтение знаковых целых */
           default:
             dp = ak_true;
         }
       }
      break;

    case TOCTET_STRING:
      if(( error = ak_tlv_get_octet_string( tlv, &ptr, &len )) == ak_error_ok ) {
        size_t i, j, row = len >> 4, /* количество строк, в строке по 16 символов */
               tail = len%16; /* количество символов в последней строке */
        char *fsym = VER_LINE;
        struct asn1 asn;

       /*  в начале, обычный шестнадцатеричный вывод
           это все вместо простого fprintf( fp, "%s\n", ak_ptr_to_hexstr( ptr, len, ak_false )); */
        ak_printf( asn1_print_function, "\n" ); /* здесь надо выводить длину в случае, когда данные распарсиваются */
        if( tlv->next == NULL ) fsym = " ";
        for( i = 0; i < row; i++ ) {
           ak_printf( asn1_print_function, "%s%s ", prefix, fsym );
           for( j = 0; j < 16; j++ ) ak_printf( asn1_print_function, " %02X", ((ak_uint8 *)ptr)[16*i+j] );
           ak_printf( asn1_print_function, "\n");
        }
        if( tail ) {
           ak_printf( asn1_print_function, "%s%s ", prefix, fsym );
           for( j = 0; j < tail; j++ ) ak_printf( asn1_print_function, " %02X", ((ak_uint8 *)ptr)[16*i+j] );
           ak_printf( asn1_print_function, "\n");
        }

       /* теперь мы пытаемся распарсить данные (в ряде случаев, это удается сделать) */
        ak_asn1_create( &asn );
        if( ak_asn1_decode( &asn, ptr, len, ak_false ) == ak_error_ok ) {
          size_t dlen = strlen( prefix );
          strcat( prefix, "   " );
          ak_printf( asn1_print_function, "%s%s%s (decoded %u octets)%s\n", prefix,
                                ak_error_get_start_string(), LT_CORNER, (unsigned int)len, // LTB_CORNERS
                                                                       ak_error_get_end_string( ));
          ak_asn1_print( &asn );
          prefix[dlen] = 0;
        }
        ak_asn1_destroy( &asn) ;
        ak_error_set_value( ak_error_ok );
      }
       else dp = ak_true;
      break;

    case TBIT_STRING:
      memset( &bs, 0, sizeof( struct bit_string ));
      if(( error = ak_tlv_get_bit_string( tlv, &bs )) == ak_error_ok ) {
        size_t i, j, row = bs.len >> 4, /* количество строк, в строке по 16 символов */
               tail = bs.len%16; /* количество символов в последней строке */
        char *fsym = VER_LINE;

       /*  как и ранее, обычный шестнадцатеричный вывод */
        ak_printf( asn1_print_function, "\n" ); /* здесь надо выводить длину в случае, когда данные распарсиваются */
        if( tlv->next == NULL ) fsym = " ";
        for( i = 0; i < row; i++ ) {
           ak_printf( asn1_print_function, "%s%s ", prefix, fsym );
           for( j = 0; j < 16; j++ ) ak_printf( asn1_print_function, " %02X", bs.value[16*i+j] );
           if(( i == row-1 ) && ( !tail ) && ( bs.unused >0 ))
             ak_printf( asn1_print_function, " (%u bits unused)\n", bs.unused );
            else ak_printf( asn1_print_function, "\n");
        }
        if( tail ) {
           ak_printf( asn1_print_function, "%s%s ", prefix, fsym );
           for( j = 0; j < tail; j++ ) ak_printf( asn1_print_function, " %02X", bs.value[16*i+j] );
           if( bs.unused > 0 ) ak_printf( asn1_print_function, " (%u bits unused)\n", bs.unused );
            else ak_printf( asn1_print_function, "\n");
        }

        /* в ряде случаев можно декодировать и битовые строки,
           например, открытый ключ, но мы этого, в общем случае, делать не будем  */
      }
       else dp = ak_true;
      break;

    case TUTF8_STRING:
      if(( error = ak_tlv_get_utf8_string( tlv, &ptr )) == ak_error_ok ) {
        ak_printf( asn1_print_function, "%s\n", (char *)ptr );
      }
       else dp = ak_true;
      break;

    case TIA5_STRING:
      if(( error = ak_tlv_get_ia5_string( tlv, &ptr )) == ak_error_ok )
        ak_printf( asn1_print_function, "%s\n", (char *)ptr );
       else dp = ak_true;
      break;

    case TPRINTABLE_STRING:
      if(( error = ak_tlv_get_printable_string( tlv, &ptr )) == ak_error_ok )
        ak_printf( asn1_print_function, "%s\n", (char *)ptr );
       else dp = ak_true;
      break;

    case TNUMERIC_STRING:
      if(( error = ak_tlv_get_numeric_string( tlv, &ptr )) == ak_error_ok )
        ak_printf( asn1_print_function, "%s\n", (char *)ptr );
       else dp = ak_true;
      break;

    case TUTCTIME:
      if(( error = ak_tlv_get_utc_time_string( tlv, &ptr )) == ak_error_ok )
        ak_printf( asn1_print_function, "%s\n", (char *)ptr );
       else dp = ak_true;
      break;

    case TGENERALIZED_TIME:
      if(( error = ak_tlv_get_generalized_time_string( tlv, &ptr )) == ak_error_ok )
        ak_printf( asn1_print_function, "%s\n", (char *)ptr );
       else dp = ak_true;
      break;

    case TOBJECT_IDENTIFIER:
      if(( error = ak_tlv_get_oid( tlv, &ptr )) == ak_error_ok ) {
        ak_printf( asn1_print_function, "%s", (char *)ptr );

       /* ищем значение в базе oid'ов */
        if(( oid = ak_oid_find_by_ni( ptr )) != NULL ) {
          ak_printf( asn1_print_function, " (%s)\n", oid->name[0] );
         }
          else {
           ak_printf( asn1_print_function, "\n");
           ak_error_set_value( ak_error_ok ); /* убираем ошибку поиска oid */
         }
      }
       else dp = ak_true;
      break;

    default: dp = ak_true;
      break;
  }

 /* случай, когда предопределенное преобразование неизвестно или выполнено с ошибкой */
  if( dp ) {
    if( tlv->data.primitive != NULL ) ak_printf( asn1_print_function, " [len: %u, data: 0x%s]\n",
             (unsigned int) tlv->len, ak_ptr_to_hexstr( tlv->data.primitive, tlv->len, ak_false ));
      else ak_printf( asn1_print_function, " [len: %u, data: %s(null)%s]\n", (unsigned int) tlv->len,
                                         ak_error_get_start_string( ), ak_error_get_end_string( ));
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param length указатель на переменную, в которую будет помещено значение длины.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае, когда узел действительно содержит
    булево значение. В противном случае возвращается код ошибки.                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_evaluate_length( ak_tlv tlv, size_t *length )
{
  size_t subtotal = 0;
  int error = ak_error_ok;

  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv context" );
  if( length == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using undefined address to length variable" );
  switch( DATA_STRUCTURE( tlv->tag )) {
   case PRIMITIVE:
     *length = 1 + ak_asn1_get_length_size( tlv->len ) + tlv->len;
     break;

   case CONSTRUCTED:
     if(( error = ak_asn1_evaluate_length( tlv->data.constructed, &subtotal )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect length evaluation of tlv element");
      else *length = 1 + ak_asn1_get_length_size(subtotal) + ( tlv->len = subtotal );
     break;

     default: return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                                         "unexpected tag's value of tlv element" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param bool Указатель на переменную, в которую будет помещено булево значение.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае, когда узел действительно содержит
    булево значение. В противном случае возвращается код ошибки.                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_bool( ak_tlv tlv, bool_t *bool )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if(( DATA_CLASS( tlv->tag ) == UNIVERSAL ) && ( TAG_NUMBER( tlv->tag ) == TBOOLEAN )) {
    if( *tlv->data.primitive == 0x00 ) *bool = ak_false;
     else *bool = ak_true;
   return ak_error_ok;
  }

 return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                              "incorrect tag value of tlv context: %u", tlv->tag );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param u32 Указатель на переменную, в которую будет помещено значение.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае, когда узел действительно содержит
    целое значение. В противном случае возвращается код ошибки.                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_uint32( ak_tlv tlv, ak_uint32 *u32 )
{
  ak_uint32 idx = 0;
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if(( DATA_CLASS( tlv->tag) == UNIVERSAL ) && ( TAG_NUMBER( tlv->tag ) == TINTEGER )) {
    /* если длина больше 5, то преобразование невозможно */
     if(( tlv->len > 5 ) || (( tlv->len == 5 ) && ( tlv->data.primitive[0] != 0 )))
       return ak_error_invalid_asn1_length;

    /* если данные отрицательны, нужна другая функция для чтения */
     if(( tlv->data.primitive[0] != 0 ) && ( tlv->data.primitive[0]&0x80 ))
       return ak_error_invalid_asn1_significance;

    /* теперь обычное чтение */
     *u32 = 0;
     while( idx < tlv->len ) {
       *u32 <<= 8; *u32 += tlv->data.primitive[idx]; idx++;
     }
    return ak_error_ok;
  }

 return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                              "incorrect tag value of tlv context: %u", tlv->tag );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \note Новая область данных не выделяется, владение выделенной областью
    осуществляется узлом ASN1 дерева.

   \param tlv указатель на структуру узла ASN1 дерева.
   \param ptr указатель на область памяти, в которой располагается последовательность октетов.
   \param len переменная, куда будет помещена длина данных
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в противном
    случае возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_octet_string( ak_tlv tlv, ak_pointer *ptr, size_t *len )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  *len = tlv->len;
  *ptr = tlv->data.primitive;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает в качестве аргумента указатель `string` на область памяти,
    в которую будет помещена utf8-строка.

    \note Новая область памяти не выделяется, владение выделенной областью
    осуществляется узлом ASN1 дерева.

    \param tlv указатель на структуру узла ASN1 дерева.
    \param string указатель на область памяти, куда будет помещена строка.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_utf8_string( ak_tlv tlv, ak_pointer *string )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  memcpy( output_buffer, tlv->data.primitive, ak_min( sizeof( output_buffer )-1, tlv->len ) );
  output_buffer[ak_min( sizeof( output_buffer )-1, tlv->len )] = 0;

  *string = output_buffer;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает в качестве аргумента указатель `string` на область памяти,
    в которую будет помещена ia5-строка, то есть строка,
    каждый символ которой имеет ASCII-код, не превосходящий 127

    \note Новая область памяти не выделяется, владение выделенной областью
    осуществляется узлом ASN1 дерева.

    \param tlv указатель на структуру узла ASN1 дерева.
    \param string указатель на область памяти, куда будет помещена строка.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_ia5_string( ak_tlv tlv, ak_pointer *string )
{
  size_t i = 0;
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  for( i = 0; i < tlv->len; i++ )
     if( tlv->data.primitive[i] > 127 )
       return ak_error_message( ak_error_wrong_asn1_decode, __func__,
                                                              "tlv element has unexpected symbol");
  memcpy( output_buffer, tlv->data.primitive, ak_min( sizeof( output_buffer )-1, tlv->len ) );
  output_buffer[ak_min( sizeof( output_buffer )-1, tlv->len )] = 0;

  *string = output_buffer;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает в качестве аргумента указатель `string` на область памяти,
    в которую будет помещена строка.

    \note Новая область памяти не выделяется, владение выделенной областью
    осуществляется узлом ASN1 дерева.

    \param tlv указатель на структуру узла ASN1 дерева.
    \param string указатель на область памяти, куда будет помещена строка.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_printable_string( ak_tlv tlv, ak_pointer *string )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if( !ak_asn1_check_prntbl_string( tlv->data.primitive, tlv->len ))
    return ak_error_message( ak_error_wrong_asn1_decode, __func__,
                                                              "tlv element has unexpected symbol");
  memcpy( output_buffer, tlv->data.primitive, ak_min( sizeof( output_buffer )-1, tlv->len ) );
  output_buffer[ak_min( sizeof( output_buffer )-1, tlv->len )] = 0;

  *string = output_buffer;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает в качестве аргумента указатель `string` на область памяти,
    в которую будет помещена numeric-строка, то есть строка,
    состоящая только из арабских цифр и пробела.

    \note Новая область памяти не выделяется, владение выделенной областью
    осуществляется узлом ASN1 дерева.

    \param tlv указатель на структуру узла ASN1 дерева.
    \param string указатель на область памяти, куда будет помещена строка.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_numeric_string( ak_tlv tlv, ak_pointer *string )
{
  size_t i = 0;
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  for( i = 0; i < tlv->len; i++ ) {
     char c = (char) tlv->data.primitive[i];
     if( !((c >= '0' && c <= '9') || c == ' ' ))
       return ak_error_message( ak_error_wrong_asn1_decode, __func__,
                                                              "tlv element has unexpected symbol");
  }
  memcpy( output_buffer, tlv->data.primitive, ak_min( sizeof( output_buffer )-1, tlv->len ) );
  output_buffer[ak_min( sizeof( output_buffer )-1, tlv->len )] = 0;

  *string = output_buffer;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция не копирует данные в структуру, а только заполняет соответствующие поля.

    \param tlv указатель на структуру узла ASN1 дерева.
    \param bs указатель на область памяти, в которой будут расположены данные
    \return В случае успеха функция возввращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_bit_string( ak_tlv tlv, ak_bit_string bs )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if( tlv->len == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                          "unexpected zero length of bit string" );
  if(( bs->unused = tlv->data.primitive[0] ) > 7 )
    return ak_error_message( ak_error_undefined_value, __func__,
                                                               "unexpected value of unused bits" );
  bs->len = tlv->len-1;
  bs->value = tlv->data.primitive+1;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент разбираются только идентификаторы, у который первое число 1 или 2,
    а второе не превосходит 32

    \param tlv указатель на структуру узла ASN1 дерева.
    \param string указатель на область памяти, куда будет помещена строка.
    \return В случае успеха функция возввращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_oid( ak_tlv tlv, ak_pointer *string )
{
  ak_uint8 *p_buff = NULL;
  size_t i = 0, curr_size = 0;

  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  p_buff = tlv->data.primitive;
  if((( p_buff[0] / 40) > 2) || ((p_buff[0] % 40) > 32)) return ak_error_wrong_asn1_decode;

  ak_snprintf( output_buffer, sizeof( output_buffer ), "%d.%d", p_buff[0] / 40, p_buff[0] % 40 );
  for( i = 1; i < tlv->len; i++ ) {
     ak_uint32 value = 0u;
     while( p_buff[i] & 0x80u ) {
          value ^= p_buff[i] & 0x7Fu;
          value = value << 7u;
          i++;
     }

     value += p_buff[i] & 0x7Fu;
     if(( curr_size = strlen( output_buffer )) >= sizeof( output_buffer ) - 12 )
       return ak_error_wrong_asn1_decode;

     ak_snprintf( output_buffer + curr_size, sizeof(output_buffer) - curr_size, ".%u", value );
  }

  *string = output_buffer;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param time указатель на область памяти, куда будет помещено преобразованное,
    локальное значение времени.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_utc_time( ak_tlv tlv, time_t *timeval )
{
  struct tm st;
  ak_uint8 *p_buff = NULL;
  time_t now = time( NULL );

  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  p_buff = tlv->data.primitive;
  if( tlv->len > sizeof( output_buffer ) - 50 )
    return ak_error_message( ak_error_wrong_length, __func__, "tlv element has unexpected length");

  if( tlv->len < 13 ||
   #ifdef AK_HAVE_CTYPE_H
     toupper( p_buff[tlv->len - 1] )
   #else
     p_buff[tlv->len - 1]
   #endif
                  != 'Z' ) return ak_error_message( ak_error_wrong_asn1_decode, __func__,
                                                              "tlv element has unexpected format");
  /* заполняем все поля нулями */
   memset( &st, 0, sizeof( struct tm ));

  /* YY */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_year = 100 + atoi( output_buffer );
   p_buff += 2;

   /* MM */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_mon = atoi( output_buffer ) - 1;
   p_buff += 2;

   /* DD */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_mday = atoi( output_buffer );
   p_buff += 2;

   /* HH */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_hour = atoi( output_buffer );
   p_buff += 2;

   /* MM */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_min = atoi( output_buffer );
   p_buff += 2;

   /* SS.mmm */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_sec = atoi( output_buffer );
   p_buff += 2;

   *timeval = mktime( &st ) +  /* добавляем то, что было отнято при помещении в asn1 дерево */
     (mktime( localtime( &now )) - mktime( gmtime( &now  )));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param string указатель на область памяти, куда будет помещена строка.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_utc_time_string( ak_tlv tlv, ak_pointer *string )
{
  time_t time = 0;
  int error = ak_error_ok;

  if(( error = ak_tlv_get_utc_time( tlv, &time )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect decoding of tlv element" );

  memset( output_buffer, 0, sizeof( output_buffer ));
  #ifdef AK_HAVE_WINDOWS_H
   ak_snprintf( output_buffer, sizeof( output_buffer ), "%s", ctime( &time ));
   output_buffer[strlen( output_buffer )-1] = ' '; /* уничтожаем символ возврата каретки */
  #else
   strftime( output_buffer, sizeof( output_buffer ), /* локализованный вывод */
                                                  "%e %b %Y %H:%M:%S (%A) %Z", localtime( &time ));
  #endif
  *string = output_buffer;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param timeval указатель на область памяти, куда будет помещено значение времени.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_generalized_time( ak_tlv tlv, time_t *timeval )
{
  struct tm st;
  ak_uint8 *p_buff = NULL;
  time_t now = time( NULL );

  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  p_buff = tlv->data.primitive;
  if( tlv->len > sizeof( output_buffer ) - 50 )
    return ak_error_message( ak_error_wrong_length, __func__, "tlv element has unexpected length");

  if( tlv->len < 15 ||
   #ifdef AK_HAVE_CTYPE_H
     toupper( p_buff[tlv->len - 1] )
   #else
     p_buff[tlv->len - 1]
   #endif
                  != 'Z' ) return ak_error_message( ak_error_wrong_asn1_decode, __func__,
                                                              "tlv element has unexpected format");
  /* заполняем поля */
   memset( &st, 0, sizeof( struct tm ));

  /* YYYY */
   memcpy( output_buffer, p_buff, 4 ); output_buffer[4] = 0;
   st.tm_year = atoi( output_buffer )-1900; /* эта поправка весьма неожиданна */
   p_buff += 4;

   /* MM */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_mon = atoi( output_buffer )-1;
   p_buff += 2;

   /* DD */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_mday = atoi( output_buffer );
   p_buff += 2;

   /* HH */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_hour = atoi( output_buffer );
   p_buff += 2;

   /* MM */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_min = atoi( output_buffer );
   p_buff += 2;

   /* SS.mmm */
   memcpy( output_buffer, p_buff, 2 ); output_buffer[2] = 0;
   st.tm_sec = atoi( output_buffer );
   p_buff += 2;

   *timeval = mktime( &st ) +  /* добавляем то, что было отнято при помещении в asn1 дерево */
     (mktime( localtime( &now )) - mktime( gmtime( &now  )));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param string указатель на область памяти, куда будет помещена строка.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_generalized_time_string( ak_tlv tlv, ak_pointer *string )
{
  time_t time = 0;
  int error = ak_error_ok;

  if(( error = ak_tlv_get_generalized_time( tlv, &time )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect decoding of tlv element" );

  memset( output_buffer, 0, sizeof( output_buffer ));
  #ifdef AK_HAVE_WINDOWS_H
   ak_snprintf( output_buffer, sizeof( output_buffer ), "%s", ctime( &time ));
   output_buffer[strlen( output_buffer)-1] = ' '; /* уничтожаем символ возврата каретки */
  #else
    strftime( output_buffer, sizeof( output_buffer ),
                                                  "%e %b %Y %H:%M:%S (%A) %Z", localtime( &time ));
  #endif
  *string = output_buffer;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param not_before переменная, в которую помещается начальное значение времени
    \param not_after переменная, в которую помещается конечное значение времени
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_validity( ak_tlv tlv, time_t *not_before, time_t *not_after )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) ||
    ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
   else asn = tlv->data.constructed;

  ak_asn1_first( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) return ak_error_invalid_asn1_tag;
  if( TAG_NUMBER( asn->current->tag ) == TUTCTIME ) {
    if(( error = ak_tlv_get_utc_time( asn->current, not_before )) != ak_error_ok )
      return ak_error_message( error, __func__,
                                       "incorrect reading of not_before time from utc_time item" );
  } else {
     if( TAG_NUMBER( asn->current->tag ) == TGENERALIZED_TIME ) {
       if(( error = ak_tlv_get_generalized_time( asn->current,
                                                                    not_before )) != ak_error_ok )
         return ak_error_message( error, __func__,
                              "incorrect reading of not_before time from generalized_time item " );
     }
      else return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                          "incorrect reading of not_before time" );
  }

  ak_asn1_next( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) return ak_error_invalid_asn1_tag;
  if( TAG_NUMBER( asn->current->tag ) == TUTCTIME ) {
    if(( error = ak_tlv_get_utc_time( asn->current, not_after )) != ak_error_ok )
      return ak_error_message( error, __func__,
                                       "incorrect reading of not_after time from utc_time item" );
  } else {
     if( TAG_NUMBER( asn->current->tag ) == TGENERALIZED_TIME ) {
       if(( error = ak_tlv_get_generalized_time( asn->current,
                                                                    not_after )) != ak_error_ok )
         return ak_error_message( error, __func__,
                              "incorrect reading of not_after time from generalized_time item " );
     }
      else return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                          "incorrect reading of not_after time" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param resource указатель на структуру ресурса.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_resource( ak_tlv tlv, ak_resource resource )
{
  ak_uint32 cnt = 0;
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

 /* проерка элемента */
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
   else asn = tlv->data.constructed;

 /* получение данных */
   ak_asn1_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
        ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   if(( error = ak_tlv_get_uint32( asn->current,
                                            (ak_uint32*) &resource->value.type )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect reading resource type" );

   ak_asn1_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   if(( error = ak_tlv_get_uint32( asn->current, &cnt )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect reading resource counter" );
   resource->value.counter = cnt;

   ak_asn1_next( asn );
   if(( error = ak_tlv_get_validity( asn->current,
                         &resource->time.not_before, &resource->time.not_after )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect reading time validity" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param algorithm указатель на oid алгоритма
    \param parameters указатель на oid параметров алгоритма, может присваиваться значение NULL

    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_get_algorithm_identifier( ak_tlv tlv, ak_oid *algorithm, ak_oid *parameters )
{
  ak_asn1 asn = NULL;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

 /* проерка элемента */
  if(( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( tlv->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
   else asn = tlv->data.constructed;

 /* получение данных */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
       ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  if(( error = ak_tlv_get_oid( asn->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading algorithm object identifier" );

  if(( *algorithm = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message( error = ak_error_oid_id, __func__,
                                                   "reading an unsupported algorithm identifier" );
 /* проверяем параметры */
  *parameters = NULL;
  if( ak_asn1_next( asn ) == ak_true ) {
    if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
       ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) {

      *parameters = NULL;
      return error;
     }

    ak_tlv_get_oid( asn->current, &ptr );
    if(( *parameters = ak_oid_find_by_id( ptr )) == NULL )
      return ak_error_message( error = ak_error_oid_id, __func__,
                                                  "reading an unsupported parameters identifier" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция предназначена для работы с обобщенными (глобальными) именами x.509.

    Предполагается что узел `tlv` еть составной узел, владеющий последовательностью элементов
    типа
   \code
    RelativeDistinguishedName ::= SET SIZE (1 .. MAX) OF AttributeTypeAndValue
   \endcode

    Функция добавляет в последовательность одну строку, определяемую типом
   \code
     AttributeTypeAndValue ::= SEQUENCE {
        type    OBJECT IDENTIFIER,
        value   ANY DEFINED BY type
     }
   \endcode

   Тип помещаемых данных определяется параметром `type`. Допустимыми
   типами являются, как минимум,
    -  1.2.840.113549.1.9.1   emailAddress
    -  2.5.4.3                CommonName
    -  2.5.4.4                Surname
    -  2.5.4.5                SerialNumber
    -  2.5.4.6                CountryName
    -  2.5.4.7                LocalityName, пример:  [Москва]
    -  2.5.4.8                StateOrProvinceName, пример: [77 г. Москва]
    -  2.5.4.9                StreetAddress
    -  2.5.4.10               Organization
    -  2.5.4.11               OrganizationUnit

    - OGRN
    - OGRNIP
    - SNILS
    - INN

   \param tlv указатель на структуру узла ASN1 дерева.
   \param type тип помещаемоцй строки с данными
   \param value помещаемая строка
   \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_add_string_to_global_name( ak_tlv tlv, const char *type, const char *value )
{
  ak_oid oid = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = NULL, asnseq = NULL;

 /* проверяем свойства узла */
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv context" );
  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED )
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                             "using not constructed tlv context" );
  if( TAG_NUMBER( tlv->tag ) != TSEQUENCE )
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                      "using tlv context which are not sequence" );
 /* проверяем корректность типа данных */
  if( type == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to attribute type" );
  if( value == NULL ) return ak_error_ok; /* ни чего не добавляем */
  if(( oid = ak_oid_find_by_ni( type )) == NULL )
    return ak_error_message( ak_error_oid_name, __func__,
                                               "unexpected name or identifier of attribute type" );
  if( oid->engine != identifier ) return ak_error_message( ak_error_oid_engine, __func__,
                                                         "unexpected engine of given identifier" );
  if( oid->mode != descriptor ) return ak_error_message( ak_error_oid_mode, __func__,
                                                           "unexpected mode of given identifier" );

 /* получаем указатель на asn1 контекст, который содержит sequence, и
    только сейчас добавляем
    SET - >
          SEQUENCE ->
                    OBJECT IDENTIFIER (тип помещаемых данных)
                    STRING                                    */

  if(( error = ak_asn1_add_oid( asn = ak_asn1_new(), oid->id[0] )) != ak_error_ok ) {
    if( asn != NULL ) ak_asn1_delete( asn );
    return ak_error_message( error, __func__, "incorrect addition of given type" );
  }
  if( strncmp( oid->name[0], "email-address", 12 ) == 0 ) {
    error = ak_asn1_add_ia5_string( asn, value );
  } else {
     if( strncmp( oid->name[0], "country-name", 11 ) == 0 ) {
       error = ak_asn1_add_printable_string( asn, value );
     } else {
        error = ak_asn1_add_utf8_string( asn, value );
       }
  }
  if( error != ak_error_ok ) {
    if( asn != NULL ) ak_asn1_delete( asn );
    return ak_error_message( error, __func__, "incorrect addition of given string" );
  }
  if(( error = ak_asn1_add_asn1( asnseq = ak_asn1_new(), TSEQUENCE, asn )) != ak_error_ok ) {
    if( asnseq != NULL ) ak_asn1_delete( asnseq );
    return ak_error_message( error, __func__, "sequence addition error" );
  }
  if(( error = ak_asn1_add_asn1( tlv->data.constructed, TSET, asnseq )) != ak_error_ok ) {
    if( asnseq != NULL ) ak_asn1_delete( asnseq );
    return ak_error_message( error, __func__, "sequence addition error" );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на копируемую структуру узла ASN1 дерева.
    \return Функция возвращает указатель на структуру узла. Данная структура должна
    быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
    удаления дерева, в который данный узел будет входить.
    В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
    функции ak_error_get_value().                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_duplicate_global_name( ak_tlv tlv )
{
  ak_asn1 asn = NULL;
  ak_tlv newtlv = NULL;

 /* проверяем свойства узла */
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to tlv context" );
    return NULL;
  }
  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__, "using not constructed tlv context" );
    return NULL;
  }
  if( TAG_NUMBER( tlv->tag ) != TSEQUENCE ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                      "using tlv context which are not sequence" );
    return NULL;
  }

 /* теперь создаем новый объект */
  if(( newtlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect memory allocation for new tlv context" );
    return NULL;
  }

 /* исключаем частные случаи */
  if(( asn = tlv->data.constructed ) == NULL ) return newtlv;
  if( asn->count == 0 ) return newtlv;

 /* теперь перебор узлов
    в случае возникновения ошибки - сообщаем, устанавливаем код, но работу не прекращаем */
  ak_asn1_first( asn );
  do{
      ak_oid oid = NULL;
      ak_pointer ptr = NULL;
      ak_asn1 asnset = NULL, asnseq = NULL;

      if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asn->current->tag ) != TSET )) {
        ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                    "source tlv context hasn't SET as correct subtree (tag: %u)",
                                                                  TAG_NUMBER( asn->current->tag ));
        continue;
      }
      if(( asnset = asn->current->data.constructed )->count != 1 ) {
        ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                "source tlv context hasn't correct count of subtrees (count: %u)",
                                                                     (unsigned int)asnset->count );
        continue;
      }
      if(( DATA_STRUCTURE( asnset->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asnset->current->tag ) != TSEQUENCE )) {
        ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                        "nested asn1 context hasn't sequence as correct subtree" );
        continue;
      }
      if(( asnseq = asnset->current->data.constructed )->count != 2 ) {
        ak_error_message( ak_error_invalid_asn1_count, __func__,
                                          "nested asn1 context hasn't correct count of subtrees" );
        continue;
      }

     /* только сейчас, на исходе ночи )), получаем значения, которые должны быть скопированы */
      ak_asn1_first( asnseq );
      ak_tlv_get_oid( asnseq->current, &ptr );
      if(( oid = ak_oid_find_by_id( ptr )) == NULL ) {
        ak_error_message( ak_error_invalid_asn1_count, __func__,
                                                    "source tlv contains a wrong attribute type" );
        continue;
      }
      ak_asn1_next( asnseq );
      if( ak_tlv_get_utf8_string( asnseq->current, &ptr ) == ak_error_ok ) {
        ak_tlv_add_string_to_global_name( newtlv, oid->id[0], ptr );
      }
  } while( ak_asn1_next( asn ));

 return newtlv;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_print_global_name( ak_tlv tlv )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

 /* проверяем свойства узла */
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv context" );
  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED )
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                             "using not constructed tlv context" );
  if( TAG_NUMBER( tlv->tag ) != TSEQUENCE )
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                      "using tlv context which are not sequence" );
 /* исключаем частные случаи */
  if(( asn = tlv->data.constructed ) == NULL ) return ak_error_ok;
  if( asn->count == 0 ) return ak_error_ok;

 /* теперь перебор узлов
    в случае возникновения ошибки - сообщаем, устанавливаем код, но работу не прекращаем */
  ak_asn1_first( asn );
  do{
      ak_oid oid = NULL;
      ak_pointer ptr = NULL;
      ak_asn1 asnset = NULL, asnseq = NULL;

      if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asn->current->tag ) != TSET )) {
        ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                              "source tlv context hasn't set as correct subtree" );
        continue;
      }
      if(( asnset = asn->current->data.constructed )->count != 1 ) {
        ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                           "source tlv context hasn't correct count of subtrees" );
        continue;
      }
      if(( DATA_STRUCTURE( asnset->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asnset->current->tag ) != TSEQUENCE )) {
        ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                        "nested asn1 context hasn't sequence as correct subtree" );
        continue;
      }
      if(( asnseq = asnset->current->data.constructed )->count != 2 ) {
        ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                          "nested asn1 context hasn't correct count of subtrees" );
        continue;
      }

     /* только сейчас, на исходе ночи )), получаем значения, которые должны быть скопированы */
      ak_asn1_first( asnseq );
      ak_tlv_get_oid( asnseq->current, &ptr );
      if(( oid = ak_oid_find_by_id( ptr )) == NULL ) {
        ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                                    "source tlv contains a wrong attribute type" );
        continue;
      }
      ak_asn1_next( asnseq );
      if( ak_tlv_get_utf8_string( asnseq->current, &ptr ) == ak_error_ok ) {
        ak_printf( asn1_print_function, "%s: %s", oid->name[1], (char *)ptr );
        if( asn->current->next != NULL ) ak_printf( asn1_print_function, ", " );
         else ak_printf( asn1_print_function, " " );
      }
  } while( ak_asn1_next( asn ));

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param string указатель на область памяти, в котороую выводится расширенное имя
    \param size размер области (в октетах)
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_snprintf_global_name( ak_tlv tlv, char *string, const size_t size )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok, stridx = 0;

  memset( string, 0, size );

 /* проверяем свойства узла */
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv context" );
  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED )
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                             "using not constructed tlv context" );
  if( TAG_NUMBER( tlv->tag ) != TSEQUENCE )
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                      "using tlv context which are not sequence" );
 /* исключаем частные случаи */
  if(( asn = tlv->data.constructed ) == NULL ) return ak_error_ok;
  if( asn->count == 0 ) return ak_error_ok;

 /* теперь перебор узлов
    в случае возникновения ошибки - сообщаем, устанавливаем код, но работу не прекращаем */
  ak_asn1_first( asn );
  do{
      ak_oid oid = NULL;
      ak_pointer ptr = NULL;
      ak_asn1 asnset = NULL, asnseq = NULL;

      if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asn->current->tag ) != TSET )) {
        ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                              "source tlv context hasn't set as correct subtree" );
        continue;
      }
      if(( asnset = asn->current->data.constructed )->count != 1 ) {
        ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                           "source tlv context hasn't correct count of subtrees" );
        continue;
      }
      if(( DATA_STRUCTURE( asnset->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asnset->current->tag ) != TSEQUENCE )) {
        ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                        "nested asn1 context hasn't sequence as correct subtree" );
        continue;
      }
      if(( asnseq = asnset->current->data.constructed )->count != 2 ) {
        ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                          "nested asn1 context hasn't correct count of subtrees" );
        continue;
      }

     /* только сейчас, на исходе ночи )), получаем значения, которые должны быть скопированы */
      ak_asn1_first( asnseq );
      ak_tlv_get_oid( asnseq->current, &ptr );
      if(( oid = ak_oid_find_by_id( ptr )) == NULL ) {
        ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                                    "source tlv contains a wrong attribute type" );
        continue;
      }
      ak_asn1_next( asnseq );
      if( ak_tlv_get_utf8_string( asnseq->current, &ptr ) == ak_error_ok ) {
        size_t lp = strlen( ptr ), ln = strlen( oid->name[0] );
        if( stridx + lp + ln + 7 < size - 1 ) {
          string[stridx++] = ' '; string[stridx++] = ' ';
          string[stridx++] = ' '; string[stridx++] = ' ';
          memcpy( string + stridx, oid->name[0], ln );
          stridx += ln;
          string[stridx++] = ':';
          string[stridx++] = ' ';
          memcpy( string + stridx, ptr, lp );
          stridx += lp;
          if( asn->current->next != NULL ) {
            string[stridx++] = '\n';
          }
        }
         else break;
      }
  } while( ak_asn1_next( asn ));

  string[stridx] = 0;
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция проводит сравнение построчно (сначала oid, потом его значение)
    \param right указатель на первую сравниваемую структуру узла ASN1 дерева.
    \param left указатель на вторую сравниваемую структуру узла ASN1 дерева.
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_compare_global_names( ak_tlv right, ak_tlv left )
{
  ak_asn1 asn_left = NULL, asn_right = NULL;

  if(( right == NULL ) || ( left == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer" );
  if(( DATA_STRUCTURE( right->tag ) != CONSTRUCTED ) ||
     ( DATA_STRUCTURE( left->tag ) != CONSTRUCTED ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                             "using not constructed tlv context" );
  if(( TAG_NUMBER( right->tag ) != TSEQUENCE ) || ( TAG_NUMBER( left->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                                      "using tlv context which are not sequence" );
 /* стравниваем длины обобщенных имен */
  if( (asn_right = right->data.constructed)->count != (asn_left = left->data.constructed)->count )
    {
      return ak_error_message( ak_error_not_equal_data, __func__,
                                          "the given global names has different element's count" );
    }
 /* теперь поэлементное сравнение */
  ak_asn1_first( asn_right );
  ak_asn1_first( asn_left );
  do{
      char memory[1025];
      ak_oid oid_right = NULL, oid_left = NULL;
      ak_pointer ptr_right = NULL, ptr_left = NULL;
      ak_asn1 asnset_right = NULL, asnset_left = NULL;

     /* выполняем проверки и спускаемся вниз
        мы ожидаем set с одним элементом, которым является последовательность пар - oid/строка */
      if(( DATA_STRUCTURE( asn_right->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asn_right->current->tag ) != TSET ))
        return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                        "right source tlv context hasn't set as correct subtree" );
      if(( DATA_STRUCTURE( asn_left->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asn_left->current->tag ) != TSET ))
        return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                         "left source tlv context hasn't set as correct subtree" );

      if(( asnset_right = asn_right->current->data.constructed )->count != 1 )
        return ak_error_message( ak_error_invalid_asn1_count, __func__,
                                     "right source tlv context hasn't correct count of subtrees" );
      if(( asnset_left = asn_left->current->data.constructed )->count != 1 )
        return ak_error_message( ak_error_invalid_asn1_count, __func__,
                                      "left source tlv context hasn't correct count of subtrees" );

      if(( DATA_STRUCTURE( asnset_right->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asnset_right->current->tag ) != TSEQUENCE ))
        return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                  "nested right asn1 context hasn't sequence as correct subtree" );
      if(( DATA_STRUCTURE( asnset_left->current->tag ) != CONSTRUCTED ) ||
         ( TAG_NUMBER( asnset_left->current->tag ) != TSEQUENCE ))
        return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                   "nested left asn1 context hasn't sequence as correct subtree" );

      if(( asnset_right = asnset_right->current->data.constructed )->count != 2 )
        return ak_error_message( ak_error_invalid_asn1_count, __func__,
                                    "nested right asn1 context hasn't correct count of subtrees" );
      if(( asnset_left = asnset_left->current->data.constructed )->count != 2 )
        return ak_error_message( ak_error_invalid_asn1_count, __func__,
                                     "nested left asn1 context hasn't correct count of subtrees" );

     /* только сейчас получаем значения, которые должны сравниваться между собой */
      ak_asn1_first( asnset_right );
      ak_asn1_first( asnset_left );

      ak_tlv_get_oid( asnset_right->current, &ptr_right );
      if(( oid_right = ak_oid_find_by_id( ptr_right )) == NULL )
        return ak_error_message( ak_error_wrong_oid, __func__,
                                              "right source tlv contains a wrong attribute type" );
      ak_tlv_get_oid( asnset_left->current, &ptr_left );
      if(( oid_left = ak_oid_find_by_id( ptr_left )) == NULL )
        return ak_error_message( ak_error_wrong_oid, __func__,
                                               "left source tlv contains a wrong attribute type" );
      if( strcmp( oid_right->id[0], oid_left->id[0] ) != 0 )
        return ak_error_message( ak_error_not_equal_data, __func__,
                                          "the given global names has different attribute types" );

      ak_asn1_next( asnset_right );
      ak_asn1_next( asnset_left );

      memset( memory, 0 , sizeof( memory ));
      ak_tlv_get_utf8_string( asnset_right->current, &ptr_right );
      strncpy( memory, ptr_right, sizeof( memory )-1 );

      ak_tlv_get_utf8_string( asnset_right->current, &ptr_left );
      if( strcmp( memory, ptr_left ) != 0 )
        return ak_error_message( ak_error_not_equal_data, __func__,
                                                  "the given global names has different values" );

  } while(( ak_asn1_next( asn_right ) && ak_asn1_next( asn_left )));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*!
    \param name Обобщенное имя, должно быть предварительно создано.
    \param idx Строка (oid идентификатор), которым отмечены данные,
           например, для получения Common Name надо указать строку: 2.5.4.3
    \param size Размер найденных данных
    \return Функция возвращает указатель строку символов (данные не копируются и хранятся
            в asn1 дереве). В случае ошибки возвращается NULL и устанавливается код ошибки,
            который можно получить с помощью вызова ak_error_get_value().                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_tlv_get_string_from_global_name( ak_tlv name, const char *idx, size_t *size )
{
  ak_asn1 lst = NULL;

  if( name == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to global name" );
    return NULL;
  }
  if( idx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to object identifier" );
    return NULL;
  }

 /* начинаем перебор всех элементов */
  if(( lst = name->data.constructed ) != NULL ) {
    ak_asn1_first( lst );
    do{
        ak_pointer ptr = NULL;
        ak_asn1 sq = NULL;

        if( lst->current != NULL ) sq = lst->current->data.constructed;
          else break;

        ak_asn1_first( sq = sq->current->data.constructed );
        ak_tlv_get_oid( sq->current, &ptr );
        if( strncmp( idx, ptr, strlen( idx )) == 0 ) {
          ak_asn1_next( sq );
          if( size != NULL ) *size = sq->current->len; /* получаем длину строки */

          memcpy( output_buffer, sq->current->data.primitive, sq->current->len );
          output_buffer[sq->current->len] = 0;
          return (ak_uint8 *)output_buffer;
        }
    } while( ak_asn1_next( lst ));
  }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
                       /*  функции для разбора/создания слоев ASN1 дерева */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_create( ak_asn1 asn1 )
{
  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  asn1->current = NULL;
  asn1->count = 0;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выделяет память и инициализирует начальное состояние.

   \return В случае успеха возвращется указатель на созданный контекст asn1 дерева. В случае
   ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
   функции ak_error_get_value().                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_asn1 ak_asn1_new( void )
{
  int error = ak_error_ok;
  ak_asn1 asn = malloc( sizeof( struct asn1 ));
  if(( error = ak_asn1_create( asn )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect creation of new asn1 context" );

 return asn;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_next( ak_asn1 asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }
  if( asn1->current == NULL ) return ak_false;
  if( asn1->current->next != NULL ) { asn1->current = asn1->current->next; return ak_true; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_prev( ak_asn1 asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }
  if( asn1->current == NULL ) return ak_false;
  if( asn1->current->prev != NULL ) { asn1->current = asn1->current->prev; return ak_true; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_last( ak_asn1 asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }
  if( asn1->current == NULL ) return ak_false;
  while( asn1->current->next != NULL ) { asn1->current = asn1->current->next; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_first( ak_asn1 asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }
  if( asn1->current == NULL ) return ak_false;
  while( asn1->current->prev != NULL ) { asn1->current = asn1->current->prev; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_remove( ak_asn1 asn1 )
{
  ak_tlv n = NULL, m = NULL;
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }

 /* если список пуст */
  if( asn1->current == NULL ) return ak_false;
 /* если в списке только один элемент */
  if(( asn1->current->next == NULL ) && ( asn1->current->prev == NULL )) {
    asn1->current = ak_tlv_delete( asn1->current );
    asn1->count = 0;
    return ak_false;
  }

 /* теперь список полон */
  n = asn1->current->prev;
  m = asn1->current->next;
  if( m != NULL ) { /* делаем активным (замещаем удаляемый) следующий элемент */
    ak_tlv_delete( asn1->current );
    asn1->current = m;
    if( n == NULL ) asn1->current->prev = NULL;
      else { asn1->current->prev = n; n->next = m; }
    asn1->count--;
    return ak_true;
  } else /* делаем активным предыдущий элемент */
       {
         ak_tlv_delete( asn1->current );
         asn1->current = n; asn1->current->next = NULL;
         asn1->count--;
         return ak_true;
       }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Алгоритм работы функции аналогичен алгоритму функции ak_asn1_remove(),
   только текущий узел не удаляется, а возвращается пользователю. Пользователь должен позднее
   самостоятельно удалить узел.

  \param asn1 уровень asn1 дерева, из которого изымается текущий узел.
  \return В случае успеха функция возвращает указатель на изъятый узел.
  Если asn1 дерево пусто, а также в случае возникновения ошибки возвращается NULL. Код ошибки
  может быть получен с помощью вызова функции ak_error_get_value().                                */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_asn1_exclude( ak_asn1 asn1 )
{
  ak_tlv n = NULL, m = NULL, tlv = NULL;
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return NULL;
  }

 /* если список пуст */
  if( asn1->current == NULL ) return NULL;
 /* если в списке только один элемент */
  if(( asn1->current->next == NULL ) && ( asn1->current->prev == NULL )) {
    tlv = asn1->current; /* элемент, который будет возвращаться */
    asn1->current = NULL;
    asn1->count = 0;
    return tlv;
  }

 /* теперь список полон => развлекаемся */
  n = asn1->current->prev;
  m = asn1->current->next;
  tlv = asn1->current; /* сохраняем указатель */
  tlv->next = tlv->prev = NULL;

  if( m != NULL ) { /* если следующий элемент списка определен (отличен от NULL),
                      то мы делаем его активным и замещаем им изымаемый элемент) */
    asn1->current = m;
    if( n == NULL ) asn1->current->prev = NULL;
      else { asn1->current->prev = n; n->next = m; }
    asn1->count--;
    return tlv;

  } else /* делаем активным предыдущий элемент */
       {
         asn1->current = n; asn1->current->next = NULL;
         asn1->count--;
         return tlv;
       }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_destroy( ak_asn1 asn1 )
{
  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  while( ak_asn1_remove( asn1 ) == ak_true );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_asn1_delete( ak_pointer asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return NULL;
  }
  ak_asn1_destroy( (ak_asn1) asn1 );
  free( asn1 );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_tlv( ak_asn1 asn1, ak_tlv tlv )
{ 
  ak_tlv ptr = tlv;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
 /* если узел неопределен, то вставляем null */
  if( ptr == NULL )
   if(( ptr = ak_tlv_new_primitive( TNULL, 0, NULL, ak_false )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                                        "incorrect creation of NULL tlv context" );
 /* вставляем узел в конец списка */
  ak_asn1_last( asn1 );
  if( asn1->current == NULL ) asn1->current = ptr;
   else {
          ptr->prev = asn1->current;
          asn1->current->next = ptr;
          asn1->current = ptr;
        }
  asn1->count++;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция кодирует значение, которое содержится в переменной `bool`, и помещает его на
    текущий уровень ASN1 дерева.
    \param asn1 указатель на текущий уровень ASN1 дерева.
    \param bool булева переменная.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_bool( ak_asn1 asn1, const bool_t bool )
{
  ak_tlv tlv = NULL;
  ak_uint8 val = 0x00;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  if( bool ) val = 0xFFu;
  if(( tlv = ak_tlv_new_primitive( TBOOLEAN, 1, &val, ak_true )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv element" );

 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция кодирует значение, которое содержится в переменной `u32`, и помещает его на
    текущий уровень ASN1 дерева.
    \param asn1 указатель на текущий уровень ASN1 дерева.
    \param u32 целочисленная беззнаковая переменная.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_uint32( ak_asn1 asn1, const ak_uint32 u32 )
{
  size_t len = 0;
  ak_uint8 byte = 0;
  ak_tlv tlv = NULL;
  ak_uint32 val = u32;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
 /* вычисляем количество значащих октетов */
  if(( byte = (ak_uint8)( u32>>24 )) != 0 ) len = 4;
   else if(( byte = (ak_uint8)( u32>>16 )) != 0 ) len = 3;
         else if(( byte = (ak_uint8)( u32>>8 )) != 0 ) len = 2;
                else { len = 1; byte = (ak_uint8) u32; }

 /* проверяем старший бит, если он установлен, т.е. byte > 127,
    то при кодировании будем использовать дополнительный октет */
  if( byte&0x80 ) len++;

 /* создаем элемент и выделяем память */
  if(( tlv = ak_tlv_new_primitive( TINTEGER, len, NULL, ak_true )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv element" );

 /* заполняем выделенную память значениями */
  memset( tlv->data.primitive, 0, len );
  do{
      tlv->data.primitive[len-1] = val&0xFF;  val >>= 8;
  } while( --len > 0 );

 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция кодирует значение, которое содержится в переменной типа `mpzn` (большое целое число)
    и помещает его на текущий уровень ASN1 дерева.    
    \param asn1 указатель на текущий уровень ASN1 дерева.
    \param tag тип размещаемого элемента; в подавляющем большинстве случаев должен
     принимать значение \ref TINTEGER
    \param n указатель на большое целое число
    \param size количество элементов массива, составляющего большое целое число; данный аргумент
    должен принимать значения \ref ak_mpzn256_size или \ref ak_mpzn512_size.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_mpzn( ak_asn1 asn1, ak_uint8 tag, ak_uint64 *n, const size_t size )
{
  ak_tlv tlv = NULL;
  size_t idx = 0, len = size*sizeof( ak_uint64 ), sz = 0;
  ak_uint8 be[ sizeof( ak_uint64 )*ak_mpznmax_size ]; /* максимально большое целое число */

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  if( n == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to mpzn number" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                             "using mpzn number with zero length" );
  if( size > ak_mpznmax_size ) return ak_error_message( ak_error_wrong_length, __func__,
                                                         "using mpzn number with very large size" );
 /* получаем массив байт в правильной кодировке */
  memset( be, 0, sizeof( be ));
  ak_mpzn_to_little_endian( n, size, be, sizeof( be ), ak_true );

 /* ищем первый ненулевой октет, одновременно определяем длину копируемых данных */
  do{
    if( be[idx] == 0 ) idx++;
     else break;
  } while( idx < len );
  if( idx == len ) return ak_asn1_add_uint32( asn1, 0 );
   else len -= idx;

 /* проверяем старший октет */
  sz = len; //sz = ( be[idx]&0x80 ) ? len+1 : len;

 /* создаем элемент и выделяем память */
  if(( tlv = ak_tlv_new_primitive( tag, sz, NULL, ak_true )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv element" );

 /* заполняем выделенную память значениями */
  memset( tlv->data.primitive, 0, sz );
  memcpy( tlv->data.primitive + (sz - len), be+idx, len );

 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция кодирует значение, которое содержится в переменной `ptr`, и помещает его на
    текущий уровень ASN1 дерева.
    \param asn1 указатель на текущий уровень ASN1 дерева.
    \param ptr указатель на произвольную область памяти, интерпретируемую как последовательность октетов
    \param len размер последовательности октетов
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_octet_string( ak_asn1 asn1, const ak_pointer ptr, const size_t len )
{
  ak_tlv tlv = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if(( ptr != NULL ) && ( len != 0 )) {
   /* создаем элемент и выделяем память */
    if(( tlv = ak_tlv_new_primitive( TOCTET_STRING, len, ptr, ak_true )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                             "incorrect creation of tlv element" );
  }
   else
    /* создаем NULL */
    if(( tlv = ak_tlv_new_primitive( TNULL, 0, NULL, ak_false )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                        "incorrect creation of null tlv element" );

 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn1 указатель на текущий уровень ASN1 дерева.
    \param string строка, содержащая последовательность символов, заканчивающуюся нулем (null-строка)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_utf8_string( ak_asn1 asn1, const char *string )
{
  ak_tlv tlv = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  if( string != NULL ) {
   /* создаем элемент и выделяем память */
    if(( tlv = ak_tlv_new_primitive( TUTF8_STRING,
                                   strlen(string), (ak_pointer) string, ak_true )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                             "incorrect creation of tlv element" );
  }
   else
    /* создаем NULL */
    if(( tlv = ak_tlv_new_primitive( TNULL, 0, NULL, ak_false )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                        "incorrect creation of null tlv element" );
 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn1 указатель на текущий уровень ASN1 дерева.
    \param string строка, содержащая последовательность символов, заканчивающуюся нулем (null-строка)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_ia5_string( ak_asn1 asn1, const char *string )
{
  ak_tlv tlv = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if( string != NULL ) {
    size_t i = 0;
    for( i = 0; i < strlen( string ); i++ )
       if( string[i] > 127 ) return ak_error_message( ak_error_wrong_asn1_encode, __func__,
                                                                   "string has unexpected symbol");
   /* создаем элемент и выделяем память */
    if(( tlv = ak_tlv_new_primitive( TIA5_STRING,
                                  strlen(string), (ak_pointer) string, ak_true )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                             "incorrect creation of tlv element" );
  }
   else
    /* создаем NULL */
    if(( tlv = ak_tlv_new_primitive( TNULL, 0, NULL, ak_false )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                        "incorrect creation of null tlv element" );
 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn1 указатель на текущий уровень ASN1 дерева.
    \param string строка, содержащая последовательность символов (printable string)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_printable_string( ak_asn1 asn1, const char *string )
{
  ak_tlv tlv = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if( string != NULL ) {
    if( !ak_asn1_check_prntbl_string(( ak_uint8 * )string, strlen( string )))
      return ak_error_message( ak_error_wrong_asn1_encode, __func__,
                                                                   "string has unexpected symbol");
   /* создаем элемент и выделяем память */
    if(( tlv = ak_tlv_new_primitive( TPRINTABLE_STRING,
                                  strlen(string), (ak_pointer) string, ak_true )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                             "incorrect creation of tlv element" );
  }
   else
    /* создаем NULL */
    if(( tlv = ak_tlv_new_primitive( TNULL, 0, NULL, ak_false )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                        "incorrect creation of null tlv element" );
 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn1 указатель на текущий уровень ASN1 дерева.
    \param string строка, содержащая последовательность символов, заканчивающуюся нулем (null-строка)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_numeric_string( ak_asn1 asn1, const char *string )
{
  ak_tlv tlv = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if( string != NULL ) {
    size_t i = 0;
    for( i = 0; i < strlen( string ); i++ ) {
       char c = string[i];
        if( !((c >= '0' && c <= '9') || c == ' ' ))
          return ak_error_message( ak_error_wrong_asn1_encode, __func__,
                                                                   "string has unexpected symbol");
    }
   /* создаем элемент и выделяем память */
    if(( tlv = ak_tlv_new_primitive( TNUMERIC_STRING,
                                  strlen(string), (ak_pointer) string, ak_true )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                             "incorrect creation of tlv element" );
  }
   else
    /* создаем NULL */
    if(( tlv = ak_tlv_new_primitive( TNULL, 0, NULL, ak_false )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                        "incorrect creation of null tlv element" );
 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn1 указатель на текущий уровень ASN1 дерева.
    \param string строка, содержащая указатель на структуру, описывающую битовую строку.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_bit_string( ak_asn1 asn1, ak_bit_string bs )
{
  ak_tlv tlv = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if( bs != NULL ) {
    if( bs->len == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "addition of zero length bit string" );
    if( bs->unused > 7 ) return ak_error_message( ak_error_undefined_value, __func__,
                                                "addition bit string with incorrect unused bits" );
   /* добавляем битовую строку */
    if(( tlv = ak_tlv_new_primitive( TBIT_STRING, bs->len+1, NULL, ak_true )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                             "incorrect creation of tlv element" );
     tlv->data.primitive[0] = bs->unused;
     memcpy( tlv->data.primitive+1, bs->value, bs->len );

  } else
    /* создаем NULL */
    if(( tlv = ak_tlv_new_primitive( TNULL, 0, NULL, ak_false )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                        "incorrect creation of null tlv element" );
 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент кодируются только идентификаторы, у которых первое число равно 1 или 2,
    а второе не превосходит 32

   \param asn1 указатель на текущий уровень ASN1 дерева.
   \param string входная строка, содержая идентификатор в виде чисел, разделенных точками
   \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_oid( ak_asn1 asn1, const char *string )
{
  size_t p_size;
  ak_tlv tlv = NULL;
  ak_uint64 num = 0;
  ak_uint8 *p_enc_oid = NULL;
  char *obj_id = ( char * )string, *p_objid_end = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if( string == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer object identifier" );
 /* в начале определяем длину и выделяем память */
  if(( p_size = ak_asn1_get_length_oid( string )) == 0 )
    return ak_error_message( ak_error_wrong_length, __func__,
                                          "incorrect calculation of encoded identifier's length" );
  if(( tlv = ak_tlv_new_primitive( TOBJECT_IDENTIFIER, p_size, NULL, ak_true )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                             "incorrect creation of tlv element" );
 /* кодируем элемент */
  p_enc_oid = tlv->data.primitive;

  num = strtoul( obj_id, &p_objid_end, 10);
  obj_id = ++p_objid_end;
  num = num * 40 + strtol((char *) obj_id, &p_objid_end, 10);
  *(p_enc_oid++) = (ak_uint8) num;

  while( *p_objid_end != '\0' ) {
        obj_id = ++p_objid_end;
        num = strtoul((char *) obj_id, &p_objid_end, 10);

        if (num > 0x7Fu)
        {
            ak_uint8 seven_bits;
            ak_int8 i = 3;
            while( i > 0 )
            {
                seven_bits = (ak_uint8) ((num >> ((ak_uint8) i * 7u)) & 0x7Fu);
                if (seven_bits)
                    *(p_enc_oid++) = (ak_uint8) (0x80u ^ seven_bits);
                i--;
            }
        }

        *(p_enc_oid++) = (ak_uint8) (num & 0x7Fu);
    }

 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! При сохранении времени происходит его преобразование из локального времени,
    в UTC (что приводит к несколько часовому сдвигу).

   \param asn1 указатель на текущий уровень ASN1 дерева.
    \param time переменная, содержащая локальное время (возвращенное, например, функцией time()).
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_utc_time( ak_asn1 asn1, time_t time )
{
  char str[16];
  ak_tlv tlv = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
 /* в начале выделяем память (ее размер известен заранее) */
  if(( tlv = ak_tlv_new_primitive( TUTCTIME, 13, NULL, ak_true )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv element" );

 /* получаем детальное значение времени */
  memset( str, 0, sizeof( str ));
 {
  #ifdef AK_HAVE_WINDOWS_H
   #ifdef _MSC_VER
     struct tm tm;
     gmtime_s( &tm, &time );
     ak_snprintf( str, sizeof( str ), "%02u%02u%02u%02u%02u%02uZ",
                       tm.tm_year%100, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec );
   #else
     struct tm *tmptr = gmtime( &time );
     ak_snprintf( str, sizeof( str ), "%02u%02u%02u%02u%02u%02uZ",
                                    tmptr->tm_year%100, tmptr->tm_mon+1, tmptr->tm_mday,
                                                    tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec );
   #endif
  #else
     struct tm tm;
     gmtime_r( &time, &tm );
     ak_snprintf( str, sizeof( str ), "%02u%02u%02u%02u%02u%02uZ",
                       tm.tm_year%100, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec );
  #endif
 }
  memcpy( tlv->data.primitive, str, 13 );
 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает структуру `Validity`, которая содержит два примитивных элемента -
    начало и окончание временного интервала.
    ASN.1 структура определяется следующим образом.

\code
Time ::= CHOICE {
     utcTime        UTCTime,
     generalTime    GeneralizedTime
}

Validity ::= SEQUENCE {
     notBefore      Time,
     notAfter       Time
}
\endcode

   После создания структура добавляется в текущий уровень asn1 дерева.

   Время, которое помещается в структуру `Validity`, приводится из локального времени во
   время по Гринвичу. При чтении структуры должно производиться обратное преобразование.

   TODO: Согласно RFC 5280 даты до 2050 года должны сохранятся как UTCTime (это сделано)
   даты, начиная с 1 января 2050 года должны сохранятся как GeneralTime. (это надо сделать)

   \param asn1 указатель на текущий уровень ASN.1 дерева.
   \param not_before начало временного интервала; локальное время, может быть получено
   с помощью вызова функции time(),
   \param not_before окончание временного интервала; предыдущее значение, увеличенное на
   соответвующую константу.
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_validity( ak_asn1 asn1, time_t not_before, time_t not_after )
{
  int error = ak_error_ok;
  ak_asn1 asn_validity = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if(( error = ak_asn1_create( asn_validity = ak_asn1_new())) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );

 /* последовательно вставляем два значения */
  if(( error = ak_asn1_add_utc_time( asn_validity, not_before )) != ak_error_ok ) {
    ak_asn1_delete( asn_validity );
    return ak_error_message( error, __func__, "incorrect adding \"not before\" time" );
  }
  if(( error = ak_asn1_add_utc_time( asn_validity, not_after )) != ak_error_ok ) {
    ak_asn1_delete( asn_validity );
    return ak_error_message( error, __func__, "incorrect adding \"not after\" time" );
  }

 return ak_asn1_add_asn1( asn1, TSEQUENCE, asn_validity );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param root ASN.1 структура, к которой добавляется новая структура
    \param skey секретный ключ, содержащий зашифровываемые данные
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_resource( ak_asn1 root, ak_resource resource )
{
  ak_asn1 params = NULL;
  int error = ak_error_ok;

  if(( params = ak_asn1_new( )) == NULL ) return ak_error_message( ak_error_get_value(),
                                                  __func__, "incorrect creation of asn1 context" );
  if(( error = ak_asn1_add_uint32( params, resource->value.type )) != ak_error_ok ) {
    ak_asn1_delete( params );
    return ak_error_message( error, __func__, "incorrect adding secret key resource type" );
  }
  if(( error = ak_asn1_add_uint32( params,
                                          (ak_uint32) resource->value.counter )) != ak_error_ok ) {
    ak_asn1_delete( params );
    return ak_error_message( error, __func__, "incorrect adding secret key resource value" );
  }
  if(( error = ak_asn1_add_validity( params,
                          resource->time.not_before, resource->time.not_after )) != ak_error_ok ) {
    ak_asn1_delete( params );
    ak_error_message( error, __func__, "incorrect adding secret key time validity" );
  }

 /* вставляем изготовленную последовательность и выходим */
 return ak_asn1_add_asn1( root, TSEQUENCE, params );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает `SEQUENCE`, которая содержит два примитивных элемента -
    идентификатор алгоритма и один идентификатор его параметров.

    В RFC 5280 этот  тип данных определяется следующим образом

\code
AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL
}
\endcode

   Мы используем в качестве параметров либо явно заданный идентификатор,
   либо значение NULL. После создания структура добавляется в текущий уровень asn1 дерева.

   \param asn1 указатель на текущий уровень ASN.1 дерева.
   \param algorithm идентификатор криптографического алгоритма
   \param parameters идентификатор параметров алгоритма, если идентификатор равен NULL,
   то в asn1 структуру ни чего не помещается.
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_algorithm_identifier( ak_asn1 asn1, ak_oid algorithm, ak_oid parameters )
{
  ak_asn1 params = NULL;
  int error = ak_error_ok;

  if( algorithm == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to algorithm identifier" );
  if(( params = ak_asn1_new( )) == NULL ) return ak_error_message( ak_error_get_value(),
                                                  __func__, "incorrect creation of asn1 context" );
  if(( error = ak_asn1_add_oid( params, algorithm->id[0] )) != ak_error_ok ) {
    ak_asn1_delete( params );
    return ak_error_message( error, __func__, "incorrect addition of algorithm identifier" );
  }
  if( parameters != NULL ) { /* добавляем только ненулевое значение */
    if(( error = ak_asn1_add_oid( params, parameters->id[0] )) != ak_error_ok ) {
      ak_asn1_delete( params );
      return ak_error_message( error, __func__, "incorrect addition of algorithm parameters" );
    }
  }

 /* вставляем изготовленную последовательность и выходим */
 return ak_asn1_add_asn1( asn1, TSEQUENCE, params );
}


/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_add_asn1( ak_asn1 asn1, ak_uint8 tag, ak_asn1 down )
{
  ak_tlv tlv = NULL;
  ak_uint8 contag = tag;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to root asn1 element" );
  if( down == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  if( !( contag&CONSTRUCTED )) contag ^= CONSTRUCTED;
  if(( tlv = ak_tlv_new_constructed( contag, down )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv element" );

 return ak_asn1_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*!  Для вывода используется функция fprintf( stdout, ... )
    (может быть изменена с помощью вызова ak_asn1_set_print_function() )

    \param asn1 указатель на текущий уровень ASN.1 дерева.
    файл должен быть преварительно открыт на запись.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_print( ak_asn1 asn1 )
{
  ak_tlv x = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
 /* перебираем все узлы текущего слоя, начиная с первого */
  x = asn1->current;
  ak_asn1_first( asn1 );
  if( asn1->current == NULL ) /* это некорректная ситуация, поэтому сообщение выделяется красным */
    ak_printf( asn1_print_function, "%s%s (null)%s\n", prefix,
                                          ak_error_get_start_string(), ak_error_get_end_string( ));
   else { /* перебор всех доступных узлов */
    do{
      ak_tlv_print( asn1->current );
    } while( ak_asn1_next( asn1 ));
  }

 /* восстанавливаем исходное состояние */
  asn1->current = x;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn1 указатель на уровень ASN.1 дерева, в который помещается декодированная
    последовательность
    \param ptr указатель на область памяти, содержащей фрагмент der-последовательности
    \param size длина фрагмента (в октетах)
    \param flag булева переменная, указывающая: надо ли выделять память под данные asn1 дерева,
    или нет. Если флаг истиннен, то данные из области памяти, на которую указывает ptr
    (примитивные узлы дерева), копируются в новую область памяти, которую контролирует asn1 контекст.
    Если флаг ложен, то данные не копируются и в asn1 дерево помещаются только указатели на
    соответствующие области в ptr.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_decode( ak_asn1 asn1, const ak_pointer ptr, const size_t size, bool_t flag )
{
  size_t len = 0;
  ak_tlv tlv = NULL;
  ak_asn1 asnew = NULL;
  int error = ak_error_ok;
  ak_uint8 *pcurr = NULL, *pend = NULL, tag = 0;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to der-sequence" );
 /* инициируем переменные */
  pcurr = (ak_uint8 *) ptr;
  pend = pcurr + size;

 /* перебираем все возможные фрагменты */
  while( pcurr < pend ) {
    ak_asn1_get_tag_from_der( &pcurr, &tag );

    if(( error = ak_asn1_get_length_from_der( &pcurr, &len )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect decoding of data's length" );
    if( pcurr + len > pend ) return ak_error_wrong_length;
      /* полный вывод должен иметь вид
         return ak_error_message( ak_error_wrong_length, __func__, "wrong der-sequence length");

         однако частые ошибки при декодировании произвольных данных
         портят внешний вид .. ))                                  */

    switch( DATA_STRUCTURE( tag )) {
     /* добавляем в дерево примитивный элемент */
      case PRIMITIVE:
        if(( tlv = ak_tlv_new_primitive( tag, len, pcurr, flag )) == NULL )
          return ak_error_message( ak_error_get_value(), __func__,
                                                             "incorrect creation of tlv context" );
        if(( error = ak_asn1_add_tlv( asn1, tlv )) != ak_error_ok )
          return ak_error_message( error, __func__,
                                           "incorrect addition of tlv context into asn1 context" );
        break;

     /* добавляем в дерево составной элемент */
      case CONSTRUCTED:
        if(( error = ak_asn1_decode( asnew = ak_asn1_new(), pcurr, len, flag )) != ak_error_ok ) {
          ak_asn1_delete( asnew );
          return ak_error_message( error, __func__, "incorrect decoding of asn1 context" );
        }
        if(( error = ak_asn1_add_asn1( asn1, tag, asnew )) != ak_error_ok ) {
          ak_asn1_delete( asnew );
          return ak_error_message( error, __func__,
                                          "incorrect addition of asn1 context into asn1 context" );
        }
        break;

      default: return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                                         "unexpected tag's value of tlv element" );
    }
    pcurr += len;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_evaluate_length( ak_asn1 asn, size_t *total )
{
  int error = ak_error_ok;
  size_t length = 0, subtotal = 0;

  ak_asn1_first( asn );
  if( asn->current == NULL ) {
   /* это случай, когда asn1 уровень создан, но он ни чего не содержит */
    *total = 0;
    return ak_error_ok;
  }

 /* перебор всех доступных узлов */
  do{
     ak_tlv tlv = asn->current;
     switch( DATA_STRUCTURE( tlv->tag )) {
       case PRIMITIVE:
         length += 1 + ak_asn1_get_length_size( tlv->len ) + tlv->len;
         break;

       case CONSTRUCTED:
         if(( error = ak_asn1_evaluate_length(
                                              tlv->data.constructed, &subtotal )) != ak_error_ok )
           return ak_error_message( error, __func__, "incorrect length evaluation of tlv element");
          else length += 1 + ak_asn1_get_length_size(subtotal) + ( tlv->len = subtotal );
         break;

       default: return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                                         "unexpected tag's value of tlv element" );
     }
  } while( ak_asn1_next( asn ));

  *total = length;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Кодирование тега элемента ASN.1 дерева
    \param pp_buff указатель на область памяти, в которую записывается результат кодирования
    \param tag тег
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_put_tag( ak_uint8** pp_buff, ak_uint8 tag )
{
    if( !pp_buff )
      return ak_error_message( ak_error_null_pointer, __func__, "null pointer to buffer");

    **pp_buff = tag;
    (*pp_buff)++;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Кодирование длины элемента ASN.1 дерева
    \param pp_buff указатель на область памяти, в которую записывается результат кодирования
    \param len длина
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_put_length( ak_uint8** pp_buff, ak_uint32 len )
{
 ak_uint32 len_byte_cnt = ak_asn1_get_length_size( len );

    if( !pp_buff )
      return ak_error_message( ak_error_null_pointer, __func__, "null pointer to buffer");

    if( len_byte_cnt == 1 ) {
        (**pp_buff) = ( ak_uint32 ) len;
        (*pp_buff)++;
    }
    else
    {
        (**pp_buff) = ( ak_uint8 )( 0x80u ^ (ak_uint8) (--len_byte_cnt));
        (*pp_buff)++;

        do
        {
            (**pp_buff) = ( ak_uint8 ) ((len >> (8u * --len_byte_cnt)) & 0xFFu);
            (*pp_buff)++;
        }while( len_byte_cnt != 0 );
    }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Однопроходная процедура кодирования одого ASN.1 уровня
  \param asn1 указатель на текущий уровень ASN.1 дерева
  \param buf указатель на область памяти, куда будет помещена закодированная der-последовательность
  \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_encode_asn1( ak_asn1 asn, ak_uint8 **buf )
{
  int error = ak_error_ok;

  ak_asn1_first( asn );
  if( asn->current == NULL ) return ak_error_ok;

  do{
     ak_tlv tlv = asn->current;

    /* сохраняем общую часть */
     if(( error = ak_asn1_put_tag( buf, tlv->tag )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect tag encoding of tlv element" );
     if(( error = ak_asn1_put_length( buf, tlv->len )) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect length encoding of tlv element" );

     switch( DATA_STRUCTURE( tlv->tag )) {

       case PRIMITIVE:
         memcpy( *buf, tlv->data.primitive, tlv->len );
         *buf += tlv->len;
         break;

       case CONSTRUCTED:
         if(( error = ak_asn1_encode_asn1( tlv->data.constructed, buf )) != ak_error_ok )
           return ak_error_message( error, __func__, "incorrect encoding of constructed element" );
         break;

       default: return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                                         "unexpected tag's value of tlv element" );
     }
  } while( ak_asn1_next( asn ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Реализуется двупроходная процедура:
    - в ходе первого прохода по ASN.1 дереву вычисляется размер, занимаемый низлежащими
      уровнями дерева;
    - в ходе второго прохода выполняется кодирование данных.

  \param asn1 указатель на текущий уровень ASN.1 дерева
  \param ptr указатель на область памяти, куда будет помещена закодированная der-последовательность
  \param size длина сформированного фрагмента (в октетах);

  \note Перед вызовом функции переменная `size` должна быть инициализирована значением,
  указывающим максимальный объем выделенной области памяти. Если данное значение окажется меньше
  необходимого, то будет возбуждена ошибка, а необходимое значение будет помещено в `size`.

  \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_encode( ak_asn1 asn1, ak_pointer ptr, size_t *size )
{
  size_t tlen = 0;
  ak_uint8 *buf = ptr;
  int error = ak_error_ok;

  if(( error = ak_asn1_evaluate_length( asn1, &tlen )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect evaluation of asn1 context length" );
  if( *size < tlen ) {
    *size = tlen;
    return ak_error_wrong_length;
  }

 /* теперь памяти достаточно */
  *size = tlen;
  if(( error = ak_asn1_encode_asn1( asn1, &buf )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect encoding of asn1 context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Так же, как и для функции ak_asn1_encode(), реализуется двупроходная процедура,
    в ходе которой
    - в начале вычисляется длина данных,
    - а потом производится кодирование.

  \param tlv указатель на структуру узла ASN1 дерева.
  \param ptr указатель на область памяти, куда будет помещена закодированная der-последовательность
  \param size длина сформированного фрагмента (в октетах);

  \note Перед вызовом функции переменная `size` должна быть инициализирована значением,
  указывающим максимальный объем выделенной области памяти. Если данное значение окажется меньше
  необходимого, то будет возбуждена ошибка, а необходимое значение будет помещено в `size`.

  \return Функция возвращает \ref ak_error_ok (ноль) в случае, когда узел действительно содержит
  булево значение. В противном случае возвращается код ошибки.                                     */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_encode( ak_tlv tlv, ak_pointer ptr, size_t *size )
{
  size_t tlen = 0;
  ak_uint8 *buf = ptr;
  int error = ak_error_ok;

  if(( error = ak_tlv_evaluate_length( tlv, &tlen )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect evaluation of asn1 context length" );
  if( *size < tlen ) {
    *size = tlen;
    return ak_error_wrong_length;
  }

 /* теперь памяти достаточно, сохраняем общую часть */
  *size = tlen;
  if(( error = ak_asn1_put_tag( &buf, tlv->tag )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect tag encoding of tlv element" );
  if(( error = ak_asn1_put_length( &buf, tlv->len )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect length encoding of tlv element" );

  switch( DATA_STRUCTURE( tlv->tag )) {

    case PRIMITIVE:
      memcpy( buf, tlv->data.primitive, tlv->len );
      break;

    case CONSTRUCTED:
      if(( error = ak_asn1_encode_asn1( tlv->data.constructed, &buf )) != ak_error_ok )
        return ak_error_message( error, __func__, "incorrect encoding of constructed element" );
      break;

    default: return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                                         "unexpected tag's value of tlv element" );
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                                 /* функции для работы с файлами */
/* ----------------------------------------------------------------------------------------------- */
/*! \param asn указатель на текущий уровень ASN.1 дерева
    \param filename имя файла, в который записываются данные
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_export_to_derfile( ak_asn1 asn, const char *filename )
{
   struct file fp;
   ssize_t wbb = 0;
   size_t len = 0, wb = 0;
   ak_uint8 *buffer = NULL;
   int error = ak_error_ok;

   if(( error = ak_asn1_evaluate_length( asn, &len )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect evaluation total asn1 context length" );

  /* кодируем */
   if(( buffer = malloc( len )) == NULL )
     return ak_error_message( ak_error_out_of_memory, __func__,
                                                  "incorrect memory allocation for der-sequence" );
   if(( error = ak_asn1_encode( asn, buffer, &len )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect encoding of asn1 context" );
     goto lab2;
   }

  /* сохраняем */
   if(( error = ak_file_create_to_write( &fp, filename )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__, "incorrect creation a file %s", filename );
     goto lab2;
   }
   do{
     wbb = ak_file_write( &fp, buffer, len );
     if( wbb == -1 ) {
       ak_error_message( error = ak_error_get_value(), __func__ ,
                                                     "incorrect writing an encoded data to file" );
       goto lab3;
     }
      else wb += (size_t) wbb;
   } while( wb < len );

   lab3: ak_file_close( &fp );
   lab2: free( buffer );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Константы, используемые для сохранения закодированной информации. */
 const char *crypto_content_titles[] = {
  "",
  "ENCRYPTED SYMMETRIC KEY",
  "PRIVATE KEY",
  "CERTIFICATE",
  "CERTIFICATE REQUEST",
  "ENCRYPTED DATA",
  "PLAIN DATA",
  "PKCS7"
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn указатель на текущий уровень ASN.1 дерева
    \param filename имя файла, в который записываются данные
    \param type тип сохраняемого контента, используется для формирования заголовков pem-файла.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_export_to_pemfile( ak_asn1 asn, const char *filename, crypto_content_t type )
{
  ak_uint8 out[4];
  struct file ofile;
  int error = ak_error_ok;
  ak_uint8 *buffer = NULL, *ptr = NULL;
  size_t len = 0, cnt = 0, idx, blocks, tail;

 /* получаем длину */
  if(( error = ak_asn1_evaluate_length( asn, &len )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect evaluation total asn1 context length" );

 /* кодируем/декодируем */
  blocks = len/3;
  if(( tail = len - 3*blocks ) != 0 ) len = 3*(blocks+1); /* увеличиваем объем до кратного трем
                              после декодирования переменная len снова примет истинное значение */
  if(( ptr = buffer = malloc( len )) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__,
                                                  "incorrect memory allocation for der-sequence" );
  memset( buffer, 0, len );
  if(( error = ak_asn1_encode( asn, buffer, &len )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of asn1 context" );
    goto lab2;
  }

 /* сохраняем закодированый буффер */
  if(( error = ak_file_create_to_write( &ofile, filename )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation a file for secret key" );
    goto lab2;
  }

  ak_file_printf( &ofile, "-----BEGIN %s-----\n", crypto_content_titles[type] );

  for( idx = 0; idx < blocks; idx++ ) {
     ak_base64_encodeblock( ptr, out, 3);
     ak_file_printf( &ofile, "%c%c%c%c", out[0], out[1], out[2], out[3] );
     ptr += 3;
     if( ++cnt == 16 ) { /* 16х4 = 64 символа в одной строке */
       ak_file_printf( &ofile, "\n" );
       cnt = 0;
     }
  }
  if( tail ) {
    ak_base64_encodeblock( ptr, out, tail );
    ak_file_printf( &ofile, "%c%c%c%c", out[0], out[1], out[2], out[3] );
    ++cnt;
    ak_file_printf( &ofile, "\n" );
  } else
     if(( cnt != 16 ) && ( cnt != 0 )) ak_file_printf( &ofile, "\n" );

  ak_file_printf( &ofile, "-----END %s-----\n", crypto_content_titles[type] );
  ak_file_close( &ofile );

  lab2: free( buffer );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn указатель на текущий уровень ASN.1 дерева
    \param filename имя файла, в который записываются данные
    \param format формат, в котором сохраняются данные
    \param content тип сохраняемого контента, используется для формирования заголовков pem-файла.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_export_to_file( ak_asn1 asn, const char *filename,
                                                export_format_t format, crypto_content_t content )
{
  int error = ak_error_ok;

  switch( format ) {
    case asn1_der_format:
      if(( error = ak_asn1_export_to_derfile( asn, filename )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                               "incorrect export asn1 context to %s (asn1_der_format)", filename );
      break;

    case asn1_pem_format:
      if(( error = ak_asn1_export_to_pemfile( asn, filename, content )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                               "incorrect export asn1 context to %s (asn1_pem_format)", filename );
      break;
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция сперва считывает данные из файла `filename` считая, что он содержит чистую
    der-последовательность. После считывания данных производится попытка их декодирования.

    Если декодирование происходит неудачно, то функция предполагает, что der-последовательность
    содержится в файле закодированная в кодировке base64. Как правило, в таком виде
    может хранится ключевая информация. Происходит повторное считывание информации и
    повторная попытка декодирования считанных данных.

    В случае успешного считывания данных, формат хранения помещается в переменную format.
    Если считывание произошло с ошибкой, то значение переменной format не определено.

    \param asn уровень ASN.1 в который помещается считываемое значение
    \param filename имя файла, в котором содержится der-последовательность
    \param format если указатель не равен NULL, то по даному адресу размещается
    формат считанных данных.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_import_from_file( ak_asn1 asn, const char *filename, export_format_t *format )
{
  int error = ak_error_ok;
  ak_uint8 *ptr = NULL, buffer[2048];
  size_t size = sizeof( buffer );

 /* считываем данные */
  if(( ptr = ak_ptr_load_from_file( buffer, &size, filename )) == NULL )
   return ak_error_message_fmt( ak_error_get_value(), __func__,
                                                 "incorrect data reading from %s file", filename );
 /* декодируем считанную последовательность
    при этом, поскольку считанная последовательность располагается в стеке, то
    данные дублируются в ASN.1 дереве */
  if(( error = ak_asn1_decode( asn, ptr, size, ak_true )) != ak_error_ok )
    ak_error_message( error, __func__,
                    "incorrect decoding a der-sequence, trying to decode data as \"pem\" format" );

 /* очищаем, при необходимости, выделенную память */
  if( ptr != buffer ) free( ptr );
  if( error == ak_error_ok ) {
    if( format != NULL ) *format = asn1_der_format;
    return ak_error_ok; /* если декодировали успешно, то выходим */
  }
 /* заново инициализируем локальные переменные */
  size = sizeof( buffer );
  while( ak_asn1_remove( asn ) == ak_true );

 /* теперь пытаемся считать base64 */
  if(( ptr = ak_ptr_load_from_base64_file( buffer, &size, filename )) == NULL )
   return ak_error_message_fmt( ak_error_get_value(), __func__,
                                  "incorrect reading base64 encoded data from file %s", filename );

  if(( error = ak_asn1_decode( asn, ptr, size, ak_true )) != ak_error_ok )
    ak_error_message_fmt( error, __func__,
                               "incorrect decoding a der-sequence readed from file %s", filename );

 /* очищаем, при необходимости, выделенную память */
  if( ptr != buffer ) free( ptr );
  if( error == ak_error_ok ) {
    if( format != NULL ) *format = asn1_pem_format;
    ak_error_set_value( ak_error_ok ); /* в случае успеха очищаем ошибки неудачной конвертации */
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                              /* функции внешнего интерфейса */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция может считывать данные из файлов двух форматов:
    - данные содержатся в виде der-последовательности,
    - данные содержатся в виде der-последовательности, которая, в свою очередь,
      закодирована в кодировке base64 (формат PEM для сертификатов и секретных ключей).

   \param filename файл, содержащий закодированное ASN.1 дерево.
    перед вызовом функции десткриптор должен быть открыт; может принимать значения stdout и stderr.
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_print_asn1( const char *filename )
{
  struct asn1 asn;
  int error = ak_error_ok;

 /* создаем контекст */
  if(( error = ak_asn1_create( &asn )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );

 /* считываем данные и выводим в консоль */
  if(( error = ak_asn1_import_from_file( &asn, filename, NULL )) == ak_error_ok ) {
    ak_asn1_print( &asn );
  }
  ak_asn1_destroy( &asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param infile имя конвертируемого файла
    \param outfile имя файла, в котороый помещается результат конвертации
    \param format формат результирующего файла (pem или der)
    \param content тип контента; используется для вывода символьной строки, описывающей в pem
    формате тип контента; для формата der значение роли не играет.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_convert_asn1( const char *infile, const char *outfile,
                                                export_format_t format, crypto_content_t content )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

 /* 1. Считываем дерево из файла */
  if(( asn = ak_asn1_new( )) == NULL ) return ak_error_message( ak_error_get_value(),
                                              __func__, "incorrect creation of new asn1 context" );
  if(( error = ak_asn1_import_from_file( asn, infile, NULL )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                        "incorrect reading an asn1 context from file %s", infile );
    goto labex;
  }

 /* 2. Сохраняем созданное дерево в файл */
  switch( format ) {
    case asn1_der_format:
      if(( error = ak_asn1_export_to_derfile( asn, outfile )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in der format", outfile );
      break;

    case asn1_pem_format:
      if(( error = ak_asn1_export_to_pemfile( asn, outfile, content )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in pem format", outfile );
      break;
  }

  labex:
   if( asn != NULL ) ak_asn1_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param infile имя разделяемого файла
    \param format формат результирующего файла (pem или der)
    \param content тип контента; используется для вывода символьной строки, описывающей в pem
    формате тип контента; для формата der значение роли не играет.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_split_asn1( const char *infile,
                                                export_format_t format, crypto_content_t content )
{
  ak_asn1 asn = NULL;
  unsigned int cnt = 0;
  int error = ak_error_ok;
  char outfile[FILENAME_MAX];

 /* 1. Считываем дерево из файла */
  if(( asn = ak_asn1_new( )) == NULL ) return ak_error_message( ak_error_get_value(),
                                              __func__, "incorrect creation of new asn1 context" );
  if(( error = ak_asn1_import_from_file( asn, infile, NULL )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                        "incorrect reading an asn1 context from file %s", infile );
    goto labex;
  }

 /* 2. Для каждого узла выполняем одно и тоже действие */
  ak_asn1_first( asn );
  while( asn->count ) {
    ak_asn1 next = ak_asn1_new();
    ak_tlv tlv = ak_asn1_exclude( asn );
    ak_asn1_add_tlv( next, tlv );
    if( format == asn1_der_format )
      ak_snprintf( outfile, sizeof( outfile ), "%s-%04u.der", infile, cnt );
     else ak_snprintf( outfile, sizeof( outfile ), "%s-%04u.pem", infile, cnt );

    switch( format ) {
      case asn1_der_format:
        if(( error = ak_asn1_export_to_derfile( next, outfile )) != ak_error_ok ) {
          ak_error_message_fmt( error, __func__,
                               "incorrect export asn1 context to file %s in der format", outfile );
          goto labex;
        }
        break;
      case asn1_pem_format:
        if(( error = ak_asn1_export_to_pemfile( next, outfile, content )) != ak_error_ok )
        {
          ak_error_message_fmt( error, __func__,
                               "incorrect export asn1 context to file %s in pem format", outfile );
          goto labex;
        }
        break;
    }
    ++cnt;
    ak_asn1_delete( next );
  }

  labex:
   if( asn != NULL ) ak_asn1_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-asn1-build.c                                                                     */
/*! \example test-asn1-parse.c                                                                     */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_asn1.c  */
/* ----------------------------------------------------------------------------------------------- */
