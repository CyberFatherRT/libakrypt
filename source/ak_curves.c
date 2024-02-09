/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_curves.с                                                                               */
/*  - содержит реализацию функций для работы с эллиптическими кривыми.                             */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef AK_HAVE_STRINGS_H
 #include <strings.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет величину \f$\Delta \equiv -16(4a^3 + 27b^2) \pmod{p} \f$, зависящую
    от параметров эллиптической кривой

    @param d Вычет, в который помещается вычисленное значение.
    @param ec Контекст эллиптической кривой, для которой вычисляется ее дискриминант               */
/* ----------------------------------------------------------------------------------------------- */
 void ak_mpzn_set_wcurve_discriminant( ak_uint64 *d, ak_wcurve ec )
{
  ak_mpznmax s, one = ak_mpznmax_one;

 /* определяем константы 4 и 27 в представлении Монтгомери */
  ak_mpzn_set_ui( d, ec->size, 4 );
  ak_mpzn_set_ui( s, ak_mpznmax_size, 27 );
  ak_mpzn_mul_montgomery( d, d, ec->r2, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->r2, ec->p, ec->n, ec->size );

 /* вычисляем 4a^3 (mod p) значение в представлении Монтгомери */
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, ec->a, ec->p, ec->n, ec->size );

 /* вычисляем значение 4a^3 + 27b^2 (mod p) в представлении Монтгомери */
  ak_mpzn_mul_montgomery( s, s, ec->b, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->b, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( d, d, s, ec->p, ec->size );

 /* определяем константу -16 в представлении Монтгомери и вычисляем D = -16(4a^3+27b^2) (mod p) */
  ak_mpzn_set_ui( s, ec->size, 16 );
  ak_mpzn_sub( s, ec->p, s, ec->size );
  ak_mpzn_mul_montgomery( s, s, ec->r2, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( d, d, s, ec->p, ec->n, ec->size );

 /* возвращаем результат (в обычном представлении) */
  ak_mpzn_mul_montgomery( d, d, one, ec->p, ec->n, ec->size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ec Контекст эллиптической кривой, для которой проверяется, что ее дискриминант
    отличен от нуля.

    @return Функция возвращает \ref ak_error_ok в случае, если дискриминант отличен от нуля.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wcurve_discriminant_is_ok( ak_wcurve ec )
{
  ak_mpznmax d;
  if( ec == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                               "using a null pointer to elliptic curve context" );
  ak_mpzn_set_wcurve_discriminant( d, ec );
  if( ak_mpzn_cmp_ui( d, ec->size, 0 ) == ak_true ) return ak_error_curve_discriminant;
   else return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Для проведения проверки функция вырабатывает случайное число \f$ t \pmod{q} \f$ и проверяет
    выполнимость равенства \f$ t \cdot t^{-1} \equiv 1 \pmod{q}\f$.

    @param ec Контекст эллиптической кривой.

    @return Функция возвращает \ref ak_error_ok в случае, если параметры определены корректно.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wcurve_check_order_parameters( ak_wcurve ec )
{
  ak_mpzn512 r, s, t;
  struct random generator;

  ak_random_create_lcg( &generator );
  ak_mpzn_set_random( t, ec->size, &generator );
  ak_mpzn_rem( t, t, ec->q, ec->size );
  ak_random_destroy( &generator );

  ak_mpzn_set_ui( r, ec->size, 2 );
  ak_mpzn_sub( r, ec->q, r, ec->size );
  ak_mpzn_modpow_montgomery( s, t, r, ec->q, ec->nq, ec->size );
  ak_mpzn_mul_montgomery( t, s, t, ec->q, ec->nq, ec->size );

  ak_mpzn_mul_montgomery( t, t, ec->r2q, ec->q, ec->nq, ec->size );
  ak_mpzn_mul_montgomery( t, t, ec->point.z, ec->q, ec->nq, ec->size );
  ak_mpzn_mul_montgomery( t, t, ec->point.z, ec->q, ec->nq, ec->size );
  if( ak_mpzn_cmp_ui( t, ec->size, 1 )) return ak_error_ok;
   else return ak_error_curve_order_parameters;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает на вход контекст эллиптической кривой, заданной в короткой форме Вейерштрасса,
    и выполняет следующие математические проверки

     - проверяется, что модуль кривой (простое число \f$ p \f$) удовлетворяет неравенству
       \f$ 2^{n-32} < p < 2^n \f$, где \f$ n \f$ это либо 256, либо 512 в зависимости от
       параметров кривой,
     - проверяется, что дискриминант кривой отличен от нуля по модулю \f$ p \f$,
     - проверяется, что фиксированная точка кривой, содержащаяся в контексте эллиптической кривой,
       действительно принадлежит эллиптической кривой,
     - проверяется, что порядок этой точки кривой равен простому числу \f$ q \f$,
       содержащемуся в контексте эллиптической кривой.

     @param ec контекст структуры эллиптической кривой, содержащий в себе значения параметров.
     Константные значения структур, которые могут быть использованы библиотекой,
     задаются в файле \ref ak_parameters.h

     @return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае,
     возвращается код ошибки.                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wcurve_is_ok( ak_wcurve ec )
{
  ak_mpznmax temp;
  struct wpoint wp;
  const char *str = NULL;
  int error = ak_error_ok;

 /* создали кривую и проверяем веоичину старшего коэффициента ее молуля */
  if( ec->p[ ec->size-1 ] < 0x100000000LL )
    return ak_error_message( ak_error_curve_prime_modulo, __func__ ,
                                           "using elliptic curve parameters with wrong module" );

 /* проверяем соответствие данных в памяти их символьному представлению */
  if(( str = ak_mpzn_to_hexstr( ec->p, ec->size )) == NULL )
    return ak_error_message( error, __func__ , "incorrect convertation mpzn integer to string" );
#ifdef AK_HAVE_STRINGS_H
  if( strncasecmp( str, ec->pchar, strlen( ec->pchar )) != 0 )
#else
  if( strncmp( str, ec->pchar, strlen( ec->pchar )) != 0 )
#endif
    return ak_error_message( ak_error_wrong_endian, __func__,
                                               "incorrect convertation mpzn integer to string" );
 /* теперь обратный тест */
  if(( error = ak_mpzn_set_hexstr( temp, ec->size, ec->pchar )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect convertation string to mpzn integer" );
  if( ak_mpzn_cmp( temp, ec->p, ec->size ) != 0 )
    return ak_error_message( ak_error_wrong_endian, __func__,
                                               "incorrect convertation string to mpzn integer" );
 /* проверяем, что дискриминант кривой отличен от нуля */
  if(( error = ak_wcurve_discriminant_is_ok( ec )) != ak_error_ok )
    return ak_error_message( ak_error_curve_discriminant, __func__ ,
                                       "using elliptic curve parameters with zero discriminant" );
 /* теперь проверяем принадлежность точки кривой */
  if(( error = ak_wpoint_set( &wp, ec )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorect asiigning a temporary point" );
  if( ak_wpoint_is_ok( &wp, ec ) != ak_true )
    return ak_error_message( ak_error_curve_point, __func__ ,
                                               "elliptic curve parameters has incorrect point" );
  if( ak_wpoint_check_order( &wp, ec ) != ak_true )
    return ak_error_message( ak_error_curve_point_order, __func__ ,
                                                         "elliptic curve point has wrong order" );
 /* тестируем параметры порядка группы точек, используемые для выработки и проверки электронной подписи */
  if(( error = ak_wcurve_check_order_parameters( ec )) != ak_error_ok )
    return ak_error_message( error, __func__ ,
                  "elliptic curve has wrong parameters for calculation in prime field modulo q" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выводит в файл аудита значения параметров эллиптической кривой                  */
/* ----------------------------------------------------------------------------------------------- */
 static void inline ak_wcurve_to_log( ak_wcurve ec, int error )
{
  char *str = NULL;
  ak_mpznmax one = ak_mpznmax_one, tmp;
  ak_oid oid = ak_oid_find_by_data( ec );

  if( oid != NULL ) {
    ak_error_message_fmt( error, __func__, "elliptic curve: %s (oid: %s)",
                                                                       oid->name[0], oid->id[0] );
    ak_mpzn_mul_montgomery( tmp, ec->a, one, ec->p, ec->n, ec->size );
    ak_error_message_fmt( error, __func__, " a = %s",
                                     str = ak_mpzn_to_hexstr_alloc( tmp, ec->size )); free( str );
    ak_mpzn_mul_montgomery( tmp, ec->b, one, ec->p, ec->n, ec->size );
    ak_error_message_fmt( error, __func__, " b = %s",
                                     str = ak_mpzn_to_hexstr_alloc( tmp, ec->size )); free( str );
    ak_error_message_fmt( error, __func__, " b = %s",
                                   str = ak_mpzn_to_hexstr_alloc( ec->b, ec->size )); free( str );
    ak_error_message_fmt( error, __func__, " p = %s",
                                   str = ak_mpzn_to_hexstr_alloc( ec->p, ec->size )); free( str );
    ak_error_message_fmt( error, __func__, " q = %s",
                                   str = ak_mpzn_to_hexstr_alloc( ec->q, ec->size )); free( str );
    ak_error_message_fmt( error, __func__, "px = %s",
                             str = ak_mpzn_to_hexstr_alloc( ec->point.x, ec->size )); free( str );
    ak_error_message_fmt( error, __func__, "py = %s",
                             str = ak_mpzn_to_hexstr_alloc( ec->point.y, ec->size )); free( str );
    ak_error_message_fmt( error, __func__, "pz = %s",
                             str = ak_mpzn_to_hexstr_alloc( ec->point.z, ec->size )); free( str );
  }
   else ak_error_message( error, __func__, "unexpected parameters set of elliptic curve" );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fp дескриптор файла; файл должен быть предварительно открыт для записи.
    \param curve имя или идентификатор эллиптической кривой.
     @return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае,
     возвращается код ошибки.                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_print_curve( FILE *fp , const char *curve )
{
  size_t jdx = 0;
  ak_mpznmax one = ak_mpznmax_one, tmp;
  ak_oid oid = ak_oid_find_by_ni( curve );
  ak_wcurve ec = NULL;

  if( oid == NULL ) return ak_error_message( ak_error_wrong_oid, __func__,
                                          "using unexpected name or idenifier of elliptic curve" );
  if( oid->engine != identifier ) return ak_error_message( ak_error_oid_engine, __func__,
                                                "using name or idenifier with unexpected engine" );
  if( oid->mode != wcurve_params ) return ak_error_message( ak_error_oid_engine, __func__,
                                                  "using name or idenifier with unexpected mode" );
  ec = oid->data;
  fprintf( fp, "curve: %s\n", oid->name[0] );
  while( oid->name[++jdx] != NULL ) fprintf( fp, "       %s\n", oid->name[jdx] );
  fprintf( fp, "\noid:   %s\n", oid->id[0] );
  jdx = 0;
  while( oid->id[++jdx] != NULL ) fprintf( fp, "       %s\n", oid->id[jdx] );

  fprintf( fp, "\nforms:\n");
  fprintf( fp, "  short Weierstrass form:   y^2 = x^3 + ax + b (mod p)\n");

  fprintf( fp, "\nparameters:\n");

  ak_mpzn_mul_montgomery( tmp, ec->a, one, ec->p, ec->n, ec->size );
  fprintf( fp, "  a =  0x%s\n", ak_mpzn_to_hexstr( tmp, ec->size ));
  ak_mpzn_mul_montgomery( tmp, ec->b, one, ec->p, ec->n, ec->size );
  fprintf( fp, "  b =  0x%s\n", ak_mpzn_to_hexstr( tmp, ec->size ));

  fprintf( fp, "  p =  0x%s\n", ak_mpzn_to_hexstr( ec->p, ec->size ));
  fprintf( fp, "  q =  0x%s\n", ak_mpzn_to_hexstr( ec->q, ec->size ));
  fprintf( fp, "  c =  0x%02x [cofactor]\n\n", (unsigned int) ec->cofactor );

  fprintf( fp, "point:\n px =  0x%s\n", ak_mpzn_to_hexstr( ec->point.x, ec->size ));
  fprintf( fp, " py =  0x%s\n", ak_mpzn_to_hexstr( ec->point.y, ec->size ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Проверяются параметры всех эллиптических кривых, доступных через механизм OID.
    Проверка производится путем вызова функции ak_wcurve_is_ok().

    @return Возвращает ak_true в случае успешного тестирования. В случае возникновения
    ошибки функция возвращает ak_false. Код ошибки можеть быть получен с помощью вызова
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_wcurves( void )
{
  ak_oid oid = NULL;
  bool_t result = ak_true;
  int reason = ak_error_ok, audit = ak_log_get_level();

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing Weierstrass curves started" );

 /* организуем цикл по перебору всех известных библиотеке параметров эллиптических кривых */
  oid = ak_oid_find_by_engine( identifier );
  while( oid != NULL ) {
    if( oid->mode == wcurve_params ) {
      ak_wcurve wc = NULL;
      if(( wc = ( ak_wcurve ) oid->data ) == NULL )  {
        ak_error_message( ak_error_null_pointer, __func__,
                                           "internal error with null pointer to wcurve paramset" );
        result = ak_false;
        goto lab_exit;
      }
      if(( reason = ak_wcurve_is_ok( wc )) != ak_error_ok ) {
        char *p = NULL;
        switch( reason ) {
          case ak_error_curve_discriminant     : p = "discriminant"; break;
          case ak_error_curve_point            : p = "base point"; break;
          case ak_error_curve_point_order      : p = "base point order"; break;
          case ak_error_curve_prime_modulo     : p = "prime modulo p"; break;
          case ak_error_curve_order_parameters : p = "prime order parameters"; break;
          case ak_error_wrong_endian           : p = "incorrect representation of prime modulo";
                                                 break;
          default : p = "unexpected parameter";
        }
        ak_wcurve_to_log( wc, reason );
        ak_error_message_fmt( reason, __func__ , "curve %s (OID: %s) has wrong %s",
                                                           oid->name[0], oid->id[0], p );
        result = ak_false;
        goto lab_exit;
      } else
          if( audit > ak_log_standard ) {
            ak_error_message_fmt( ak_error_ok, __func__ , "curve %s (OID: %s) is Ok",
                                                              oid->name[0], oid->id[0] );
          }
    }
    oid = ak_oid_findnext_by_engine( oid, identifier );
  }

 lab_exit:
  if( !result ) ak_error_message( ak_error_get_value(), __func__ ,
                                                          "incorrect testing Weierstrass curves" );
   else if( audit >= ak_log_maximum ) ak_error_message( ak_error_get_value(), __func__ ,
                                                 "testing Weierstrass curves ended successfully" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*          реализация операций с точками эллиптической кривой в короткой форме Вейерштрасса       */
/* ----------------------------------------------------------------------------------------------- */
/*! @param wp точка \f$ P \f$ эллиптической кривой, которой присваивается значение,
    содержащееся в контексте эллиптической кривой.
    @param wc эллиптическая кривая, которой принадлежит точка.
    @return Функция возвращает \ref ak_error_ok. В случае, когда один  из контекстов
    равен NULL, то возвращается \ref ak_error_null_pointer.                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wpoint_set( ak_wpoint wp, ak_wcurve wc )
{
  if( wp == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                                   "using null pointer to elliptic curve point" );
  if( wc == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                                         "using null pointer to elliptic curve" );
 /* копируем данные */
  memcpy( wp->x, wc->point.x, wc->size*sizeof( ak_uint64 ));
  memcpy( wp->y, wc->point.y, wc->size*sizeof( ak_uint64 ));
  memcpy( wp->z, wc->point.z, wc->size*sizeof( ak_uint64 ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param wp точка \f$ P \f$ эллиптической кривой, которой присваивается значение
    бесконечно удаленной точки.
    @param wc эллиптическая кривая, которой принадлежит точка.
    @return Функция возвращает \ref ak_error_ok. В случае, когда один  из контекстов
    равен NULL, то возвращается \ref ak_error_null_pointer.                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wpoint_set_as_unit( ak_wpoint wp, ak_wcurve wc )
{
  if( wp == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                                   "using null pointer to elliptic curve point" );
  ak_mpzn_set_ui( wp->x, wc->size, 0 );
  ak_mpzn_set_ui( wp->y, wc->size, 1 );
  ak_mpzn_set_ui( wp->z, wc->size, 0 );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param wp точка \f$ P \f$ эллиптической кривой, которой присваивается новое значение.
    @param wq точка \f$ Q \f$ эллиптической кривой, значение которой присваивается.
    @param wc эллиптическая кривая, которой принадлежат обе точки.
    @return Функция возвращает \ref ak_error_ok. В случае, когда один  из контекстов
    равен NULL, то возвращается \ref ak_error_null_pointer.                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_wpoint_set_wpoint( ak_wpoint wp, ak_wpoint wq, ak_wcurve wc )
{
  if( wp == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                                   "using null pointer to elliptic curve point" );
  if( wq == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                                   "using null pointer to elliptic curve point" );
  if( wc == NULL ) ak_error_message( ak_error_null_pointer, __func__ ,
                                                         "using null pointer to elliptic curve" );
  memcpy( wp->x, wq->x, wc->size*sizeof( ak_uint64 ));
  memcpy( wp->y, wq->y, wc->size*sizeof( ak_uint64 ));
  memcpy( wp->z, wq->z, wc->size*sizeof( ak_uint64 ));

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Для заданной точки \f$ P = (x:y:z) \f$ функция проверяет,
    что точка принадлежит эллиптической кривой, то есть что выполнено сравнение
    \f$ yz^2 \equiv x^3 + axz^2 + bz^3 \pmod{p}\f$.

    @param wp точка \f$ P \f$ эллиптической кривой
    @param ec эллиптическая кривая, на принадлежность которой проверяется точка \f$P\f$.

    @return Функция возвращает \ref ak_true если все проверки выполнены. В противном случае
    возвращается \ref ak_false.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_wpoint_is_ok( ak_wpoint wp, ak_wcurve ec )
{
  ak_mpznmax t, s;
  memset( t, 0, sizeof(ak_uint64)*ak_mpznmax_size );
  memset( s, 0, sizeof(ak_uint64)*ak_mpznmax_size );

 /* Проверяем принадлежность точки заданной кривой */
  ak_mpzn_set( t, ec->a, ec->size );
  ak_mpzn_mul_montgomery( t, t, wp->x, ec->p, ec->n, ec->size );
  ak_mpzn_set( s, ec->b, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->z, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( t, t, s, ec->p, ec->size ); // теперь в t величина (ax+bz)

  ak_mpzn_set( s, wp->z, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( t, t, s, ec->p, ec->n, ec->size ); // теперь в t величина (ax+bz)z^2

  ak_mpzn_set( s, wp->x, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->x, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( t, t, s, ec->p, ec->size ); // теперь в t величина x^3 + (ax+bz)z^2

  ak_mpzn_set( s, wp->y, ec->size );
  ak_mpzn_mul_montgomery( s, s, s, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( s, s, wp->z, ec->p, ec->n, ec->size ); // теперь в s величина x^3 + (ax+bz)z^2

  if( ak_mpzn_cmp( t, s, ec->size )) return ak_false;
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Точка эллиптической кривой \f$ P = (x:y:z) \f$ заменяется значением \f$ 2P  = (x_3:y_3:z_3)\f$,
    то есть складывается сама с собой (удваивается).
    При вычислениях используются соотношения, основанные на результатах работы
    D.Bernstein, T.Lange, <a href="http://eprint.iacr.org/2007/286">Faster addition and doubling
     on elliptic curves</a>, 2007.

    \code
      XX = X^2
      ZZ = Z^2
      w = a*ZZ+3*XX
      s = 2*Y*Z
      ss = s^2
      sss = s*ss
      R = Y*s
      RR = R^2
      B = (X+R)^2-XX-RR
      h = w^2-2*B
      X3 = h*s
      Y3 = w*(B-h)-2*RR
      Z3 = sss
    \endcode

    @param wp удваиваемая точка \f$ P \f$ эллиптической кривой.
    @param ec эллиптическая кривая, которой принадлежит точка \f$P\f$.                             */
/* ----------------------------------------------------------------------------------------------- */
 inline void ak_wpoint_double( ak_wpoint wp, ak_wcurve ec )
{
 ak_mpznmax u1, u2, u3, u4, u5, u6, u7;

 if( ak_mpzn_cmp_ui( wp->z, ec->size, 0 ) == ak_true ) return;
 if( ak_mpzn_cmp_ui( wp->y, ec->size, 0 ) == ak_true ) {
   ak_wpoint_set_as_unit( wp, ec );
   return;
 }
 // dbl-2007-bl
 ak_mpzn_mul_montgomery( u1, wp->x, wp->x, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( u2, wp->z, wp->z, ec->p, ec->n, ec->size );
 ak_mpzn_lshift_montgomery( u4, u1, ec->p, ec->size );
 ak_mpzn_add_montgomery( u4, u4, u1, ec->p, ec->size );
 ak_mpzn_mul_montgomery( u3, u2, ec->a, ec->p, ec->n, ec->size );
 ak_mpzn_add_montgomery( u3, u3, u4, ec->p, ec->size );  // u3 = az^2 + 3x^2
 ak_mpzn_mul_montgomery( u4, wp->y, wp->z, ec->p, ec->n, ec->size );
 ak_mpzn_lshift_montgomery( u4, u4, ec->p, ec->size );   // u4 = 2yz
 ak_mpzn_mul_montgomery( u5, wp->y, u4, ec->p, ec->n, ec->size ); // u5 = 2y^2z
 ak_mpzn_lshift_montgomery( u6, u5, ec->p, ec->size ); // u6 = 2u5
 ak_mpzn_mul_montgomery( u7, u6, wp->x, ec->p, ec->n, ec->size ); // u7 = 8xy^2z
 ak_mpzn_lshift_montgomery( u1, u7, ec->p, ec->size );
 ak_mpzn_sub( u1, ec->p, u1, ec->size );
 ak_mpzn_mul_montgomery( u2, u3, u3, ec->p, ec->n, ec->size );
 ak_mpzn_add_montgomery( u2, u2, u1, ec->p, ec->size );
 ak_mpzn_mul_montgomery( wp->x, u2, u4, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( u6, u6, u5, ec->p, ec->n, ec->size );
 ak_mpzn_sub( u6, ec->p, u6, ec->size );
 ak_mpzn_sub( u2, ec->p, u2, ec->size );
 ak_mpzn_add_montgomery( u2, u2, u7, ec->p, ec->size );
 ak_mpzn_mul_montgomery( wp->y, u2, u3, ec->p, ec->n, ec->size );
 ak_mpzn_add_montgomery( wp->y, wp->y, u6, ec->p, ec->size );
 ak_mpzn_mul_montgomery( wp->z, u4, u4, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( wp->z, wp->z, u4, ec->p, ec->n, ec->size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для двух заданных точек эллиптической кривой \f$ P = (x_1: y_1: z_1) \f$ и
    \f$ Q = (x_2:y_2:z_2)\f$ вычисляется сумма \f$ P+Q = (x_3:y_3:z_3)\f$,
    которая присваивается точке \f$ P\f$.

    Для вычислений используются соотношения,
    приведенные в работе H.Cohen, A.Miyaji and T.Ono
    <a href=http://link.springer.com/chapter/10.1007/3-540-49649-1_6>Efficient elliptic curve
    exponentiation using mixed coordinates</a>, 1998.

    \code
      Y1Z2 = Y1*Z2
      X1Z2 = X1*Z2
      Z1Z2 = Z1*Z2
      u = Y2*Z1-Y1Z2
      uu = u^2
      v = X2*Z1-X1Z2
      vv = v^2
      vvv = v*vv
      R = vv*X1Z2
      A = uu*Z1Z2-vvv-2*R
      X3 = v*A
      Y3 = u*(R-A)-vvv*Y1Z2
      Z3 = vvv*Z1Z2
    \endcode

    Если в качестве точки \f$ Q \f$ передается точка \f$ P \f$,
    то функция ak_wpoint_add() корректно обрабатывает такую ситуацию и вызывает функцию
    удвоения точки ak_wpoint_double().

    @param wp1 Точка \f$ P \f$, в которую помещается результат операции сложения; первое слагаемое
    @param wp2 Точка \f$ Q \f$, второе слагаемое
    @param ec Эллиптическая кривая, которой принадллежат складываемые точки                        */
/* ----------------------------------------------------------------------------------------------- */
 inline void ak_wpoint_add( ak_wpoint wp1, ak_wpoint wp2, ak_wcurve ec )
{
  ak_mpznmax u1, u2, u3, u4, u5, u6, u7;

  if( ak_mpzn_cmp_ui( wp2->z, ec->size, 0 ) == ak_true ) return;
  if( ak_mpzn_cmp_ui( wp1->z, ec->size, 0 ) == ak_true ) {
    ak_wpoint_set_wpoint( wp1, wp2, ec );
    return;
  }
  // поскольку удвоение точки с помощью формул сложения дает бесконечно удаленную точку,
  // необходимо выполнить проверку
  ak_mpzn_mul_montgomery( u1, wp1->x, wp2->z, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u2, wp2->x, wp1->z, ec->p, ec->n, ec->size );
  if( ak_mpzn_cmp( u1, u2, ec->size ) == 0 ) { // случай совпадения х-координат точки
    ak_mpzn_mul_montgomery( u1, wp1->y, wp2->z, ec->p, ec->n, ec->size );
    ak_mpzn_mul_montgomery( u2, wp2->y, wp1->z, ec->p, ec->n, ec->size );
    if( ak_mpzn_cmp( u1, u2, ec->size ) == 0 ) // случай полного совпадения точек
      ak_wpoint_double( wp1, ec );
     else ak_wpoint_set_as_unit( wp1, ec );
    return;
  }

  //add-1998-cmo-2
  ak_mpzn_mul_montgomery( u1, wp1->x, wp2->z, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u2, wp1->y, wp2->z, ec->p, ec->n, ec->size );
  ak_mpzn_sub( u2, ec->p, u2, ec->size );
  ak_mpzn_mul_montgomery( u3, wp1->z, wp2->z, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u4, wp2->y, wp1->z, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( u4, u4, u2, ec->p, ec->size );
  ak_mpzn_mul_montgomery( u5, u4, u4, ec->p, ec->n, ec->size );
  ak_mpzn_sub( u7, ec->p, u1, ec->size );
  ak_mpzn_mul_montgomery( wp1->x, wp2->x, wp1->z, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( wp1->x, wp1->x, u7, ec->p, ec->size );
  ak_mpzn_mul_montgomery( u7, wp1->x, wp1->x, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u6, u7, wp1->x, ec->p, ec->n, ec->size);
  ak_mpzn_mul_montgomery( u1, u7, u1, ec->p, ec->n, ec->size );
  ak_mpzn_lshift_montgomery( u7, u1, ec->p, ec->size );
  ak_mpzn_add_montgomery( u7, u7, u6, ec->p, ec->size );
  ak_mpzn_sub( u7, ec->p, u7, ec->size );
  ak_mpzn_mul_montgomery( u5, u5, u3, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( u5, u5, u7, ec->p, ec->size );
  ak_mpzn_mul_montgomery( wp1->x, wp1->x, u5, ec->p, ec->n, ec->size );
  ak_mpzn_mul_montgomery( u2, u2, u6, ec->p, ec->n, ec->size );
  ak_mpzn_sub( u5, ec->p, u5, ec->size );
  ak_mpzn_add_montgomery( u1, u1, u5, ec->p, ec->size );
  ak_mpzn_mul_montgomery( wp1->y, u4, u1, ec->p, ec->n, ec->size );
  ak_mpzn_add_montgomery( wp1->y, wp1->y, u2, ec->p, ec->size );
  ak_mpzn_mul_montgomery( wp1->z, u6, u3, ec->p, ec->n, ec->size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для точки \f$ P = (x:y:z) \f$ функция вычисляет аффинное представление,
    задаваемое следующим вектором \f$ P = \left( \frac{x}{z} \pmod{p}, \frac{y}{z} \pmod{p}, 1\right) \f$,
    где \f$ p \f$ модуль эллиптической кривой.

    @param wp Точка кривой, которая приводится к аффинной форме
    @param ec Эллиптическая кривая, которой принадлежит точка                                      */
/* ----------------------------------------------------------------------------------------------- */
 void ak_wpoint_reduce( ak_wpoint wp, ak_wcurve ec )
{
 ak_mpznmax u, one = ak_mpznmax_one;
 if( ak_mpzn_cmp_ui( wp->z, ec->size, 0 ) == ak_true ) {
   ak_wpoint_set_as_unit( wp, ec );
   return;
 }

 ak_mpzn_set_ui( u, ec->size, 2 );
 ak_mpzn_sub( u, ec->p, u, ec->size );
 ak_mpzn_modpow_montgomery( u, wp->z, u, ec->p, ec->n, ec->size ); // u <- z^{p-2} (mod p)
 ak_mpzn_mul_montgomery( u, u, one, ec->p, ec->n, ec->size );

 ak_mpzn_mul_montgomery( wp->x, wp->x, u, ec->p, ec->n, ec->size );
 ak_mpzn_mul_montgomery( wp->y, wp->y, u, ec->p, ec->n, ec->size );
 ak_mpzn_set_ui( wp->z, ec->size, 1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для заданной точки \f$ P = (x:y:z) \f$ и заданного целого числа (вычета) \f$ k \f$
    функция вычисляет кратную точку \f$ Q \f$, удовлетворяющую
    равенству \f$  Q = [k]P = \underbrace{P+ \cdots + P}_{k}\f$.

    При вычислении используется метод `лесенки Монтгомери`, выравнивающий время работы алгоритма
    вне зависимости от вида числа \f$ k \f$.

    \b Для \b информации:
     \li Функция не приводит результирующую точку \f$ Q \f$ к аффинной форме.
     \li Исходная точка \f$ P \f$ и результирующая точка \f$ Q \f$ могут совпадать.

    @param wq Точка \f$ Q \f$, в которую помещается результат.
    @param wp Точка \f$ P \f$, которая возводится в степень.
    @param k Степень кратности.
    @param size Размер степени \f$ k \f$ в машинных словах - значение, как правило,
    задаваемое константой \ref ak_mpzn256_size или \ref ak_mpzn512_size. В общем случае
    может приниимать любое неотрицательное значение.
    @param ec Эллиптическая кривая, на которой происходят вычисления                               */
/* ----------------------------------------------------------------------------------------------- */
 void ak_wpoint_pow( ak_wpoint wq, ak_wpoint wp, ak_uint64 *k, size_t size, ak_wcurve ec )
{
  ak_uint64 uk = 0;
  long long int i, j;
  struct wpoint Q, R; /* две точки из лесенки Монтгомери */

 /* начальные значения для переменных */
  ak_wpoint_set_as_unit( &Q, ec );
  ak_wpoint_set_wpoint( &R, wp, ec );

 /* полный цикл по всем(!) битам числа k */
  for( i = size-1; i >= 0; i-- ) {
     uk = k[i];
     for( j = 0; j < 64; j++ ) {
       if( uk&0x8000000000000000LL ) { ak_wpoint_add( &Q, &R, ec ); ak_wpoint_double( &R, ec ); }
        else { ak_wpoint_add( &R, &Q, ec ); ak_wpoint_double( &Q, ec ); }
       uk <<= 1;
     }
  }
 /* копируем полученный результат */
  ak_wpoint_set_wpoint( wq, &Q, ec );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для заданной точки \f$ P = (x:y:z) \f$ функция проверяет
    что порядок точки действительно есть величина \f$ q \f$, заданная в параметрах
    эллиптической кривой, то есть проверяется выполнимость равенства \f$ [q]P = \mathcal O\f$,
    где \f$ \mathcal O \f$ - бесконечно удаленная точка (ноль группы точек эллиптической кривой),
    а \f$ q \f$ порядок подгруппы, в которой реализуются вычисления.

    @param wp точка \f$ P \f$ эллиптической кривой
    @param ec эллиптическая кривая, на принадлежность которой проверяется точка \f$P\f$.

    @return Функция возвращает \ref ak_true если все проверки выполнены. В противном случае
    возвращается \ref ak_false.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_wpoint_check_order( ak_wpoint wp, ak_wcurve ec )
{
  struct wpoint ep;

  ak_wpoint_set_as_unit( &ep, ec );
  ak_wpoint_pow( &ep, wp, ec->q, ec->size, ec );
  return ak_mpzn_cmp_ui( ep.z, ec->size, 0 );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_curves.c  */
/* ----------------------------------------------------------------------------------------------- */
