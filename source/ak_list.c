/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2004 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_list.с                                                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
/*! @param string Строка, помещаемая в узел дерева.
    @return Функция возвращает указатель на созданый узел дерева. В случае возникновения ошибки
    возвращается NULL.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_list_node ak_list_node_new_string( const char *string )
{
  ak_list_node node = malloc( sizeof( struct list_node ));

  if( !node ) {
    ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
    return NULL;
  }
  memset( node, 0, sizeof( struct list_node ));

  if(( node->data =
                   #ifdef _WIN32
                    strdup( string )
                   #else
                    strndup( string, FILENAME_MAX )
                   #endif
                                                   ) == NULL ) {
    ak_error_message( ak_error_duplicate, __func__, "incorrect string duplication" );
    free( node );
    return NULL;
  }
  node->prev = node->next = NULL;
 return node;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_list_node_delete( ak_list_node node )
{
  if( !node ) {
    ak_error_message( ak_error_null_pointer, __func__, "deleting null pointer" );
    return NULL;
  }
  if( node->data != NULL ) free( node->data );
  free( node );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_list_create( ak_list list )
{
  if( !list )
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
  list->current = NULL;
  list->count = 0;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_list ak_list_new( void )
{
  ak_list list = malloc( sizeof( struct list ));

  if( !list ) {
    ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
    return NULL;
  }
  if( ak_list_create( list ) != ak_error_ok ) {
    free( list );
    list = NULL;
  }
 return list;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_list_next( ak_list list )
{
  if( !list ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
    return ak_false;
  }
  if( list->current == NULL ) return ak_false;
  if( list->current->next != NULL ) { list->current = list->current->next; return ak_true; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_list_prev( ak_list list )
{
  if( !list ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
    return ak_false;
  }
  if( list->current == NULL ) return ak_false;
  if( list->current->prev != NULL ) { list->current = list->current->prev; return ak_true; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_list_last( ak_list list )
{
  if( !list ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
    return ak_false;
  }
  if( list->current == NULL ) return ak_false;
  while( list->current->next != NULL ) { list->current = list->current->next; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_list_first( ak_list list )
{
  if( !list ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
    return ak_false;
  }
  if( list->current == NULL ) return ak_false;
  while( list->current->prev != NULL ) { list->current = list->current->prev; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_list_remove( ak_list list )
{
  ak_list_node n = NULL, m = NULL;
  if( !list ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
    return ak_false;
  }
 /* если список пуст */
  if( list->current == NULL ) return ak_false;
 /* если в списке только один элемент */
  if(( list->current->next == NULL ) && ( list->current->prev == NULL )) {
    list->current = ak_list_node_delete( list->current );
    list->count = 0;
    return ak_false;
  }

 /* теперь список полон */
  n = list->current->prev;
  m = list->current->next;
  if( m != NULL ) { /* делаем активным (замещаем удаляемый) следующий элемент */
    ak_list_node_delete( list->current );
    list->current = m;
    if( n == NULL ) list->current->prev = NULL;
      else { list->current->prev = n; n->next = m; }
    list->count--;
    return ak_true;
  } else /* делаем активным предыдущий элемент */
       {
         ak_list_node_delete( list->current );
         list->current = n; list->current->next = NULL;
         list->count--;
         return ak_true;
       }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Алгоритм работы функции аналогичен алгоритму функции ak_list_remove(),
   только текущий узел не удаляется, а возвращается пользователю. Пользователь должен позднее
   самостоятельно удалить узел.

  \param list список, из которого изымается текущий узел.
  \return В случае успеха функция возвращает указатель на изъятый узел.
  Если asn1 дерево пусто, а также в случае возникновения ошибки возвращается NULL. Код ошибки
  может быть получен с помощью вызова функции ak_error_get_value().                                */
/* ----------------------------------------------------------------------------------------------- */
 ak_list_node ak_list_exclude( ak_list list )
{
  ak_list_node n = NULL, m = NULL, tlv = NULL;
  if( !list ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
    return NULL;
  }
 /* если список пуст */
  if( list->current == NULL ) return NULL;
 /* если в списке только один элемент */
  if(( list->current->next == NULL ) && ( list->current->prev == NULL )) {
    tlv = list->current; /* элемент, который будет возвращаться */
    list->current = NULL;
    list->count = 0;
    return tlv;
  }

 /* теперь список полон => развлекаемся */
  n = list->current->prev;
  m = list->current->next;
  tlv = list->current; /* сохраняем указатель */
  tlv->next = tlv->prev = NULL;

  if( m != NULL ) { /* если следующий элемент списка определен (отличен от NULL),
                      то мы делаем его активным и замещаем им изымаемый элемент) */
    list->current = m;
    if( n == NULL ) list->current->prev = NULL;
      else { list->current->prev = n; n->next = m; }
    list->count--;
    return tlv;

  } else /* делаем активным предыдущий элемент */
       {
         list->current = n; list->current->next = NULL;
         list->count--;
         return tlv;
       }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_list_destroy( ak_list list )
{
  if( !list )
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
  while( ak_list_remove( list ) == ak_true );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_list_delete( ak_list list )
{
  if( !list ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
    return NULL;
  }
  ak_list_destroy( list );
  free( list );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_list_add_node( ak_list list, ak_list_node node )
{
  if( !list )
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to list context" );
  if( !node ) return ak_error_null_pointer;

 /* вставляем узел в конец списка */
  ak_list_last( list );
  if( list->current == NULL ) list->current = node;
   else {
          node->prev = list->current;
          list->current->next = node;
          list->current = node;
        }
  list->count++;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_list.c  */
/* ----------------------------------------------------------------------------------------------- */
