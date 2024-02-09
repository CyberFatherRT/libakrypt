/* --------------------------------------------------------------------------------- */
/* Пример example-g02n02.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

/* пользовательская структура, хранящая обрабатываемые данные
   может иметь произвольный вид */
 struct my_data {
     int x, y;
     char name[16];
 };

/* пользовательская функция для создания узла двусвязного списка */
 static ak_list_node create_new_node( int x, int y, char *str )
{
   struct my_data *md = NULL;
   struct list_node *node = NULL;

   if(( node = calloc( 1, sizeof( struct list_node ))) == NULL ) return NULL;
   if(( node->data = calloc( 1, sizeof( struct my_data ))) == NULL ) {
     free( node );
     return ( node = NULL );
   }

   md = node->data; md->x = x; md->y = y;
   memset( md->name, 0, sizeof( md->name ));
   memcpy( md->name, str, ak_min( sizeof( md->name ) -1, strlen( str )));

 return node;
}

/* --------------------------------------------------------------------------------- */
/* основная программа, иллюстрирующая процессы создания, обхода и удаления списка    */
 int main( void )
{
  int i = 0;
  struct list ll;

   /* создаем двусвязный список */
    ak_list_create( &ll );

   /* создаем и помещаем в список некоторое количество случайных узлов,
      каждому узлу даем собственное имя */
    for( i = 1; i < 8; i++ ) {
       char name[16];

       memset( name, 0, 16 );
       ak_snprintf( name, 15, "hello-%f", i );
       ak_list_add_node( &ll, create_new_node( rand(), rand(), name ));
    }

   /* выводим данные о созданном списке */
    printf("count: %lu\n", ll.count );

   /* обрабатываем весь список,
      начиная с первого помещенного в него элемента */
    ak_list_first( &ll );
    do{
     /* получаем указатель на хранящиеся данные */
      struct my_data *md = ll.current->data;

     /* выполняем код обработки данных */
      printf("x: %08x, y: %8x, name: %s\n", md->x, md->y, md->name );
    }
     while( ak_list_next( &ll ));

   /* добавим, что пара функций
        - ak_list_last()
        - ak_list_prev()
      позволяет обработать весь список в обратном порядке */

   /* удаляем все узлы из списка
      в процессе удаления списка удаляются и пользовательские данные */
    ak_list_destroy( &ll );

 return EXIT_SUCCESS;
}
