/* --------------------------------------------------------------------------------- */
/* Пример example-g02n03.c                                                           */
/* --------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
   ak_list lp = ak_list_new();

  /* помещаем в созданный список несколько бессмертных строк */
   ak_list_add_node( lp,
     ak_list_node_new_string( "I kill'd the slave that was a-hanging thee." ));
   ak_list_add_node( lp,
     ak_list_node_new_string( "Gentle, and low, an excellent thing in woman." ));
   ak_list_add_node( lp,
     ak_list_node_new_string( "What is't thou say'st? Her voice was ever soft," ));
   ak_list_add_node( lp,
     ak_list_node_new_string( "Cordelia, Cordelia! stay a little. Ha!" ));
   ak_list_add_node( lp,
     ak_list_node_new_string( "I might have saved her; now she's gone for ever!" ));
   ak_list_add_node( lp,
     ak_list_node_new_string( "A plague upon you, murderers, traitors all!" ));

  /* обрабатываем весь список с конца в начало */
   ak_list_last( lp );
   do {
      printf(" %s\n", (char *)lp->current->data );
   } while( ak_list_prev( lp ));

  /* удаляем все строки из списка, а также сам список */
    ak_list_delete( lp );

 return EXIT_SUCCESS;
}
