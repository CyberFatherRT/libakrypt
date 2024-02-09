/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_kuznechik.h                                                                            */
/*  - содержит реализацию алгоритма блочного шифрования Кузнечик,                                  */
/*    регламентированного ГОСТ Р 34.12-2015                                                        */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Нелинейное биективное преобразование байт, используемое в алгоритмах
    Стрибог (ГОСТ Р 34.11-2012) и Кузнечик (ГОСТ Р 34.12-2015). */
/* ---------------------------------------------------------------------------------------------- */
 static const sbox gost_pi = {
   0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
   0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
   0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
   0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
   0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
   0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
   0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
   0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
   0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
   0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
   0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
   0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
   0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
   0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
   0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
   0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
 };

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Обратная нелинейная перестановка байт, используемая в алгоритме
    Кузнечик (ГОСТ Р 34.12-2015). */
/* ---------------------------------------------------------------------------------------------- */
 const static sbox gost_pinv = {
   0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
   0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
   0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
   0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
   0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
   0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
   0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
   0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
   0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
   0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
   0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
   0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
   0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
   0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
   0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
   0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
 };

/* ---------------------------------------------------------------------------------------------- */
 const static linear_register gost_lvec ={
  0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94 };

/* ---------------------------------------------------------------------------------------------- */
/*! \brief 16-я степень сопровождающей матрицы линейного регистра сдвига, определяемого в
    алгоритме Кузнечик (ГОСТ Р 34.12-2015). */
/* ---------------------------------------------------------------------------------------------- */
 const static linear_matrix gost_L = {
 { 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94 },
 { 0x94, 0xA5, 0x3C, 0x44, 0xD1, 0x8D, 0xB4, 0x54, 0xDE, 0x6F, 0x77, 0x5D, 0x96, 0x74, 0x2D, 0x84 },
 { 0x84, 0x64, 0x48, 0xDF, 0xD3, 0x31, 0xA6, 0x30, 0xE0, 0x5A, 0x44, 0x97, 0xCA, 0x75, 0x99, 0xDD },
 { 0xDD, 0x0D, 0xF8, 0x52, 0x91, 0x64, 0xFF, 0x7B, 0xAF, 0x3D, 0x94, 0xF3, 0xD9, 0xD0, 0xE9, 0x10 },
 { 0x10, 0x89, 0x48, 0x7F, 0x91, 0xEC, 0x39, 0xEF, 0x10, 0xBF, 0x60, 0xE9, 0x30, 0x5E, 0x95, 0xBD },
 { 0xBD, 0xA2, 0x48, 0xC6, 0xFE, 0xEB, 0x2F, 0x84, 0xC9, 0xAD, 0x7C, 0x1A, 0x68, 0xBE, 0x9F, 0x27 },
 { 0x27, 0x7F, 0xC8, 0x98, 0xF3, 0x0F, 0x54, 0x08, 0xF6, 0xEE, 0x12, 0x8D, 0x2F, 0xB8, 0xD4, 0x5D },
 { 0x5D, 0x4B, 0x8E, 0x60, 0x01, 0x2A, 0x6C, 0x09, 0x49, 0xAB, 0x8D, 0xCB, 0x14, 0x87, 0x49, 0xB8 },
 { 0xB8, 0x6E, 0x2A, 0xD4, 0xB1, 0x37, 0xAF, 0xD4, 0xBE, 0xF1, 0x2E, 0xBB, 0x1A, 0x4E, 0xE6, 0x7A },
 { 0x7A, 0x16, 0xF5, 0x52, 0x78, 0x99, 0xEB, 0xD5, 0xE7, 0xC4, 0x2D, 0x06, 0x17, 0x62, 0xD5, 0x48 },
 { 0x48, 0xC3, 0x02, 0x0E, 0x58, 0x90, 0xE1, 0xA3, 0x6E, 0xAF, 0xBC, 0xC5, 0x0C, 0xEC, 0x76, 0x6C },
 { 0x6C, 0x4C, 0xDD, 0x65, 0x01, 0xC4, 0xD4, 0x8D, 0xA4, 0x02, 0xEB, 0x20, 0xCA, 0x6B, 0xF2, 0x72 },
 { 0x72, 0xE8, 0x14, 0x07, 0x49, 0xF6, 0xD7, 0xA6, 0x6A, 0xD6, 0x11, 0x1C, 0x0C, 0x10, 0x33, 0x76 },
 { 0x76, 0xE3, 0x30, 0x9F, 0x6B, 0x30, 0x63, 0xA1, 0x2B, 0x1C, 0x43, 0x68, 0x70, 0x87, 0xC8, 0xA2 },
 { 0xA2, 0xD0, 0x44, 0x86, 0x2D, 0xB8, 0x64, 0xC1, 0x9C, 0x89, 0x48, 0x90, 0xDA, 0xC6, 0x20, 0x6E },
 { 0x6E, 0x4D, 0x8E, 0xEA, 0xA9, 0xF6, 0xBF, 0x0A, 0xF3, 0xF2, 0x8E, 0x93, 0xBF, 0x74, 0x98, 0xCF }
};

/* ---------------------------------------------------------------------------------------------- */
/*! \brief 16-я степень обратной матрицы к сопровождающей матрице линейного регистра сдвига,
     определяемого в алгоритме Кузнечик (ГОСТ Р 34.12-2015). */
/* ---------------------------------------------------------------------------------------------- */
 const static linear_matrix gost_Linv  = {
 { 0xCF, 0x98, 0x74, 0xBF, 0x93, 0x8E, 0xF2, 0xF3, 0x0A, 0xBF, 0xF6, 0xA9, 0xEA, 0x8E, 0x4D, 0x6E },
 { 0x6E, 0x20, 0xC6, 0xDA, 0x90, 0x48, 0x89, 0x9C, 0xC1, 0x64, 0xB8, 0x2D, 0x86, 0x44, 0xD0, 0xA2 },
 { 0xA2, 0xC8, 0x87, 0x70, 0x68, 0x43, 0x1C, 0x2B, 0xA1, 0x63, 0x30, 0x6B, 0x9F, 0x30, 0xE3, 0x76 },
 { 0x76, 0x33, 0x10, 0x0C, 0x1C, 0x11, 0xD6, 0x6A, 0xA6, 0xD7, 0xF6, 0x49, 0x07, 0x14, 0xE8, 0x72 },
 { 0x72, 0xF2, 0x6B, 0xCA, 0x20, 0xEB, 0x02, 0xA4, 0x8D, 0xD4, 0xC4, 0x01, 0x65, 0xDD, 0x4C, 0x6C },
 { 0x6C, 0x76, 0xEC, 0x0C, 0xC5, 0xBC, 0xAF, 0x6E, 0xA3, 0xE1, 0x90, 0x58, 0x0E, 0x02, 0xC3, 0x48 },
 { 0x48, 0xD5, 0x62, 0x17, 0x06, 0x2D, 0xC4, 0xE7, 0xD5, 0xEB, 0x99, 0x78, 0x52, 0xF5, 0x16, 0x7A },
 { 0x7A, 0xE6, 0x4E, 0x1A, 0xBB, 0x2E, 0xF1, 0xBE, 0xD4, 0xAF, 0x37, 0xB1, 0xD4, 0x2A, 0x6E, 0xB8 },
 { 0xB8, 0x49, 0x87, 0x14, 0xCB, 0x8D, 0xAB, 0x49, 0x09, 0x6C, 0x2A, 0x01, 0x60, 0x8E, 0x4B, 0x5D },
 { 0x5D, 0xD4, 0xB8, 0x2F, 0x8D, 0x12, 0xEE, 0xF6, 0x08, 0x54, 0x0F, 0xF3, 0x98, 0xC8, 0x7F, 0x27 },
 { 0x27, 0x9F, 0xBE, 0x68, 0x1A, 0x7C, 0xAD, 0xC9, 0x84, 0x2F, 0xEB, 0xFE, 0xC6, 0x48, 0xA2, 0xBD },
 { 0xBD, 0x95, 0x5E, 0x30, 0xE9, 0x60, 0xBF, 0x10, 0xEF, 0x39, 0xEC, 0x91, 0x7F, 0x48, 0x89, 0x10 },
 { 0x10, 0xE9, 0xD0, 0xD9, 0xF3, 0x94, 0x3D, 0xAF, 0x7B, 0xFF, 0x64, 0x91, 0x52, 0xF8, 0x0D, 0xDD },
 { 0xDD, 0x99, 0x75, 0xCA, 0x97, 0x44, 0x5A, 0xE0, 0x30, 0xA6, 0x31, 0xD3, 0xDF, 0x48, 0x64, 0x84 },
 { 0x84, 0x2D, 0x74, 0x96, 0x5D, 0x77, 0x6F, 0xDE, 0x54, 0xB4, 0x8D, 0xD1, 0x44, 0x3C, 0xA5, 0x94 },
 { 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Развернутые раундовые ключи и маски алгоритма Кузнечик.
    \details Массив содержит в себе записанные последовательно следующие ключи и маски
    (последовательно, по 10 ключей из двух 64-х битных слов на каждый ключ)
      - раундовые ключи для алгоритма зашифрования
      - раундовые ключи для алгоритма расшифрования
      - маски для раундовых ключей алгоритма зашифрования
      - маски для раундовых ключей алгоритма расшифрования. */
 typedef ak_uint64 ak_kuznechik_expanded_keys[80];

/* ---------------------------------------------------------------------------------------------- */
 static struct kuznechik_params kuznechik_parameters;

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает два элемента конечного поля \f$\mathbb F_{2^8}\f$, определенного
     согласно ГОСТ Р 34.12-2015.                                                                  */
/* ---------------------------------------------------------------------------------------------- */
 static ak_uint8 ak_bckey_context_kuznechik_mul_gf256( ak_uint8 x, ak_uint8 y )
{
  ak_uint8 z = 0;
  while( y ) {
    if( y&0x1 ) z ^= x;
    x = ((ak_uint8)(x << 1)) ^ ( x & 0x80 ? 0xC3 : 0x00 );
    y >>= 1;
  }
 return z;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает вектор w на матрицу D, результат помещается в вектор x.                */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_matrix_mul_vector( linear_matrix D, ak_uint8 *w, ak_uint8* x )
{
  int i = 0, j = 0;
  for( i = 0; i < 16; i++ ) {
    ak_uint8 z = ak_bckey_context_kuznechik_mul_gf256( D[i][0], w[0] );
    for( j = 1; j < 16; j++ ) z ^= ak_bckey_context_kuznechik_mul_gf256( D[i][j], w[j] );
    x[i] = z;
  }
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция возводит квадратную матрицу в квадрат. */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_bckey_context_kuznechik_square_matrix( linear_matrix a )
{
  int i, j, k;
  linear_matrix c;

 /* умножаем */
  for( i = 0; i < 16; i++ )
   for( j = 0; j < 16; j++ ) {
      c[i][j] = 0;
      for( k = 0; k < 16; k++ )
         c[i][j] ^= ak_bckey_context_kuznechik_mul_gf256( a[i][k], a[k][j] );
   }
 /* копируем */
  for( i = 0; i < 16; i++ )
   for( j = 0; j < 16; j++ ) a[i][j] = c[i][j];
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует линейное преобразование L согласно ГОСТ Р 34.12-2015
    (шестнадцать тактов работы линейного регистра сдвига).                                        */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_linear_steps( ak_uint8 *w  )
{
  int i = 0, j = 0;
  for( j = 0; j < 16; j++ ) {
     ak_uint8 z = ak_bckey_context_kuznechik_mul_gf256( w[0], kuznechik_parameters.reg[0] );
     for( i = 1; i < 16; i++ ) {
        w[i-1] = w[i];
        z ^= ak_bckey_context_kuznechik_mul_gf256( w[i], kuznechik_parameters.reg[i] );
     }
     w[15] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для заданного линейного регистра сдвига, задаваемого набором коэффициентов `reg`,
    функция вычисляет 16-ю степень сопровождающей матрицы.

    \param reg Набор коэффициентов, определяющих линейный регистр сдвига
    \param matrix Сопровождающая матрица
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_kuznechik_generate_matrix( const linear_register reg, linear_matrix matrix )
{
  size_t i = 0;

 /* создаем сопровождающую матрицу */
  memset( matrix, 0, sizeof( linear_matrix ));
  for( i = 1; i < 16; i++ ) matrix[i-1][i] = 0x1;
  for( i = 0; i < 16; i++ ) matrix[15][i] = reg[i];

 /* возводим сопровождающую матрицу в 16-ю степень */
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_kuznechik_invert_matrix( linear_matrix matrix, linear_matrix matrixinv )
{
  ak_uint8 i, j;
 /* некоторый фокус */
  for( i = 0; i < 16; i++ ) {
     for( j = 0; j < 16; j++ ) matrixinv[15-i][15-j] = matrix[i][j];
  }
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_kuznechik_invert_permutation( const sbox pi, sbox pinv )
{
  ak_uint32 idx = 0;
  for( idx = 0; idx < sizeof( sbox ); idx++ ) pinv[pi[idx]] = ( ak_uint8 )idx;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_kuznechik_init_tables( const linear_register reg,
                                                          const sbox pi, ak_kuznechik_params par )
{
  int i, j, l, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

  if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                "wrong value for \"openssl_compability\" option" );
 /* сохраняем необходимое */
  memcpy( par->reg, reg, sizeof( linear_register ));
  memcpy( par->pi, pi, sizeof( sbox ));

 /* вырабатываем матрицы */
  ak_bckey_kuznechik_generate_matrix( reg, par->L );
  ak_bckey_kuznechik_invert_matrix( par->L, par->Linv );

 /* обращаем таблицы замен */
  ak_bckey_kuznechik_invert_permutation( pi, par->pinv );

 /* теперь вырабатываем развернутые таблицы */
  for( i = 0; i < 16; i++ ) {
     for( j = 0; j < 256; j++ ) {
       ak_uint8 b[16], ib[16];
       for( l = 0; l < 16; l++ ) {
          b[15*oc + (1-2*oc)*l] = ak_bckey_context_kuznechik_mul_gf256( par->L[l][i], par->pi[j] );
          ib[15*oc + (1-2*oc)*l] =
                             ak_bckey_context_kuznechik_mul_gf256( par->Linv[l][i], par->pinv[j] );
       }
       memcpy( par->enc[i][j], b, 16 );
       memcpy( par->dec[i][j], ib, 16 );
     }
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_kuznechik_init_gost_tables( void )
{
  int audit = ak_log_get_level(),
      error = ak_bckey_kuznechik_init_tables( gost_lvec, gost_pi, &kuznechik_parameters );

  if( error != ak_error_ok )
    return ak_error_message( error, __func__,
                                           "generation of GOST R 34.12-2015 parameters is wrong" );
  if( audit >= ak_log_maximum ) return ak_error_message( ak_error_ok, __func__ ,
                                              "generation of GOST R 34.12-2015 parameters is Ok" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                функции для работы с контекстом                                  */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма Кузнечик.
    \param skey Указатель на контекст секретного ключа, содержащего развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_delete_keys( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
  if( skey->data != NULL ) {
   /* теперь очистка и освобождение памяти */
    if(( error = ak_ptr_wipe( skey->data, sizeof( ak_kuznechik_expanded_keys ),
                                                             &skey->generator )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect wiping an internal data" );
      memset( skey->data, 0, sizeof( ak_kuznechik_expanded_keys ));
    }
    ak_aligned_free( skey->data );
    skey->data = NULL;
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма Кузнечик.
    \param skey Указатель на контекст секретного ключа, в который помещаются развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_schedule_keys( ak_skey skey )
{
  ak_uint8 reverse[64];
  int i = 0, j = 0, l = 0, kdx = 2;
  ak_uint64 a0[2], a1[2], c[2], t[2], idx = 0;
  ak_int64 oc = ak_libakrypt_get_option_by_name( "openssl_compability" );
  ak_uint64 *ekey = NULL, *mkey = NULL, *dkey = NULL, *xkey = NULL, *rkey = NULL, *lkey = NULL;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( skey->key_size != 32 ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                              "unsupported length of secret key" );
 /* проверяем целостность ключа */
  if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
 /* удаляем былое */
  if( skey->data != NULL ) ak_kuznechik_delete_keys( skey );

 /* далее, по-возможности, выделяем выравненную память */
  if(( skey->data = ak_aligned_malloc( sizeof( ak_kuznechik_expanded_keys ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );
 /* получаем указатели на области памяти */
  ekey = ( ak_uint64 *)skey->data;                  /* 10 прямых раундовых ключей */
  dkey = ( ak_uint64 *)skey->data + 20;           /* 10 обратных раундовых ключей */
  mkey = ( ak_uint64 *)skey->data + 40;   /* 10 масок для прямых раундовых ключей */
  xkey = ( ak_uint64 *)skey->data + 60; /* 10 масок для обратных раундовых ключей */
  if( oc ) { /* разворачиваем ключ в каноническое представление */
    for( i = 0; i < 32; i++ ) {
       reverse[i] = skey->key[31-i];
       reverse[32+i] = skey->key[63-i];
    }
    lkey = ( ak_uint64 *)reverse;
    rkey = ( ak_uint64 *)( reverse + skey->key_size );
  } else {
    lkey = ( ak_uint64 *)skey->key; /* исходный ключ */
    rkey = ( ak_uint64 *)( skey->key + skey->key_size );
  }

 /* за один вызов вырабатываем маски для прямых и обратных ключей */
  skey->generator.random( &skey->generator, mkey, 40*sizeof( ak_uint64 ));

 /* только теперь выполняем алгоритм развертки ключа */
  a0[0] = lkey[0]^rkey[0]; a0[1] = lkey[1]^rkey[1];
  a1[0] = lkey[2]^rkey[2]; a1[1] = lkey[3]^rkey[3];

  ekey[0] = a1[0]^mkey[0]; ekey[1] = a1[1]^mkey[1];
  dkey[0] = a1[0]^xkey[0]; dkey[1] = a1[1]^xkey[1];

  ekey[2] = a0[0]^mkey[2]; ekey[3] = a0[1]^mkey[3];
  ak_kuznechik_matrix_mul_vector( kuznechik_parameters.Linv,
                                            (ak_uint8 *)a0, (ak_uint8 *)( dkey+2 ));
  dkey[2] ^= xkey[2]; dkey[3] ^= xkey[3];

  for( j = 0; j < 4; j++ ) {
     for( i = 0; i < 8; i++ ) {
      #ifdef AK_LITTLE_ENDIAN
        c[0] = ++idx; /* вычисляем константу алгоритма согласно ГОСТ Р 34.12-2015 */
      #else
        c[0] = bswap_64( ++idx );
      #endif
        c[1] = 0;
        ak_kuznechik_linear_steps(( ak_uint8 *)c );

        t[0] = a1[0] ^ c[0]; t[1] = a1[1] ^ c[1];
        for( l = 0; l < 16; l++ ) ((ak_uint8 *)t)[l] = kuznechik_parameters.pi[ ((ak_uint8 *)t)[l]];
        ak_kuznechik_linear_steps(( ak_uint8 *)t );

        t[0] ^= a0[0]; t[1] ^= a0[1];
        a0[0] = a1[0]; a0[1] = a1[1];
        a1[0] = t[0];  a1[1] = t[1];
     }
     kdx += 2;
     ekey[kdx] = a1[0]^mkey[kdx]; ekey[kdx+1] = a1[1]^mkey[kdx+1];
     ak_kuznechik_matrix_mul_vector( kuznechik_parameters.Linv,
                                         ( ak_uint8 *)a1, (ak_uint8 *)( dkey+kdx ));
     dkey[kdx] ^= xkey[kdx]; dkey[kdx+1] ^= xkey[kdx+1];

     kdx += 2;
     ekey[kdx] = a0[0]^mkey[kdx]; ekey[kdx+1] = a0[1]^mkey[kdx+1];
     ak_kuznechik_matrix_mul_vector( kuznechik_parameters.Linv,
                                         ( ak_uint8 *)a0, (ak_uint8 *)( dkey+kdx ));
     dkey[kdx] ^= xkey[kdx]; dkey[kdx+1] ^= xkey[kdx+1];
  }

  if( oc ) { /* теперь инвертируем обратно вычисленные значения */
    ak_uint8 ch, *pe = (ak_uint8 *)ekey, *pm = (ak_uint8 *)mkey;
    for( i = 0; i < 160; i +=16 ) {
       for( j = 0; j < 8; j++ ) {
         ch = pe[i+j]; pe[i+j] = pe[i+15-j]; pe[i+15-j] = ch;
         ch = pm[i+j]; pm[i+j] = pm[i+15-j]; pm[i+15-j] = ch;
       }
    }
    pe = (ak_uint8 *)dkey; pm = (ak_uint8 *)xkey;
    for( i = 0; i < 160; i +=16 ) {
       for( j = 0; j < 8; j++ ) {
         ch = pe[i+j]; pe[i+j] = pe[i+15-j]; pe[i+15-j] = ch;
         ch = pm[i+j]; pm[i+j] = pm[i+15-j]; pm[i+15-j] = ch;
       }
    }
    ak_ptr_wipe( reverse, sizeof( reverse ), &skey->generator );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_encrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_uint64 *ekey = ( ak_uint64 *)skey->data;
  ak_uint64 *mkey = ( ak_uint64 *)skey->data + 40;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 s, t, x[2];
  ak_uint8 *b = (ak_uint8 *)x;

  x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];
  while( i < 18 ) {
     x[0] ^= ekey[i]; x[0] ^= mkey[i];
     x[1] ^= ekey[++i]; x[1] ^= mkey[i++];

     t  = kuznechik_parameters.enc[ 0][b[ 0]][0];
     t ^= kuznechik_parameters.enc[ 1][b[ 1]][0];
     t ^= kuznechik_parameters.enc[ 2][b[ 2]][0];
     t ^= kuznechik_parameters.enc[ 3][b[ 3]][0];
     t ^= kuznechik_parameters.enc[ 4][b[ 4]][0];
     t ^= kuznechik_parameters.enc[ 5][b[ 5]][0];
     t ^= kuznechik_parameters.enc[ 6][b[ 6]][0];
     t ^= kuznechik_parameters.enc[ 7][b[ 7]][0];
     t ^= kuznechik_parameters.enc[ 8][b[ 8]][0];
     t ^= kuznechik_parameters.enc[ 9][b[ 9]][0];
     t ^= kuznechik_parameters.enc[10][b[10]][0];
     t ^= kuznechik_parameters.enc[11][b[11]][0];
     t ^= kuznechik_parameters.enc[12][b[12]][0];
     t ^= kuznechik_parameters.enc[13][b[13]][0];
     t ^= kuznechik_parameters.enc[14][b[14]][0];
     t ^= kuznechik_parameters.enc[15][b[15]][0];

     s  = kuznechik_parameters.enc[ 0][b[ 0]][1];
     s ^= kuznechik_parameters.enc[ 1][b[ 1]][1];
     s ^= kuznechik_parameters.enc[ 2][b[ 2]][1];
     s ^= kuznechik_parameters.enc[ 3][b[ 3]][1];
     s ^= kuznechik_parameters.enc[ 4][b[ 4]][1];
     s ^= kuznechik_parameters.enc[ 5][b[ 5]][1];
     s ^= kuznechik_parameters.enc[ 6][b[ 6]][1];
     s ^= kuznechik_parameters.enc[ 7][b[ 7]][1];
     s ^= kuznechik_parameters.enc[ 8][b[ 8]][1];
     s ^= kuznechik_parameters.enc[ 9][b[ 9]][1];
     s ^= kuznechik_parameters.enc[10][b[10]][1];
     s ^= kuznechik_parameters.enc[11][b[11]][1];
     s ^= kuznechik_parameters.enc[12][b[12]][1];
     s ^= kuznechik_parameters.enc[13][b[13]][1];
     s ^= kuznechik_parameters.enc[14][b[14]][1];
     s ^= kuznechik_parameters.enc[15][b[15]][1];

     x[0] = t; x[1] = s;
  }
  x[0] ^= ekey[18]; x[1] ^= ekey[19];
  ((ak_uint64 *)out)[0] = x[0] ^ mkey[18];
  ((ak_uint64 *)out)[1] = x[1] ^ mkey[19];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_decrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_uint64 *dkey = ( ak_uint64 *)skey->data + 20;
  ak_uint64 *xkey = ( ak_uint64 *)skey->data + 60;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 t, s, x[2];
  ak_uint8 *b = ( ak_uint8 *)x;
 x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];
  for( i = 0; i < 16; i++ ) b[i] = kuznechik_parameters.pi[b[i]];

  i = 19;
  while( i > 1 ) {
     t  = kuznechik_parameters.dec[ 0][b[ 0]][0];
     t ^= kuznechik_parameters.dec[ 1][b[ 1]][0];
     t ^= kuznechik_parameters.dec[ 2][b[ 2]][0];
     t ^= kuznechik_parameters.dec[ 3][b[ 3]][0];
     t ^= kuznechik_parameters.dec[ 4][b[ 4]][0];
     t ^= kuznechik_parameters.dec[ 5][b[ 5]][0];
     t ^= kuznechik_parameters.dec[ 6][b[ 6]][0];
     t ^= kuznechik_parameters.dec[ 7][b[ 7]][0];
     t ^= kuznechik_parameters.dec[ 8][b[ 8]][0];
     t ^= kuznechik_parameters.dec[ 9][b[ 9]][0];
     t ^= kuznechik_parameters.dec[10][b[10]][0];
     t ^= kuznechik_parameters.dec[11][b[11]][0];
     t ^= kuznechik_parameters.dec[12][b[12]][0];
     t ^= kuznechik_parameters.dec[13][b[13]][0];
     t ^= kuznechik_parameters.dec[14][b[14]][0];
     t ^= kuznechik_parameters.dec[15][b[15]][0];

     s  = kuznechik_parameters.dec[ 0][b[ 0]][1];
     s ^= kuznechik_parameters.dec[ 1][b[ 1]][1];
     s ^= kuznechik_parameters.dec[ 2][b[ 2]][1];
     s ^= kuznechik_parameters.dec[ 3][b[ 3]][1];
     s ^= kuznechik_parameters.dec[ 4][b[ 4]][1];
     s ^= kuznechik_parameters.dec[ 5][b[ 5]][1];
     s ^= kuznechik_parameters.dec[ 6][b[ 6]][1];
     s ^= kuznechik_parameters.dec[ 7][b[ 7]][1];
     s ^= kuznechik_parameters.dec[ 8][b[ 8]][1];
     s ^= kuznechik_parameters.dec[ 9][b[ 9]][1];
     s ^= kuznechik_parameters.dec[10][b[10]][1];
     s ^= kuznechik_parameters.dec[11][b[11]][1];
     s ^= kuznechik_parameters.dec[12][b[12]][1];
     s ^= kuznechik_parameters.dec[13][b[13]][1];
     s ^= kuznechik_parameters.dec[14][b[14]][1];
     s ^= kuznechik_parameters.dec[15][b[15]][1];

     x[0] = t; x[1] = s;

     x[1] ^= dkey[i]; x[1] ^= xkey[i--];
     x[0] ^= dkey[i]; x[0] ^= xkey[i--];
  }
  for( i = 0; i < 16; i++ ) b[i] = kuznechik_parameters.pinv[b[i]];

  x[0] ^= dkey[0]; x[1] ^= dkey[1];
  (( ak_uint64 *) out)[0] = x[0] ^ xkey[0];
  (( ak_uint64 *) out)[1] = x[1] ^ xkey[1];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).

    Реализуется симметричное преобразование, введенное для совместимости с библиотекой openssl
    и другими реализациями.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_encrypt_with_mask_oc( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_uint64 *ekey = ( ak_uint64 *)skey->data;
  ak_uint64 *mkey = ( ak_uint64 *)skey->data + 40;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 s, t, x[2];
  ak_uint8 *b = (ak_uint8 *)x;

  x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];
  while( i < 18 ) {
     x[0] ^= ekey[i]; x[0] ^= mkey[i];
     x[1] ^= ekey[++i]; x[1] ^= mkey[i++];

     t  = kuznechik_parameters.enc[ 0][b[15]][0];
     t ^= kuznechik_parameters.enc[ 1][b[14]][0];
     t ^= kuznechik_parameters.enc[ 2][b[13]][0];
     t ^= kuznechik_parameters.enc[ 3][b[12]][0];
     t ^= kuznechik_parameters.enc[ 4][b[11]][0];
     t ^= kuznechik_parameters.enc[ 5][b[10]][0];
     t ^= kuznechik_parameters.enc[ 6][b[ 9]][0];
     t ^= kuznechik_parameters.enc[ 7][b[ 8]][0];
     t ^= kuznechik_parameters.enc[ 8][b[ 7]][0];
     t ^= kuznechik_parameters.enc[ 9][b[ 6]][0];
     t ^= kuznechik_parameters.enc[10][b[ 5]][0];
     t ^= kuznechik_parameters.enc[11][b[ 4]][0];
     t ^= kuznechik_parameters.enc[12][b[ 3]][0];
     t ^= kuznechik_parameters.enc[13][b[ 2]][0];
     t ^= kuznechik_parameters.enc[14][b[ 1]][0];
     t ^= kuznechik_parameters.enc[15][b[ 0]][0];

     s  = kuznechik_parameters.enc[ 0][b[15]][1];
     s ^= kuznechik_parameters.enc[ 1][b[14]][1];
     s ^= kuznechik_parameters.enc[ 2][b[13]][1];
     s ^= kuznechik_parameters.enc[ 3][b[12]][1];
     s ^= kuznechik_parameters.enc[ 4][b[11]][1];
     s ^= kuznechik_parameters.enc[ 5][b[10]][1];
     s ^= kuznechik_parameters.enc[ 6][b[ 9]][1];
     s ^= kuznechik_parameters.enc[ 7][b[ 8]][1];
     s ^= kuznechik_parameters.enc[ 8][b[ 7]][1];
     s ^= kuznechik_parameters.enc[ 9][b[ 6]][1];
     s ^= kuznechik_parameters.enc[10][b[ 5]][1];
     s ^= kuznechik_parameters.enc[11][b[ 4]][1];
     s ^= kuznechik_parameters.enc[12][b[ 3]][1];
     s ^= kuznechik_parameters.enc[13][b[ 2]][1];
     s ^= kuznechik_parameters.enc[14][b[ 1]][1];
     s ^= kuznechik_parameters.enc[15][b[ 0]][1];

     x[0] = t; x[1] = s;
  }
  x[0] ^= ekey[18]; x[1] ^= ekey[19];
  ((ak_uint64 *)out)[0] = x[0] ^ mkey[18];
  ((ak_uint64 *)out)[1] = x[1] ^ mkey[19];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).

    Реализуется симметричное преобразование, введенное для совместимости с библиотекой openssl
    и другими реализациями.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_decrypt_with_mask_oc( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_uint64 *dkey = ( ak_uint64 *)skey->data + 20;
  ak_uint64 *xkey = ( ak_uint64 *)skey->data + 60;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint64 t, s, x[2];
  ak_uint8 *b = ( ak_uint8 *)x;

  x[0] = (( ak_uint64 *) in)[0]; x[1] = (( ak_uint64 *) in)[1];
  for( i = 0; i < 16; i++ ) b[i] = kuznechik_parameters.pi[b[i]];

  i = 19;
  while( i > 1 ) {
     t  = kuznechik_parameters.dec[ 0][b[15]][0];
     t ^= kuznechik_parameters.dec[ 1][b[14]][0];
     t ^= kuznechik_parameters.dec[ 2][b[13]][0];
     t ^= kuznechik_parameters.dec[ 3][b[12]][0];
     t ^= kuznechik_parameters.dec[ 4][b[11]][0];
     t ^= kuznechik_parameters.dec[ 5][b[10]][0];
     t ^= kuznechik_parameters.dec[ 6][b[ 9]][0];
     t ^= kuznechik_parameters.dec[ 7][b[ 8]][0];
     t ^= kuznechik_parameters.dec[ 8][b[ 7]][0];
     t ^= kuznechik_parameters.dec[ 9][b[ 6]][0];
     t ^= kuznechik_parameters.dec[10][b[ 5]][0];
     t ^= kuznechik_parameters.dec[11][b[ 4]][0];
     t ^= kuznechik_parameters.dec[12][b[ 3]][0];
     t ^= kuznechik_parameters.dec[13][b[ 2]][0];
     t ^= kuznechik_parameters.dec[14][b[ 1]][0];
     t ^= kuznechik_parameters.dec[15][b[ 0]][0];

     s  = kuznechik_parameters.dec[ 0][b[15]][1];
     s ^= kuznechik_parameters.dec[ 1][b[14]][1];
     s ^= kuznechik_parameters.dec[ 2][b[13]][1];
     s ^= kuznechik_parameters.dec[ 3][b[12]][1];
     s ^= kuznechik_parameters.dec[ 4][b[11]][1];
     s ^= kuznechik_parameters.dec[ 5][b[10]][1];
     s ^= kuznechik_parameters.dec[ 6][b[ 9]][1];
     s ^= kuznechik_parameters.dec[ 7][b[ 8]][1];
     s ^= kuznechik_parameters.dec[ 8][b[ 7]][1];
     s ^= kuznechik_parameters.dec[ 9][b[ 6]][1];
     s ^= kuznechik_parameters.dec[10][b[ 5]][1];
     s ^= kuznechik_parameters.dec[11][b[ 4]][1];
     s ^= kuznechik_parameters.dec[12][b[ 3]][1];
     s ^= kuznechik_parameters.dec[13][b[ 2]][1];
     s ^= kuznechik_parameters.dec[14][b[ 1]][1];
     s ^= kuznechik_parameters.dec[15][b[ 0]][1];

     x[0] = t; x[1] = s;

     x[1] ^= dkey[i]; x[1] ^= xkey[i--];
     x[0] ^= dkey[i]; x[0] ^= xkey[i--];
  }
  for( i = 0; i < 16; i++ ) b[i] = kuznechik_parameters.pinv[b[i]];

  x[0] ^= dkey[0]; x[1] ^= dkey[1];
  (( ak_uint64 *) out)[0] = x[0] ^ xkey[0];
  (( ak_uint64 *) out)[1] = x[1] ^ xkey[1];
}

/* ----------------------------------------------------------------------------------------------- */
/*! После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    \param bkey Контекст секретного ключа алгоритма блочного шифрования.
    \return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create_kuznechik( ak_bckey bkey )
{
  int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context" );
  if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                "wrong value for \"openssl_compability\" option" );

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( error = ak_bckey_create( bkey, 32, 16 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

 /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oid_find_by_name( "kuznechik" )) == NULL ) {
    ak_error_message( error = ak_error_get_value(), __func__,
                                        "wrong search of predefined kuznechik block cipher OID" );
    ak_bckey_destroy( bkey );
    return error;
  }

 /* ресурс ключа устанавливается в момент присвоения ключа */

 /* устанавливаем методы */
  bkey->schedule_keys = ak_kuznechik_schedule_keys;
  bkey->delete_keys = ak_kuznechik_delete_keys;
  if( oc ) {
    bkey->encrypt = ak_kuznechik_encrypt_with_mask_oc;
    bkey->decrypt = ak_kuznechik_decrypt_with_mask_oc;
  }
   else {
    bkey->encrypt = ak_kuznechik_encrypt_with_mask;
    bkey->decrypt = ak_kuznechik_decrypt_with_mask;
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                      функции тестирования                                       */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_libakrypt_test_kuznechik_parameters( void )
{
  struct hash ctx;
  ak_uint8 out[16];
  struct kuznechik_params parameters;
  int error = ak_error_ok, audit = ak_log_get_level(),
      oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

  ak_uint8 esum[16] = {
                 0x5b,0x80,0x54,0xb3,0x4e,0x81,0x09,0x94,0xcc,0x83,0x8b,0x8e,0x53,0xba,0x9d,0x18 };
  ak_uint8 esum2[16] = {
                 0x07,0x0e,0x54,0xd9,0xce,0xd5,0x3d,0xdf,0xeb,0xc5,0x42,0x9b,0x63,0x1d,0x72,0x1a };
  ak_uint8 dsum[16] = {
                 0xbf,0x07,0xdf,0x13,0x1e,0x30,0xcd,0xa1,0x26,0x14,0xba,0x2c,0xfb,0x28,0xec,0xa3 };
  ak_uint8 dsum2[16] = {
                 0xbb,0x15,0xc5,0x0f,0x2e,0x12,0x8b,0xec,0xe9,0xab,0x8f,0x7e,0xe1,0x6d,0xcd,0xd6 };

  if(( oc < 0 ) || ( oc > 1 )) {
    ak_error_message_fmt( ak_error_wrong_option, __func__,
                                         "wrong option's value \"openssl_compability\" = %d", oc );
    return ak_false;
  }
  if( audit >= ak_log_maximum )
    switch( oc ) {
     case 0:  ak_error_message( ak_error_ok, __func__,
                                             "using plain realization of kuznechik block cipher" );
              break;
     case 1:  ak_error_message( ak_error_ok, __func__,
               "using inverted realization of kuznechik block cipher (openssl compability mode)" );
              break;
     default: ak_error_message_fmt( ak_error_wrong_option, __func__,
                                         "wrong option's value \"openssl_compability\" = %d", oc );
              return ak_false;
    }

 /* вырабатываем значения параметров */
  ak_bckey_kuznechik_init_tables( gost_lvec, gost_pi, &parameters );

 /* проверяем генерацию обратной перестановки */
  if( !ak_ptr_is_equal_with_log( parameters.pinv, gost_pinv, sizeof( sbox ))) {
    ak_error_message( ak_error_not_equal_data, __func__,
                                         "incorrect generation of nonlinear inverse permutation" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                                     "inverse permutation is Ok" );

 /* проверяем генерацию сопровождающей матрицы линейного регистра сдвига и обратной к ней */
  if( !ak_ptr_is_equal( parameters.L, gost_L, sizeof( linear_matrix ))) {
    size_t i = 0;
    ak_error_message( ak_error_not_equal_data, __func__,
                                              "incorrect generation of linear reccurence matrix" );
    ak_error_message( 0, __func__, "matrix:" );
    for( i = 0; i < 16; i++ ) {
      ak_error_message_fmt( 0, __func__,
        "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        parameters.L[i][0],  parameters.L[i][1],  parameters.L[i][2],  parameters.L[i][3],
        parameters.L[i][4],  parameters.L[i][5],  parameters.L[i][6],  parameters.L[i][7],
        parameters.L[i][8],  parameters.L[i][9],  parameters.L[i][10], parameters.L[i][11],
              parameters.L[i][12], parameters.L[i][13], parameters.L[i][14], parameters.L[i][15] );
    }
    return ak_false;
  }

  if( !ak_ptr_is_equal( parameters.Linv, gost_Linv, sizeof( linear_matrix ))) {
    size_t i = 0;
    ak_error_message( ak_error_not_equal_data, __func__,
                                              "incorrect generation inverse of companion matrix" );
    ak_error_message( 0, __func__, "inverse matrix:" );
    for( i = 0; i < 16; i++ ) {
      ak_error_message_fmt( 0, __func__,
        "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        parameters.Linv[i][0],  parameters.Linv[i][1],  parameters.Linv[i][2],
        parameters.Linv[i][3],  parameters.Linv[i][4],  parameters.Linv[i][5],
        parameters.Linv[i][6],  parameters.Linv[i][7],  parameters.Linv[i][8],
        parameters.Linv[i][9],  parameters.Linv[i][10], parameters.Linv[i][11],
        parameters.Linv[i][12], parameters.Linv[i][13], parameters.Linv[i][14],
                                                                          parameters.Linv[i][15] );
    }
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                       "companion matrix and it's inverse is Ok" );
 /* проверяем выработанные таблицы */
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of hash function context" );
    return ak_false;
  }
  ak_hash_ptr( &ctx, parameters.enc, sizeof( expanded_table ), out, sizeof( out ));
  if( !ak_ptr_is_equal_with_log( out, oc ? esum2 : esum, sizeof( out ))) {
    ak_hash_destroy( &ctx );
    ak_error_message( ak_error_not_equal_data, __func__,
                                                      "incorrect hash value of encryption table" );
    return ak_false;
  }

  ak_hash_ptr( &ctx, parameters.dec, sizeof( expanded_table ), out, sizeof( out ));
  if( !ak_ptr_is_equal_with_log( out, oc ? dsum2 : dsum, sizeof( out ))) {
    ak_hash_destroy( &ctx );
    ak_error_message( ak_error_not_equal_data, __func__,
                                                      "incorrect hash value of encryption table" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                   "expanded encryption/decryption tables is Ok" );
  ak_hash_destroy( &ctx );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_libakrypt_test_kuznechik_complete( void )
{
  size_t i = 0;
  struct bckey bkey;
  ak_uint8 myout[256];
  bool_t result = ak_true;
  int error = ak_error_ok, audit = ak_log_get_level(),
      oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

 /* тестовый ключ из ГОСТ Р 34.13-2015, приложение А.1 */
  ak_uint8 key[32] = {
    0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
    0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88
  };

 /* этот вектор является заркальным разворотм key относительно центра 32-х октетного вектора */
  ak_uint8 oc_key[32] = {
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
  };

 /* открытый текст из ГОСТ Р 34.13-2015, приложение А.1, подлежащий зашифрованию
    первый блок совпадает с блоком тестовых данных из ГОСТ Р 34.12-2015          */
  ak_uint8 in[64] = {
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
    0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
    0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
    0x11,0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22
  };

 /* этот вектор являестся массивом in, состоящим из 16 октетных векторов, каждый
    из которых зеркально развернут относительно своего центра. Данный разворот
    отличается от разворота секретного ключа. */
  ak_uint8 oc_in[64] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11
  };

 /* результат простой замены */
  ak_uint8 outecb[64] = {
    0xcd,0xed,0xd4,0xb9,0x42,0x8d,0x46,0x5a,0x30,0x24,0xbc,0xbe,0x90,0x9d,0x67,0x7f,
    0x8b,0xd0,0x18,0x67,0xd7,0x52,0x54,0x28,0xf9,0x32,0x00,0x6e,0x2c,0x91,0x29,0xb4,
    0x57,0xb1,0xd4,0x3b,0x31,0xa5,0xf5,0xf3,0xee,0x7c,0x24,0x9d,0x54,0x33,0xca,0xf0,
    0x98,0xda,0x8a,0xaa,0xc5,0xc4,0x02,0x3a,0xeb,0xb9,0x30,0xe8,0xcd,0x9c,0xb0,0xd0
  };
  ak_uint8 oc_outecb[64] = {
    0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd,
    0xb4,0x29,0x91,0x2c,0x6e,0x00,0x32,0xf9,0x28,0x54,0x52,0xd7,0x67,0x18,0xd0,0x8b,
    0xf0,0xca,0x33,0x54,0x9d,0x24,0x7c,0xee,0xf3,0xf5,0xa5,0x31,0x3b,0xd4,0xb1,0x57,
    0xd0,0xb0,0x9c,0xcd,0xe8,0x30,0xb9,0xeb,0x3a,0x02,0xc4,0xc5,0xaa,0x8a,0xda,0x98,
  };

 /* инициализационный вектор для режима гаммирования (счетчика) */
  ak_uint8 ivctr[8] = { 0xf0,0xce,0xab,0x90,0x78,0x56,0x34,0x12 };
  ak_uint8 oc_ivctr[8] = { 0x12,0x34,0x56,0x78,0x90,0xab,0xce,0xf0 };

 /* результат применения режима гаммирования из ГОСТ Р 34.12-2015 */
  ak_uint8 outctr[64] = {
    0xb8,0xa1,0xbd,0x40,0xa2,0x5f,0x7b,0xd5,0xdb,0xd1,0x0e,0xc1,0xbe,0xd8,0x95,0xf1,
    0xe4,0xde,0x45,0x3c,0xb3,0xe4,0x3c,0xf3,0x5d,0x3e,0xa1,0xf6,0x33,0xe7,0xee,0x85,
    0xa5,0xa3,0x64,0x35,0xf1,0x77,0xe8,0xd5,0xd3,0x6e,0x35,0xe6,0x8b,0xe8,0xea,0xa5,
    0x73,0xba,0xbd,0x20,0x58,0xd1,0xc6,0xd1,0xb6,0xba,0x0c,0xf2,0xb1,0xfa,0x91,0xcb
  };
  ak_uint8 oc_outctr[64] = {
    0xf1,0x95,0xd8,0xbe,0xc1,0x0e,0xd1,0xdb,0xd5,0x7b,0x5f,0xa2,0x40,0xbd,0xa1,0xb8,
    0x85,0xee,0xe7,0x33,0xf6,0xa1,0x3e,0x5d,0xf3,0x3c,0xe4,0xb3,0x3c,0x45,0xde,0xe4,
    0xa5,0xea,0xe8,0x8b,0xe6,0x35,0x6e,0xd3,0xd5,0xe8,0x77,0xf1,0x35,0x64,0xa3,0xa5,
    0xcb,0x91,0xfa,0xb1,0xf2,0x0c,0xba,0xb6,0xd1,0xc6,0xd1,0x58,0x20,0xbd,0xba,0x73,
  };

 /* инициализационный вектор для режима простой замены с зацеплением */
  ak_uint8 ivcbc[32] = {
    0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
    0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23
  };
  ak_uint8 openssl_ivcbc[32] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
    0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
  };

 /* зашифрованный блок из ГОСТ Р 34.12-2015 для режима простой замены с зацеплением */
  ak_uint8 outcbc[64] = {
    0x27, 0xcc, 0x7d, 0x6d, 0x3d, 0x2e, 0xe5, 0x90, 0x4d, 0xfa, 0x85, 0xa0, 0xd4, 0x72, 0x99, 0x68,
    0xac, 0xa5, 0x5e, 0x8d, 0x44, 0x8e, 0x1e, 0xaf, 0xa6, 0xec, 0x78, 0xb4, 0x61, 0xe6, 0x26, 0x28,
    0xd0, 0x90, 0x9d, 0xf4, 0xb0, 0xe8, 0x40, 0x56, 0xe8, 0x99, 0x19, 0xe9, 0xf1, 0xab, 0x7b, 0xfe,
    0x70, 0x39, 0xb6, 0x60, 0x15, 0x9a, 0x2d, 0x1a, 0x63, 0x5c, 0x89, 0x5a, 0x06, 0x88, 0x76, 0x16
  };
  ak_uint8 openssl_outcbc[64] = {
    0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
    0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
    0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
    0x16, 0x76, 0x88, 0x06, 0x5a, 0x89, 0x5c, 0x63, 0x1a, 0x2d, 0x9a, 0x15, 0x60, 0xb6, 0x39, 0x70
  };

 /* инициализационный вектор для режима гаммирования с обратной связью по выходу (ofb) */
  ak_uint8 ivofb[32] = {
    0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
    0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23
  };

 /* значение синхропосылки для командной строки:
    1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819 */
  ak_uint8 openssl_ivofb[32] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
    0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
  };

 /* зашифрованный блок из ГОСТ Р 34.13-2015, прил. А.1.3*/
  ak_uint8 outofb[64] = {
    0x95, 0xbd, 0x7a, 0x89, 0x5e, 0x79, 0x1f, 0xff, 0x24, 0x2b, 0x84, 0xb1, 0x59, 0x0a, 0x80, 0x81,
    0xbf, 0x26, 0x93, 0x9d, 0x36, 0x21, 0xb5, 0x8f, 0xb4, 0xfa, 0x8c, 0x04, 0xa7, 0x47, 0x5b, 0xed,
    0x13, 0x8a, 0x28, 0x10, 0xfc, 0xe7, 0x0f, 0xc8, 0xb1, 0xb8, 0xa0, 0x3c, 0xac, 0x57, 0xa2, 0x66,
    0x50, 0x31, 0x90, 0xf6, 0x43, 0x22, 0x29, 0xa0, 0x60, 0x86, 0x13, 0x66, 0xc0, 0xbb, 0x3e, 0x20
  };
  ak_uint8 openssl_outofb[64] = {
    0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
    0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
    0x66, 0xa2, 0x57, 0xac, 0x3c, 0xa0, 0xb8, 0xb1, 0xc8, 0x0f, 0xe7, 0xfc, 0x10, 0x28, 0x8a, 0x13,
    0x20, 0x3e, 0xbb, 0xc0, 0x66, 0x13, 0x86, 0x60, 0xa0, 0x29, 0x22, 0x43, 0xf6, 0x90, 0x31, 0x50
  };

 /* зашифрованный блок из ГОСТ Р 34.13-2015, прил. А.1.5 */
  ak_uint8 outcfb[64] = {
    0x95, 0xbd, 0x7a, 0x89, 0x5e, 0x79, 0x1f, 0xff, 0x24, 0x2b, 0x84, 0xb1, 0x59, 0x0a, 0x80, 0x81,
    0xbf, 0x26, 0x93, 0x9d, 0x36, 0x21, 0xb5, 0x8f, 0xb4, 0xfa, 0x8c, 0x04, 0xa7, 0x47, 0x5b, 0xed,
    0xb5, 0x38, 0xa2, 0x97, 0x4e, 0x26, 0x2d, 0x84, 0x38, 0x8d, 0xc6, 0x5c, 0xeb, 0xa8, 0xf2, 0x79,
    0xd1, 0xf4, 0xfb, 0x44, 0xdd, 0xd9, 0x5b, 0xc7, 0xe6, 0x2d, 0x92, 0x4e, 0xcd, 0xbe, 0xfe, 0x4f
  };
  ak_uint8 openssl_outcfb[64] = {
    0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
    0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
    0x79, 0xf2, 0xa8, 0xeb, 0x5c, 0xc6, 0x8d, 0x38, 0x84, 0x2d, 0x26, 0x4e, 0x97, 0xa2, 0x38, 0xb5,
    0x4f, 0xfe, 0xbe, 0xcd, 0x4e, 0x92, 0x2d, 0xe6, 0xc7, 0x5b, 0xd9, 0xdd, 0x44, 0xfb, 0xf4, 0xd1
  };

 /* значение имитовставки согласно ГОСТ Р 34.13-2015 (раздел А.1.6) */
  ak_uint8 imito[8] = {
    /* 0x67, 0x9C, 0x74, 0x37, 0x5B, 0xB3, 0xDE, 0x4D - первая часть выработанного блока */
    0xE3, 0xFB, 0x59, 0x60, 0x29, 0x4D, 0x6F, 0x33
  };
  ak_uint8 openssl_imito[8] = {
    0x33, 0x6f, 0x4d, 0x29, 0x60, 0x59, 0xfb, 0xe3
 /* 0x4d, 0xde, 0xb3, 0x5b, 0x37, 0x74, 0x9c, 0x67 - остальные вырабатываемые байты */
  };

 /* Проверка используемого режима совместимости */
  if(( oc < 0 ) || ( oc > 1 )) {
    ak_error_message( ak_error_wrong_option, __func__,
                                                "wrong value for \"openssl_compability\" option" );
    return ak_false;
  }

 /* Проверка тестируемых данных */
  for( i = 0; i < sizeof( key ); i++ )
    if( key[i] != oc_key[31-i] ) result = ak_false;
  if( result != ak_true ) {
    ak_error_message( ak_error_invalid_value, __func__,
                                            "incorrect constant values for kuznechik secret key" );
    return ak_false;
  }

 /* --------------------------------------------------------------------------- */
 /* 1. Создаем контекст ключа алгоритма Кузнечик и устанавливаем значение ключа */
 /* --------------------------------------------------------------------------- */
  if(( error = ak_bckey_create_kuznechik( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of kuznechik secret key context");
    return ak_false;
  }

  if(( error = ak_bckey_set_key( &bkey, oc ? oc_key : key,
                                                                 sizeof( key ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong creation of test key" );
    result = ak_false;
    goto exit;
  }

 /* ------------------------------------------------------------------------------------------- */
 /* 2. Проверяем независимую обработку блоков - режим простой замены согласно ГОСТ Р 34.12-2015 */
 /* ------------------------------------------------------------------------------------------- */
  if(( error = ak_bckey_encrypt_ecb( &bkey, oc ? oc_in : in,
                                                           myout, sizeof( in ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong ecb mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? oc_outecb : outecb, sizeof( outecb ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the ecb mode encryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }

  if(( error = ak_bckey_decrypt_ecb( &bkey, oc ? oc_outecb : outecb,
                                                       myout, sizeof( outecb ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong ecb mode decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? oc_in : in, sizeof( in ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the ecb mode decryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                "the ecb mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* --------------------------------------------------------------------------- */
 /* 3. Проверяем режим гаммирования согласно ГОСТ Р 34.12-2015                  */
 /* --------------------------------------------------------------------------- */
  if(( error = ak_bckey_ctr( &bkey, oc ? oc_in : in,
                   myout, sizeof( in ), oc ? oc_ivctr : ivctr, sizeof( ivctr ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong counter mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? oc_outctr : outctr, sizeof( outecb ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the counter mode encryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }

  if(( error = ak_bckey_ctr( &bkey, myout,
               myout, sizeof( outecb ), oc ? oc_ivctr : ivctr, sizeof( ivctr ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong counter mode decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? oc_in : in, sizeof( in ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the counter mode decryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                "the counter mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* --------------------------------------------------------------------------- */
 /* 4. Проверяем режим простой замены c зацеплением согласно ГОСТ Р 34.12-2015  */
 /* --------------------------------------------------------------------------- */
  if(( error = ak_bckey_encrypt_cbc( &bkey, oc ? oc_in : in, myout, sizeof( in ),
                                   oc ? openssl_ivcbc : ivcbc, sizeof( ivcbc ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong cbc mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? openssl_outcbc : outcbc, sizeof( outcbc ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the cbc mode encryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }
  if(( error = ak_bckey_decrypt_cbc( &bkey, oc ? openssl_outcbc : outcbc, myout,
                 sizeof( outcbc ), oc ? openssl_ivcbc : ivcbc, sizeof( ivcbc ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong cbc mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? oc_in : in, sizeof( in ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the cbc mode encryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the cbc mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* -------------------------------------------------------------------------------------- */
 /* 5. Проверяем режим гаммирования c обратной связью по выходу согласно ГОСТ Р 34.12-2015 */
 /* -------------------------------------------------------------------------------------- */
  if(( error = ak_bckey_ofb( &bkey, oc ? oc_in : in,
              myout, sizeof( in ), oc ? openssl_ivofb : ivofb, sizeof( ivofb ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong ofb mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? openssl_outofb : outofb, sizeof( outofb ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the ofb mode encryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }

  if(( error = ak_bckey_ofb( &bkey, oc ? openssl_outofb : outofb,
          myout, sizeof( outofb ), oc ? openssl_ivofb : ivofb, sizeof( ivofb ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong ofb mode decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? oc_in : in, sizeof( in ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the ofb mode decryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                "the ofb mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* -------------------------------------------------------------------------------------- */
 /* 6. Проверяем режим гаммирования c обратной связью по шифртексту */
 /* -------------------------------------------------------------------------------------- */
  if(( error = ak_bckey_encrypt_cfb( &bkey, oc ? oc_in : in,
              myout, sizeof( in ), oc ? openssl_ivofb : ivofb, sizeof( ivofb ))) != ak_error_ok ) {
               /* используемая синхропосылка совпадает с вектором из режима ofb */
    ak_error_message( error, __func__ , "wrong cfb mode encryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? openssl_outcfb : outcfb, sizeof( outcfb ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the cfb mode encryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }

  if(( error = ak_bckey_decrypt_cfb( &bkey, oc ? openssl_outcfb : outcfb,
          myout, sizeof( outcfb ), oc ? openssl_ivofb : ivofb, sizeof( ivofb ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong cfb mode decryption" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? oc_in : in, sizeof( in ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                        "the cfb mode decryption test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                "the cfb mode encryption/decryption test from GOST R 34.13-2015 is Ok" );

 /* --------------------------------------------------------------------------- */
 /* 10. Тестируем режим выработки имитовставки (плоская реализация).            */
 /* --------------------------------------------------------------------------- */
  if(( error = ak_bckey_cmac( &bkey, oc ? oc_in : in,
                                                     sizeof( in ), myout, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong cmac calculation" );
    result = ak_false;
    goto exit;
  }
  if( !ak_ptr_is_equal_with_log( myout, oc ? openssl_imito : imito, 8 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                        "the cmac integrity test from GOST R 34.13-2015 is wrong");
    result = ak_false;
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                          "the cmac integrity test from GOST R 34.13-2015 is Ok" );
 /* освобождаем ключ и выходим */
  exit:
  if(( error = ak_bckey_destroy( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong destroying of secret key" );
    return ak_false;
  }

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_libakrypt_test_kuznechik( void )
{
  int audit = audit = ak_log_get_level();
  int oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

 /* мы тестируем алгоритм Магма в двух режимах совместимисти,
    вызывая для этого функцию тестирования дважды

    1. сначала запуск в базовом режиме работы библиотеки */
   ak_libakrypt_set_openssl_compability( ak_false );
   if( !ak_libakrypt_test_kuznechik_parameters( )) { /* тестируем стандартные параметры алгоритма */
    ak_error_message( ak_error_get_value(), __func__,
                             "incorrect testing of predefined parameters from GOST R 34.12-2015" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                 "testing of predefined parameters from GOST R 34.12-2015 is Ok" );
  /* тестируем работу алоритма на контрольных примерах из ГОСТов и рекомендаций */
  if( !ak_libakrypt_test_kuznechik_complete( )) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect testing of kuznechik block cipher" );
    return ak_false;
  }

 /* 2. потом запускаем тестирование в режиме совместимости с openssl */
   ak_libakrypt_set_openssl_compability( ak_true );
   if( !ak_libakrypt_test_kuznechik_parameters( )) { /* тестируем стандартные параметры алгоритма */
    ak_error_message( ak_error_get_value(), __func__,
                             "incorrect testing of predefined parameters from GOST R 34.12-2015" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                 "testing of predefined parameters from GOST R 34.12-2015 is Ok" );
  /* тестируем работу алоритма на контрольных примерах из ГОСТов и рекомендаций */
  if( !ak_libakrypt_test_kuznechik_complete( )) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect testing of kuznechik block cipher" );
    return ak_false;
  }

 /* 3. восстанавливаем первоначальное состояние */
   ak_libakrypt_set_openssl_compability( oc );
   if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                        "testing of kuznechik block ciper is Ok" );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_kuznechik.c  */
/* ----------------------------------------------------------------------------------------------- */
