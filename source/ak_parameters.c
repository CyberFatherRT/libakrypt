/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_parameters.с                                                                           */
/*  - содержит значения фиксированных параметров криптографических алгоритмов                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой из тестового примера ГОСТ Р 34.10-2012 (Приложение А.1). */
/*! \code
      a = "7",
      b = "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
      p = "8000000000000000000000000000000000000000000000000000000000000431",
      q = "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
     px = "2",
     py = "8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_tc26_gost_3410_2012_256_paramSetTest = {
  ak_mpzn256_size,
  1,
  { 0xffffffffffffc983LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0x7fffffffffffffffLL }, /* a (в форме Монтгомери) */
  { 0x807bbfa323a3952aLL, 0x004469b4541a2542LL, 0x20391abe272c66adLL, 0x58df983a171cd5aeLL }, /* b (в форме Монтгомери) */
  { 0x0000000000000431LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x8000000000000000LL }, /* p */
  { 0x0000000000464584LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* r2 */
  { 0xc59cfc193accf5b3LL, 0x50fe8a1892976154LL, 0x0000000000000001LL, 0x8000000000000000LL }, /* q */
  { 0xecaed44677f7f28dLL, 0x4af1f8ac73c6c555LL, 0xc0db8b05c83ad16aLL, 0x6e749e5b503b112aLL }, /* r2q */
  {
    { 0x0000000000000002LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* px */
    { 0x2b96abbcea7e8fc8LL, 0x85c97f0a9ca26712LL, 0xbd6316030e16d19cLL, 0x08e2a8a0e65147d4LL }, /* py */
    { 0x0000000000000001LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }  /* pz */
  },
  0xdbf951d5883b2b2fLL, /* n */
  0x66ff43a234713e85LL, /* nq */
  "8000000000000000000000000000000000000000000000000000000000000431",
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetA). */
/*! \code
      a = "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
      b = "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
      q = "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
     px = "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
     py = "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_tc26_gost_3410_2012_256_paramSetA = {
  ak_mpzn256_size,
  4, /* cofactor */
  { 0x6d0078e62fc81048LL, 0x94db4f98bfb73698LL, 0x75e9b60631449efdLL, 0xca0709cc398e1cd1LL }, /* a */
  { 0xacd1216d5cc63966LL, 0x534b728e6773c810LL, 0xfb4e95d31a5032feLL, 0xb76e3775f6a4aee7LL }, /* b */
  { 0xfffffffffffffd97LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL }, /* p */
  { 0x000000000005cf11LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* r2 */
  { 0xc115af556c360c67LL, 0x0fd8cddfc87b6635LL, 0x0000000000000000LL, 0x4000000000000000LL }, /* q */
  { 0x57cb446240dd1710LL, 0x7556091c4805caa4LL, 0xd0593365f9384bcdLL, 0x0fb1fbc48b0f0eb4LL }, /* r2q */
  {
    { 0x8b2582fe742daa28LL, 0x658b9196932e02c7LL, 0x880923425712b2bbLL, 0x91e38443a5e82c0dLL }, /* px */
    { 0xaf268adb32322e5cLL, 0x5fde0b5344766740LL, 0x895786c4bb46e956LL, 0x32879423ab1a0375LL }, /* py */
    { 0x0000000000000001LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }  /* pz */
  },
  0x46f3234475d5add9LL, /* n */
  0x035bdd1aeafdb0a9LL, /* nq */
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой, определяемые RFC-4357, set A (вариант КриптоПро). */
/*! \code
      a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
      b = "A6",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
      q = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
     px = "1",
     qx = "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_rfc4357_gost_3410_2001_paramSetA = {
  ak_mpzn256_size,
  1,
  { 0xfffffffffffff65cLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL }, /* a */
  { 0x0000000000019016LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* b */
  { 0xfffffffffffffd97LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL }, /* p */
  { 0x000000000005cf11LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* r2 */
  { 0x45841b09b761b893LL, 0x6c611070995ad100LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL }, /* q */
  { 0x9ac2d7858e79a469LL, 0xfb07f8222e76dd52LL, 0xf74885d08a3714c6LL, 0x551fe9cb451179dbLL }, /* r2q */
  {
    { 0x0000000000000001LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* px */
    { 0x22acc99c9e9f1e14LL, 0x35294f2ddf23e3b1LL, 0x27df505a453f2b76LL, 0x8d91e471e0989cdaLL }, /* py */
    { 0x0000000000000001LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }  /* pz */
  },
  0x46f3234475d5add9LL, /* n */
  0x9ee6ea0b57c7da65LL, /* nq */
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой, определяемые RFC-4357, set B (вариант КриптоПро). */
/*! \code
      a = "8000000000000000000000000000000000000000000000000000000000000C96",
      b = "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
      p = "8000000000000000000000000000000000000000000000000000000000000C99",
      q = "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
     px = "1",
     py = "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_rfc4357_gost_3410_2001_paramSetB = {
  ak_mpzn256_size,
  1,
  { 0x0000000000004b96LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* a */
  { 0x8dcc455aa9c5a084LL, 0x91ab42df6cf438a8LL, 0x8f8aa907eeac7d11LL, 0x3ce5d221f6285375LL }, /* b */
  { 0x0000000000000c99LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x8000000000000000LL }, /* p */
  { 0x00000000027acdc4LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* r2 */
  { 0xe497161bcc8a198fLL, 0x5f700cfff1a624e5LL, 0x0000000000000001LL, 0x8000000000000000LL }, /* q */
  { 0x29b721f4e6cd7823LL, 0x2a3104a7ea43e855LL, 0x4a2e7e2f6882cf10LL, 0x09d1d2c4e5082466LL }, /* r2q */
  {
    { 0x0000000000000001LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* px */
    { 0x744bf8d717717efcLL, 0xc545c9858d03ecfbLL, 0xb83d1c3eb2c070e5LL, 0x3fa8124359f96680LL }, /* py */
    { 0x0000000000000001LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }  /* pz */
  },
  0xbd667ab8a3347857LL, /* n */
  0xca89614990611a91LL, /* nq */
  "8000000000000000000000000000000000000000000000000000000000000c99",
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой, определяемые RFC-4357, set C (вариант КриптоПро). */
/*! \code
       a = "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
       b = "805A",
       p = "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
       q = "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
      px = "0",
      py = "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_rfc4357_gost_3410_2001_paramSetC = {
  ak_mpzn256_size,
  1,
  { 0x5ffcd69d0ae34c07LL, 0x0d9628a05ad19921LL, 0x5799e9d81848eb56LL, 0x0a1ce1dcc49b8526LL }, /* a */
  { 0x4be8a4e93bda2acfLL, 0x79cc0e3e90d382ddLL, 0x3ba4c8b01d9cc79bLL, 0x5cc73b5a966609e9LL }, /* b */
  { 0x7998f7b9022d759bLL, 0xcf846e86789051d3LL, 0xab1ec85e6b41c8aaLL, 0x9b9f605f5a858107LL }, /* p */
  { 0x409973b4c427fceaLL, 0x1017bb39c2d346c5LL, 0x186304212849c07bLL, 0x807a394ede097652LL }, /* r2 */
  { 0xf02f3a6598980bb9LL, 0x582ca3511eddfb74LL, 0xab1ec85e6b41c8aaLL, 0x9b9f605f5a858107LL }, /* q */
  { 0xe94faab66aba180eLL, 0x04fda8694afda24bLL, 0xc67e5d0ee96e8ed3LL, 0x7aa61b49a49d4759LL }, /* r2q */
  {
    { 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* px */
    { 0x366e550dfdb3bb67LL, 0x4d4dc440d4641a8fLL, 0x3cbf3783cd08c0eeLL, 0x41ece55743711a8cLL }, /* py */
    { 0x0000000000000001LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }  /* pz */
  },
  0xdf6e6c2c727c176dLL, /* n */
  0xa1c6af0a552f7577LL, /* nq */
  "9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b",
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 256-ти битной эллиптической кривой, построенные в диссертационной работе Нестеренко А.Ю. (приложение А, набор N0). */
/*! \code
      a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD2158",
      b = "42DFDE56DD26BB76EBA94CE9565E562BED1FB994675632A264AFEF327AA4E5FF",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD215B",
      q = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF2C1B759991830C6B5DCC785B195C4EDB",
     px = "2",
     py = "011E47B6E40DC7F783B9F4FC84D085884B9B88CA9EC7DA8C5567C9D87F68A17F"
    \endcode

    Данная кривая обладает следующими характеристиками:

    - модуль кривой удовлетворяет равенству \f$ p = 2^{256} - 188069\f$,
    - числа \f$ p \f$ и \f$ p_1 = \frac{p-1}{2} \f$ являются простыми,
    - аналогично, числа \f$ q \f$ и \f$ q_1 = \frac{q-1}{2} \f$ также являются простыми,
    - кофактор равен единице и порядок всей группы точек \f$ m = q\f$,
    - дискриминант кольца эндоморфизмов \f$ d = -354691387 \f$,
    - число классов \f$ h = 2464 \f$.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_axel_gost_3410_2012_256_paramSet_N0 = {
  ak_mpzn256_size,
  1,
  { 0xFFFFFFFFFFF4856CLL, 0xFFFFFFFFFFFFFFFFLL, 0xFFFFFFFFFFFFFFFFLL, 0xFFFFFFFFFFFFFFFFLL }, /* a */
  { 0x5537E72FFE703FE3LL, 0xCB8A1CEFBFBC3F5BLL, 0x4EA3980725DF7C30LL, 0xF9C75C119775CB55LL }, /* b */
  { 0XFFFFFFFFFFFD215BLL, 0XFFFFFFFFFFFFFFFFLL, 0XFFFFFFFFFFFFFFFFLL, 0XFFFFFFFFFFFFFFFFLL }, /* p */
  { 0x000000083C369659LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* r2 */
  { 0x5DCC785B195C4EDBLL, 0x2C1B759991830C6BLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL }, /* q */
  { 0x5F1888618BB22F59LL, 0xB1264EDCDEE377ACLL, 0xD5FFD504DC5F765DLL, 0xAF62882BAB696033LL }, /* r2q */
  {
    { 0x0000000000000002LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }, /* px */
    { 0x5567C9D87F68A17FLL, 0x4B9B88CA9EC7DA8CLL, 0x83B9F4FC84D08588LL, 0x011E47B6E40DC7F7LL }, /* py */
    { 0x0000000000000001LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL }  /* pz */
  },
  0x71A1662E6FA1D92DLL, /* n */
  0x40BB2313A95302ADLL, /* nq */
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd215b",
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой из тестового примера ГОСТ Р 34.10-2012 (Приложение А.2). */
/*! \code
      a = "7",
      b = "1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC",
      p = "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373",
      q = "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF",
     px = "24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A",
     py = "2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_tc26_gost_3410_2012_512_paramSetTest = {
  ak_mpzn512_size,
  1,
  { 0xd029a50f056849c5, 0xc102fa1830a665e5, 0x93678fa569b3c155, 0x61dff2a95e2108c5, 0x3500e30d3e698dd3, 0xb9cafa8506ed8887, 0xb1b73df28851b571, 0x3e261f7e31fc8188 }, /* a */
  { 0x3d869f8d06cde456, 0x22167b920ce0bfcb, 0xf7fdd636df3cc250, 0x45228319a5e6292d, 0xfd513828d9ad288d, 0xc7d45cb277e670aa, 0x04890c718bc5c744, 0x1a693f403fc50f21 }, /* b */
  { 0x1664bbf528be6373, 0x35b8336fac224dd8, 0x0458047e80e4546d, 0xf1d852741af4704a, 0xd4eb7c09b5d2d15d, 0x922b14b2ffb90f04, 0x550d267b6b2fee80, 0x4531acd1fe0023c7 }, /* p */
  { 0x001c10bc2d005b65, 0x4b907a71e647ee63, 0xe417d58d200c2aa0, 0x0815b9eb1e7dd300, 0xca0bc8af77c8690a, 0xfcd983cfb7c663d9, 0x01fde9ca99de0852, 0x1d887dcd9cd19c10 }, /* r2 */
  { 0xd644aaf187e6e6df, 0xd86e25edbe23c595, 0x19905c5eecc423f1, 0xa82f2d7ecb1dbac7, 0xd4eb7c09b5d2d15d, 0x922b14b2ffb90f04, 0x550d267b6b2fee80, 0x4531acd1fe0023c7 }, /* q */
  { 0xb03174e56db6ba90, 0x561500cb39a9b66b, 0x929e0924887fab48, 0xe23c04dc39c8c930, 0x0cc44723bcc36979, 0xd70dfcccc3dd062f, 0x80bc9d923a08f9a9, 0x3057350e3201bb36 }, /* r2q */
  {
    { 0xb530f1b120248a9a, 0x8bc849977fac33b4, 0xc6b60aa7eee804e2, 0xfd60611262cd838d, 0x25f91093a68cd762, 0x5213b3b3d7057cc8, 0xf396bf6ebbfd7a6c, 0x24d19cc64572ee30 }, /* px */
    { 0x6dbb92cb1add371e, 0xdc1a18b91b24640b, 0xf7eb3351e1ee4e43, 0x83ab156d77f1496b, 0xf32447c259f39b2c, 0xcfbf061e91e5f2c3, 0x0d020613c857acdd, 0x2bb312a43bd2ce6e }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0xd6412ff7c29b8645LL, /* n */
  0x50bc7d084a21aae1LL, /* nq */
  "4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373",
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetA). */
/*! \code
      a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
      b = "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
      q = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
     px = "3",
     py = "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_tc26_gost_3410_2012_512_paramSetA = {
  ak_mpzn512_size,
  1,
  { 0xfffffffffffff71c, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* a */
  { 0x3e2a1b8106e8a17d, 0x3e694a40649ca74b, 0x7cd5ed6575cbfc5f, 0x84e4722c383c8743, 0x9527086e6e4db48e, 0x2d4b3fda85c534b6, 0x9d2dd3769d088dff, 0x57e4a0c5f647c2e3 }, /* b */
  { 0xfffffffffffffdc7, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* p */
  { 0x000000000004f0b1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0xcacdb1411f10b275, 0x9b4b38abfad2b85d, 0x6ff22b8d4e056060, 0x27e69532f48d8911, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* q */
  { 0x546775b92106e979, 0xb55cd33800ab10e6, 0x80b08b27e9cebbc7, 0xa06b76a2bae6fc86, 0xc7433579e382956f, 0xbab8be5dd7b1651d, 0xee028bf9d8ed3314, 0xb66ae6c00bebd6c3 }, /* r2q */
  {
    { 0x0000000000000003, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x89a589cb5215f2a4, 0x8028fe5fc235f5b8, 0x3d75e6a50e3a41e9, 0xdf1626be4fd036e9, 0x778064fdcbefa921, 0xce5e1c93acf1abc1, 0xa61b8816e25450e6, 0x7503cfe87a836ae3 }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x58a1f7e6ce0f4c09LL, /* n */
  0x02ccc1665d51f223LL, /* nq */
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetB). */
/*! \code
      a = "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
      b = "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
      p = "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
      q = "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
     px = "2",
     py = "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_tc26_gost_3410_2012_512_paramSetB = {
  ak_mpzn512_size,
  1,
  { 0x000000000000029a, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* a */
  { 0xdbe748c318a75dd6, 0xc954a7809097bfc1, 0x6553cd27e2d5a471, 0xb99b326049435cf3, 0xe9eac8a216d2c5e7, 0x260b45a102d0cc51, 0x8636181d6c5bd56d, 0x638259a12c5765bc }, /* b */
  { 0x000000000000006f, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000 }, /* p */
  { 0x000000000000c084, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0xc6346c54374f25bd, 0x8b996712101bea0e, 0xacfdb77bd9d40cfa, 0x49a1ec142565a545, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000 }, /* q */
  { 0x3163da9749d3cb8b, 0x267d56905313f38b, 0xc55538cf997acac4, 0xb1532b08f1e25e5c, 0xc385980eb887a3f9, 0x9f96043308eeb401, 0xf96232d7a52b18fe, 0x21c65cda4cadccc0 }, /* r2q */
  {
    { 0x0000000000000002, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* px */
    { 0x7e21340780fe41bd, 0x28041055f94ceeec, 0x152cbcaaf8c03988, 0xdcb228fd1edf4a39, 0xbe6dd9e6c8ec7335, 0x3c123b697578c213, 0x2c071e3647a8940f, 0x1a8f7eda389b094c }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x4e6a171024e6a171LL, /* n */
  0xc07d62492cbac26bLL, /* nq */
  "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f",
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры 512-ти битной эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetC). */
/*! \code
      a = "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
      b = "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",
      p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
      q = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED",
     px = "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148",
     py = "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F",
    \endcode                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const struct wcurve id_tc26_gost_3410_2012_512_paramSetC = {
  ak_mpzn512_size,
  4,
  { 0xd341ab3699869915, 0x3d6c9273ccebc4c1, 0x486b484c83cb0726, 0x9a8145b812d1a7b0, 0x2003251cadf8effa, 0x6b20d9f8b7db94f1, 0xdd0c19f57c9cc019, 0x408aa82ae77985ca }, /* a */
  { 0xb304002a3c03ce62, 0xcbe7bfdf359dc095, 0x57398fea29abadad, 0x3ce46aec38657034, 0xabf0edb5e37f775e, 0x63ccffc5280e7697, 0x6754d90e93579656, 0xc9b558b380cc6f00 }, /* b */
  { 0xfffffffffffffdc7, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff }, /* p */
  { 0x000000000004f0b1, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }, /* r2 */
  { 0x94623cef47f023ed, 0xc8eda9e7a769a126, 0x4c33a9ff5147502c, 0xc98cdba46506ab00, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff }, /* q */
  { 0xe58fa18ee6ca4eb6, 0xe79280282d956fca, 0xd016086ec2d4f903, 0x542f8f3fa490666a, 0x04f77045db49adc9, 0x314e0a57f445b20e, 0x8910352f3bea2192, 0x394c72054d8503be }, /* r2q */
  {
    { 0xc5bc7928c1950148, 0xc6fb85487eae97aa, 0xa7b9033db9ed3610, 0xa27272a7ae602bf2, 0xd385f7074cea043a, 0x2295b7a9cbaef021, 0xebe241ce593ef5de, 0xe2e31edfc23de7bd }, /* px */
    { 0xd0396e9a9addc40f, 0x04f726aa854bae07, 0xef32d85822423b63, 0xe18e2d33e3021ed2, 0x8c108c3d2090ff9b, 0x7939804d6527378b, 0xabbccff5911cb857, 0xf5ce40d95b5eb899 }, /* py */
    { 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 }  /* pz */
  },
  0x58a1f7e6ce0f4c09LL, /* n */
  0x0ed9d8e0b6624e1bLL, /* nq */
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
 };

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                ak_parameters.c  */
/* ----------------------------------------------------------------------------------------------- */
