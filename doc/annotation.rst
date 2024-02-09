Аннотация
=========

Цель разработки библиотеки заключается в создании СКЗИ с
открытым исходным кодом, удовлетворяющего рекомендациям по стандартизации Р 1323565.1.012-2017
«`Принципы разработки и модернизации шифровальных (криптографических) средств защиты
информации <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-012-2017-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-printsipy-razrabotki-i-modernizatsii-shifrovalnykh-kriptograficheskikh-sredstv-zashchity-informatsii.html>`__» по классу КС3.


В библиотеке реализованы следующие криптографические преобразования.

 1. Бесключевые функции хеширования «Стрибог-256» и «Стрибог-512»,
    регламентируемые стандартом `ГОСТ Р 34.11-2012 <https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-11-2012-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-funktsiya-kheshirovaniya.html>`__.

 2. Алгоритмы блочного шифрования данных «Магма» и «Кузнечик»,
    регламентируемые стандартом `ГОСТ Р 34.12-2015 <https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-12-2015-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-blochnye-shifry.html>`__.

 3. Процедуры зашифрования/расшифрования данных c помощью алгоритмов блочного шифрования
    в следующих режимах (согласно `ГОСТ Р 34.13-2015 <https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-13-2015-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-rezhimy-raboty-blochnykh-shifrov.html>`__):

    * режим простой замены (`ECB`, `electronic codebook mode`),
    * режим гаммирования (`CTR`, `counter mode`),
    * режим гаммирования с обратной связью по выходу (`OFB`, `output feedback mode`),
    * режим простой замены с зацеплением (`CBC`, `cipher block chaining mode`),
    * режим гаммирования с обратной связью по шифртексту (`CFB`, `cipher feedback mode`),

 4. Дополнительные режимы работы блочных шифров:

    * режим `ACPKM`, регламентируемый рекомендациями по стандартизации `Р 1323565.1.017-2018 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-017-2018-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-kriptograficheskie-algoritmy-soputstvuyushchie-primeneniyu-algoritmov-blochnogo-shifrovaniya.html>`__,
    * режим `XTS`, регламентируемый стандартом `IEEE 1619-2007 <https://standards.ieee.org/standard/1619-2007.html>`__.

 5. Алгоритмы выработки имитовставки (кода аутентичности сообщения):

    * алгоритм `HMAC`, регламентированный рекомендациями `Р 50.1.113-2016 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-50-1-113-2016-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-kriptograficheskie-algoritmy-soputstvuyushchie-primeneniyu-algoritmov-elektronnoy-tsifrovoy-podpisi-i-funktsii-kheshirovaniya.html>`__;
    * алгоритм `NMAC`, регламентированный рекомендациями `Р 1323565.1.022-2018 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-022-2018-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-funktsii-vyrabotki-proizvodnogo-klyucha-.html>`__;
    * алгоритм `CMAC` (`OMAC1`), регламентированный стандартом `ГОСТ Р 34.13-2015 <https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-13-2015-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-rezhimy-raboty-blochnykh-shifrov.html>`__.

 6. Режимы работы блочных шифров, реализующие аутентифицированное шифрование, т.е. шифрование с одновременным вычислением имитовставки:

    * режим `MGM (Multilinear Galois Mode)`, регламентируемый рекомендациями по стандартизации `Р 1323565.1.026-2019 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-026-2019-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-rezhimy-raboty-blochnykh-shifrov-realizuyushchie-autentifitsirovannoe-shifrovanie.html>`__.

 7. Программные и биологические генераторы псевдо-случайных чисел:

    * линейный конгруэнтный генератор (используется для генерации уникальных номеров ключей),
    * генератор-интерфейс, использующий чтение из произвольных файлов, в частности, файловых устройств `/dev/random` и `/dev/urandom`,
    * генератор-интерфейс к системному генератору псевдо-случайных значений, реализованному в ОС `Windows`,
    * нелинейный конгруэнтый генератор с обратной квадратичной связью,
    * генератор, использующий функцию хеширования «Стрибог-512», в соответствии с алгоритмом, описанным 
      в рекомендациях по стандартизации `Р 1323565.1.006-2017 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-006-2017-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-mekhanizmy-vyrabotki-psevdosluchaynykh-posledovatelnostey.html>`__.

 8. Алгоритм развертки ключа из пароля `PBKDF2`, регламентированный рекомендациями по стандартизации `Р 50.1.111-2016 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-50-1-111-2016-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-parolnaya-zashchita-klyuchevoy-informatsii.html>`__.

 9. Процедуры выработки производной ключевой информации:

    * алгоритм `KDF_GOSTR3411_2012_256`, регламентированный в рекомендациях по стандартизации `Р 50.1.113-2016 <https://tc26.ru/standard/rs/%D0%A0%2050.1.113-2016.pdf>`__, раздел 4.4,
    * полное множество однотипных алгоритмов,
      регламентированных в рекомендациях по стандартизации `Р 1323565.1.022-2018 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-022-2018-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-funktsii-vyrabotki-proizvodnogo-klyucha-.html>`__, раздел 5.

 10. Алгоритмы, реализующие элементарные арифметические операции в конечных простых полях фиксированной размерности 256 и 512 бит
     с помощью преобразования Монтгомери.
     Алгоритмы, реализующие арифметические операции в
     полях :math:`\mathbb F_{2^{64}}, \mathbb F_{2^{128}}, \mathbb F_{2^{256}}, \mathbb F_{2^{512}}` характеристики 2.

 11. Алгоритмы, реализующие операцию вычисления кратной точки на эллиптических кривых, удовлетворяющих требованиям стандарта `ГОСТ Р 34.10-2012 <https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-10-2012-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-protsessy-formirovaniya-i-proverki-elektronnoy-tsifrovoy-podpisi.html>`__. Реализована поддержка всех отечественных параметров эллиптических кривых, регламентированных рекомендациями по стандартизации `Р 1323565.1.024–2019 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-132356-1-024-2019-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-parametry-ellipticheskikh-krivykh-dlya-kriptograficheskikh-algoritmov-i-protokolov19.html>`__, а также ряд нестандартизированных кривых.

 12. Процедуры выработки и проверки электронной подписи, регламентированные стандартом на электронную подпись `ГОСТ Р 34.10-2012 <https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-10-2012-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-protsessy-formirovaniya-i-proverki-elektronnoy-tsifrovoy-podpisi.html>`__. Используется формат подписи, определяемый рекомендациями по стандартизации `Р 1323565.1.023-2018 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-023-2018-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-ispolzovanie-algoritmov-gost-r-34-10-2012-gost-r-34-11-2012-v-sertifikate-spiske-annulirovannykh-sertifikatov-crl-i-zaprose-na-sertifikat-pkcs-10-infrastruktury-o.html>`__.

 13. Процедуры низкого уровня для кодирования и декодирования данных в формате ASN.1
     с поддержкой DER и PEM кодировок, в частности,
     реализовано преобразование двоичных данных в base64 и обратно согласно `RFC 4648 <https://www.rfc-editor.org/rfc/rfc4648>`__.

 14. Алгоритмы генерации запросов на сертификат открытого ключа, а также алгоритмы генерации
     сертификатов открытых ключей в формате рекомендаций `ITU X.509 <https://www.itu.int/rec/T-REC-X.509/en>`__ с поддержкой дополнительных указаний, содержащихся в рекомендациях по стандартизации `Р 1323565.1.023-2018 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-023-2018-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-ispolzovanie-algoritmov-gost-r-34-10-2012-gost-r-34-11-2012-v-sertifikate-spiske-annulirovannykh-sertifikatov-crl-i-zaprose-na-sertifikat-pkcs-10-infrastruktury-o.html>`__.

 15. Схема Блома для распределения ключевой информации и выработки ключей парной связи (общих симметричных ключей)
     в соответствии с рекомендациями по стандартизации `Р 1323565.1.028-2019 <https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-028-2019-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-kriptograficheskie-mekhanizmy-zashchishchennogo-vzaimodeystviya-kontrolnykh-i-izmeritelnykh-ustroystv.html>`__.


Вместе с библиотекой собирается и инсталлируется консольная утилита `aktool <aktool.html>`__,
предоставляющая пользователю возможности по управлению криптографическими ключами и их сертификатами,
шифрованию и имитозащите данных, а также вычислению и проверке электронной подписи.


Поддерживается работа библиотеки на следующих аппаратных платформах:

   * `x86`, `x64`,

   * `arm32v7`, `arm32v7eb`,

   * `mips32` и `mips64`.


Поддерживается работа библиотеки в следующих операционных системах:

   * семейство операционных систем `Linux`,

   * `FreeBSD`,

   * семейство `Windows` (от `Windows 7` и старше).


Также были проведены успешные запуски библиотеки под управлением следующих операционных систем: `ReactOS <https://reactos.org/>`__,
`SailfishOS <https://sailfishos.org/>`__, а также `PetaLinux <https://www.xilinx.com/products/design-tools/embedded-software/petalinux-sdk.html>`__.

Поддерживается сборка библиотеки при помощи следующих компиляторов:

   * `gcc` (в частности `mingw` под Windows),

   * `clang`,

   * `Microsoft Visual Studio` (начиная с версии `MSVC10`),

   * `TinyCC`,

   * `Intel C Compiler`.

