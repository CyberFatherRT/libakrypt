#! /bin/bash
# скрипт для проверки совместимости реализаций openssl и aktool
# в части выработки и проверки сертификатов открытых ключей
#
# указываем расположение утилиты aktool
export AKTOOL=aktool;
#
# указываем расположение файла конфигурации openssl
export SSLCONF=/etc/ssl/openssl.cnf;
#
# ------------------------------------------------------------------------------------------------- #
crt_exit() {
rm -f openssl256_request.csr openssl256.key openssl512_request.csr
rm -f aktool256_request.csr aktool256.key aktool512_request.csr
rm -f openssl512_ca.crt openssl512.key
rm -f aktool512.key aktool512_ca.crt
rm -f openssl256_certificate.crt aktool256_certificate.crt
rm -f openssl256_aktool_certificate.crt aktool256_aktool_certificate.crt
rm -f openssl512_ca.srl
exit
}
#
# ------------------------------------------------------------------------------------------------- #
echo "1. Проверяем наличие тестируемых программ"; echo;
# ------------------------------------------------------------------------------------------------- #
openssl engine gost -c -vvvv
if [[ $? -ne 0 ]]
then echo "openssl не найден"; exit;
fi
${AKTOOL} test --crypt
if [[ $? -ne 0 ]]
then echo "${AKTOOL} не найден"; exit;
fi
echo " ";
#
# ------------------------------------------------------------------------------------------------- #
echo; echo "2. Проверяем возможность создания и взаимной проверки запросов на сертификат"; echo;
# ------------------------------------------------------------------------------------------------- #
# создаем запрос на сертификат 256 бит
openssl req -newkey gost2012_256 -pkeyopt paramset:A -out openssl256_request.csr -keyout openssl256.key -passout pass:321azO -subj "/C=RU/ST=Somewhere/L=Lies/O=The Truth/OU=But Where?/CN=Openssl Team (256)"
if [[ $? -ne 0 ]]
then echo "openssl не может создать запрос на сертификат (256 бит)"; exit;
fi
#
# и мы пытаемся это прочесть и верифицировать
${AKTOOL} k -v openssl256_request.csr --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать запрос на сертификат (256 бит)"; exit;
fi
echo "запрос openssl256_request.csr верифицирован";
#
# создаем запрос на сертификат 512 бит
openssl req -newkey gost2012_512 -pkeyopt paramset:A -out openssl512_request.csr -keyout openssl512.key -passout pass:321azO -subj "/CN=Openssl Team (512)"
if [[ $? -ne 0 ]]
then echo "openssl не может создать запрос на сертификат (512 бит)"; exit;
fi
# и мы пытаемся это прочесть и верифицировать
${AKTOOL} k -v openssl512_request.csr --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать запрос на сертификат (512 бит)"; exit;
fi
echo "запрос openssl512_request.csr верифицирован";
echo;
#
# теперь сами создаем запрос на сертификат и проверяем его с помощью openssl
${AKTOOL} k -nt sign256 -o aktool256.key --outpass 321azO --op aktool256_request.csr --to pem --id "/ct=RU/st=Somewhere/lt=Lies/or=The Truth/ou=With Overall Gladness/ln=But Where?/em=email@somewhere.lies/cn=Aktool Team (256)"
#
openssl req -verify -in aktool256_request.csr -text -noout
if [[ $? -ne 0 ]]
then echo "openssl не может верифицировать aktool256_request.csr"; exit;
fi
echo "запрос aktool256_request.csr верифицирован";echo;
#
# создаем запрос на сертификат (512 бит) и проверяем его с помощью openssl
${AKTOOL} k -nt sign512 --curve ec512c -o aktool512.key --outpass 321azO --op aktool512_request.csr --to pem --id "Example"
#
openssl req -verify -in aktool512_request.csr -text -noout
if [[ $? -ne 0 ]]
then echo "openssl не может верифицировать aktool512_request.csr"; exit;
fi
echo "запрос aktool512_request.csr верифицирован";echo;
echo;
#
# завершая с запросами, верифицируем сами себя
${AKTOOL} k -v aktool256_request.csr --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать запрос на сертификат (256 бит)"; exit;
fi
echo "запрос aktool256_request.csr верифицирован"; echo;
#
${AKTOOL} k -v aktool512_request.csr --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать запрос на сертификат (512 бит)"; exit;
fi
echo "запрос aktool512_request.csr верифицирован"; echo;
#
# ------------------------------------------------------------------------------------------------- #
echo; echo "3. Проверяем возможность создания и взаимной проверки самоподписанных сертификатов"; echo;
# ------------------------------------------------------------------------------------------------- #
# сперва, создаем самоподписанный сертификат с помощью aktool
${AKTOOL} k -nt sign512 --curve ec512b -o aktool512.key --outpass 321azO --op aktool512_ca.crt --to certificate --id "/cn=Aktool Team CA (512)" --days 1 --ca --pathlen 77
if [[ $? -ne 0 ]]
then echo "aktool не может создать самоподписанный сертификат"; exit;
fi
# проверяем его через openssl
echo ""
openssl verify -CAfile aktool512_ca.crt aktool512_ca.crt
if [[ $? -ne 0 ]]
then echo "openssl не может верифицировать самоподписанный сертификат"; exit;
fi
echo "aktool512_ca.crt верифицирован";
# проверяем его самостоятельно
echo ""
${AKTOOL} k -v aktool512_ca.crt --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать самоподписанный сертификат"; exit;
fi
#
#
# создаем самоподписанный сертификат
# для openssl в файле конфигурации нужно указать, что keyUsage = keyCertSign
openssl req -x509 -newkey gost2012_512 -pkeyopt paramset:A -out openssl512_ca.crt -keyout openssl512.key -passout pass:321azO -subj "/C=RU/ST=Somewhere/L=Lies/O=The Truth/OU=But Where? Part II/CN=Openssl Team (512)"
if [[ $? -ne 0 ]]
then echo "openssl не может создать самоподписанный сертификат"; exit;
fi
# и мы пытаемся это прочесть и верифицировать
${AKTOOL} k -v openssl512_ca.crt --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать самоподписанный сертификат"; exit;
fi
echo "openssl512_ca.crt верифицирован";
#
#
# ------------------------------------------------------------------------------------------------- #
echo; echo "4. Проверяем процедуры подписания запросов на сертифкат секретным ключом эмитента"; echo;
# ------------------------------------------------------------------------------------------------- #
#
echo 012345 > openssl512_ca.srl
openssl x509 -req -days 730 -CA openssl512_ca.crt -passin pass:321azO -CAkey openssl512.key -extfile ${SSLCONF} -extensions usr_cert -in openssl256_request.csr -out openssl256_certificate.crt
if [[ $? -ne 0 ]]
then echo "openssl не может создать сертификат пользователя"; exit;
fi
openssl verify -CAfile openssl512_ca.crt openssl256_certificate.crt
if [[ $? -ne 0 ]]
then echo "openssl не может верифицировать сертификат пользователя"
fi
echo ""
${AKTOOL} k -v openssl256_certificate.crt --ca-cert openssl512_ca.crt --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат пользователя, возможно, нужно добавить \"keyUsage = keyCertSign\" в файл ${SSLCONF}"; exit;
fi
echo ""
openssl x509 -req -days 730 -CA openssl512_ca.crt -passin pass:321azO -CAkey openssl512.key -extfile ${SSLCONF} -extensions usr_cert -in aktool256_request.csr -out aktool256_certificate.crt
if [[ $? -ne 0 ]]
then echo "openssl не может создать сертификат пользователя"; exit;
fi
openssl verify -CAfile openssl512_ca.crt aktool256_certificate.crt
#
${AKTOOL} k -v aktool256_certificate.crt --ca-cert openssl512_ca.crt --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат пользователя, возможно, нужно добавить \"keyUsage = keyCertSign\" в файл ${SSLCONF}"; exit;
fi
echo ""
#
#
#
## теперь тестим генерацию сертификатов
##
## реализуем обратную процедуру - теперь aktool вырабатывает сертификаты
#
#
${AKTOOL} k -s openssl256_request.csr --ca-key aktool512.key --inpass 321azO --ca-cert aktool512_ca.crt --op openssl256_aktool_certificate.crt --to pem
#
openssl verify -CAfile aktool512_ca.crt openssl256_aktool_certificate.crt
#
#
${AKTOOL} k -v openssl256_aktool_certificate.crt --ca-cert aktool512_ca.crt
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат пользователя"; exit;
fi

echo ""
${AKTOOL} k -s aktool256_request.csr --ca-key aktool512.key --inpass 321azO --ca-cert aktool512_ca.crt --op aktool256_aktool_certificate.crt --to pem
#
openssl verify -CAfile aktool512_ca.crt aktool256_aktool_certificate.crt
${AKTOOL} k -v aktool256_aktool_certificate.crt --ca-cert aktool512_ca.crt
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат пользователя"; exit;
fi

# ------------------------------------------------------------------------------------------------- #
echo; echo "5. Очищаем за собой пространство"; echo;
# ------------------------------------------------------------------------------------------------- #
crt_exit;
