##########################################################################
#! /bin/bash
# проверка способов выработки и проверки контрольных сумм и имитовставок
#
export AKTOOL=aktool
#
# может использоваться, например, так
# export AKTOOL="qemu-mips64 -L /usr/mips64-linux-gnuabi64/ ./aktool"
##########################################################################
#
run() {
${AKTOOL} $1
if [[ $? -ne 0 ]]
then echo "${AKTOOL} не может выполнить $1"; exit;
fi
}
#
echo "Тестируем функции хэширования"
run "i * --tag -o result.streebog256"
echo "Ok (Стрибог256)";
cat result.streebog256
run "i -c result.streebog256 --ignore-errors"
#
run "i -a streebog512 -p "*.s?" . -o result.streebog512"
echo "Ok (Стрибог512)";
cat result.streebog512
run "i -c result.streebog512 -a streebog512 --ignore-errors"
#
#
echo; echo "Тестируем алгоритмы hmac"
run "k -nt hmac-streebog256 -o hmac256.key --outpass 132a"
echo;
run "i --key hmac256.key --inpass 132a --tag . -o result.hmac-streebog256"
cat result.hmac-streebog256
run "i -c result.hmac-streebog256 --key hmac256.key --inpass 132a"
echo;
#
#
run "k -nt hmac-streebog512 -o hmac512.key --outpass 132a"
echo;
run "i --key hmac512.key --inpass 132a * -o result.hmac-streebog512"
cat result.hmac-streebog512
run "i -c result.hmac-streebog512 --key hmac512.key --inpass 132a"
echo;
#
#
echo; echo "Тестируем алгоритмы выработки имитовставки с использованием шифра Магма"
run "k -nt magma -o magma.key --outpass 123"
run "i --key magma.key -m cmac-magma --inpass 123 * -o result.magma"
echo
cat result.magma
run "i -c result.magma --key magma.key -m cmac-magma --inpass 123"
echo
#
#
echo; echo "Тестируем алгоритмы выработки имитовставки с использованием шифра Кузнечик"
run "k -nt kuznechik -o kuznechik.key --outpass 123"
run "i --key kuznechik.key -m cmac-kuznechik --inpass 123 --tag * -o result.kuznechik"
echo
cat result.kuznechik
run "i -c result.kuznechik --key kuznechik.key -m cmac-kuznechik --inpass 123 --dont-show-stat"
#
#
rm -f magma.key kuznechik.key hmac256.key hmac512.key
rm -f result.*
echo "Тест пройден"
