# -------------------------------------------------------------------------------------
# /bin/bash
#
# Пример иллюстрирует процесс создания ключевой системы и последующего шифрования
# данных с использованием асимметричного алгоритма шифрования
# -------------------------------------------------------------------------------------
#
# 1. Создаем ключи центра сертификации
aktool k -nt sign512 --curve ec512b --ca -o ca.key --outpass z12Ajq --op ca.crt --to certificate --id "Root CA" --days 1
#
# 2. Создаем ключевую пару для получателя сообщений
aktool k -nt sign256 -o user.key --outpass 1Qlm21u --op user_request.csr --to pem --id "Local User"
aktool k -v user_request.csr
aktool k --show user.key
#
# 3. Вырабатываем сертификат пользователя 
#    (с добавлением расширения, содержащего номер секретного ключа)
aktool k --sign user_request.csr --key-encipherment --secret-key-number `aktool k --show-number user.key` --ca-key ca.key --inpass z12Ajq --ca-cert ca.crt --op user.crt --to pem
aktool k -v user.crt --ca-cert ca.crt --verbose
#
# 4. Вырабатываем данные для тестирования
dd if=/dev/zero of=file bs=1M count=72
aktool i file -o results.streebog

# выводим информацию об исходном файле
echo; echo "Значение хешкода для исходного (не зашифрованного) файла"
cat results.streebog

# -------------------------------------------------------------------------------------
# Первый эксперимент, используется пароль для шифрования контейнера,
# разбиение на случайные фрагменты,
# алгоритм шифрования Кузнечик в режиме MGM (по-умолчанию)
# -------------------------------------------------------------------------------------
echo; echo "Эксперимент N1. Простое шифрование с помощью режима mgm-kuznechik (по-умолчанию)"
cp file file.old
aktool e file --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file01.bin --delete-source -m mgm-kuznechik
#
# выводим информацию о зашифрованном файле
echo; echo "Значение хешкода для зашифрованного файла"
aktool i file01.bin
ls -la file01.bin

#
# Расшифрование исходных данных
aktool d file01.bin --inpass jQa6 --key user.key --keypass 1Qlm21u --delete-source
aktool i -c results.streebog --dont-show-stat

#
# -------------------------------------------------------------------------------------
# Второй эксперимент, используется предварительное сжатие данных,
# заранее созданный ключ для шифрования контейнера,
# алгоритм шифрования Магма в режиме MGM
# -------------------------------------------------------------------------------------
echo; echo "Создаем ключ для шифрования контейнера"
aktool k -nt hmac-streebog512 -o psk.512 --outpass mag13s
#
echo; echo "Экперимент N2. Шифрование с использованием ключа контейнера и предварительным сжатием (mgm-magma)"
aktool e file -m mgm-magma --bz2 --ck psk.512 --ckpass mag13s --cert user.crt --ca-cert ca.crt --delete-source -o file02.bin
# выводим информацию о зашифрованном файле
echo; echo "Значение хешкода для зашифрованного файла"
aktool i file02.bin
ls -la file02.bin
#
echo; echo "Расшифрование."
aktool d file02.bin --ck psk.512 --ckpass mag13s --key user.key --keypass 1Qlm21u --delete-source
aktool i -c results.streebog --dont-show-stat
#
# -------------------------------------------------------------------------------------
# Третий эксперимент, тестирующий различные алгоритмы шифрования
# -------------------------------------------------------------------------------------
echo; echo "Эксперимент N3. Многократное шифрование в следующих режимах:"
aktool s --oid aead | grep aead
#
echo;echo "Зашифрование."
aktool e file -m ctr-cmac-kuznechik --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file01.enc --delete-source
aktool e file01.enc -m ctr-cmac-magma --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file02.enc --delete-source
aktool e file02.enc -m mgm-magma --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file03.enc --delete-source
aktool e file03.enc -m mgm-kuznechik --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file04.enc --delete-source
aktool e file04.enc -m ctr-hmac-magma-streebog256 --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file05.enc --delete-source
aktool e file05.enc -m ctr-hmac-kuznechik-streebog256 --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file06.enc --delete-source
aktool e file06.enc -m ctr-hmac-magma-streebog512 --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file07.enc --delete-source
aktool e file07.enc -m ctr-hmac-kuznechik-streebog512 --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file08.enc --delete-source
aktool e file08.enc -m ctr-nmac-magma --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file09.enc --delete-source
aktool e file09.enc -m ctr-nmac-kuznechik --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file10.enc --delete-source

# режимы семейства xtsmac выдают ошибку
# aktool e file10.enc -m xtsmac-magma --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file11.enc --audit 2 --audit-file stderr
# aktool e file11.enc -m xtsmac-kuznechik --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file12.enc --delete-source
#
echo; echo "Процесс зашифрования завершен."
aktool i file10.enc
ls -la *.enc

#
# Поскольку мы знаем имена файлов, которые будут расшифрованы,
# то указываем их в командной строке, несмотря на то, что они пока еще не существуют
# опция --delete-source удаляет файлы сразу после их расшифрования
echo; echo "Расшифрование."
aktool d file10.enc file09.enc file08.enc file07.enc file06.enc file05.enc file04.enc file03.enc file02.enc file01.enc --inpass jQa6 --key user.key --keypass 1Qlm21u --delete-source
aktool i file
ls -la file
#
# Проверка контрольной суммы расшифрованого файла
aktool i -c results.streebog --dont-show-stat
echo " ";
diff -s file file.old
#
# -------------------------------------------------------------------------------------
#  В завершение экспериментов, удаляем созданные временные файлы
# -------------------------------------------------------------------------------------
rm -f ca.key ca.crt user_request.csr user.key user.crt psk.512 file file.old results.streebog
