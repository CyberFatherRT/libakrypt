#!/bin/bash
# Testing a Blom key generation scheme
export AKTOOL=aktool
#
#
${AKTOOL} test --crypt
if [[ $? -ne 0 ]]
then echo "executable file ${AKTOOL} not found"; exit;
fi
echo " ";
#
# 1. Master key generation
${AKTOOL} k -na blom-master --size 512 --field 512 -o master.key --outpass-hex ab0421ae --verbose
#
# 2. Personal key for user A generation
${AKTOOL} k -na blom-user --key master.key --id User_A --inpass-hex ab0421ae --outpass-hex 001324ac -o user_a.key --verbose
#
# 3. Personal key for user B generation
${AKTOOL} k -na blom-user --key master.key --id User_B --inpass-hex ab0421ae --outpass-hex 001324ac -o user_b.key --verbose
#
# 4. Pairwise keys generation
${AKTOOL} k -na blom-pairwise --key user_a.key --inpass-hex 001324ac --id User_B --target undefined -o pairwise_ab.key --verbose
${AKTOOL} k -na blom-pairwise --key user_b.key --inpass-hex 001324ac --id User_A --target undefined -o pairwise_ba.key --verbose
#
# 5. Pairwise keys (as magma block cipher) generation
${AKTOOL} k -na blom-pairwise --key user_a.key --inpass-hex 001324ac --id User_B --target magma -o magma_ab.key --to pem --outpass qt5z@a --verbose
${AKTOOL} k -na blom-pairwise --key user_b.key --inpass-hex 001324ac --id User_A --target magma -o magma_ba.key --to pem --outpass 1324%1 --verbose
#
# 6. Listening
echo " ";
ls -la master.key user_a.key user_b.key pairwise_ab.key pairwise_ba.key magma_ab.key magma_ba.key
#
echo " ";
diff -s pairwise_ab.key pairwise_ba.key
#
echo " ";
cat magma_ab.key
cat magma_ba.key
#
# 7. Removing
rm master.key user_a.key user_b.key pairwise_ab.key pairwise_ba.key magma_ab.key magma_ba.key
