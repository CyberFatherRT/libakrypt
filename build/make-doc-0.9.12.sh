#/bin/bash
mkdir -p /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/doc
cd /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/sphinx 
make html
cd html
tar -cjvf /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/doc/libakrypt-doc-0.9.12.tar.bz2 *
cd ..
make man
cp /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/sphinx/man/aktool.1 /home/godfather/personal/Chef/ChefDesktop/libakrypt/aktool 
cp /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/sphinx/man/aktool.1 /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/doc/aktool.1 
gzip --force /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/doc/aktool.1 
make latexpdf
cp /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/sphinx/latex/libakrypt.pdf /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/doc/libakrypt-doc-0.9.12.pdf
cp /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/sphinx/latex/libakrypt.pdf /home/godfather/personal/Chef/ChefDesktop/libakrypt/build/sphinx/html/api/akrypt-library.pdf
cd /home/godfather/personal/Chef/ChefDesktop/libakrypt/build
