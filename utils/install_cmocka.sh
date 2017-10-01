#!/bin/bash -e

wget --no-check-certificate https://cmocka.org/files/1.1/cmocka-1.1.1.tar.xz
tar xf cmocka-1.1.1.tar.xz
cd cmocka-1.1.1
mkdir -p build
cd build
cmake ..
make cmocka_shared

cd ../..
rm -f cmocka-1.1.1.tar.xz
