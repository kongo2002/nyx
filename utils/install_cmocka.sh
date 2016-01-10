#!/bin/bash -e

wget https://cmocka.org/files/1.0/cmocka-1.0.0.tar.xz
tar xf cmocka-1.0.0.tar.xz
cd cmocka-1.0.0
mkdir build
cd build
cmake ..
make cmocka_shared

cd ../..
rm -f cmocka-1.0.0.tar.xz
