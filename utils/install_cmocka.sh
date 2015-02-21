#!/bin/sh

wget https://cmocka.org/files/1.0/cmocka-1.0.0.tar.xz
tar xf cmocka-1.0.0.tar.xz
cd cmocka-1.0.0
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make
sudo make install
cd ../..
rm -rf cmocka-1.0.0
