#!/bin/bash -e

wget https://cmocka.org/files/1.0/cmocka-1.0.0.tar.xz
tar xf cmocka-1.0.0.tar.xz
cd cmocka-1.0.0
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make

if which sudo >/dev/null 2>&1; then
    sudo make install
else
    make install
fi

cd ../..
rm -rf cmocka-1.0.0 cmocka-1.0.0.tar.xz
