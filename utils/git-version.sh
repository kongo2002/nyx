#!/bin/sh

if [ -d .git -a -r .git ]; then
    GIT_VERSION=$(git describe --always 2>/dev/null)

    if [ x"$GIT_VERSION" != x ]; then
        echo "-DGIT_VERSION=\\\"$GIT_VERSION\\\""
    fi
fi
