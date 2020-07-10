#!/usr/bin/env bash
export LC_ALL=C
export VERSION=master
export SIGNER='Ghost'
export LXC_BRIDGE=lxcbr0
./gitian-build.py -c --build --no-commit -j 32 -m 40000 $SIGNER $VERSION
