#!/usr/bin/env bash
export LC_ALL=C
export VERSION=0.19.1.2
export SIGNER='Ghost'
export LXC_BRIDGE=lxcbr0
./gitian-build.py --build --no-commit -j 32 -m 40000 $SIGNER $VERSION
