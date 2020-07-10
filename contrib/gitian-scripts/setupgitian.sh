#!/usr/bin/env bash
export LC_ALL=C
export VERSION=master
export SIGNER='Ghost'
./gitian-build.py --setup $SIGNER $VERSION
