export VERSION=0.19.1.6
export SIGNER='akshaynexus'
export LXC_BRIDGE=lxcbr0
./gitian-build.py --build --no-commit -j 32 -m 64000 $SIGNER $VERSION
