#!/usr/bin/env bash
# Set DISTNAME, BRANCH and MAKEOPTS to the desired settings
export LC_ALL=C
DISTNAME=ghost-0.20.99.1
MAKEOPTS="-j31"
BRANCH='contd-testnet'
export SKIP_AUTO_DEPS=true
clear
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with sudo"
   exit 1
fi
if [[ $PWD != $HOME ]]; then
   echo "This script must be run from ~/"
   exit 1
fi
if [ ! -f ~/MacOSX10.14.sdk.tar.gz ]
then
        echo "Before executing script.sh transfer MacOSX10.14.sdk.tar.gz to ~/"
        exit 1
fi
export PATH_orig=$PATH

echo @@@
echo @@@"Installing Dependencies"
echo @@@
sudo dpkg --add-architecture i386
sudo apt-get install -y --force-yes libudev1:i386
apt install -y curl gcc-mingw-w64-i686 gcc-mingw-w64-base  imagemagick librsvg2-bin libudev-dev g++-mingw-w64-x86-64 nsis bc  binutils-arm-linux-gnueabihf g++-7-multilib gcc-7-multilib binutils-gold git pkg-config autoconf libtool automake bsdmainutils ca-certificates python g++ mingw-w64 g++-mingw-w64 nsis zip rename librsvg2-bin libtiff-tools cmake imagemagick libcap-dev libz-dev libbz2-dev python-dev python-setuptools fonts-tuffy
# sudo update-alternatives --config x86_64-w64-mingw32-g++
# sudo update-alternatives --config x86_64-w64-mingw32-gcc
sudo apt-get install g++-mingw-w64-i686
# sudo update-alternatives --config x86_64-w64-mingw32-g++
# sudo update-alternatives --config x86_64-w64-mingw32-gcc
cd ~/

# Removes any existing builds and starts clean WARNING
# rm -rf ~/sign-ghost ~/release-ghost

git clone git@github.com:ghost-coin/ghost-private.git ghost
cd ~/ghost
git checkout $BRANCH
git pull

echo @@@
echo @@@"Building linux 64 binaries"
echo @@@

mkdir -p ~/release-ghost
cd ~/ghost/depends
make HOST=x86_64-linux-gnu $MAKEOPTS
cd ~/ghost
export PATH=$PWD/depends/x86_64-linux-gnu/native/bin:$PATH
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-linux-gnu/share/config.site ./configure --prefix=/ --disable-ccache --disable-maintainer-mode --disable-dependency-tracking --enable-glibc-back-compat --enable-reduce-exports --disable-bench --disable-gui-tests CFLAGS="-O2 -g" CXXFLAGS="-O2 -g" LDFLAGS="-static-libstdc++"
make $MAKEOPTS 
make -C src check-security
make -C src check-symbols 
mkdir ~/linux64
make install DESTDIR=~/linux64/$DISTNAME
cd ~/linux64
find . -name "lib*.la" -delete
find . -name "lib*.a" -delete
rm -rf $DISTNAME/lib/pkgconfig
find ${DISTNAME}/bin -type f -executable -exec ../ghost/contrib/devtools/split-debug.sh {} {} {}.dbg \;
find ${DISTNAME}/lib -type f -exec ../ghost/contrib/devtools/split-debug.sh {} {} {}.dbg \;
find $DISTNAME/ -not -name "*.dbg" | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ~/release-ghost/$DISTNAME-x86_64-linux-gnu.tar.gz
cd ~/ghost
rm -rf ~/linux64
make clean
export PATH=$PATH_orig


echo @@@
echo @@@"Building general sourcecode"
echo @@@

cd ~/ghost
export PATH=$PWD/depends/x86_64-linux-gnu/native/bin:$PATH
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-linux-gnu/share/config.site ./configure --prefix=/
make dist
SOURCEDIST='echo ghost-*.tar.gz'
mkdir -p ~/ghost/temp
cd ~/ghost/temp
tar xf ../$SOURCEDIST
find ghost-* | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ../$SOURCEDIST
cd ~/ghost
mv $SOURCEDIST ~/release-ghost
rm -rf temp
make clean
export PATH=$PATH_orig


# echo @@@
# echo @@@"Building linux 32 binaries"
# echo @@@

# cd ~/
# mkdir -p ~/wrapped/extra_includes/i686-pc-linux-gnu
# ln -s /usr/include/x86_64-linux-gnu/asm ~/wrapped/extra_includes/i686-pc-linux-gnu/asm

# for prog in gcc g++; do
# rm -f ~/wrapped/${prog}
# cat << EOF > ~/wrapped/${prog}
# #!/usr/bin/env bash
# REAL="`which -a ${prog} | grep -v $PWD/wrapped/${prog} | head -1`"
# for var in "\$@"
# do
#   if [ "\$var" = "-m32" ]; then
#     export C_INCLUDE_PATH="$PWD/wrapped/extra_includes/i686-pc-linux-gnu"
#     export CPLUS_INCLUDE_PATH="$PWD/wrapped/extra_includes/i686-pc-linux-gnu"
#     break
#   fi
# done
# \$REAL \$@
# EOF
# chmod +x ~/wrapped/${prog}
# done

# export PATH=$PWD/wrapped:$PATH
# export HOST_ID_SALT="$PWD/wrapped/extra_includes/i386-linux-gnu"
# cd ~/ghost/depends
# make HOST=i686-pc-linux-gnu $MAKEOPTS
# unset HOST_ID_SALT
# cd ~/ghost
# export PATH=$PWD/depends/i686-pc-linux-gnu/native/bin:$PATH
# ./autogen.sh
# CONFIG_SITE=$PWD/depends/i686-pc-linux-gnu/share/config.site ./configure --prefix=/ --disable-ccache --disable-maintainer-mode --disable-dependency-tracking --enable-glibc-back-compat --enable-reduce-exports --disable-bench --disable-gui-tests CFLAGS="-O2 -g" CXXFLAGS="-O2 -g" LDFLAGS="-static-libstdc++"
# make $MAKEOPTS 
# make -C src check-security
# make -C src check-symbols 
# mkdir -p ~/linux32
# make install DESTDIR=~/linux32/$DISTNAME
# cd ~/linux32
# find . -name "lib*.la" -delete
# find . -name "lib*.a" -delete
# rm -rf $DISTNAME/lib/pkgconfig
# find ${DISTNAME}/bin -type f -executable -exec ../ghost/contrib/devtools/split-debug.sh {} {} {}.dbg \;
# find ${DISTNAME}/lib -type f -exec ../ghost/contrib/devtools/split-debug.sh {} {} {}.dbg \;
# find $DISTNAME/ -not -name "*.dbg" | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ~/release-ghost/$DISTNAME-i686-pc-linux-gnu.tar.gz
# cd ~/ghost
# rm -rf ~/linux32
# rm -rf ~/wrapped
# make clean
# export PATH=$PATH_orig


# echo @@@
# echo @@@ "Building linux ARM binaries"
# echo @@@

# cd ~/ghost/depends
# make HOST=arm-linux-gnueabihf $MAKEOPTS
# cd ~/ghost
# export PATH=$PWD/depends/arm-linux-gnueabihf/native/bin:$PATH
# ./autogen.sh
# CONFIG_SITE=$PWD/depends/arm-linux-gnueabihf/share/config.site ./configure --prefix=/ --disable-ccache --disable-maintainer-mode --disable-dependency-tracking --enable-glibc-back-compat --enable-reduce-exports --disable-bench --disable-gui-tests CFLAGS="-O2 -g" CXXFLAGS="-O2 -g" LDFLAGS="-static-libstdc++"
# make $MAKEOPTS 
# make -C src check-security
# mkdir -p ~/linuxARM
# make install DESTDIR=~/linuxARM/$DISTNAME
# cd ~/linuxARM
# find . -name "lib*.la" -delete
# find . -name "lib*.a" -delete
# rm -rf $DISTNAME/lib/pkgconfig
# find ${DISTNAME}/bin -type f -executable -exec ../ghost/contrib/devtools/split-debug.sh {} {} {}.dbg \;
# find ${DISTNAME}/lib -type f -exec ../ghost/contrib/devtools/split-debug.sh {} {} {}.dbg \;
# find $DISTNAME/ -not -name "*.dbg" | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ~/release-ghost/$DISTNAME-arm-linux-gnueabihf.tar.gz
# cd ~/ghost
# rm -rf ~/linuxARM
# make clean
# export PATH=$PATH_orig


# echo @@@
# echo @@@ "Building linux aarch64 binaries"
# echo @@@

# cd ~/ghost/depends
# make HOST=aarch64-linux-gnu $MAKEOPTS
# cd ~/ghost
# export PATH=$PWD/depends/aarch64-linux-gnu/native/bin:$PATH
# ./autogen.sh
# CONFIG_SITE=$PWD/depends/aarch64-linux-gnu/share/config.site ./configure --prefix=/ --disable-ccache --disable-maintainer-mode --disable-dependency-tracking --enable-glibc-back-compat --enable-reduce-exports --disable-bench --disable-gui-tests CFLAGS="-O2 -g" CXXFLAGS="-O2 -g" LDFLAGS="-static-libstdc++"
# make $MAKEOPTS 
# make -C src check-security
# mkdir -p ~/linuxaarch64
# make install DESTDIR=~/linuxaarch64/$DISTNAME
# cd ~/linuxaarch64
# find . -name "lib*.la" -delete
# find . -name "lib*.a" -delete
# rm -rf $DISTNAME/lib/pkgconfig
# find ${DISTNAME}/bin -type f -executable -exec ../ghost/contrib/devtools/split-debug.sh {} {} {}.dbg \;
# find ${DISTNAME}/lib -type f -exec ../ghost/contrib/devtools/split-debug.sh {} {} {}.dbg \;
# find $DISTNAME/ -not -name "*.dbg" | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ~/release-ghost/$DISTNAME-aarch64-linux-gnu.tar.gz
# cd ~/ghost
# rm -rf ~/linuxaarch64
# make clean
# export PATH=$PATH_orig


echo @@@
echo @@@ "Building windows 64 binaries"
echo @@@

update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix 
mkdir -p ~/release-ghost/unsigned/
mkdir -p ~/sign-ghost/win64
PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g') # strip out problematic Windows %PATH% imported var
cd ~/ghost/depends
make HOST=x86_64-w64-mingw32 $MAKEOPTS
cd ~/ghost
export PATH=$PWD/depends/x86_64-w64-mingw32/native/bin:$PATH
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/ --disable-ccache --disable-maintainer-mode --disable-dependency-tracking --enable-reduce-exports --disable-bench --disable-gui-tests CFLAGS="-O2 -g" CXXFLAGS="-O2 -g"
make $MAKEOPTS 
make -C src check-security
make deploy
rename 's/-setup\.exe$/-setup-unsigned.exe/' -- *setup*
cp -f ghost-*setup*.exe ~/release-ghost/unsigned/
mkdir -p ~/win64
make install DESTDIR=~/win64/$DISTNAME
cd ~/win64
mv ~/win64/$DISTNAME/bin/*.dll ~/win64/$DISTNAME/lib/
find . -name "lib*.la" -delete
find . -name "lib*.a" -delete
rm -rf $DISTNAME/lib/pkgconfig
find $DISTNAME/bin -type f -executable -exec x86_64-w64-mingw32-objcopy --only-keep-debug {} {}.dbg \; -exec x86_64-w64-mingw32-strip -s {} \; -exec x86_64-w64-mingw32-objcopy --add-gnu-debuglink={}.dbg {} \;
find ./$DISTNAME -not -name "*.dbg"  -type f | sort | zip -X@ ./$DISTNAME-x86_64-w64-mingw32.zip
mv ./$DISTNAME-x86_64-*.zip ~/release-ghost/$DISTNAME-win64.zip
cd ~/
rm -rf win64
cp -rf ghost/contrib/windeploy ~/sign-ghost/win64
cd ~/sign-ghost/win64/windeploy
mkdir -p unsigned
mv ~/ghost/ghost-*setup-unsigned.exe unsigned/
find . | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ~/sign-ghost/$DISTNAME-win64-unsigned.tar.gz
cd ~/sign-ghost
rm -rf win64
cd ~/ghost
rm -rf release-ghost
make clean
export PATH=$PATH_orig


# echo @@@
# echo @@@ "Building windows 32 binaries"
# echo @@@

# update-alternatives --set i686-w64-mingw32-g++ /usr/bin/i686-w64-mingw32-g++-posix 
# mkdir -p ~/sign-ghost/win32
# PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g') 
# cd ~/ghost/depends
# make HOST=i686-w64-mingw32 $MAKEOPTS
# cd ~/ghost
# export PATH=$PWD/depends/i686-w64-mingw32/native/bin:$PATH
# ./autogen.sh
# CONFIG_SITE=$PWD/depends/i686-w64-mingw32/share/config.site ./configure --prefix=/ --disable-ccache --disable-maintainer-mode --disable-dependency-tracking --enable-reduce-exports --disable-bench --disable-gui-tests CFLAGS="-O2 -g" CXXFLAGS="-O2 -g"
# make $MAKEOPTS 
# make -C src check-security
# make deploy
# rename 's/-setup\.exe$/-setup-unsigned.exe/' *setup.exe
# cp -f ghost-*setup*.exe ~/release-ghost/unsigned/
# mkdir -p ~/win32
# make install DESTDIR=~/win32/$DISTNAME
# cd ~/win32
# mv ~/win32/$DISTNAME/bin/*.dll ~/win32/$DISTNAME/lib/
# find . -name "lib*.la" -delete
# find . -name "lib*.a" -delete
# rm -rf $DISTNAME/lib/pkgconfig
# find $DISTNAME/bin -type f -executable -exec i686-w64-mingw32-objcopy --only-keep-debug {} {}.dbg \; -exec i686-w64-mingw32-strip -s {} \; -exec i686-w64-mingw32-objcopy --add-gnu-debuglink={}.dbg {} \;
# find ./$DISTNAME -not -name "*.dbg"  -type f | sort | zip -X@ ./$DISTNAME-i686-w64-mingw32.zip
# mv ./$DISTNAME-i686-w64-*.zip ~/release-ghost/$DISTNAME-win32.zip
# cd ~/
# rm -rf win32
# cp -rf ghost/contrib/windeploy ~/sign-ghost/win32
# cd ~/sign-ghost/win32/windeploy
# mkdir -p unsigned
# mv ~/ghost/ghost-*setup-unsigned.exe unsigned/
# find . | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ~/sign-ghost/$DISTNAME-win32-unsigned.tar.gz
# cd ~/sign-ghost
# rm -rf win32
# cd ~/ghost
# rm -rf release-ghost
# make clean
# export PATH=$PATH_orig


echo @@@
echo @@@ "Building OSX binaries"
echo @@@

mkdir -p ~/ghost/depends/SDKs
cp ~/MacOSX10.14.sdk.tar.gz ~/ghost/depends/SDKs/MacOSX10.14.sdk.tar.gz
cd ~/ghost/depends/SDKs && tar -xf MacOSX10.14.sdk.tar.gz 
rm -rf MacOSX10.14.sdk.tar.gz 
cd ~/ghost/depends
make $MAKEOPTS HOST="x86_64-apple-darwin14"
cd ~/ghost
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-apple-darwin14/share/config.site ./configure --prefix=/ --disable-ccache --disable-maintainer-mode --disable-dependency-tracking --enable-reduce-exports --disable-bench --disable-gui-tests GENISOIMAGE=$PWD/depends/x86_64-apple-darwin14/native/bin/genisoimage
make $MAKEOPTS 
mkdir -p ~/OSX
export PATH=$PWD/depends/x86_64-apple-darwin14/native/bin:$PATH
make install-strip DESTDIR=~/OSX/$DISTNAME
make osx_volname
make deploydir
mkdir -p unsigned-app-$DISTNAME
cp osx_volname unsigned-app-$DISTNAME/
cp contrib/macdeploy/detached-sig-apply.sh unsigned-app-$DISTNAME
cp contrib/macdeploy/detached-sig-create.sh unsigned-app-$DISTNAME
cp $PWD/depends/x86_64-apple-darwin14/native/bin/dmg $PWD/depends/x86_64-apple-darwin14/native/bin/genisoimage unsigned-app-$DISTNAME
cp $PWD/depends/x86_64-apple-darwin14/native/bin/x86_64-apple-darwin14-codesign_allocate unsigned-app-$DISTNAME/codesign_allocate
cp $PWD/depends/x86_64-apple-darwin14/native/bin/x86_64-apple-darwin14-pagestuff unsigned-app-$DISTNAME/pagestuff
mv dist unsigned-app-$DISTNAME
cd unsigned-app-$DISTNAME
find . | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ~/sign-ghost/$DISTNAME-osx-unsigned.tar.gz
cd ~/ghost
make deploy -j32
$PWD/depends/x86_64-apple-darwin14/native/bin/dmg dmg "Ghost-Core.dmg" ~/release-ghost/unsigned/$DISTNAME-osx-unsigned.dmg
rm -rf unsigned-app-$DISTNAME dist osx_volname dpi36.background.tiff dpi72.background.tiff
cd ~/OSX
find . -name "lib*.la" -delete
find . -name "lib*.a" -delete
rm -rf $DISTNAME/lib/pkgconfig
find $DISTNAME | sort | tar --no-recursion --mode='u+rw,go+r-w,a+X' --owner=0 --group=0 -c -T - | gzip -9n > ~/release-ghost/$DISTNAME-osx64.tar.gz
cd ~/ghost
rm -rf ~/OSX
make clean
export PATH=$PATH_orig
