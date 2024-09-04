#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
SYSROOT=$(aarch64-none-linux-gnu-gcc -print-sysroot)
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
IMAGE_FILE=${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image
if [ ! -e ${IMAGE_FILE} ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # Kernel build steps
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- mrproper
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- defconfig
    make -j4 ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- all
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- modules
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- dtbs

fi

echo "Adding the Image in outdir"
if [ -e ${IMAGE_FILE} ]; then
    cp ${IMAGE_FILE} ${OUTDIR}/Image
else
    echo "Image was not generated. Exiting"
    exit 1
fi

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# Create necessary base directories
mkdir rootfs
cd rootfs
mkdir bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib /usr/sbin
mkdir -p var/log


cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    
    echo "Configure busybox"
    make distclean
    make defconfig    
else
    cd busybox
fi

echo "Make and install busybox"
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Library dependencies"
${CROSS_COMPILE}readelf -a busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a busybox | grep "Shared library"


echo "Add library dependencies to rootfs"
cp -v ${SYSROOT}/lib/ld-linux-aarch64.so.1 ${OUTDIR}/rootfs/lib/ld-linux-aarch64.so.1
cp -v ${SYSROOT}/lib64/libm.so.6 ${OUTDIR}/rootfs/lib64/libm.so.6
cp -v ${SYSROOT}/lib64/libresolv.so.2 ${OUTDIR}/rootfs/lib64/libresolv.so.2
cp -v ${SYSROOT}/lib64/libc.so.6 ${OUTDIR}/rootfs/lib64/libc.so.6

echo "Make device nodes"
cd ${OUTDIR}/rootfs
sudo mknod -m 666 dev/null c 1 3 
sudo mknod -m 600 dev/console c 5 1

echo "Clean and build the writer utility"
cd ${FINDER_APP_DIR}
pwd
make clean
make CROSS_COMPILE=${CROSS_COMPILE}

echo "Copy the finder related scripts and executables to the /home directory on the target rootfs"
cp -rvt ${OUTDIR}/rootfs/home writer writer.sh finder.sh finder-test.sh autorun-qemu.sh
mkdir -p ${OUTDIR}/rootfs/home/conf
cp -rvt ${OUTDIR}/rootfs/home/conf conf/username.txt conf/assignment.txt

echo "Chown the root directory"
cd ${OUTDIR}/rootfs
sudo chown -R root:root *

echo "Create initramfs.cpio.gz"
cd ${OUTDIR}/rootfs
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
cd ${OUTDIR}
gzip -f initramfs.cpio

