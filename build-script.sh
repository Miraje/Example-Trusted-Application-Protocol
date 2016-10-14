#!/bin/bash
# To get this to work, you should have things setup according to the repo setup
# described on optee_os GitHub pages.

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

export HOST_CROSS_COMPILE=$DIR/..//toolchains/aarch64/bin/aarch64-linux-gnu-
export TA_CROSS_COMPILE=$DIR/..//toolchains/aarch32/bin/arm-linux-gnueabihf-
export TEEC_EXPORT=$DIR/..//optee_client/out/export
export TA_DEV_KIT_DIR=$DIR/..//optee_os/out/arm/export-ta_arm32

export PLATFORM=vexpress
export PLATFORM_FLAVOR=juno

if [ "$1" = "clean" ]; then
	make clean
elif [ "$1" = "all" ]; then
	make clean
	make
else
	make
fi
