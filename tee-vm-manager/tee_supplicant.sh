#!/bin/bash
export PATH=$(dirname $0)/bin
export LD_LIBRARY_PATH=$PATH

tee-supplicant $PATH/tee.elf

