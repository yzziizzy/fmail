#!/bin/bash

gcc _build.c -lutil -o ._build -ggdb \
	&& ./._build \
	&& gdb -x ~/.gdbinit -ex=r --args ./fmail $@
