# pipeclean.elf - the seal. Send it to port 9021 before closing the host app.
#
#   nc <ps5-ip> 9021 < pipeclean.elf
#
# A prebuilt pipeclean.elf ships next to this file, so building is optional. To
# rebuild you need ps5-payload-sdk (https://github.com/ps5-payload-dev/sdk), then
# point PS5_PAYLOAD_SDK at where you installed it:
#
#   PS5_PAYLOAD_SDK=~/opt/ps5-payload-sdk make
#
# Two things break without an absolute path or a correct LLVM_CONFIG. The SDK's
# prospero-llvm-config probes llvm-config-23 down to -15 and may pick a version
# whose lld is not installed, and LLVM_CONFIG is passed through readlink -f, which
# resolves a bare name against the current directory.

ifdef PS5_PAYLOAD_SDK
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
endif

PS5_HOST ?= ps5
PS5_PORT ?= 9021

CFLAGS += -Wall -O2

all: pipeclean.elf

pipeclean.elf: pipeclean.c
	$(CC) $(CFLAGS) -o $@ $<

send: pipeclean.elf
	@echo "sending to $(PS5_HOST):$(PS5_PORT)"
	nc $(PS5_HOST) $(PS5_PORT) < pipeclean.elf

clean:
	rm -f pipeclean.elf

.PHONY: all send clean
