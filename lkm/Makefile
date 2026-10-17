obj-m += vrkiller.o

CFLAGS_vrkiller.o := -Os -fno-asynchronous-unwind-tables -fno-unwind-tables

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) \
		ARCH=arm64 \
		LLVM=1 \
		modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) \
		ARCH=arm64 \
		LLVM=1 \
		clean
	rm -f vrkiller.lds

.PHONY: all clean
