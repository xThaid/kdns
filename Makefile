KERNELDIR = /lib/modules/$(shell uname -r)/build

obj-m += kdns.o
kdns-objs := proto.o dns.o main.o

ccflags-y := -std=gnu99

all: module

module:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
