obj-m = xt_dpi.o
#KVERSION = $(shell uname -r)
KVERSION=2.6.32.60

IPTABLES_SRC = /root/iptables/

IPTABLES_INCLUDE = -I$(IPTABLES_SRC)/include
IPTABLES_VERSION = $(shell cat $(IPTABLES_SRC)/Makefile | grep -e '^IPTABLES_VERSION:=' | cut -d"=" -f2)
IPTABLES_OPTION = -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\"
	
all: xt_dpi.ko libipt_DPI.so

xt_dpi.ko:
	make -C /lib/modules/$(KVERSION)/build/ M=$(PWD) modules 

libipt_DPI.so: libipt_DPI.c
	$(CC) $(CFLAGS) $(IPTABLES_OPTION) $(IPTABLES_INCLUDE) -fPIC -c libipt_DPI.c
	ld -shared -o libipt_DPI.so libipt_DPI.o

clean:	
	make -C /lib/modules/$(KVERSION)/build/ M=$(PWD) clean
	rm *.o *.so

