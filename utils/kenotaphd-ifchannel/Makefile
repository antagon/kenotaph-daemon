#
# Copyright (c) 2016, CodeWard.org
#

CFLAGS = -std=gnu99 -O2 -pedantic -Wall -ggdb -I../../src/

TARGET = kenotaphd-ifchannel
INSTALL_DIR = /usr/local/sbin
KENOTAPHD_SRCDIR = ../../src

.PHONY: clean install

all: $(TARGET)

install:
	install --mode 755 $(TARGET) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

clean:
	rm -f *.o $(TARGET)

$(TARGET): main.o config.o pathname.o
	$(CC) $(CFLAGS) $^ -o $(TARGET) -lconfuse

main.o: main.c
	$(CC) $(CFLAGS) -c $<

config.o: $(KENOTAPHD_SRCDIR)/config.c $(KENOTAPHD_SRCDIR)/config.h
	$(CC) $(CFLAGS) -c $<

pathname.o: $(KENOTAPHD_SRCDIR)/pathname.c $(KENOTAPHD_SRCDIR)/pathname.h
	$(CC) $(CFLAGS) -c $<

