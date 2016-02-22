#
# Copyright (c) 2016, CodeWard.org
#

CC = gcc
CFLAGS = -std=gnu99 -O2 -pedantic -Wall -ggdb

TARGET = kenotaphd
INSTALL_DIR = /usr/local/sbin

.PHONY: clean install

all: $(TARGET)

install:
	install --mode 755 $(TARGET) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

clean:
	rm -f *.o $(TARGET)

$(TARGET): main.o config.o session_data.o pathname.o hostport_parser.o nmsg_queue.o pidfile.o
	$(CC) $(CFLAGS) $^ -o $(TARGET) -lpcap -lconfuse

main.o: main.c
	$(CC) $(CFLAGS) -c $<

config.o: config.c config.h
	$(CC) $(CFLAGS) -c $<

session_data.o: session_data.c session_data.h
	$(CC) $(CFLAGS) -c $<

pathname.o: pathname.c pathname.h
	$(CC) $(CFLAGS) -c $<

hostport_parser.o: hostport_parser.c hostport_parser.h
	$(CC) $(CFLAGS) -c $<

nmsg_queue.o: nmsg_queue.c nmsg_queue.h
	$(CC) $(CFLAGS) -c $<

pidfile.o: pidfile.c pidfile.h
	$(CC) $(CFLAGS) -c $<

