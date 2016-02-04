#
# Copyright (c) 2016, CodeWard.org
#
#
TARGET = kenotaphd.1.gz
INSTALL_DIR = /usr/share/man/man1

all: $(TARGET)

install:
	install --mode 0644 $(TARGET) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

clean:
	rm -f $(TARGET)

$(TARGET): kenotaphd.1
	gzip -f -k -9 $<

