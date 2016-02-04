#
# Copyright (c) 2016, CodeWard.org
#

all:
	$(MAKE) -C src/
	$(MAKE) -C doc/

install:
	$(MAKE) -C src/ $@
	$(MAKE) -C doc/ $@

uninstall:
	$(MAKE) -C src/ $@
	$(MAKE) -C doc/ $@

clean:
	$(MAKE) -C src/ $@
	$(MAKE) -C doc/ $@

