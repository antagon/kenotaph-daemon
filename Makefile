#
# Copyright (c) 2016, CodeWard.org
#

all:
	$(MAKE) -C src/
	$(MAKE) -C doc/
	$(MAKE) -C utils/

install:
	$(MAKE) -C src/ $@
	$(MAKE) -C doc/ $@
	$(MAKE) -C utils/ $@

uninstall:
	$(MAKE) -C src/ $@
	$(MAKE) -C doc/ $@
	$(MAKE) -C utils/ $@

clean:
	$(MAKE) -C src/ $@
	$(MAKE) -C doc/ $@
	$(MAKE) -C utils/ $@

