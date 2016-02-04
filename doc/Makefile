TARGET = kenotaphd.1.gz

all: $(TARGET)
	#groff -man -Tascii $< > $(TARGET)

$(TARGET): kenotaphd.1
	gzip -f -k -9 $<

clean:
	rm -f $(TARGET)

