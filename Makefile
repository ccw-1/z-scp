CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -O2
TARGET  = z-scp

.PHONY: all clean install

all: $(TARGET)

$(TARGET): z-scp.c
	$(CC) $(CFLAGS) -o $@ $<

install: $(TARGET)
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)

clean:
	rm -f $(TARGET)
