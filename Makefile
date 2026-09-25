CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -O2
TARGET  = z-scp
MCP     = z-scp-mcp

.PHONY: all clean install

all: $(TARGET) $(MCP)

$(TARGET): z-scp.c
	$(CC) $(CFLAGS) -o $@ $<

$(MCP): z-scp-mcp.c
	$(CC) $(CFLAGS) -o $@ $<

install: $(TARGET) $(MCP)
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)
	install -m 755 $(MCP) $(DESTDIR)/usr/local/bin/$(MCP)

clean:
	rm -f $(TARGET) $(MCP)
