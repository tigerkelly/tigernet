# Makefile — tigernet

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=gnu11 -D_DEFAULT_SOURCE
LIBS    = -lpcap -lpthread
TARGET  = tigernet
SRC     = tigernet.c

PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
