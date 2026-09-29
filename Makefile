CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
# GCC 8 needs -lstdc++fs; add it only when the linker accepts it
FSLIB := $(shell echo 'int main(){}' | $(CXX) -x c++ - -lstdc++fs -o /dev/null 2>/dev/null && echo -lstdc++fs)
PREFIX ?= /usr/local

all: security_toolkit

security_toolkit: security_toolkit.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(FSLIB)

install: security_toolkit
	install -Dm755 security_toolkit $(DESTDIR)$(PREFIX)/sbin/security_toolkit

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/security_toolkit

clean:
	rm -f security_toolkit

.PHONY: all install uninstall clean
