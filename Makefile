# This file is part of termOTP, a TOTP program for your terminal.
# https://github.com/marcopaganini/termotp.
.PHONY: arch clean install

bin := termotp
bindir := /usr/local/bin
archdir := arch
src := $(wildcard *.go)
git_tag := $(shell git describe --always --tags)

# Default target
${bin}: Makefile ${src}
	CGO_ENABLED=0 go build -v -ldflags "-X main.Build=${git_tag}" -o "${bin}"

clean:
	rm -f "${bin}"
	rm -f "docs/${bin}.1"

install: ${bin}
	install -m 755 "${bin}" "${bindir}"
