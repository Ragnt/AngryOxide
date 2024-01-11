prog :=angryoxide

debug ?=


EXECUTABLES = rustc cargo
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH")))


ifdef debug
  release :=
  target :=debug
  extension :=debug
else
  release :=--release
  target :=release
  extension :=
endif

build:
	cargo build $(release)

install:
	cp target/$(target)/$(prog) /usr/bin/$(prog)
	cp completions/$(prog) $(shell pkg-config --variable=completionsdir bash-completion)/

all: build install
 
help:
	@echo "usage: make $(prog) [debug=1]"