.PHONY: clean build

all: build

build:
	@./build.sh

clean:
	@rm -rf *.gz *.iso
