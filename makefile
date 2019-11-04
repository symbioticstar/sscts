.ONESHELL:
all:
	gcc comparer.c result.c sandbox.c sscts.c -o sscts -O2 -lseccomp -Wall -static
	cd comparer
	cargo build --release
install:
	cp sscts /usr/bin
	cp comparer/target/release/ojcmp /usr/bin 
