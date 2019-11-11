.ONESHELL:
all:
	gcc result.c sandbox.c sscts.c cgroup.c -o sscts -O2 -lseccomp -Wall
	gcc simple_comparer.c -O2 -o sc -static -Wall
	cd comparer
	cargo build --release
install:
	cp sscts /usr/local/bin
	cp comparer/target/release/ojcmp /usr/local/bin 
