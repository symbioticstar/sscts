all:
	gcc comparer.c result.c sandbox.c sscts.c -o sscts -O2 -lseccomp -Wall -static
	gcc simple_comparer.c -o comparer -O2
install:
	cp comparer sscts /usr/bin