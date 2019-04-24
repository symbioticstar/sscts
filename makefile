all:
	gcc comparer.c result.c sandbox.c sscts.c -o sscts -O2 -lseccomp -Wall -static
