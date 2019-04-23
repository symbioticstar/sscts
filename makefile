all:
	gcc result.c sandbox.c sscts.c -o sscts -O2 -lseccomp -Wall