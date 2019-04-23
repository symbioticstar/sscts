all:
	gcc result.c sandbox.c main.c -o main -O2 -lseccomp -Wall