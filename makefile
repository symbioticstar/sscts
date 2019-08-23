all:
	gcc result.c sscts.c -o ssctss -O2 -lseccomp -Wall -static
