all: mingw-backtrace.dll test.exe

CFLAGS += -Wall -Os -I . -g

LIBBT = libbacktrace/pecoff.o libbacktrace/read.o libbacktrace/alloc.o libbacktrace/posix.o \
	libbacktrace/dwarf.o libbacktrace/sort.o libbacktrace/state.o

mingw-backtrace.dll: mingw-backtrace.o $(LIBBT)
	$(CC) -o $@ -shared $^

test.exe: test.c
	$(CC) -Wall -O0 -g1 -o $@ $^

clean:
	rm -f mingw-backtrace.dll test.exe *.o $(LIBBT)
