#include <windows.h>
#include <stdio.h>

static void
foo()
{
	int *f=NULL;
	*f = 0;
}

static void
bar()
{
	foo();
}

int
main()
{
	if (!LoadLibraryA("mingw-backtrace.dll")) {
		fprintf(stderr, "failed to load dll %d\n", (int)GetLastError());
		return 1;
	}
	bar();

	return 0;
}
