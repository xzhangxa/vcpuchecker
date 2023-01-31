#include <stdio.h>

extern int hfi_main();
extern void hfi_exit();

int main(int argc, char *argv[])
{
	int ret = 0;

	ret = hfi_main();

	return ret;
}
