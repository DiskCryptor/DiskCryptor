#include <windows.h>
#include <stdlib.h>

/*
 * Simple secure_alloc/secure_free stubs for standalone crypto tests.
 * These provide basic functionality without requiring the driver.
 */

void* secure_alloc(unsigned long length)
{
	void *ptr = VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (ptr != NULL) {
		VirtualLock(ptr, length);
		memset(ptr, 0, length);
	}
	return ptr;
}

void secure_free(void *ptr)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (ptr != NULL && VirtualQuery(ptr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
		SecureZeroMemory(ptr, mbi.RegionSize);
		VirtualUnlock(ptr, mbi.RegionSize);
		VirtualFree(ptr, 0, MEM_RELEASE);
	}
}
