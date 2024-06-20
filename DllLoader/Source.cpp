#include <Windows.h>
#include <stdio.h>

typedef void (WINAPI* t_accessPD)(char* outbuf, const size_t len, const size_t i);

int main() {
	HMODULE hModule = LoadLibrary(L"UntrustedDll.dll");
	printf("hModule = #%d\n", hModule);

	t_accessPD accessPD = (t_accessPD)GetProcAddress(hModule, "accessPersonalData");
	printf("hModule = #%d\n", accessPD);
	if (accessPD == NULL) {
		return -1;
	}
	char buffer[1024] = { 0 };
	accessPD(buffer, 1024, 5);
	printf("hModule = %s\n", buffer);

	return 0;
}