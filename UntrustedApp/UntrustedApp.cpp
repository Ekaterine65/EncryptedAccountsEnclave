#include <stdio.h>
#include <memory.h>
#include <string.h>


#define BUFLEN 1024
/*
const char* personalData[] = {
	"Diane Davis U99857184",
	"Caleb White 316363937",
	"Nicole Rogers 972688406",
	"Jonathan Young J15917635",
	"Richard Lopez 015975175",
	"Scott Stevens 704245295",
	"Rebecca Jackson 696123513",
	"Erin Marshall I61724538",
	"Jessica Franklin F48074190",
	"Katie Farley S20774514"
};

void accessPD(
	char * outbuf,		// ВЫХОДНОЙ параметр
	const size_t len,	// максимальная длина буфера
	const size_t i)		// номер элемента в массиве
{
	size_t maxPD = sizeof(personalData) / sizeof(char*);
	if (i >= maxPD) {
		//outbuf = nullptr;
		memset(outbuf, '\0', len);
	}
	else {
		size_t len = strlen(personalData[i]);
		strcpy_s(outbuf, BUFLEN, personalData[i]);
	}
}
*/

/* 1. специфичные заголовки для использования анклава */
#include "sgx_urts.h" // вместо #include <string.h>
#include "sgx_tseal.h"
#include "Enclave_u.h"
#define ENCLAVE_FILE L"Enclave.signed.dll"

int main() {

	/* 2 активация анклава*/
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	const wchar_t libname[] = ENCLAVE_FILE; // L"Enclave.signed.dll";

	ret = sgx_create_enclave(libname, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}

	for (;;) {
		int idx = -1;
		printf_s("Input i: ");
		int readData = scanf_s("%d", &idx);
		if (readData != 1) {
			printf_s("***Exit***");
			return -1;
		}
		char buffer[BUFLEN] = { 0 };
		accessPD(eid, buffer, BUFLEN, idx);
		printf_s("Retrieved string: %s\n", buffer);
	}

	/* 3. Выгрузить анклав */
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;

	printf_s("***Exit***");
	return 0;
}