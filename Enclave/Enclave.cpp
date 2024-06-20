#include "Enclave_t.h"

#include "sgx_trts.h"

#include <string.h> //есть в Intel SGX SDK 
//#include <memory.h> // не подключается из Intel SGX SDK

#define BUFLEN 1024

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
	char* outbuf,		// ВЫХОДНОЙ параметр
	const size_t len,	// максимальная длина буфера
	const size_t i)		// номер элемента в массиве
{
	size_t maxPD = sizeof(personalData) / sizeof(char*);
	if (i >= maxPD) {
		//outbuf = nullptr;
		memset((void*)outbuf, 0, len);
	}
	else {
		const size_t datalen = strlen(personalData[i]);
		memcpy(outbuf, personalData[i], datalen);
	}
}
