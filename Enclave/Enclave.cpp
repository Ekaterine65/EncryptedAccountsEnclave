#include "Enclave_t.h"

#include "sgx_trts.h"

#include <string.h> //���� � Intel SGX SDK 
//#include <memory.h> // �� ������������ �� Intel SGX SDK

#define BUFLEN 1024

char personalData[100][BUFLEN];

void accessPD(
	char* outbuf,		// �������� ��������
	const size_t len,	// ������������ ����� ������
	const size_t i)		// ����� �������� � �������
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

void setPD(
	char* inbuf, 
	const size_t len, 
	const size_t i) 
{
	size_t maxPD = sizeof(personalData) / sizeof(personalData[0]);
	if (i < maxPD) {
		memset(personalData[i], 0, BUFLEN);
		size_t copyLen = len < BUFLEN ? len : BUFLEN - 1;
		memcpy(personalData[i], inbuf, copyLen);
	}
}
