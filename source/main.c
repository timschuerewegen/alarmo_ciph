#include <windows.h>
#include <userenv.h>
#include <stdio.h>

struct import_key_blob_aes_128
{
	BLOBHEADER header;
	DWORD size;
	BYTE data[16];
};

struct alarmo_aes
{
	BYTE key[16];
	BYTE iv[16];
};

int main(int argc, char *argv[])
{
	int retval = 1;
	HCRYPTKEY hkey = 0;
	HCRYPTPROV hprov = 0;
	DWORD size;
	struct import_key_blob_aes_128 import_key_blob = { 0 };
	DWORD mode;
	DWORD size_left;
	HANDLE file_src = INVALID_HANDLE_VALUE;
	HANDLE file_dst = INVALID_HANDLE_VALUE;
	HANDLE file_key = INVALID_HANDLE_VALUE;
	DWORD aes_counter = 0;
	const BYTE ciph_header[] = { 'C', 'I', 'P', 'H', 0, 0, 0, 0 };
	const BYTE ciph_sig[256] = { 0 };
	DWORD br, bw;
	BYTE data1[256], data2[256];
	char filename[MAX_PATH];
	struct alarmo_aes aes = { 0 };
	BOOL file_src_ciph;

	if (argc != 3)
	{
		printf("ERROR: no input/output file specified\n");
		goto cleanup;
	}

	if (GetEnvironmentVariableA("USERPROFILE", filename, sizeof(filename)) == 0)
	{
		printf("ERROR: GetEnvironmentVariableA error %d\n", GetLastError());
		goto cleanup;
	}

	strcat(filename, "\\.alarmo\\aes_key_iv.bin");

	file_key = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (file_key == INVALID_HANDLE_VALUE)
	{
		printf("ERROR: CreateFile error %d\n", GetLastError());
		printf("Could not open \"%s\"\n", filename);
		goto cleanup;
	}

	if (!ReadFile(file_key, &aes, sizeof(aes), &br, NULL))
	{
		printf("ERROR: ReadFile error 0x%x\n", GetLastError());
		goto cleanup;
	}

	CloseHandle(file_key);

	strcpy(filename, argv[1]);
	file_src = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (file_src == INVALID_HANDLE_VALUE)
	{
		printf("ERROR: CreateFile error %d\n", GetLastError());
		printf("Could not open \"%s\"\n", filename);
		goto cleanup;
	}

	strcpy(filename, argv[2]);
	file_dst = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (file_dst == INVALID_HANDLE_VALUE)
	{
		printf("ERROR: CreateFile error %d\n", GetLastError());
		printf("Could not open \"%s\"\n", filename);
		goto cleanup;
	}

	size_left = GetFileSize(file_src, NULL);

	if (!ReadFile(file_src, data1, sizeof(ciph_header), &br, NULL))
	{
		printf("ERROR: ReadFile error 0x%x\n", GetLastError());
		goto cleanup;
	}

	file_src_ciph = ((br == sizeof(ciph_header)) && (memcmp(data1, ciph_header, sizeof(ciph_header)) == 0));

	printf("%s ...\n", file_src_ciph ? "decrypt" : "encrypt");

	if (file_src_ciph)
	{
		size_left = size_left - sizeof(ciph_header) - 256;
	}
	else
	{
		if (SetFilePointer(file_src, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			printf("ERROR: SetFilePointer failed\n");
			goto cleanup;
		}
	}

	if (!file_src_ciph)
	{
		if (!WriteFile(file_dst, ciph_header, sizeof(ciph_header), &bw, NULL))
		{
			printf("ERROR: WriteFile error 0x%x\n", GetLastError());
			goto cleanup;
		}
	}

	if (!CryptAcquireContext(&hprov, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		printf("ERROR: CryptAcquireContext error 0x%x\n", GetLastError());
		goto cleanup;
	}

	import_key_blob.header.bType = PLAINTEXTKEYBLOB;
	import_key_blob.header.bVersion = CUR_BLOB_VERSION;
	import_key_blob.header.reserved = 0;
	import_key_blob.header.aiKeyAlg = CALG_AES_128;
	import_key_blob.size = sizeof(aes.key);
	memcpy(import_key_blob.data, aes.key, sizeof(aes.key));
	if (!CryptImportKey(hprov, (LPCBYTE)&import_key_blob, sizeof(import_key_blob), 0, 0, &hkey))
	{
		printf("ERROR: CryptImportKey error 0x%x\n", GetLastError());
		goto cleanup;
	}

	mode = CRYPT_MODE_ECB;
	if (!CryptSetKeyParam(hkey, KP_MODE, (LPCBYTE)&mode, 0))
	{
		printf("ERROR: CryptSetKeyParam error 0x%x\n", GetLastError());
		goto cleanup;
	}

	while (size_left > 0)
	{
		if (!ReadFile(file_src, data1, __min(size_left, 16), &br, NULL))
		{
			printf("ERROR: ReadFile error 0x%x\n", GetLastError());
			goto cleanup;
		}

		size_left = size_left - br;

		size = 16;
		memcpy(data2, aes.iv, sizeof(aes.iv));
		data2[12] = (BYTE)(aes_counter >> 24);
		data2[13] = (BYTE)(aes_counter >> 16);
		data2[14] = (BYTE)(aes_counter >> 8);
		data2[15] = (BYTE)(aes_counter >> 0);
		aes_counter++;
		if (!CryptEncrypt(hkey, 0, TRUE, 0, data2, &size, sizeof(data2)))
		{
			printf("ERROR: CryptEncrypt error 0x%x\n", GetLastError());
			goto cleanup;
		}

		for (DWORD i = 0; i < br; i++)
		{
			data1[i] = data1[i] ^ data2[i];
		}

		if (!WriteFile(file_dst, data1, br, &bw, NULL))
		{
			printf("ERROR: WriteFile error 0x%x\n", GetLastError());
			goto cleanup;
		}
	}

	if (!file_src_ciph)
	{
		if (!WriteFile(file_dst, ciph_sig, sizeof(ciph_sig), &bw, NULL))
		{
			printf("ERROR: WriteFile error 0x%x\n", GetLastError());
			goto cleanup;
		}
	}

	printf("done\n");

	retval = 0;

cleanup:

	if (hkey != 0)
	{
		CryptDestroyKey(hkey);
	}

	if (hprov != 0)
	{
		CryptReleaseContext(hprov, 0);
	}

	if (file_dst != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_dst);
	}

	if (file_src != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_src);
	}

	return retval;
}
