#include <Windows.h>
#include "lc.h"
#include <stdio.h>
#define EXPORTABLE __declspec(dllexport)

static lc_handle_t vx = NULL;

#ifdef __cplusplus
extern "C"{
#endif
	
EXPORTABLE int WINAPI S_LC_open(int vendor, int index, lc_handle_t* handle) { 
	int res = LC_open(vendor,index, handle); 
	if (!res) { printf("Handle Value: %p\n", *handle); }
	vx = *handle;
	return res;
}
EXPORTABLE int WINAPI S_LC_passwd(lc_handle_t handle, int type, unsigned char* passwd) {
	printf("Handle: %p\n", handle);
	printf("Type: %04X\n", type);
	printf("Passwd: %s\n", passwd);
	return LC_passwd(vx, 1, (unsigned char*)"a81c046a");
}
EXPORTABLE int WINAPI S_LC_close(lc_handle_t handle) {
	printf("Close: %p\n", handle);
	return LC_close(handle);
}
EXPORTABLE int WINAPI S_LC_read(lc_handle_t handle, int block, unsigned char* buffer) {return LC_read(handle, block, buffer);}
EXPORTABLE int WINAPI S_LC_encrypt(lc_handle_t handle, unsigned char* plaintext, unsigned char* ciphertext) {return LC_encrypt(handle, plaintext, ciphertext);}
EXPORTABLE int WINAPI S_LC_decrypt(lc_handle_t handle, unsigned char* ciphertext, unsigned char* plaintext) { return LC_encrypt(handle, ciphertext, plaintext); }
EXPORTABLE int WINAPI S_LC_get_hardware_info(lc_handle_t handle, LC_hardware_info* info) { return LC_get_hardware_info(handle, info); }

EXPORTABLE void WINAPI S_LC_TEST() {
	lc_handle_t handle;
	int res, i;
	// opening LC device
	res = LC_open(0x3F3F3F3F, 0, &handle);
	if (res) {
		printf("open failed\n");
	}
	printf("\nopen success!\n");

	// verify normal user password
	res = LC_passwd(handle, 1, (unsigned char*) "a81c046a");  
	if (res) {
		LC_close(handle);
		printf("verify password failed\n");
		return;
	}
	printf("\nverify password success!\n");
	LC_close(handle);
}
#ifdef __cplusplus
}
#endif


