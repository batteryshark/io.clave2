#include <Windows.h>
#include <stdio.h>

typedef int lc_handle_t;

#define LCAPI __stdcall

int LCAPI(*LC_open)(int vendor, int index, lc_handle_t *handle) = 0;
int LCAPI(*LC_passwd)(lc_handle_t handle, int type, unsigned char *passwd) = 0;
int LCAPI(*LC_encrypt)(lc_handle_t handle, unsigned char *plaintext,  unsigned char *ciphertext) = 0;
int LCAPI(*LC_read)(lc_handle_t handle, int block, unsigned char *buffer) = 0;
int LCAPI(*LC_close)(lc_handle_t handle) = 0;




void print_hex(unsigned char* data, unsigned int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}


static BYTE test_data[16] = { 0x53,0x4B,0x2D,0xD0,0x86,0x90,0x52,0xD0,0x62,0xFC,0x6A,0x5D,0x6D,0x39,0x3E,0x6C };
int main(int argv) {

    if (argv > 1) {
        LoadLibraryA("io.clave2.dll");
    }

    HMODULE lc_dll = LoadLibraryA("ext\\LC.dll");
    if(!lc_dll){
        printf("Error: Could not Bind to LC/Sense_LC.dll");
        return -1;
    }

    LC_open = GetProcAddress(lc_dll,"LC_open");
    LC_passwd = GetProcAddress(lc_dll,"LC_passwd");
    LC_encrypt = GetProcAddress(lc_dll,"LC_encrypt");
    LC_read = GetProcAddress(lc_dll,"LC_read");
    LC_close = GetProcAddress(lc_dll,"LC_close");

    if(!LC_open){
        printf("Error: Could not Bind to DLL Functions\n");
        return -1;
    }


    BYTE enc_data[16] = { 0x00 };
    int status = 0;
    int hLC;
    status = LC_open(0x3F3F3F3F, 1, &hLC);
    if (status) {
        printf("LC OPEN FAILED: %04X!\n", status);
        if (status != 8) {
            return -1;
        }

    }
    printf("LC OPEN OK!\n");

    printf("LC Passwd...\n");
    status = LC_passwd(hLC, 1, (unsigned char*)"12345678");
    if (status) {
        printf("LC_Passwd Failed: %04X!\n", status);
        return -1;
    }
    printf("LC_Passwd OK!\n");

    printf("LC_encrypt...\n");

    if (LC_encrypt(hLC, test_data, enc_data)) {
        printf("LC_encrypt Failed!\n");
        return -1;
    }
    printf("LC_encrypt OK!\n");
    print_hex(enc_data, 16);
    unsigned char mem_read[512] = { 0x00 };
    status = LC_read(hLC, 0, mem_read);
    if (status) {
        printf("LC_read Failed: %04X!\n", status);
        return -1;
    }
    printf("LC_read OK!\n");
    print_hex(mem_read, sizeof(mem_read));

    printf("Closing Handle...\n");
    LC_close(hLC);
    printf("Handle Closed!\n");

    return 0;
}
