#pragma once

// Transaction Defines
#define OP_AUTHENTICATION 0x00
#define OP_HW_INFO 0x02
#define OP_READ 0x03
#define OP_CONVERT 0x08
#define OP_SESSION 0x0B
#define LOGIN_ADMIN 0
#define LOGIN_USER 1
#define LOGIN_AUTH 2
#define LOGOUT 3
#define CONVERT_ENCRYPT 0x00
#define CONVERT_DECRYPT 0x01

#define IOCTL_HID_GET_FEATURE 0xB0192
#define IOCTL_HID_SET_FEATURE 0xB0191
#define IOCTL_HID_GET_SERIALNUMBER_STRING 0xB01C2
#define IOCTL_HID_GET_COLLECTION_INFORMATION 0xB01A8
#define IOCTL_HID_GET_COLLECTION_DESCRIPTOR 0xB0193



int InitClave2EmuWindows(char* ini_path);
void ProcessClave2IoctlWindows(unsigned int IoControlCode, unsigned char* InputBuffer,unsigned int InputBufferLength,unsigned char* OutputBuffer,unsigned int OutputBufferLength);
