#include "aes.h"

#include "io.clave2.protocol.h"

static unsigned char ApiBaseExchangeKey[16] = {0x70,0x25,0x4E,0x4D,0x73,0xF5,0x89,0xFD,0xF0,0xAC,0x4E,0xD3,0x52,0x94,0x14,0x67};
static unsigned char ApiBaseCoeff = 0x5B;

void GenerateExchangeKey(unsigned char* input_data, unsigned char* output_data){
    unsigned char ExchangeKey[16] = {0x00};
    unsigned char FakeIv[16] = {0x00};
    for(int i=0;i<16;i++){
        ExchangeKey[i] = ApiBaseExchangeKey[i] ^ ApiBaseCoeff;
    }
    AES_CBC_encrypt_buffer(output_data,input_data,16,ExchangeKey,FakeIv);
}

void EncodeDecodeBuffer(unsigned char* input_data, unsigned int input_length, unsigned char* session_key){
    for (int i = 0; i < input_length - 1; i++) {
        input_data[i + 1] ^= session_key[i % 0x04];
    }
}