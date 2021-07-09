#pragma once
void GenerateExchangeKey(unsigned char* input_data, unsigned char* output_data);
void EncodeDecodeBuffer(unsigned char* input_data, unsigned int input_length, unsigned char* session_key);