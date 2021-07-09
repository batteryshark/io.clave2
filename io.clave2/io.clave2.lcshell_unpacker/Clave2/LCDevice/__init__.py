import struct

import hid
import binascii
from .constants import *
from .utils import generate_exchange_key, RequestPacket, ResponsePacket



class LCDevice:
    def __init__(self, device: hid.Device):
        self.session_key = b"\x00" * 16
        self.device = device
        self.last_error = LC_SUCCESS

    def print_last_error(self):
        print(self.last_error)
        return self.last_error

    def transact(self, operation, param_1=0, param_2=0, param_3=0, data=b""):
        request_packet = RequestPacket(self.session_key, operation, param_1, param_2, param_3, data)
        if PACKET_DEBUG:
            print(f"Request: {binascii.hexlify(request_packet.raw())}")
        if self.device.send_feature_report(request_packet.encode_packet()) != PACKET_SIZE:
            print("Error Sending Request to Hardware.")
            self.last_error = LC_HARDWARE_COMMUNICATE_ERROR
            return False, None

        raw_response = self.device.get_feature_report(0, PACKET_SIZE)
        if len(raw_response) != PACKET_SIZE:
            self.last_error = LC_HARDWARE_COMMUNICATE_ERROR
            return False, None
        response_packet = ResponsePacket(self.session_key,raw_response)
        if PACKET_DEBUG:
            print(f"Response: {binascii.hexlify(response_packet.decoded_response())}")
        self.last_error = DONGLE_ERROR_MAP.get(response_packet.status,LC_OTHER_ERROR)
        if self.last_error:
            return False, response_packet
        return True, response_packet

    def memory_read(self, address, amount):
        status,response = self.transact(OP_READ,(address & 0xFF00) >> 8,address & 0xFF,amount)
        if not status or self.last_error:
            return False
        return True, response.data


    def memory_write(self, address, data):
        status,response = self.transact(OP_WRITE,(address & 0xFF00) >> 8,address & 0xFF,len(data),data)
        if not status or self.last_error:
            return False
        return True

    def authenticate(self, operation_mode, data=b"00000000"):
        status,response = self.transact(OP_AUTHENTICATE,operation_mode,0,len(data),data)
        if not status or self.last_error:
            return False
        return True

    def convert(self, mode, in_data):
        if mode not in [0,1]:
            self.last_error = LC_INVALID_PARAMETER
            return False,b""
        status, response = self.transact(OP_CONVERT,mode,0,len(in_data),in_data)
        if not status or self.last_error:
            return False, b""
        return True, response.data

    def get_info(self):
        status, response = self.transact(OP_HW_INFO)
        if not status or self.last_error:
            return False, {}
        info = {
            'developer_id': response.data[0:8].decode('utf-16').rstrip('\x00'),
            'serial_number': response.data[8:24].decode('utf-16').rstrip('\x00'),
            'mfg_date': struct.unpack("<I", response.data[24:28])[0],
            'flash_date': struct.unpack("<I", response.data[28:32])[0]
        }
        return True, info

    def hmac(self, data):
        if len(data) > 0x40:
            print("Can only Have a Max of 64 bytes of input data to HMAC")
            self.last_error = LC_INVALID_PARAMETER
            return False,b""
        status, response = self.transact(OP_SIGN,OP_SIGN_MODE_INIT)
        if not status:
            return False,b""
        # TODO: Add chunked support.
        status, response = self.transact(OP_SIGN, OP_SIGN_MODE_UPDATE,0,len(data),data)
        if not status:
            return False,b""
        status, response = self.transact(OP_SIGN, OP_SIGN_MODE_FINALIZE)
        if not status:
            return False,b""
        return True, response.data

    def change_auth_password(self, old_password, new_password):
        pw = old_password+new_password
        status, response = self.transact(OP_CHANGE_PASSWD,2,0,len(pw),pw)
        if not status:
            return False
        return True

    def init_system_block(self, address):
        status, response = self.transact(OP_INIT_SYSTEM,(address & 0xFF00) >> 8,address & 0xFF)
        if not status:
            return False
        return True

    def init_memory_block(self, address):
        status, response = self.transact(OP_INIT_MEM,(address & 0xFF00) >> 8,address & 0xFF)
        if not status:
            return False
        return True

    def clear_memory(self, address, amount):
        status, response = self.transact(OP_CLEAR,(address & 0xFF00) >> 8,address & 0xFF,amount)
        if not status:
            return False
        return True

    def update(self, mode, param_2=0, param_3=0, data=b""):
        status, response = self.transact(OP_UPDATE, mode, param_2, param_3, data)
        if not status:
            self.print_last_error()
            return False
        return True

    def session(self,operation_mode=OP_SESSION_MODE_SET_EXCHANGE_KEY):
        if operation_mode is OP_SESSION_MODE_SET_EXCHANGE_KEY:
            decrypted_exchange_key,exchange_key = generate_exchange_key()
            status, response = self.transact(OP_SESSION, operation_mode,0,len(decrypted_exchange_key),decrypted_exchange_key)
            if not status or self.last_error:
                return False
            self.session_key = exchange_key
            return True
        return False




