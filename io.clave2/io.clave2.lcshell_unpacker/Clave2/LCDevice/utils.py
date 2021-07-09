import struct
import random
from Crypto.Cipher import AES

from .constants import API_BASE_EXCHANGE_KEY, LC_OTHER_ERROR, PACKET_SIZE

# Generate random bytes in 32bit blocks.
def generate_random_data(num_blocks=4):
    data = b""
    for i in range(0, num_blocks):
        data += struct.pack("<I", (int(random.randint(0, 0xFFFFFFFF) * 0.000030517578125 * 255.0)) & 0xFFFFFFFF)
    return data


# Generate Exchange Key for Session
def generate_exchange_key():
    exk = bytearray(API_BASE_EXCHANGE_KEY)
    for i in range(0, len(exk)):
        exk[i] ^= 0x5B
    cipher = AES.new(exk, AES.MODE_CBC, iv=b"\x00" * 16)
    exchange_key = generate_random_data()
    return cipher.decrypt(exchange_key), exchange_key



class ResponsePacket:
    def __init__(self, packet_key, raw_data):
        self.raw_data = raw_data
        self.packet_key = packet_key
        self.status = LC_OTHER_ERROR
        self.val_1 = 0
        self.val_2 = 0
        self.val_3 = 0
        self.data = b""
        self.decoded_data = self.decode_packet()
        self.load_response()

    def decoded_response(self):
        return self.decoded_data

    def load_response(self):
        self.status = self.decoded_data[0]
        self.val_1 = self.decoded_data[1]
        self.val_2 = self.decoded_data[2]
        self.val_3 = self.decoded_data[3]
        if self.val_3:
            self.data = self.decoded_data[4:4+self.val_3]

    # Decode a Response Packet from the Dongle
    def decode_packet(self):
        # Tear off null byte prefix.
        in_data = bytearray(self.raw_data[1:])
        # Truncate "key" to 4 bytes as it's all we'll need.
        packet_key = self.packet_key[:4]
        # Decode packet data with key.
        for i in range(0, len(in_data)):
            in_data[i] = (in_data[i] ^ packet_key[i % len(packet_key)]) & 0xFF
        # Get Size of Response Packet
        payload_size = in_data[3]
        decoded_packet_size = 4 + payload_size
        return in_data[:decoded_packet_size]

class RequestPacket:
    def __init__(self, packet_key, operation, param_1=0, param_2=0, param_3=0, data = b""):
        if type(data) is str:
            data = data.encode('ascii')
        self.packet_key = packet_key
        self.operation = operation
        self.param_1 = param_1
        self.param_2 = param_2
        self.param_3 = param_3
        self.data = data

    def raw(self):
        return struct.pack("B", self.operation) + \
               struct.pack("B", self.param_1) + \
               struct.pack("B", self.param_2) + \
               struct.pack("B", self.param_3) + \
               self.data

    # Encode a Request Packet
    def encode_packet(self):
        in_data = self.raw()
        # Truncate "key" to 4 bytes as it's all we'll need.
        packet_key = self.packet_key[:4]
        # Pad out to multiple of 4.
        mod_amt = len(in_data) % 4
        padding = b""
        if mod_amt > 0:
            padding += b"\x00" * (4 - mod_amt)
        in_data = bytearray(in_data + padding)
        # Encode packet data with key.
        for i in range(0, len(in_data)):
            in_data[i] = (in_data[i] ^ packet_key[i % len(packet_key)]) & 0xFF
        # Fill the rest of the packet with random
        rand_amt = (PACKET_SIZE - 1) - len(in_data)
        num_random_blocks = (int(rand_amt / 4))
        random_padding = generate_random_data(num_blocks=num_random_blocks)
        # Prepend a null byte.
        encoded_packet = b"\x00" + in_data + random_padding
        # Truncate as a sanity check.
        return encoded_packet[:PACKET_SIZE]
