import binascii
import hashlib
import hmac
import struct

import hid
from LCDevice.constants import *
from LCDevice import LCDevice

class LCApi:
    def __init__(self, developer_id=0, index=0):
        status, selected_device = self.open_device(developer_id, index)
        if status:
            self.device = LCDevice(selected_device)
            if not self.device.session(OP_SESSION_MODE_SET_EXCHANGE_KEY):
                self.device.print_last_error()


    def open_device(self, developer_id, index):
        device_list = []
        devices = hid.enumerate(vid=SENSELOCK_VENDOR_ID, pid=LC_PRODUCT_ID)
        for entry in devices:
            d = hid.Device(path=entry['path'])
            if developer_id != 0:
                if d.serial.startswith(developer_id):
                    device_list.append(d)
            else:
                device_list.append(d)

        if len(device_list) < index + 1:
            print("ERR: No Devices match developer ID or given index.")
            return False, None
        return True, device_list[index]

    def logout(self):
        if not self.device.authenticate(OP_AUTHENTICATE_MODE_LOGOUT, b"00000000"):
            return False
        return True

    def login(self, user_type, password):
        if user_type not in [OP_AUTHENTICATE_MODE_LOGIN_ADMIN,
                             OP_AUTHENTICATE_MODE_LOGIN_USER,
                             OP_AUTHENTICATE_MODE_LOGIN_AUTH] or len(password) != 8:
            return False, LC_INVALID_PARAMETER
        if not self.device.authenticate(user_type, password):
            return False, self.device.last_error
        return True, LC_SUCCESS

    def set_password(self, user_type, password,number_retries=-1):
        if user_type not in [0,1,2]:
            print("Error: User Type must be 0-2")
            self.device.last_error = LC_INVALID_PARAMETER
            return False
        # Admin and User Cannot Have Retries Set
        if user_type in [0,1]:
            number_retries = -1
        retry_b = struct.pack("b",number_retries)
        retry_b+=retry_b
        if type(password) is str:
            password = password.encode('ascii')
        password_payload = password+retry_b
        res = self.device.init_memory_block(UPDATE_SECURE_WRITE_OFFSET)
        if not res:
            return False
        offset = SECRET_COMMIT_OFFSET
        chunk_size = 0x40
        while offset < USER_SECRET_MAP[user_type]['offset']:
            if offset + chunk_size > USER_SECRET_MAP[user_type]['offset']:
                chunk_size = USER_SECRET_MAP[user_type]['offset'] - offset
            res = self.device.clear_memory(offset,chunk_size)
            offset += chunk_size
        res = self.device.clear_memory(USER_SECRET_MAP[user_type]['final_offset'],USER_SECRET_MAP[user_type]['final_size'])
        if not res:
            return False
        res = self.device.memory_write(USER_SECRET_MAP[user_type]['offset']+AUTH_WRITE_MAP_OFFSET,password_payload)
        if not res:
            return False
        res = self.device.init_system_block(USER_SECRET_MAP[user_type]['offset']-0x100)
        if not res:
            return False
        return True

    def set_key(self, key_type, key):
        if key_type not in [0, 1]:
            print("Error: Invalid Key Type Specified.")
            self.device.last_error = LC_INVALID_PARAMETER
            return False

        if len(key) != 20:
            print("Error: Key must be 20 bytes.")
            self.device.last_error = LC_INVALID_PARAMETER
            return False

        res = self.device.init_memory_block(UPDATE_SECURE_WRITE_OFFSET)
        if not res:
            return False

        offset = SECRET_COMMIT_OFFSET
        offset_end = KEY_MEMORY_OFFSET_END
        chunk_size = 0x40
        while offset < offset_end:
            if offset + chunk_size > offset_end:
                chunk_size = offset_end - offset
            res = self.device.clear_memory(offset,chunk_size)
            if not res:
                return False
            offset += chunk_size

        key_flag = 0
        if key_type == 0:
            key_flag = UPDATE_KEY_OFFSET - UNK_SECRET_1_OFFSET
        elif key_type == 1:
            key_flag = HMAC_KEY_OFFSET - UNK_SECRET_1_OFFSET

        res = self.device.clear_memory(UNK_SECRET_1_OFFSET,key_flag)
        if not res:
            return False

        res = self.device.clear_memory(key_flag+UNK_SECRET_1_OFFSET,len(key))
        if not res:
            return False
        if key_type == 0:
            res = self.device.memory_write(UPDATE_KEY_OFFSET+AUTH_WRITE_MAP_OFFSET, key)
        elif key_type == 1:
            res = self.device.memory_write(HMAC_KEY_OFFSET+AUTH_WRITE_MAP_OFFSET, key)
        if not res:
            return False
        commit_offset = UPDATE_KEY_OFFSET - SECRET_BASE_OFFSET

        #res = self.device.init_system_block(commit_offset+SECRET_COMMIT_OFFSET)
        #if not res:
        #    return False

        return True

    def encrypt(self, input_data):
        if len(input_data) != 0x10:
            print("Error - Convert Requires 16 bytes of data.")
            return False, b""
        res, data = self.device.convert(OP_CONVERT_MODE_ENCRYPT,input_data)
        if not res:
            return False,b""
        return True,data

    def decrypt(self, input_data):
        if len(input_data) != 0x10:
            print("Error - Convert Requires 16 bytes of data.")
            return False, b""
        res, data = self.device.convert(OP_CONVERT_MODE_DECRYPT,input_data)
        if not res:
            return False, b""
        return True, data

    def read(self, block_number):
        if block_number not in [0,1,2,3]:
            self.device.last_error = LC_INVALID_PARAMETER
            return False, b""
        read_data = b""
        read_offset = 0
        chunk_size = 0x40
        bank_offset,bank_size = BANK_MAP[block_number]
        bank_end = bank_offset + bank_size
        while read_offset < bank_end:
            if bank_offset + chunk_size > bank_end:
                chunk_size = bank_end - bank_offset
            res, data = self.device.memory_read(read_offset,chunk_size)
            if not res:
                return False, b""
            read_data+=data
            read_offset+=chunk_size
        return True, read_data

    def write(self, block_number, data):
        if block_number not in [0,1,2,3]:
            self.device.last_error = LC_INVALID_PARAMETER
            return False
        bank_offset, bank_size = BANK_MAP[block_number]
        if len(data) != bank_size:
            print(f"Data Must be Bank Size: {bank_size}")
        write_offset = 0
        chunk_size = 0x40
        bank_end = bank_offset + bank_size
        while write_offset < bank_end:
            if bank_offset + chunk_size > bank_end:
                chunk_size = bank_end - bank_offset
            res = self.device.memory_write(write_offset,data[write_offset:write_offset+chunk_size])
            if not res:
                return False
            write_offset+=chunk_size
        return True

    def get_hardware_info(self):
        return self.device.get_info()

    def get_software_info(self):
        return True, 0x8F
    def change_auth_password(self, old_password, new_password):
        if len(old_password) !=8 or len(new_password) != 8:
            print("Old and New Password Must be 8 Bytes!")
            self.device.last_error = LC_INVALID_PARAMETER
            return False
        return self.device.change_auth_password(old_password, new_password)

    def hmac_software(self, input_data, input_key):
        if len(input_key) != 20:
            self.device.last_error = LC_INVALID_PARAMETER
            return False, b""
        return True, hmac.new(input_key, input_data, digestmod=hashlib.sha1).digest()

    def hmac(self, input_data):
        return self.device.hmac(input_data)

    def update(self, update_data):
        # Can only be done with Type USER [1]
        if len(update_data) != 549:
            print("Error: Update can only be 549 bytes.")
            self.device.last_error = LC_INVALID_PARAMETER
            return False

        # Check HMAC of Update Package
        pkg_hmac = update_data[:-20]
        block_to_update = update_data[0x210]
        if block_to_update not in [0,1,2,3]:
            print("Error: Block To Update Should be 0-3")
            self.device.last_error = LC_INVALID_PARAMETER
            return False

        # First - Check to see if we can actually write with the logged in session.
        res = self.device.init_memory_block(UPDATE_SECURE_WRITE_OFFSET)
        if not res:
            return False

        # 0a 00 03 00 - Update [Set Block]
        res = self.device.update(OP_UPDATE_MODE_SET_BLOCK, block_to_update)
        if not res:
            return False

        # 0a 01 00 40 ... - Write block
        # 0a 01 01 40 ..  - write block (offset block one) -> 5 offset
        write_counter = 0
        write_offset = 0
        chunk_size = 0x40
        # Note: This MIGHT just be 512 for every block... not sure.
        block_size = BANK_MAP[block_to_update][1]
        while write_offset < block_size:
            if write_offset + chunk_size > (write_offset+block_size):
                chunk_size = (write_offset+block_size) - write_offset
            res = self.device.update(OP_UPDATE_MODE_WRITE_BLOCK,write_counter,chunk_size,update_data[write_offset:write_offset+chunk_size])
            if not res:
                return False
            write_offset += chunk_size
            write_counter +=1
        # 0a 02 00 11 30 00 35 00 31 00 36 00 36 00 38 00 37 00 36 00 03 - validate serial + block
        res = self.device.update(OP_UPDATE_MODE_VALIDATE_HEADER,0,len(update_data[0x200:0x211]),update_data[0x200:0x211])
        if not res:
            return False
        # 0a 03 00 14 54 44 f6 c3 f7 04 1a c1 60 3d 73 f1 1e 6f c1 50 6b 08 64 ea - Validate HMAC
        res = self.device.update(OP_UPDATE_MODE_VALIDATE_SIGNATURE,0,len(update_data[0x211:]),update_data[0x211:])
        if not res:
            return False

        # Check to see if we can actually write with the logged in session.
        res = self.device.init_memory_block(UPDATE_SECURE_WRITE_OFFSET)
        if not res:
            return False

        return True

    def generate_update_pkg(self, bank_number, bank_data, serial_number, password):
        if bank_number not in [0,1,2,3]:
            print("Error: Only banks 0-3 can have a package generated for them.")
            self.device.last_error = LC_INVALID_PARAMETER
            return False, b""
        if len(bank_data) != 512:
            print("Error: Bank Data must be 512 bytes!")
            self.device.last_error = LC_INVALID_PARAMETER
            return False, b""
        if len(serial_number) != 8:
            print("Error: Serial Number must be 8 characters.")
            self.device.last_error = LC_INVALID_PARAMETER
            return False, b""

        if len(password) != 20:
            print("Error: Password must be 20 bytes.")
            self.device.last_error = LC_INVALID_PARAMETER

            return False, b""
        serial_number = serial_number.encode('utf-16')[2:]
        update_pkg = bank_data + serial_number + struct.pack("B",bank_number)
        res, digest = self.hmac_software(update_pkg,password)
        if res is False:
            print("HMAC Software Error")
            return False, b""

        return True, update_pkg + digest

    def get_secret_info(self):
        res,data = self.device.memory_read(UNK_SECRET_1_OFFSET,UNK_SECRET_1_SIZE)
        if not res:
            return False
        print(f"Unknown Secret 1: {binascii.hexlify(data)}")
        res,data = self.device.memory_read(UNK_SECRET_2_OFFSET,UNK_SECRET_2_SIZE)
        if not res:
            return False
        print(f"Unknown Secret 2: {binascii.hexlify(data)}")
        res,data = self.device.memory_read(UNK_SECRET_3_OFFSET,UNK_SECRET_3_SIZE)
        if not res:
            return False
        print(f"Unknown Secret 3: {binascii.hexlify(data)}")
        res,data = self.device.memory_read(UNK_SECRET_4_OFFSET,UNK_SECRET_4_SIZE)
        if not res:
            return False
        print(f"Unknown Secret 4: {binascii.hexlify(data)}")
        res,data = self.device.memory_read(HMAC_KEY_OFFSET,HMAC_KEY_SIZE)
        if not res:
            return False
        print(f"HMAC Secret: {binascii.hexlify(data)}")
        res,data = self.device.memory_read(UPDATE_KEY_OFFSET,UPDATE_KEY_SIZE)
        if not res:
            return False
        print(f"Update Secret: {binascii.hexlify(data)}")
        res,data = self.device.memory_read(ADMIN_PASS_OFFSET,ADMIN_PASS_SIZE)
        if not res:
            return False
        print(f"Admin Password: {binascii.hexlify(data[:8])}")
        print(f"Admin Retries/Counter: {binascii.hexlify(data[8:])}")
        res,data = self.device.memory_read(USER_PASS_OFFSET,USER_PASS_SIZE)
        if not res:
            return False
        admin_password = data[:8]
        print(f"User Password: {binascii.hexlify(data[:8])}")
        print(f"User Retries/Counter: {binascii.hexlify(data[8:])}")
        res,data = self.device.memory_read(AUTH_PASS_OFFSET,AUTH_PASS_SIZE)
        if not res:
            return False
        print(f"Auth Password: {binascii.hexlify(data[:8])}")
        print(f"Auth Retries/Counter: {binascii.hexlify(data[8:])}")
        return True, admin_password
