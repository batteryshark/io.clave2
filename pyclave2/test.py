import binascii

from LCApi import LCApi

def test_convert(d: LCApi):
    print("Test Convert [Encrypt/Decrypt]...")
    opt = b"1234567890123456"
    res,ctxt = d.encrypt(opt)
    if(not res):
        print("Encrypt Failed")
        return False
    print("Encrypt OK!")
    print(binascii.hexlify(ctxt))

    res, ptxt = d.decrypt(ctxt)
    if (not res):
        print("Decrypt Failed")
        return False
    print("Encrypt / Decrypt OK!")
    print(binascii.hexlify(ptxt))
    return True


def test_read_write(d: LCApi):
    print("Test Write / Read...")
    write_data = b"1" * 512
    res = d.write(0, write_data)
    if not res:
        print("Test Write Fail!")
        return False
    print("Test Write OK!")
    res, read_data = d.read(0)
    if not res:
        print("Test Read Fail")
        return False

    print("Test Read OK!")
    print(binascii.hexlify(read_data))
    return True

def test_get_secret_info(d: LCApi):
    res = d.get_secret_info()
    return True

def test_get_hardware_info(d: LCApi):
    print("Test Get Hardware Info...")
    res, info = d.get_hardware_info()
    if res:
        print("Get Info OK!")
        print(info)
        return True
    else:
        print("Get Info Error!")
        return False

def test_hmac(d: LCApi):
    print("Test HMAC [Hardware]")
    res, digest = d.hmac(b"THE_RAIN_IN_SPAIN")
    if res:
        print("HMAC OK!")
        print(binascii.hexlify(digest))
        return True
    else:
        print("HMAC Error!")
        return False

def test_change_auth_password(d: LCApi):
    print("Test Change Auth Password")
    oapw = "12345678"
    napw = "55667788"
    res = api.change_auth_password(oapw,napw)
    if not res:
        print("Test Change Auth Password Fail!")
        return False
    print("Test Change Auth Password OK!")
    return True

def test_set_password(d: LCApi):
    print("Test Set Admin Password")
    res = api.set_password(0,"12345678")
    if not res:
        print("Test Set Password Fail!")
        return False
    print("Test Set User Password")
    res = api.set_password(1,"12345678")
    if not res:
        print("Test Set Password Fail!")
        return False
    print("Test Set Auth Password")
    res = api.set_password(2,"12345678",6)
    if not res:
        print("Test Set Password Fail!")
        return False

def test_gen_upkg(d: LCApi):
    print("Test Update Package Generation")
    password = b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
    serial = "05166876"
    data = b"\x01" * 512
    res, pkg = d.generate_update_pkg(2, data, serial, password)
    if res is False:
        print("Generate Update Package Failed!")
        return False
    print("Generate Update Package OK!")
    print(binascii.hexlify(pkg))
    return True

def test_update(d: LCApi):
    print("Test Update")
    upd_data = binascii.unhexlify("010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010130003500310036003600380037003600025537f7ef00a584ec03cb8965c470388638ed77c1")
    if d.update(upd_data) is False:
        print("Update Fail!")
        return False
    print("Update OK!")
    return True

def test_set_key(d: LCApi):
    print("Test Set Key: 0 - Remote Update Key")
    key = b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
    if d.set_key(0,key) == False:
        print("Set Key Fail!")
        return False
    print("Test Set Key 0: OK!")
    print("Test Set Key: 1 - Authentication Key")
    if d.set_key(1,key) == False:
        print("Set Key Fail!")
        return False
    print("Test Set Key 1: OK!")
    return True

if __name__ == "__main__":
    api = LCApi()
    res, status_code = api.login(1,"12345678")
    if not res:
        print("Login Failed!")
        exit(-1)
    #test_convert(api)
    #test_read_write(api)
    #test_get_hardware_info(api)
    #test_hmac(api)
    #test_change_auth_password(api)
    #test_set_password(api)
    test_get_secret_info(api)
    #test_gen_upkg(api)
    #test_set_key(api)
    #test_update(api)
    api.logout()


"""

Update
Set Key

"""