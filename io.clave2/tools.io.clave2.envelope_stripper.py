# Script to Patch out Debug and Integrity Checks in a Senselock Clave2 Enveloped Executable
import struct
import pefile
import sys
import os
import binascii



def rva_to_file_offset(path_to_exe,rva):
	
	pe = pefile.PE(path_to_exe)
	pd = pe.dump_dict()
	va = rva - pd['OPTIONAL_HEADER']['ImageBase']['Value']
	
	for section in pd['PE Sections']:
			begin = section['VirtualAddress']['Value']
			end = section['VirtualAddress']['Value'] + section['Misc_VirtualSize']['Value']
			if(va > begin and va < end):
				file_offset = rva - section['VirtualAddress']['Value'] + section['PointerToRawData']['Value']
				file_offset -= pd['OPTIONAL_HEADER']['ImageBase']['Value']
				del pe
				return file_offset
	return 0
	del pe


def get_oep(path_to_exe,va_ep):
	file_ep = rva_to_file_offset(path_to_exe,va_ep)
	start = file_ep+0x5B
	with open(path_to_exe,"rb") as f:
		f.seek(start)
		abs_ptr_addr = struct.unpack("<I",f.read(4))[0]
		abs_file_addr = rva_to_file_offset(path_to_exe,abs_ptr_addr)
		f.seek(abs_file_addr)
		return struct.unpack("<I",f.read(4))[0]

def get_exe_info(path_to_exe):
	pe = pefile.PE(path_to_exe)
	pd = pe.dump_dict()
	
	pi = {
		'va_ep':0,
		'file_ep':0,
		'va_oep':0
	}
	
	pi['va_ep'] = pd['OPTIONAL_HEADER']['AddressOfEntryPoint']['Value'] + pd['OPTIONAL_HEADER']['ImageBase']['Value']
	pi['file_ep'] = rva_to_file_offset(path_to_exe,pi['va_ep'])
	pi['va_oep'] = get_oep(path_to_exe,pi['va_ep'])

	return pi

def get_dongle_info(path_to_exe,prep_offset):
	ddb = {
		'developer_id':0,
		'general_password':"",
		'wrapped_exe_key':""
	}
	with open(path_to_exe,"rb") as f:
		f.seek(prep_offset+0x65)
		ptr_senselock_data = struct.unpack("<I",f.read(4))[0]
		f.seek(rva_to_file_offset(path_to_exe,ptr_senselock_data))
		buffer = f.read(0x428)
		ddb['developer_id'] = struct.unpack("<I",buffer[0x404:0x408])[0]
		ddb['general_password'] = buffer[0x420:0x428]
		ddb['wrapped_exe_key'] = binascii.hexlify(buffer[0x410:0x420])
		print(ddb)
	return ddb

def nop_region(data,offset,amt):
	print("NOP Region: 0x%04X %d Bytes" % (offset,amt))
	data[offset:offset+amt] = b"\x90" * amt
	return data

def patch_exe(path_to_exe,exe_info):
	data = b""
	with open(path_to_exe,"rb") as f:
		data = bytearray(f.read())
	
	# Start Function Address
	start = exe_info['file_ep']
	
	# Get Dongle Info
	prep_address = (start+0x60) + 4 + struct.unpack("<i",data[start+0x60:start+0x64])[0]
	ddb = get_dongle_info(path_to_exe,prep_address)
	print("Clave2 Info:")
	print(ddb)
	
	
	# NOP Initial VM Checks
	#data = nop_region(data,start+0x6B,0x43)
	# NOP Checksum 1, Location 1
	data = nop_region(data,start+0x1DC,0x05)
	# NOP Checksum 1, Location 2	
	data = nop_region(data,start+0x283,0x05)
	# NOP Checksum 2
	data = nop_region(data,start+0x2AF,0x05)
	
	# NOP Check Dongle, Location 1
	#data = nop_region(data,start+0x1E3,0x05)
	# NOP Check Dongle, Location 2	
	#data = nop_region(data,start+0x2FE,0x05)
	
	# Unpack Text AntiDebug Patches
	unpack_text_address = (start+0x2C9) + 4 + struct.unpack("<i",data[start+0x2C9:start+0x2CD])[0]
	#data = nop_region(data,unpack_text_address+0x12,0x14)
	data = nop_region(data,unpack_text_address+0x30,0x05)
	
	# Unpack IAT AntiDebug Patches
	unpack_iat_address = (start+0x2DA) + 4 + struct.unpack("<i",data[start+0x2DA:start+0x2DE])[0]
	# data = nop_region(data,unpack_iat_address+0x07,0x41)
	# Trap - OutputDebugStringA
	#data = nop_region(data,unpack_iat_address+0x07,0x05)
	# Patch out Trap DebugBreak
	#data = nop_region(data,unpack_iat_address+0x0C,0x05)
	# Trap Softice bp
	#data = nop_region(data,unpack_iat_address+0x11,0x05)
	# Trap int 2d
	#data = nop_region(data,unpack_iat_address+0x16,0x05)
	# Trap Divide by Zero
	#data = nop_region(data,unpack_iat_address+0x1B,0x05)
	# Trap FS_ODP_Process32NextW
	#data = nop_region(data,unpack_iat_address+0x20,0x05)
	# Trap CheckRemoteDebuggerPresent
	#data = nop_region(data,unpack_iat_address+0x25,0x05)
	# Trap NtSetInformationThread
	#data = nop_region(data,unpack_iat_address+0x2A,0x05)
	# Trap UnhandledExceptionFilter
	#data = nop_region(data,unpack_iat_address+0x2F,0x05)
	# Query Service Status
	#data = nop_region(data,unpack_iat_address+0x34,0x05)
	# FGJM Trap to Debugger trap_int3_debugcheck
	#data = nop_region(data,unpack_iat_address+0x39,0x05)
	# Trap Blockinput 1
	#data = nop_region(data,unpack_iat_address+0x3E,0x05)
	# Trap Blockinput 0
	#data = nop_region(data,unpack_iat_address+0x43,0x05)

	
	# IDK AntiDebug Patches
	#idk_address = (start+0x213) + 4 + struct.unpack("<i",data[start+0x213:start+0x217])[0]
	#data = nop_region(data,idk_address+0x11D,0x1E)
	
	output_path = os.path.splitext(path_to_exe)[0] + "_NO_ANTIDEBUG.exe"
	with open(output_path,"wb") as g:
		g.write(data)	
	return output_path
	
def usage():
	print("%s path/to/exe" % sys.argv[0])
	exit(-1)
	
if __name__=="__main__":
	if len(sys.argv) < 2:
		usage()
	if not os.path.exists(sys.argv[1]):
		print("EXE Path Invalid")
		usage()
		
	path_to_exe = sys.argv[1]
	
	exe_info = get_exe_info(path_to_exe)

	output_path = patch_exe(path_to_exe,exe_info)
	print("Created Patched EXE: %s" % output_path)
	print("OEP is 0x%04X" % exe_info['va_oep'])
	print("Done!")
	exit(0)
	