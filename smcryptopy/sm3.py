from smcryptopy._smcryptopy import lib
from smcryptopy._smcryptopy import ffi

def sm3_hash(msg_bytes: bytes) -> str:
    hash_result_ptr = lib.sm3_hash(ffi.new('unsigned char[]', msg_bytes), len(msg_bytes))
    hash_result_str = ffi.string(hash_result_ptr).decode('utf-8')
    lib.free_char_array(hash_result_ptr)
    return hash_result_str

def sm3_hash_string(msg_str: str) -> str:
    hash_result_ptr = lib.sm3_hash_string(ffi.new('char[]', msg_str.encode('utf-8')))
    hash_result_str = ffi.string(hash_result_ptr).decode('utf-8')
    lib.free_char_array(hash_result_ptr)
    return hash_result_str

def sm3_hash_file(file_path: str) -> None:
    hash_result_ptr = lib.sm3_hash_file(ffi.new('char[]', file_path.encode('utf-8')))
    hash_result_str = ffi.string(hash_result_ptr).decode('utf-8')
    lib.free_char_array(hash_result_ptr)
    return hash_result_str
