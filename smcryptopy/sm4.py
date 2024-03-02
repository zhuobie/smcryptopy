from smcryptopy._smcryptopy import lib
from smcryptopy._smcryptopy import ffi
from .exceptions import *

def encrypt_ecb(input_data: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('unsigned char[]', input_data)
    key_ptr = ffi.new('unsigned char[]', key)
    output_data_len_ptr = ffi.new('size_t*')
    result_ptr = lib.encrypt_ecb(input_data_ptr, len(input_data), key_ptr, len(key), output_data_len_ptr)
    output_data_len = output_data_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, output_data_len)[:]
    lib.free_byte_array(result_ptr, output_data_len)
    return(result_bytes)

def decrypt_ecb(input_data: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('unsigned char[]', input_data)
    key_ptr = ffi.new('unsigned char[]', key)
    output_data_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_ecb(input_data_ptr, len(input_data), key_ptr, len(key), output_data_len_ptr)
    output_data_len = output_data_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, output_data_len)[:]
    lib.free_byte_array(result_ptr, output_data_len)
    return(result_bytes)

def encrypt_ecb_base64(input_data: bytes, key: bytes) -> str:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('unsigned char[]', input_data)
    key_ptr = ffi.new('unsigned char[]', key)
    result_ptr = lib.encrypt_ecb_base64(input_data_ptr, len(input_data), key_ptr, len(key))
    result_str = ffi.string(result_ptr).decode('utf-8')
    lib.free_char_array(result_ptr)
    return(result_str)

def decrypt_ecb_base64(input_data: str, key: bytes) -> bytes:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('char[]', input_data.encode('utf-8'))
    key_ptr = ffi.new('unsigned char[]', key)
    output_data_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_ecb_base64(input_data_ptr, key_ptr, len(key), output_data_len_ptr)
    output_data_len = output_data_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, output_data_len)[:]
    lib.free_byte_array(result_ptr, output_data_len)
    return(result_bytes)

def encrypt_ecb_hex(input_data: bytes, key: bytes) -> str:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('unsigned char[]', input_data)
    key_ptr = ffi.new('unsigned char[]', key)
    result_ptr = lib.encrypt_ecb_hex(input_data_ptr, len(input_data), key_ptr, len(key))
    result_str = ffi.string(result_ptr).decode('utf-8')
    lib.free_char_array(result_ptr)
    return(result_str)

def decrypt_ecb_hex(input_data: str, key: bytes) -> bytes:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('char[]', input_data.encode('utf-8'))
    key_ptr = ffi.new('unsigned char[]', key)
    output_data_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_ecb_hex(input_data_ptr, key_ptr, len(key), output_data_len_ptr)
    output_data_len = output_data_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, output_data_len)[:]
    lib.free_byte_array(result_ptr, output_data_len)
    return(result_bytes)

def encrypt_ecb_to_file(input_file: str, output_file: str, key: bytes) -> None:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_file_ptr = ffi.new('char[]', input_file.encode('utf-8'))
    output_file_ptr = ffi.new('char[]', output_file.encode('utf-8'))
    key_ptr = ffi.new('unsigned char[]', key)
    lib.encrypt_ecb_to_file(input_file_ptr, output_file_ptr, key_ptr, len(key))

def decrypt_ecb_from_file(input_file: str, output_file: str, key: bytes) -> None:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_file_ptr = ffi.new('char[]', input_file.encode('utf-8'))
    output_file_ptr = ffi.new('char[]', output_file.encode('utf-8'))
    key_ptr = ffi.new('unsigned char[]', key)
    lib.decrypt_ecb_from_file(input_file_ptr, output_file_ptr, key_ptr, len(key))

def encrypt_cbc(input_data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('unsigned char[]', input_data)
    key_ptr = ffi.new('unsigned char[]', key)
    iv_ptr = ffi.new('unsigned char[]', iv)
    output_data_len_ptr = ffi.new('size_t*')
    result_ptr = lib.encrypt_cbc(input_data_ptr, len(input_data), key_ptr, len(key), iv_ptr, len(iv), output_data_len_ptr)
    output_data_len = output_data_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, output_data_len)[:]
    lib.free_byte_array(result_ptr, output_data_len)
    return(result_bytes)

def decrypt_cbc(input_data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('unsigned char[]', input_data)
    key_ptr = ffi.new('unsigned char[]', key)
    iv_ptr = ffi.new('unsigned char[]', iv)
    output_data_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_cbc(input_data_ptr, len(input_data), key_ptr, len(key), iv_ptr, len(iv), output_data_len_ptr)
    output_data_len = output_data_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, output_data_len)[:]
    lib.free_byte_array(result_ptr, output_data_len)
    return(result_bytes)

def encrypt_cbc_base64(input_data: bytes, key: bytes, iv: bytes) -> str:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('unsigned char[]', input_data)
    key_ptr = ffi.new('unsigned char[]', key)
    iv_ptr = ffi.new('unsigned char[]', iv)
    result_ptr = lib.encrypt_cbc_base64(input_data_ptr, len(input_data), key_ptr, len(key), iv_ptr, len(iv))
    result_str = ffi.string(result_ptr).decode('utf-8')
    lib.free_char_array(result_ptr)
    return(result_str)

def decrypt_cbc_base64(input_data: str, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('char[]', input_data.encode('utf-8'))
    key_ptr = ffi.new('unsigned char[]', key)
    iv_ptr = ffi.new('unsigned char[]', iv)
    output_data_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_cbc_base64(input_data_ptr, key_ptr, len(key), iv_ptr, len(iv), output_data_len_ptr)
    output_data_len = output_data_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, output_data_len)[:]
    lib.free_byte_array(result_ptr, output_data_len)
    return(result_bytes)

def encrypt_cbc_hex(input_data: bytes, key: bytes, iv: bytes) -> str:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('unsigned char[]', input_data)
    key_ptr = ffi.new('unsigned char[]', key)
    iv_ptr = ffi.new('unsigned char[]', iv)
    result_ptr = lib.encrypt_cbc_hex(input_data_ptr, len(input_data), key_ptr, len(key), iv_ptr, len(iv))
    result_str = ffi.string(result_ptr).decode('utf-8')
    lib.free_char_array(result_ptr)
    return(result_str)

def decrypt_cbc_hex(input_data: str, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_data_ptr = ffi.new('char[]', input_data.encode('utf-8'))
    key_ptr = ffi.new('unsigned char[]', key)
    iv_ptr = ffi.new('unsigned char[]', iv)
    output_data_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_cbc_hex(input_data_ptr, key_ptr, len(key), iv_ptr, len(iv), output_data_len_ptr)
    output_data_len = output_data_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, output_data_len)[:]
    lib.free_byte_array(result_ptr, output_data_len)
    return(result_bytes)

def encrypt_cbc_to_file(input_file: str, output_file: str, key: bytes, iv: bytes) -> None:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_file_ptr = ffi.new('char[]', input_file.encode('utf-8'))
    output_file_ptr = ffi.new('char[]', output_file.encode('utf-8'))
    key_ptr = ffi.new('unsigned char[]', key)
    iv_ptr = ffi.new('unsigned char[]', iv)
    lib.encrypt_cbc_to_file(input_file_ptr, output_file_ptr, key_ptr, len(key), iv_ptr, len(iv))

def decrypt_cbc_from_file(input_file: str, output_file: str, key: bytes, iv: bytes) -> None:
    if len(key) != 16:
        raise InvalidSM4Key('Key length must be 16')
    input_file_ptr = ffi.new('char[]', input_file.encode('utf-8'))
    output_file_ptr = ffi.new('char[]', output_file.encode('utf-8'))
    key_ptr = ffi.new('unsigned char[]', key)
    iv_ptr = ffi.new('unsigned char[]', iv)
    lib.decrypt_cbc_from_file(input_file_ptr, output_file_ptr, key_ptr, len(key), iv_ptr, len(iv))
