from smcryptopy._smcryptopy import lib
from smcryptopy._smcryptopy import ffi
from ._exceptions import *

def gen_keypair() -> tuple[str, str]:
    keypair_ptr = lib.gen_keypair()
    keypair = ffi.new('Keypair*', keypair_ptr[0])
    keypair_sk = ffi.string(keypair.private_key).decode('utf-8')
    keypair_pk = ffi.string(keypair.public_key).decode('utf-8')
    lib.free_struct_keypair(keypair_ptr)
    return(keypair_sk, keypair_pk)

def pk_from_sk(private_key: str) -> str:
    result_pk_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if result_pk_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    result_ptr = lib.pk_from_sk(ffi.new('char[]', private_key.encode('utf-8')))
    result_str = ffi.string(result_ptr).decode('utf-8')
    lib.free_char_array(result_ptr)
    return(result_str)

def privkey_valid(private_key: str) -> int:
    result_ptr = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    return(result_ptr)

def pubkey_valid(public_key: str) -> int:
    result_ptr = lib.pubkey_valid(ffi.new('char[]', public_key.encode('utf-8')))
    return(result_ptr)

def hex_valid(input: str) -> int:
    result_ptr = lib.hex_valid(ffi.new('char[]', input.encode('utf-8')))
    return(result_ptr)

def base64_valid(input: str) -> int:
    result_ptr = lib.base64_valid(ffi.new('char[]', input.encode('utf-8')))
    return result_ptr

def keypair_from_pem_file(pem_file: str) -> tuple[str, str]:
    keypair_ptr = lib.keypair_from_pem_file(ffi.new('char[]', pem_file.encode('utf-8')))
    keypair = ffi.new('Keypair*', keypair_ptr[0])
    keypair_sk = ffi.string(keypair.private_key).decode('utf-8')
    keypair_pk = ffi.string(keypair.public_key).decode('utf-8')
    lib.free_struct_keypair(keypair_ptr)
    return(keypair_sk, keypair_pk)

def keypair_to_pem_file(private_key: str, pem_file: str) -> None:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    pem_file_ptr = ffi.new('char[]', pem_file.encode('utf-8'))
    lib.keypair_to_pem_file(private_key_ptr, pem_file_ptr)

def pubkey_from_pem_file(pem_file: str) -> str:
    pubkey_ptr = lib.pubkey_from_pem_file(ffi.new('char[]', pem_file.encode('utf-8')))
    pubkey_str = ffi.string(pubkey_ptr).decode('utf-8')
    lib.free_char_array(pubkey_ptr)
    return(pubkey_str)

def pubkey_to_pem_file(public_key: str, pem_file: str) -> None:
    public_key_valid = lib.pubkey_valid(ffi.new('char[]', public_key.encode('utf-8')))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    pem_file_ptr = ffi.new('char[]', pem_file.encode('utf-8'))
    lib.pubkey_to_pem_file(public_key_ptr, pem_file_ptr)

def sign(id: bytes, data: bytes, private_key: str) -> bytes:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    id_ptr = ffi.new('unsigned char[]', id)
    data_ptr = ffi.new('unsigned char[]', data)
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    sig_len_ptr = ffi.new('uintptr_t*')
    result_ptr = lib.sign(id_ptr, len(id), data_ptr, len(data), private_key_ptr, sig_len_ptr)
    sig_len = sig_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, sig_len)[:]
    lib.free_byte_array(result_ptr, sig_len)
    return(result_bytes)

def verify(id: bytes, data: bytes, sign: bytes, public_key: str) -> int:
    public_key_valid = lib.pubkey_valid(public_key.encode('utf-8'))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    id_ptr = ffi.new('unsigned char[]', id)
    data_ptr = ffi.new('unsigned char[]', data)
    sign_ptr = ffi.new('unsigned char[]', sign)
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    result_ptr = lib.verify(id_ptr, len(id), data_ptr, len(data), sign_ptr, len(sign), public_key_ptr)
    return(result_ptr)

def sign_to_file(id: bytes, data: bytes, sign_file: str, private_key: str) -> None:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    id_ptr = ffi.new('unsigned char[]', id)
    data_ptr = ffi.new('unsigned char[]', data)
    sign_file_ptr = ffi.new('char[]', sign_file.encode('utf-8'))
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    lib.sign_to_file(id_ptr, len(id), data_ptr, len(data), sign_file_ptr, private_key_ptr)

def verify_from_file(id: bytes, data: bytes, sign_file: str, public_key: str) -> int:
    public_key_valid = lib.pubkey_valid(public_key.encode('utf-8'))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    id_ptr = ffi.new('unsigned char[]', id)
    data_ptr = ffi.new('unsigned char[]', data)
    sign_file_ptr = ffi.new('char[]', sign_file.encode('utf-8'))
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    result_ptr = lib.verify_from_file(id_ptr, len(id), data_ptr, len(data), sign_file_ptr, public_key_ptr)
    return(result_ptr)

def encrypt(data: bytes, public_key: str) -> bytes:
    public_key_valid = lib.pubkey_valid(public_key.encode('utf-8'))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    data_ptr = ffi.new('unsigned char[]', data)
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    enc_len_ptr = ffi.new('size_t*')
    result_ptr = lib.encrypt(data_ptr, len(data), public_key_ptr, enc_len_ptr)
    enc_len = enc_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, enc_len)[:]
    lib.free_byte_array(result_ptr, enc_len)
    return(result_bytes)

def decrypt(data: bytes, private_key: str) -> bytes:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    data_ptr = ffi.new('unsigned char[]', data)
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    dec_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt(data_ptr, len(data), private_key_ptr, dec_len_ptr)
    dec_len = dec_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, dec_len)[:]
    lib.free_byte_array(result_ptr, dec_len)
    return(result_bytes)

def encrypt_c1c2c3(data: bytes, public_key: str) -> bytes:
    public_key_valid = lib.pubkey_valid(public_key.encode('utf-8'))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    data_ptr = ffi.new('unsigned char[]', data)
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    enc_len_ptr = ffi.new('size_t*')
    result_ptr = lib.encrypt_c1c2c3(data_ptr, len(data), public_key_ptr, enc_len_ptr)
    enc_len = enc_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, enc_len)[:]
    lib.free_byte_array(result_ptr, enc_len)
    return(result_bytes)

def decrypt_c1c2c3(data: bytes, private_key: str) -> bytes:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    data_ptr = ffi.new('unsigned char[]', data)
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    dec_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_c1c2c3(data_ptr, len(data), private_key_ptr, dec_len_ptr)
    dec_len = dec_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, dec_len)[:]
    lib.free_byte_array(result_ptr, dec_len)
    return(result_bytes)

def encrypt_asna1(data: bytes, public_key: str) -> bytes:
    public_key_valid = lib.pubkey_valid(public_key.encode('utf-8'))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    data_ptr = ffi.new('unsigned char[]', data)
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    enc_len_ptr = ffi.new('size_t*')
    result_ptr = lib.encrypt_asna1(data_ptr, len(data), public_key_ptr, enc_len_ptr)
    enc_len = enc_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, enc_len)[:]
    lib.free_byte_array(result_ptr, enc_len)
    return(result_bytes)

def decrypt_asna1(data: bytes, private_key: str) -> bytes:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    data_ptr = ffi.new('unsigned char[]', data)
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    dec_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_asna1(data_ptr, len(data), private_key_ptr, dec_len_ptr)
    dec_len = dec_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, dec_len)[:]
    lib.free_byte_array(result_ptr, dec_len)
    return(result_bytes)

def encrypt_hex(data: bytes, public_key: str) -> str:
    public_key_valid = lib.pubkey_valid(public_key.encode('utf-8'))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    data_ptr = ffi.new('unsigned char[]', data)
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    result_ptr = lib.encrypt_hex(data_ptr, len(data), public_key_ptr)
    result_str = ffi.string(result_ptr).decode('utf-8')
    lib.free_char_array(result_ptr)
    return(result_str)

def decrypt_hex(data: str, private_key: str) -> bytes:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    data_ptr = ffi.new('char[]', data.encode('utf-8'))
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    dec_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_hex(data_ptr, private_key_ptr, dec_len_ptr)
    dec_len = dec_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, dec_len)[:]
    lib.free_byte_array(result_ptr, dec_len)
    return(result_bytes)

def encrypt_base64(data: bytes, public_key: str) -> str:
    public_key_valid = lib.pubkey_valid(public_key.encode('utf-8'))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    data_ptr = ffi.new('unsigned char[]', data)
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    result_ptr = lib.encrypt_base64(data_ptr, len(data), public_key_ptr)
    result_str = ffi.string(result_ptr).decode('utf-8')
    lib.free_char_array(result_ptr)
    return(result_str)

def decrypt_base64(data: str, private_key: str) -> bytes:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    data_ptr = ffi.new('char[]', data.encode('utf-8'))
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    dec_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_base64(data_ptr, private_key_ptr, dec_len_ptr)
    dec_len = dec_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, dec_len)[:]
    lib.free_byte_array(result_ptr, dec_len)
    return(result_bytes)

def encrypt_to_file(data: bytes, enc_file: str, public_key: str) -> None:
    public_key_valid = lib.pubkey_valid(public_key.encode('utf-8'))
    if public_key_valid == 0:
        raise InvalidPublicKey('Invalid public key')
    data_ptr = ffi.new('unsigned char[]', data)
    enc_file_ptr = ffi.new('char[]', enc_file.encode('utf-8'))
    public_key_ptr = ffi.new('char[]', public_key.encode('utf-8'))
    lib.encrypt_to_file(data_ptr, len(data), enc_file_ptr, public_key_ptr)

def decrypt_from_file(dec_file: str, private_key: str) -> bytes:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    dec_file_ptr = ffi.new('char[]', dec_file.encode('utf-8'))
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    dec_len_ptr = ffi.new('size_t*')
    result_ptr = lib.decrypt_from_file(dec_file_ptr, private_key_ptr, dec_len_ptr)
    dec_len = dec_len_ptr[0]
    result_bytes = ffi.buffer(result_ptr, dec_len)[:]
    lib.free_byte_array(result_ptr, dec_len)
    return(result_bytes)

def keyexchange_1ab(klen: int, id: bytes, private_key: str) -> tuple[bytes, str]:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    id_ptr = ffi.new('unsigned char[]', id)
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    data_len_ptr = ffi.new('size_t*')
    keyexchangedata_ptr = lib.keyexchange_1ab(klen, id_ptr, len(id), private_key_ptr, data_len_ptr)
    data_len = data_len_ptr[0]
    keyexchangedata = ffi.new('KeyExchangeData*', keyexchangedata_ptr[0])
    data_ptr = keyexchangedata.data
    data_bytes = ffi.buffer(data_ptr, data_len)[:]
    private_key_r_ptr = keyexchangedata.private_key_r
    private_key_r_str = ffi.string(private_key_r_ptr).decode('utf-8')
    lib.free_struct_keyexchangedata(keyexchangedata_ptr)
    return(data_bytes, private_key_r_str)

def keyexchange_2a(id: bytes, private_key: str, private_key_r: str, recive_bytes: bytes) -> tuple[str, bytes]:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    private_key_r_valid = lib.privkey_valid(ffi.new('char[]', private_key_r.encode('utf-8')))
    if private_key_r_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    id_ptr = ffi.new('unsigned char[]', id)
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    private_key_r_ptr = ffi.new('char[]', private_key_r.encode('utf-8'))
    recive_bytes_ptr = ffi.new('unsigned char[]', recive_bytes)
    s12_len_ptr = ffi.new('size_t*')
    keyexchangeresult_ptr = lib.keyexchange_2a(id_ptr, len(id), private_key_ptr, private_key_r_ptr, recive_bytes_ptr, len(recive_bytes), s12_len_ptr)
    s12_len = s12_len_ptr[0]
    keyexchangeresult = ffi.new('KeyExchangeResult*', keyexchangeresult_ptr[0])
    k_ptr = keyexchangeresult.k
    s12_ptr = keyexchangeresult.s12
    k_str = ffi.string(k_ptr).decode('utf-8')
    s12_bytes = ffi.buffer(s12_ptr, s12_len)[:]
    lib.free_struct_keyexchangeresult(keyexchangeresult_ptr)
    return(k_str, s12_bytes)

def keyexchange_2b(id: bytes, private_key: str, private_key_r: str, recive_bytes: bytes) -> tuple[str, bytes]:
    private_key_valid = lib.privkey_valid(ffi.new('char[]', private_key.encode('utf-8')))
    if private_key_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    private_key_r_valid = lib.privkey_valid(ffi.new('char[]', private_key_r.encode('utf-8')))
    if private_key_r_valid == 0:
        raise InvalidPrivateKey('Invalid private key')
    id_ptr = ffi.new('unsigned char[]', id)
    private_key_ptr = ffi.new('char[]', private_key.encode('utf-8'))
    private_key_r_ptr = ffi.new('char[]', private_key_r.encode('utf-8'))
    recive_bytes_ptr = ffi.new('unsigned char[]', recive_bytes)
    s12_len_ptr = ffi.new('size_t*')
    keyexchangeresult_ptr = lib.keyexchange_2b(id_ptr, len(id), private_key_ptr, private_key_r_ptr, recive_bytes_ptr, len(recive_bytes), s12_len_ptr)
    s12_len = s12_len_ptr[0]
    keyexchangeresult = ffi.new('KeyExchangeResult*', keyexchangeresult_ptr[0])
    k_ptr = keyexchangeresult.k
    s12_ptr = keyexchangeresult.s12
    k_str = ffi.string(k_ptr).decode('utf-8')
    s12_bytes = ffi.buffer(s12_ptr, s12_len)[:]
    lib.free_struct_keyexchangeresult(keyexchangeresult_ptr)
    return(k_str, s12_bytes)
