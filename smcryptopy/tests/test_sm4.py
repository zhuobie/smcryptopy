from smcryptopy import sm4

key = b'1234567812345678'
iv = b'0000000000000000'

enc = sm4.encrypt_ecb(b'abc', key)
dec = sm4.decrypt_ecb(enc, key)
assert(dec == b'abc')

enc = sm4.encrypt_ecb_base64(b'abc', key)
dec = sm4.decrypt_ecb_base64(enc, key)
assert(dec == b'abc')

enc = sm4.encrypt_ecb_hex(b'abc', key)
dec = sm4.decrypt_ecb_hex(enc, key)
assert(dec == b'abc')

enc = sm4.encrypt_cbc(b'abc', key, iv)
dec = sm4.decrypt_cbc(enc, key, iv)
assert(dec == b'abc')

enc = sm4.encrypt_cbc_base64(b'abc', key, iv)
dec = sm4.decrypt_cbc_base64(enc, key, iv)
assert(dec == b'abc')

enc = sm4.encrypt_cbc_hex(b'abc', key, iv)
dec = sm4.decrypt_cbc_hex(enc, key, iv)
assert(dec == b'abc')
