from smcryptopy import sm2

(sk, pk) = sm2.gen_keypair()
assert(len(sk) == 64)
assert(len(pk) == 128)
assert(sm2.hex_valid(sk))
assert(sm2.hex_valid(pk))

pk_ = sm2.pk_from_sk(sk)
assert(pk == pk_)

assert(sm2.privkey_valid(sk))
assert(sm2.pubkey_valid(pk))

sign = sm2.sign(b'yumeng', b'abc', sk)
verify = sm2.verify(b'yumeng', b'abc', sign, pk)
assert(verify)

enc = sm2.encrypt(b'abc', pk)
dec = sm2.decrypt(enc, sk)
assert(dec == b'abc')

enc = sm2.encrypt_c1c2c3(b'abc', pk)
dec = sm2.decrypt_c1c2c3(enc, sk)
assert(dec == b'abc')

enc = sm2.encrypt_asna1(b'abc', pk)
dec = sm2.decrypt_asna1(enc, sk)
assert(dec == b'abc')

enc = sm2.encrypt_hex(b'abc', pk)
assert(sm2.hex_valid(enc))
dec = sm2.decrypt_hex(enc, sk)
assert(dec == b'abc')

enc = sm2.encrypt_base64(b'abc', pk)
assert(sm2.base64_valid(enc))
dec = sm2.decrypt_base64(enc, sk)
assert(dec == b'abc')

id_a = b'a@example.com'
id_b = b'b@example.com'
klen = 16
sk_a = sm2.gen_keypair()[0]
sk_b = sm2.gen_keypair()[0]
a_1 = sm2.keyexchange_1ab(klen, id_a, sk_a)
b_1 = sm2.keyexchange_1ab(klen, id_b, sk_b)
a_k = sm2.keyexchange_2a(id_a, sk_a, a_1[1], b_1[0])
b_k = sm2.keyexchange_2b(id_b, sk_b, b_1[1], a_1[0])
assert(a_k == b_k)
