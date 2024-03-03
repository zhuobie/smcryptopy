本项目是`smcrypto`的Python3实现，该库实现了国密`SM3`、`SM2`、`SM4`算法。

## 安装

```
pip install smcryptopy
```

## 快速开始

### SM3消息摘要算法

```python
from smcryptopy import sm3

# hash结果以16进制字符串形式返回
hash = sm3.sm3_hash(b'abc')
assert(hash == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

hash = sm3.sm3_hash_string('abc')
assert(hash == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
```

### SM2非对称加密算法

```python
from smcryptopy import sm2

# 生成密钥对，以64位或128位16进制字符串形式提供，公钥不包含开头的04标识
(sk, pk) = sm2.gen_keypair()
assert(len(sk) == 64)
assert(len(pk) == 128)
assert(sm2.hex_valid(sk))
assert(sm2.hex_valid(pk))

# 从私钥导出公钥
pk_ = sm2.pk_from_sk(sk)
assert(pk == pk_)

assert(sm2.privkey_valid(sk))
assert(sm2.pubkey_valid(pk))

# 签名和验签
sign = sm2.sign(b'yumeng', b'abc', sk)
verify = sm2.verify(b'yumeng', b'abc', sign, pk)
assert(verify)

# 加密和解密
enc = sm2.encrypt(b'abc', pk)
dec = sm2.decrypt(enc, sk)
assert(dec == b'abc')

# 加密和解密，但使用c1c2c3的排列方式
enc = sm2.encrypt_c1c2c3(b'abc', pk)
dec = sm2.decrypt_c1c2c3(enc, sk)
assert(dec == b'abc')

# 加密和解密，但使用asn1编码
enc = sm2.encrypt_asna1(b'abc', pk)
dec = sm2.decrypt_asna1(enc, sk)
assert(dec == b'abc')

# 加密和解密，但密文以16进制字符串形式提供
enc = sm2.encrypt_hex(b'abc', pk)
assert(sm2.hex_valid(enc))
dec = sm2.decrypt_hex(enc, sk)
assert(dec == b'abc')

# 加密和解密，但密文以base64编码形式提供
enc = sm2.encrypt_base64(b'abc', pk)
assert(sm2.base64_valid(enc))
dec = sm2.decrypt_base64(enc, sk)
assert(dec == b'abc')

# 密钥交换
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
```

### SM4对称加密算法

```python
from smcryptopy import sm4

# 秘钥和初始向量必须为32位16进制字符串（长度为16的字节串）
key = b'1234567812345678'
iv = b'0000000000000000'

# 加密和解密，ECB模式
enc = sm4.encrypt_ecb(b'abc', key)
dec = sm4.decrypt_ecb(enc, key)
assert(dec == b'abc')

# 加密和解密，ECB模式，密文使用base64编码形式
enc = sm4.encrypt_ecb_base64(b'abc', key)
dec = sm4.decrypt_ecb_base64(enc, key)
assert(dec == b'abc')

# 加密和解密，ECB模式，密文使用16进制字符串形式
enc = sm4.encrypt_ecb_hex(b'abc', key)
dec = sm4.decrypt_ecb_hex(enc, key)
assert(dec == b'abc')

# 加密和解密，CBC模式
enc = sm4.encrypt_cbc(b'abc', key, iv)
dec = sm4.decrypt_cbc(enc, key, iv)
assert(dec == b'abc')

# 加密和解密，CBC模式，密文使用base64编码形式
enc = sm4.encrypt_cbc_base64(b'abc', key, iv)
dec = sm4.decrypt_cbc_base64(enc, key, iv)
assert(dec == b'abc')

# 加密和解密，CBC模式，密文使用16进制字符串形式
enc = sm4.encrypt_cbc_hex(b'abc', key, iv)
dec = sm4.decrypt_cbc_hex(enc, key, iv)
assert(dec == b'abc')
```
