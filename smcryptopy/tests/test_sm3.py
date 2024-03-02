from smcryptopy import sm3

hash = sm3.sm3_hash(b'abc')
assert(hash == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

hash = sm3.sm3_hash_string('abc')
assert(hash == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
