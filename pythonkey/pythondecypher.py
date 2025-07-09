import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

data_base64 = "24dNdrtdLXpbaCBnuMrA61gAtOnmP+hXPVOf2ABa50ThqXMWI0U3AZ1iStEmM2be"

aes_key_hex = "a6100a325a0e3fed267caec1c056c1b555abb3ab799ab05b26db63d9edd15ce4"  # ejemplo
key = bytes.fromhex(aes_key_hex)

raw_data = base64.b64decode(data_base64)
iv = raw_data[:16]
ciphertext = raw_data[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("Texto descifrado:", decrypted.decode("utf-8"))
