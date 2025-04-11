from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import os
import argparse

def generate_rsa_keys(private_key_file="private_key.pem", public_key_file="public_key.pem"):
    """生成 RSA 密钥对，并保存到文件中"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_key_file, "wb") as f:
        f.write(private_key)

    with open(public_key_file, "wb") as f:
        f.write(public_key)

    print(f"密钥对已生成并保存到 {private_key_file} 和 {public_key_file}。")

def encrypt_file(input_file, output_file, public_key_file):
    """使用 RSA 和 AES 加密文件内容"""
    # 加载公钥
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # 生成随机 AES 密钥
    aes_key = get_random_bytes(32)  # 256 位 AES 密钥
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)

    # 读取文件内容
    with open(input_file, "rb") as f:
        data = f.read()

    # AES 加密数据
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # RSA 加密 AES 密钥
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # 将加密后的 AES 密钥、nonce 和加密数据保存到文件
    with open(output_file, "wb") as f:
        f.write(encrypted_aes_key + b'|||')  # 保存加密后的 AES 密钥
        f.write(cipher_aes.nonce + b'|||')   # 保存 AES 非对称加密的随机数
        f.write(tag + b'|||')                # 保存 AES 的认证标签
        f.write(ciphertext)                  # 保存加密数据

    print(f"文件已加密并保存到 {output_file}")

def decrypt_file(input_file, output_file, private_key_file):
    """使用 RSA 和 AES 解密文件内容"""
    # 加载私钥
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # 读取加密文件内容
    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    # 解析加密数据
    parts = encrypted_data.split(b'|||')
    if len(parts) != 4:
        raise ValueError("加密数据格式不正确")

    encrypted_aes_key = parts[0]
    nonce = parts[1]
    tag = parts[2]
    ciphertext = parts[3]

    # RSA 解密 AES 密钥
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # AES 解密数据
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # 保存解密后的数据到文件
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"文件已解密并保存到 {output_file}")

def main():
    parser = argparse.ArgumentParser(description="RSA 和 AES 加密/解密工具")
    parser.add_argument("--generate-keys", action="store_true", help="生成 RSA 密钥对")
    parser.add_argument("--encrypt", action="store_true", help="加密文件")
    parser.add_argument("--decrypt", action="store_true", help="解密文件")
    parser.add_argument("--input", type=str, help="输入文件路径")
    parser.add_argument("--output", type=str, help="输出文件路径")
    parser.add_argument("--public-key", type=str, default="public_key.pem", help="公钥文件路径")
    parser.add_argument("--private-key", type=str, default="private_key.pem", help="私钥文件路径")

    args = parser.parse_args()

    if args.generate_keys:
        generate_rsa_keys(args.private_key, args.public_key)
    elif args.encrypt:
        if not args.input or not args.output:
            parser.error("--encrypt 需要 --input 和 --output 参数")
        encrypt_file(args.input, args.output, args.public_key)
    elif args.decrypt:
        if not args.input or not args.output:
            parser.error("--decrypt 需要 --input 和 --output 参数")
        decrypt_file(args.input, args.output, args.private_key)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
