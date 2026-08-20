import gc
import os
import sys
import termios
import subprocess
import multiprocessing
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 使用 fork 模式：直接内存复制，不读磁盘，且支持 Copy-on-Write 隔离
ctx = multiprocessing.get_context('fork')

def sandbox_execute(func):
    """
    通用沙盒执行装饰器，在 fork 的新的子进程中执行。
    凡是要求使用密钥的代码，在沙盒中执行解密
    所有密钥相关的数据，在子进程结束后会被清除。
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self._encrypted_key_buffer:
            raise ValueError("No key loaded. Please ingest a key first.")

        parent_conn, child_conn = ctx.Pipe()
        
        # 内部工作函数：在孤立的子进程中跑
        def _child_worker():
            temp_plaintext_buffer = None
            try:
                # 仅在子进程内存中解密密钥
                temp_plaintext_buffer = self._decrypt(self._encrypted_key_buffer)
                if not isinstance(temp_plaintext_buffer, bytearray):
                    temp_plaintext_buffer = bytearray(temp_plaintext_buffer)
                
                # 将解密出来的 wif_buffer 作为第一个参数，动态传给原始的业务函数
                result = func(self, temp_plaintext_buffer, *args, **kwargs)
                child_conn.send({'status': 'success', 'result': result})
            except Exception as e:
                child_conn.send({'status': 'error', 'message': str(e)})
            finally:
                # 擦除子进程内存中的明文密钥
                if temp_plaintext_buffer:
                    for i in range(len(temp_plaintext_buffer)):
                        temp_plaintext_buffer[i] = 0
                    del temp_plaintext_buffer
                
                # 销毁子进程，清除所有第三方加密库留下的脏内存
                child_conn.close()
                os._exit(0)

        try:
            # 启动沙盒进程
            process = ctx.Process(target=_child_worker)
            process.start()
            
            # 接收子进程返回的数据
            response = parent_conn.recv()
            process.join()
            
            if response.get('status') == 'error':
                raise RuntimeError(f"Sandbox error in {func.__name__}: {response.get('message')}")
                
            return response.get('result')
        finally:
            parent_conn.close()

    return wrapper

class BotsKey:
    """
    主进程常驻时，内存中只有 AES 密文，没有任何明文或 WIF 痕迹。
    执行加密或者签名用到第三方lib，在沙盒中作为临时进程调用，然后立刻销毁
    """
    def __init__(self):
        # 随机生成动态主密钥
        self._memory_master_key = os.urandom(32)
        # 存放 WIF 密钥加密后的密文
        self._encrypted_key_buffer = None

    @staticmethod
    def secure_clear(data):
        if isinstance(data, bytearray) and data:
            for i in range(len(data)):
                data[i] = 0

    def _encrypt(self, plaintext_bytes: bytes) -> bytes:
        """内部方法：使用动态主密钥加密数据"""
        iv = os.urandom(16)
        cipher = AES.new(self._memory_master_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return iv + ciphertext

    def _decrypt(self, ciphertext_bytes: bytes) -> bytearray:
        """内部方法：解密密文，返回临时的明文 bytearray"""
        iv = ciphertext_bytes[:16]
        ciphertext = ciphertext_bytes[16:]
        cipher = AES.new(self._memory_master_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return bytearray(decrypted)

    def ingest_from_stdin(self, prompt: str = "Enter WIF Key: "):
        """读取用户手动输入的私钥，加密保存"""
        self.clear_current_key()
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        new_settings = termios.tcgetattr(fd)
        new_settings[3] = (
            new_settings[3] & ~termios.ECHO & ~termios.ICANON
        )  # 关闭屏幕回显
        termios.tcsetattr(fd, termios.TCSANOW, new_settings)
        print(prompt, end="", flush=True)
        
        temp_buffer = bytearray()
        while True:
            char_byte = sys.stdin.buffer.read(1)
            if char_byte == b'\n' or char_byte == b'\r':
                break
            temp_buffer.extend(char_byte)
            
        try:
            # 加密保存为密文
            self._encrypted_key_buffer = self._encrypt(bytes(temp_buffer))
        finally:
            self.secure_clear(temp_buffer)
            termios.tcsetattr(fd, termios.TCSANOW, old_settings)
            print()
        return self

    def ingest_from_pass(self, secret_path: str, lines=2) -> str:
        """读取 Unix 'pass' 密码管理器中的私钥，并返回用户名"""
        self.clear_current_key()
        result = subprocess.run(
            ["pass", secret_path],
            capture_output=True,
            text=True,
            check=True,
        )
        try:
            pass_lines = result.stdout.strip().split("\n")
            if len(pass_lines) < lines:
                raise ValueError("pass 数据错误：第一行用户名，第二行 active wif, 第三行memo wif")
            account = pass_lines[0].strip()
            self._encrypted_key_buffer = self._encrypt(pass_lines[lines-1].strip().encode('utf-8'))
            return account
        except subprocess.CalledProcessError as e:
            # e.stderr 包含了 pass 工具的错误提示（如 "gpg: decryption failed"）
            error_msg = e.stderr.strip() if e.stderr else "未知进程错误"
            print(f"❌ 凭证读取失败: {error_msg}")
            raise RuntimeError(f"Pass 密码管理器调用失败: {error_msg}")
        finally:
            if "pass_lines" in locals():
                del pass_lines
            del result
            gc.collect()  # 回收变量

    def clear_current_key(self):
        if self._encrypted_key_buffer:
            self._encrypted_key_buffer = None
        self._memory_master_key = os.urandom(32)

    def __del__(self):
        self.clear_current_key()

    @sandbox_execute
    def generate_ddp_auth_payload(self, wif_buffer: bytearray, account_name: str) -> dict:
        import time
        import json
        from btsbots.graphene_light import PrivateKey
        from binascii import hexlify
        pKey = PrivateKey.from_wif(wif_buffer.decode('utf-8'))
        pub_key = pKey.get_public_key()

        auth_data = {
            "account": account_name,
            "site": 'btsbots.com',
            "time": int(time.time())
        }
        message_str = json.dumps(auth_data, sort_keys=True)
        sig_bytes = pKey.sign_message(message_str)
        return {
            "user": account_name,
            "pubkey": pub_key,
            "verify": {
                "data": message_str,
                "signature": hexlify(sig_bytes).decode('ascii')
            }
        }

    @sandbox_execute
    def sign_transaction(self, wif_buffer: bytearray, payload: dict) -> str:
        import bitsharesbase.signedtransactions as transactions
        #from graphenebase import transactions
        from binascii import unhexlify, hexlify
        from btsbots.graphene_light import PrivateKey

        pKey = PrivateKey.from_wif(wif_buffer.decode('utf-8'))

        transaction = transactions.Signed_Transaction(
            ref_block_num=payload["ref_block_num"],
            ref_block_prefix=payload["ref_block_prefix"],
            expiration=payload["expiration"],
            operations=payload["operations"]
        )
        final_payload = transaction.json()
        # 导出序列化后的二进制 Transaction 字节流，要去掉最后一个(空的签名数组)
        serialized_tx_bytes = bytes(transaction)[:-1]
        # 添加 BitShares Chain ID
        BTS_CHAIN_ID_HEX = "4018d7844c78f6a6c41c6a552b898022310fc5dec06da467ee7905a8dad512c8"
        signing_message = unhexlify(BTS_CHAIN_ID_HEX) + serialized_tx_bytes

        custom_sig_bytes = pKey.sign_message(signing_message)
        custom_sig_hex = hexlify(custom_sig_bytes).decode('utf-8')
        final_payload["signatures"] = [custom_sig_hex]
        return final_payload

    @sandbox_execute
    def encrypt_memo(self, wif_buffer: bytearray, payload: dict) -> dict:
        from graphenebase.account import PrivateKey, PublicKey
        from graphenebase.memo import encode_memo
        import struct
        import random 
        pub_key = PublicKey(payload["to"], prefix="BTS")
        priv_key = PrivateKey(wif_buffer.decode('utf-8'), prefix="BTS")
        
        nonce_int = random.randint(100000000000000, 9007199254740991)
        
        encrypted_hex = encode_memo(priv_key, pub_key, nonce_int, payload["message"])
        
        return {
            "from": str(priv_key.pubkey),
            "to": str(pub_key),
            "nonce": str(nonce_int),
            "message": encrypted_hex
        }

    @sandbox_execute
    def decrypt_memo(self, wif_buffer: bytearray, memo_dict: dict) -> str:
        from graphenebase.account import PrivateKey, PublicKey
        from graphenebase.memo import decode_memo # 💡 引入官方自带的解密函数

        priv_key = PrivateKey(wif_buffer.decode('utf-8'), prefix="BTS")
        pub_key = PublicKey(memo_dict["from"], prefix="BTS")
        nonce_int = int(memo_dict["nonce"])
    
        # 官方的 decode_memo 内部会自动解 AES、去 Padding 并验证 Checksum
        # 如果验证失败，它内部会抛出异常
        plaintext = decode_memo(priv_key, pub_key, nonce_int, memo_dict["message"])
    
        return plaintext
