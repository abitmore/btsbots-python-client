import gc
import os
import sys
import termios
import subprocess
import multiprocessing
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

    @staticmethod
    def _sandbox_worker(pipe, secret_byte_list, payload_data, crypto_callback):
        """在完全隔离的子进程（沙盒）中运行的内部工作函数"""
        secret_buffer = bytearray(secret_byte_list)
        try:
            # 在安全的子进程中执行用户传入的签名或加密
            result = crypto_callback(secret_buffer, payload_data)
            pipe.send({"status": "success", "result": result})
        except Exception as e:
            pipe.send({"status": "error", "message": str(e)})
            #import traceback
            #traceback.print_exc()
        finally:
            BotsKey.secure_clear(secret_buffer)
            pipe.close()
            os._exit(0)

    def sign_in_sandbox(self, payload_data, crypto_callback) -> str:
        """
        在需要签名/加密时，解密密钥并送入沙盒执行。
        """
        if not self._encrypted_key_buffer:
            raise ValueError("No key loaded. Please ingest a key first.")
            
        # 解密出密钥
        temp_plaintext_buffer = self._decrypt(self._encrypted_key_buffer)
        temp_list = list(temp_plaintext_buffer)
        
        parent_conn, child_conn = multiprocessing.Pipe()
        try:
            # 密钥送入沙盒，启动新进程执行回调函数
            process = multiprocessing.Process(
                target=self._sandbox_worker, 
                args=(child_conn, temp_list, payload_data, crypto_callback)
            )
            process.start()
            
            result = parent_conn.recv()
            process.join()
        finally:
            # 清除密钥 
            self.secure_clear(temp_plaintext_buffer)
            if "temp_list" in locals():
                for i in range(len(temp_list)):
                    temp_list[i] = 0
                del temp_list  # 解除引用
        
        if result["status"] == "success":
            return result["result"]
        else:
            raise RuntimeError(f"Sandbox runtime failure: {result['message']}")

    def clear_current_key(self):
        if self._encrypted_key_buffer:
            self._encrypted_key_buffer = None
        self._memory_master_key = os.urandom(32)

    def __del__(self):
        self.clear_current_key()

    def _generate_ddp_auth_payload(self, wif_buffer: bytearray, account_name: str) -> dict:
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

    def generate_ddp_auth_payload(self, account_name: str) -> dict:
        return self.sign_in_sandbox(account_name, self._generate_ddp_auth_payload)

    def _sign_transaction(self, wif_buffer: bytearray, payload: dict) -> str:
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

    def sign_transaction(self, payload: dict) -> dict:
        return self.sign_in_sandbox(payload, self._sign_transaction)

    def _encrypt_memo(self, wif_buffer: bytearray, payload: dict) -> dict:
        from graphenebase.account import PrivateKey, PublicKey
        from graphenebase.memo import encode_memo
        import struct
        pub_key = PublicKey(payload["to"])
        priv_key = PrivateKey(wif_buffer.decode('utf-8'))
        
        # 随机生成 64位无符号整数 nonce
        nonce_tuple = struct.unpack('Q', os.urandom(8))
        nonce = nonce_tuple[0]
        
        encrypted_hex = encode_memo(priv_key, pub_key, nonce, payload["message"])
        
        return {
            "from": str(priv_key.pubkey),
            "to": str(pub_key),
            "nonce": str(nonce),
            "message": encrypted_hex
        }

    def encrypt_memo(self, payload: str) -> dict:
        return self.sign_in_sandbox(payload, self._encrypt_memo)
