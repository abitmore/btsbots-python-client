import json
from btsbots.graphene_light import PrivateKey 
from binascii import hexlify

def authenticate_meteor_client(auth_data: dict, wif_str: str, account: str) -> dict:
    """
    处理认证数据并封装成发送给 Meteor DDP 的 Payload
    """
    try:
        priv_key_obj = PrivateKey.from_wif(wif_str)
        message_str = json.dumps(auth_data, sort_keys=True)
        sig_bytes = priv_key_obj.sign_message(message_str)
    except Exception as e:
        raise Exception(f"Pure-Python signing failed: {e}")

    login_data = {
        "user": account,
        "pubkey": priv_key_obj.get_public_key(),
        "verify": {
            "data": message_str,
            "signature": hexlify(sig_bytes).decode('ascii')
        },
        "clientType": "python"
    }

    return login_data


# ==============================================================================
# 3. 闭环合并运行测试流
# ==============================================================================

if __name__ == "__main__":
    # 【已修正】使用确定匹配的真实 WIF 私钥与预期的公钥
    test_wif = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
    test_account = "test-account"
    expected_pubkey = "BTS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"

    print("==================================================")
    print("🚀 [准备工作] 校验公钥派生一致性")
    print("==================================================")

    pKey = PrivateKey.from_wif(test_wif)
    derived_pubkey = pKey.get_public_key()
    print(f"期待的公钥值: {expected_pubkey}")
    print(f"实际计算出的: {derived_pubkey}")

    if derived_pubkey == expected_pubkey:
        print("🟢 公钥一致性校验成功！")
    else:
        print("🔴 公钥一致性校验失败，请检查逻辑。")

    print("\n==================================================")
    print("🚀 [测试 1] 验证：Meteor 模拟 Login 签名流程")
    print("==================================================")

    mock_auth_data = {
        "account": test_account,
        "timestamp": 1717171717
    }

    try:
        login_payload = authenticate_meteor_client(mock_auth_data, test_wif, test_account)
        print("🎉 测试 1 成功！生成的登录 Payload 结果：")
        print(json.dumps(login_payload, indent=4))
    except Exception as err:
        print(f"❌ 测试 1 运行失败: {err}")
