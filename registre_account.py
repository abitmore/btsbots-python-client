import asyncio
import sys
import json
from btsbots.meteor_client import MeteorDDPClient
from btsbots.graphene_light import PrivateKey
from btsbots.utils import validate_bts_username

class RegisterClient(MeteorDDPClient):
    def __init__(self):
        super().__init__()
        self.description = "BTSBots Account Registration Tool for New Users"

    def extend_arguments(self, parser):
        parser.add_argument("--invite", type=str, required=True, help="朋友分享给您的邀请码")

    async def run(self):
        await super().run()
        args = self.args

        try:
            print(f"[*] 正在向服务器验证邀请码: {args.invite} ...")
            res = await self.call("verifyInvitation", args.invite)
            print(f"✅ 邀请码有效！推荐人账号: {res.get('creator')}")

            # 引导输入并校验 BitShares 用户名规则
            while True:
                print("\n请输入您想注册的 BitShares 用户名 (要求: 8-30位，小写字母开头，仅含小写字母、数字及非连续连字符): ", end="", flush=True)
                username = sys.stdin.readline().strip()

                is_valid, err_msg = validate_bts_username(username)
                if not is_valid:
                    print(f"❌ 规则校验不通过: {err_msg}")
                    continue

                # 远程检查用户名是否已被占用
                print(f"🔍 正在检查用户名 [{username}] 在链上是否可用...")
                existing = await self.call("get_account_document_by_symbol", username)
                if existing:
                    print(f"❌ 用户名 [{username}] 已经被注册了，请换一个。")
                    continue
                break

            print(f"🎉 用户名 [{username}] 可用！正在本地为您安全生成加密 Key 对...")

            # 随机生成私钥 (Owner, Active, Memo)
            owner_priv = PrivateKey.generate()
            active_priv = PrivateKey.generate()
            memo_priv = PrivateKey.generate()

            account_data = {
                "code": args.invite,
                "newAccountName": username,
                "ownerKey": owner_priv.get_public_key(),
                "activeKey": active_priv.get_public_key(),
                "memoKey": memo_priv.get_public_key()
            }

            print("📡 正在将注册申请提交至推荐人的安全网关...")
            sub_res = await self.call("submitAccountRegistration", account_data)
            reg_id = sub_res.get("registrationId")
            print(f"⏳ 注册申请已提交 (ID: {reg_id})，等待推荐人的 SignBots 安全网关审核并代为链上广播注册...")

            # 保存凭证文件（格式严格对齐，以便 --keyfile 识别）
            filename = f"{username}_credentials.txt"
            content = f"{username}\nOwner WIF: {owner_priv.get_wif()}\nActive WIF: {active_priv.get_wif()}\nMemo WIF: {memo_priv.get_wif()}\n"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)

            # 轮询等待注册成功
            success = False
            for _ in range(30):
                await asyncio.sleep(2)
                status_res = await self.call("checkRegistrationStatus", reg_id)
                status = status_res.get("status")
                print(".", end="", flush=True)

                if status == "success":
                    success = True
                    print(f"\n✨ 服务端反馈: 链上注册成功！详情: {status_res.get('result')}")
                    break
                elif status == "failed":
                    print(f"\n❌ 推荐人网关拒绝或注册失败: {status_res.get('result')}")
                    break

            if not success:
                raise RuntimeError("等待注册超时或未获得成功回执")

            print(f"\n\n================================================================")
            print(f" 🎉 恭喜！账号注册成功！")
            print(f" 📁 您的账号私钥凭证已安全保存在本地文件: {filename}")
            print(f" ⚠️ 请务必妥善保管该文件，切勿泄露给任何人！")
            print(f"================================================================")
            print(f" 🚀 下一步指引 (使用 --keyfile 直接加载本地凭证文件):")
            print(f" 1. 启动签名守护: uv run sign_bots.py --keyfile {filename}")
            print(f" 2. 获取 OTP 登录: uv run get_otp.py --keyfile {filename}")
            print(f"================================================================")

        except Exception as err:
            print(f"\n❌ 注册流程发生错误: {err}")
        finally:
            await self.close()

async def main():
    client = RegisterClient()
    await client.run()

if __name__ == "__main__":
    asyncio.run(main())

