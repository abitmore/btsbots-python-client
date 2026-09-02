import asyncio
import argparse
from btsbots.bots_client import BotsClient

class InvitationTool(BotsClient):
    def extend_arguments(self, parser):
        super().extend_arguments(parser)
        parser.add_argument("--action", type=str, required=True, choices=["generate", "list"], help="操作类型: generate(生成) 或 list(查看)")

    async def run(self):
        await super().run()
        args = self.args
        try:
            if args.action == "generate":
                print(f"[*] 正在为账号 [{self.account_name}] 生成新的邀请码...")
                code = await self.call("generateInvitation", self.account_name)
                print("==================================================")
                print(f" ✨ 成功生成邀请码: {code}")
                print("==================================================")
            elif args.action == "list":
                print(f"[*] 正在通过 RPC 获取账号 [{self.account_name}] 的邀请码列表...")
                invitations = await self.call("listInvitations", self.account_name)

                print("==================================================")
                print(f" 📋 邀请码列表 (共 {len(invitations)} 个):")
                print("==================================================")
                for inv in invitations:
                    status = "🟢 已使用" if inv.get("status") == "used" else "🔵 未使用"
                    used_by = f" -> 注册用户: {inv.get('usedBy')}" if inv.get("usedBy") else ""
                    print(f" • 邀请码: {inv.get('code')} | 状态: {status}{used_by}")
                print("==================================================")
        except Exception as err:
            print(f"❌ 操作失败: {err}")
        finally:
            await self.close()

async def main():
    tool = InvitationTool()
    await tool.run()

if __name__ == "__main__":
    asyncio.run(main())

