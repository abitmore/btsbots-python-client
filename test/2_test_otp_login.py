import asyncio
import argparse
from btsbots.meteor_client import MeteorDDPClient
from btsbots.bots_client import BotsClient

class TestOtpLogin(BotsClient):

    def extend_arguments(self, parser):
        parser.add_argument(
            "--user",
            required=True,
            type=str,
            help="user name",
        )
        parser.add_argument(
            "--otp",
            required=True,
            type=str,
            help="otp code",
        )

    async def run(self):
        await MeteorDDPClient.run(self)
        args = self.args
        try:
            await self.login_with_otp(args.user, args.otp)
        except Exception as err:
            print(f"登陆失败: {err}")
            raise

async def main():

    client = TestOtpLogin()
    try:
        await client.run()

    except Exception as e:
        print(f"❌ OTP Retrieval Test Failed: {e}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
