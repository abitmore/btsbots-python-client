import json
import asyncio
import requests
from btsbots.signbots import SignBots
import re

def get_domain(url):
    # 匹配 https://、http:// 或直接开始，直到遇到第一个斜杠或结尾
    return re.sub(r'^(https?://)?([^/]+).*$', r'\2', url)

class OauthBots(SignBots):

    def extend_arguments(self, parser):
        super().extend_arguments(parser)
        parser.add_argument(
            "--oauth_endpoint",
            type=str,
            help="call back endpoint for Oauth",
        )
        parser.add_argument(
            "--pay_endpoint",
            type=str,
            help="call back endpoint for Pay Gateway",
        )

    async def run(self):
        await super().run()
        args = self.args
        self.oauth_endpoint= self.args.oauth_endpoint
        self.pay_endpoint= self.args.pay_endpoint
        print(self.oauth_endpoint)
        self.internal_secret = "YOUR_COMM_SECRET_KEY_77777"

    async def start_oauth_queue_listener(self):
        def _on_queue_income(action, collection, doc_id, fields):
            asyncio.create_task(self.hot_reload_strategy())
            if collection == 'login_requests' and action == 'added':
                asyncio.create_task(self._verify_and_sign_oauth(doc_id, fields))
            elif collection == 'transfer' and action == 'added':
                # print(doc_id, fields)
                asyncio.create_task(self._verify_and_sign_pay(doc_id, fields))

        self.on_data_changed = _on_queue_income
        await self.subscribe("OauthLoginRequests")
        await self.subscribe("myTransfers")
        print("⚡[BTSBots] 零信任安全守卫，签名网关，正在监听中...")

    async def _verify_and_sign_pay(self, doc_id: str, fields: dict):
        if not self.pay_endpoint:
            return
        import time

        try:
            delta_time = 0
            if isinstance(fields.get('T'), dict):
                delta_time = time.time() - fields.get('T')['$date']/1000
            else:
                delta_time = time.time() - fields.get('T')

            # 只检查5分钟内的新到付款
            if delta_time > 60*5:
                return
            users = fields.get('u') 
            if users[1] != self.account_name:
                return
            if not fields.get('m'):
                return
            # transfer 的 doc_id 为什么有个 ~ 符号？？
            tx_id = int(doc_id[1:])
            memo = await self.get_memo(tx_id)
            memo_str = self.memo_key.decrypt_memo(memo)
            #print("debug", memo_str)
            post_data = {
                "type": "payment",
                "time": int(time.time()),
                "amount": fields.get('b'),
                "asset": fields.get('a'),
                "tx_id": tx_id,
                "memo": memo_str
            }
            payload = self.active_key.sign_message(json.dumps(post_data))
            response = requests.post(self.oauth_endpoint, json=payload, timeout=5)
            
            if response.status_code == 200:
                print(f"✅ [支付成功]: 网站已成功收到账单通知，网页端即将放行！")
                return True
            else:
                print(f"❌ [通知失败]: 网站后端返回了异常代码 HTTP{response.status_code} {response.text}")
                return False
        finally:
            pass
            #await self.call('RemoveOauthLoginRequest', doc_id)

    async def _verify_and_sign_oauth(self, doc_id: str, fields: dict):
        import time
        import math
        if not self.oauth_endpoint:
            return
        try:
            verify = fields.get("verify")
            #print(fields)
            if not self.active_key.verify_message(verify):
                print(f"x [授权失败]: 签名错误")
                return
            raw_payload = json.loads(verify.get("data"))
            account = raw_payload.get("account")
            account_info = await self.get_account_info(account)
            if verify.get("pubkey") not in account_info['k']['a']:
                print(f"x [授权失败]: active key 没找到签名公钥")
                return
            if get_domain(raw_payload.get("site")) != get_domain(self.oauth_endpoint):
                print(f"x [授权失败]: 网址不符合")
                return
            timeout = int(math.fabs(time.time()-raw_payload.get("time")))
            if timeout >= 2*60*1000:
                print(f"x [授权失败]: 登陆超时 {timeout} 秒")
                return

            print(f"✅[检查通过]: 用户{raw_payload.get("account")}取得合法授权")
            print(f"📡 [等待登陆]: 正在通知商户网站...")
            post_data = {
                "type": "oauth",
                "time": int(time.time()),
                "session_id": raw_payload.get("session"),
                "username": raw_payload.get("account")
            }
            payload = self.active_key.sign_message(json.dumps(post_data))
            response = requests.post(self.oauth_endpoint, json=payload, timeout=5)
            
            if response.status_code == 200:
                print(f"✅ [登陆成功]: 商户网站已成功接收到到登录授权！")
                return True
            else:
                print(f"❌ [通知失败]: 网站后端返回了异常代码 HTTP {response.status_code}")
                return False
        finally:
            await self.call('RemoveOauthLoginRequest', doc_id)

async def main():
    bot = OauthBots("wss://btsbots.com/websocket")
    try:
        await bot.run()

        await bot.start_oauth_queue_listener()
        while True:
            await asyncio.sleep(1)

    except Exception as e:
        print(f"🚨守护进程运行异常退出: {e}", flush=True)
        import traceback
        traceback.print_exc()
    finally:
        await bot.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
