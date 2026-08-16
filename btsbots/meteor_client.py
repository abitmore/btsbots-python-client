import asyncio
import json
import uuid
import websockets
from websockets.legacy.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed
from typing import Callable, Optional
import argparse

def generate_subscription_id(pub_name: str, params: list) -> str:
    """Generates a stable, unique 16-character hexadecimal DDP Subscription ID 
    based on the subscription name and its parameters.
    """
    import hashlib
    # 1. Ensure parameters are evaluated consistently by ordering keys in dictionaries
    # (Fixes the issue where {'a': 1, 'b': 2} hashes differently than {'b': 2, 'a': 1})
    serialized_params = json.dumps(params, sort_keys=True)
    
    # 2. Combine the publication name and serialized arguments into a single string payload
    payload = f"{pub_name}::{serialized_params}"
    
    # 3. Create an MD5 hash of the payload (encoded to UTF-8 bytes)
    hasher = hashlib.md5(payload.encode('utf-8'))
    
    # 4. Return the hex digest. We slice it to 16 characters for a cleaner DDP message string.
    return hasher.hexdigest()[:16]

class MeteorDDPClient:
    def __init__(self, url: str):
        self.url: str = url 
        self.ws: Optional[websockets.WebSocketClientStream] = None
        self.on_data_changed: Optional[Callable[[str, str, str, dict], None]] = None
        self._pending_responses = {}
        self._keep_connect_task = None
        self._listener_task: Optional[asyncio.Task] = None
        self.collections: dict[str, dict[str, dict]] = {}
        self.description = "meteor ddp client"

        self.subscriptions = {}   
        self.login_token = None      # 缓存服务端回传的长期登录令牌
        self._next_id = 1            # DDP 消息序号计数器
        self.args = None

    async def run(self):
        args = self._parse_arguments()
        self.args = args
        if args.url:
            self.url = args.url
        loop = asyncio.get_running_loop()
        try:
            await self._connect()
            self._keep_connect_task = asyncio.create_task(self._keep_connect())
            # 执行具体的 Meteor 登录和业务（留给子类实现）
        except Exception as e:
            print(f"❌ 运行中发生错误: {e}")

    def _parse_arguments(self):
        """解析通用的命令行参数"""
        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument(
            "--url",
            type=str,
            default="wss://btsbots.com/websocket",
            help="Meteor DDP websocket URL",
        )
        # 允许子类扩展特定参数
        self.extend_arguments(parser)
        return parser.parse_args()

    def extend_arguments(self, parser):
        """留给子类重写：如果特定脚本需要额外参数（如 --symbol BTC），可以在这里添加"""
        pass

    async def _connect(self):
        try:
            print(f"[*] 正在连接 Meteor 节点: {self.url}")
            self.ws = await ws_connect(self.url)
            
            # DDP 协议握手帧
            await self.ws.send('{"msg": "connect", "version": "1", "support": ["1"]}')
            connected_response = await self.ws.recv()
            print("🔌[DDP 协议] 连接已激活。")
 
            # 判定是【断线恢复】还是【首次登录】
            if self.login_token:
                print(f"🔄[恢复会话] 检测到本地持有令牌，正在恢复会话...")
                resume_payload = {
                    "msg": "method",
                    "method": "login", 
                    "params": [{"resume": self.login_token}],
                    "id": f"resume_{self._next_id}"
                }
                self._next_id += 1
                await self.ws.send(json.dumps(resume_payload))
                print("🎉[恢复成功] 成功通过 resume 令牌登录！")
            else:
                print("🔑[等待登陆] 未登陆，等待认证...")
 
            # 重新激活所有数据订阅通道
            for sub_id, sub_info in self.subscriptions.items():
                sub_name = sub_info["name"]
                sub_params = sub_info["params"]
                print(f"🔄[数据重载] 正在恢复订阅: {sub_name} | 参数: {sub_params}")
                
                sub_payload = {
                    "msg": "sub",
                    "id": sub_id, 
                    "name": sub_name,
                    "params": sub_params 
                }
                await self.ws.send(json.dumps(sub_payload))
            # Start background transport loop
            self._listener_task = asyncio.create_task(self._transport_loop())
        except (ConnectionClosed, IOError, Exception) as error:
            print(f"⚠️ [异常中断] 连接失败: {error}。")
            raise

    async def call(self, method_name: str, *params) -> Any:
        msg_id = str(self._next_id)
        self._next_id += 1

        call_id = str(uuid.uuid4())
        future = asyncio.get_running_loop().create_future()
        self._pending_responses[call_id] = future

        payload = {
            "msg": "method",
            "method": method_name,
            "params": list(params),
            "id": call_id
        }
        await self.ws.send(json.dumps(payload))
        response_data = await future
        
        if (method_name == "nodeSessionLogin" or method_name == "login") and response_data:
            server_token = response_data.get("token") or response_data.get("result", {}).get("token")
            if server_token:
                self.login_token = str(server_token)

        return response_data

    async def subscribe(self, name: str, params: list = None):
        """Subscribes to a specific server data stream."""
        if params is None:
            params = []
        sub_id = generate_subscription_id(name, params)
        if sub_id in self.subscriptions:
            return

        self.subscriptions[sub_id] = {
            "name": name,
            "params": params
        }
        await self.ws.send(json.dumps({
            "msg": "sub",
            "name": name,
            "params": list(params),
            "id": sub_id
        }))

    async def close(self):
        print(f"系统正在退出...")
        if self._keep_connect_task:
            self._keep_connect_task.cancel()
            await asyncio.gather(self._keep_connect_task, return_exceptions=True)
        if self._listener_task:
            self._listener_task.cancel()
            await asyncio.gather(self._listener_task, return_exceptions=True)
        if self.ws:
            await self._safe_exit()

    async def _keep_connect(self):
        reconnect_delay = 1
        max_reconnect_delay = 120
        while True:
            await asyncio.sleep(reconnect_delay)
            if self.ws.open:
                continue
            try:
                print("try reconnect...")
                await self._connect()
                reconnect_delay = 1
            except Exception as error:
                reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)
                print(f"系统将在 {reconnect_delay} 秒后尝试恢复...")
            except asyncio.CancelledError:
                break

    async def _transport_loop(self):
        try:
            async for message in self.ws:
                data = json.loads(message)
                msg_type = data.get("msg")

                # Handle heartbeats natively
                if msg_type == "ping":
                    await self.ws.send(json.dumps({"msg": "pong", "id": data.get("id")}))
                    continue

                # Route RPC responses
                if msg_type == "result":

                    call_id = data.get("id")
                    if call_id in self._pending_responses:
                        future = self._pending_responses.pop(call_id)
                        if "error" in data:
                            future.set_exception(Exception(data["error"].get("reason", "Unknown RPC Error")))
                        else:
                            future.set_result(data.get("result"))

                # Route real-time synced database stream operations up to top handlers
                if msg_type in ["added", "changed", "removed"]:
                    collection = data.get("collection")
                    doc_id = data.get("id")
                    fields = data.get("fields", {})

                    if collection not in self.collections:
                        self.collections[collection] = {}

                    if msg_type == "added":
                        self.collections[collection][doc_id] = fields
                    elif msg_type == "changed":
                        if doc_id in self.collections[collection]:
                            self.collections[collection][doc_id].update(fields)
                    elif msg_type == "removed":
                        self.collections[collection].pop(doc_id, None)

                    # 同时将原始事件抛给上层业务路由
                    if self.on_data_changed:
                        self.on_data_changed(msg_type, collection, doc_id, fields)

        except ConnectionClosed:
            print("[DDP 连接] 连接异常中断...")

    async def _safe_exit(self):
        logout_raw_msg = {
            "msg": "method",
            "method": "logout",
            "params": [],
            "id": "exit-logout-id-999" # randomID
        }
        
        try:
            print("正在注销令牌 ...")
            await self.ws.send(json.dumps(logout_raw_msg)) 
            await asyncio.sleep(0.2) 
        except Exception as e:
            print(f"发送注销请求失败（可能连接已断开）: {e}")
        finally:
            await self.ws.close()
            print("🎉Python 客户端已安全退出。")
