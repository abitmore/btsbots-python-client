import os
import json
import time
import sqlite3
from typing import Tuple, Dict, Any, List
import asyncio

from btsbots.btsbots import BTSBots

class SignBots(BTSBots):
    def __init__(self, ddp_endpoint: str, db_path: str = "bots.sqlite", config_path: str = "security_rules.json"):
        super().__init__(ddp_endpoint, db_path)
        self.config_path = config_path
        self.seen_signatures = set()
        self.last_config_mtime: float = 0.0
        self._init_db_order()

    def _init_db_order(self):
        """Initializes localized tracking datasets inside SQLite storage."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS successful_orders (
                    block_num TEXT PRIMARY KEY, account_id TEXT NOT NULL, op_type TEXT NOT NULL,
                    sell_asset_symbol TEXT NOT NULL, sell_amount INTEGER NOT NULL,
                    receive_asset_symbol TEXT NOT NULL, receive_amount INTEGER NOT NULL, timestamp INTEGER NOT NULL
                )
            """)
            conn.commit()

    async def hot_reload_config_file(self, force: bool = False):
        try:
            if not os.path.exists(self.config_path):
                raise FileNotFoundError(f"Missing mandatory policy file: {self.config_path}")

            current_mtime = os.path.getmtime(self.config_path)
            if not force and (current_mtime <= self.last_config_mtime):
                return

            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            print(f"🔄 配置文件加载成功。规则版本更新时间: {self.config.get('updated_at')}")
            self.last_config_mtime = current_mtime
        except Exception as err:
            print(f"配置文件解析发生异常: {str(err)}")

    async def hot_reload_strategy(self, force: bool = False):
        """【安全策略加载接口】加载规则集，并核对白名单用户名与区块链账户 ID 是否对应"""
        try:
            if not await self.hot_reload_config_file(force):
                return

            user_whitelist = self.config.get("user_whitelist", {})
            for username, claimed_id in list(user_whitelist.items()):
                _, _id, = await self.get_account_brief(username)
                if _id:
                    if _id != claimed_id:
                        print(f"🚨[风控警告] 账号{username} 服务端ID {_id} 与 '{claimed_id}' 不匹配！忽略此账号。")
                        del self.config["user_whitelist"][username]
                else:
                    print(f"🚨[风控警告] 账号{claimed_id} 信息获取失败，忽略此账号。")
        except Exception as err:
            print(f"策略风控解析过程发生异常错误: {str(err)}")

    async def submit_proxy_sign_request(self, signed_envelope: dict) -> str:
        tx_id = await self.call("requestProxySign", signed_envelope)
        return str(tx_id)

    async def start_signature_queue_listener(self, on_broadcast_success: Optional[Callable[[str, str], None]] = None):
        await self.hot_reload_strategy()
        def _on_queue_income(action, collection, doc_id, fields):
            asyncio.create_task(self.hot_reload_strategy())
            if collection == 'proxy_sign_requests' and action == 'added':
                asyncio.create_task(self._audit_and_sign_worker(doc_id, fields, on_broadcast_success))

        self.on_data_changed = _on_queue_income
        await self.subscribe("allPendingSignRequests")
        print("⚡[BTSBots] 零信任安全守卫，签名网关，正在监听中...")

    async def _audit_and_sign_worker(self, doc_id: str, fields: dict, success_callback: Optional[Callable]):
        envelope = fields.get("rawTx", {})
        # 1. 检测公钥是否授权，签名是否合格
        is_valid_crypto, crypto_msg = self._verify_browser_envelope(envelope)
        if not is_valid_crypto:
            print(f"x [风控拦截]: {crypto_msg}")
            await self.call('replySignRequest', False, doc_id, f"{crypto_msg}")
            return

        raw_payload = json.loads(envelope.get("tx_string", "{}"))

        op_type = raw_payload.get("type")
        op_params = raw_payload.get("params", {})
        authenticated_sender_id = fields.get("account_id")
        account_name = fields.get("account") # 获取当前用户的比特股账号名

        # 处理第三方商户的授权登录（OAuth/扫码）请求
        if op_type == "oauth_login":
            await self.oauth_handle(doc_id, fields)
            return

        # 2. 检查 fee 是否超过限制
        is_safe, msg = self._check_fee_doc([0,1,2])
        if not is_safe:
            print(f"x [风控拦截]: {msg}")
            await self.call('replySignRequest', False, doc_id, f"{msg}")
            return

        # 3. 检查转账或者下单是否合规
        #print("debug", op_type, op_params, authenticated_sender_id)
        is_safe, status_msg = await self._audit_security_strategy(
            op_type, op_params, authenticated_sender_id
        )
        if not is_safe:
            print(f"x [审核拦截]: {status_msg}")
            await self.call('replySignRequest', False, doc_id, f"{status_msg}")
            return
        else:
            print(f"✓ [审核通过]: {status_msg}")
            print(f"  签名交易: {op_params}")

        # 4. 打包签名发送
        try:
            is_sim = op_params.get("simulate")
            block_num = await self.make_transaction([raw_payload], is_sim)
            await self.call('replySignRequest', True, doc_id,
                block_num)
            if success_callback:
                success_callback(doc_id, block_num)
            # The transaction has cleared the blockchain validation layer! Log details natively into your SQL tables
            if op_type == "limit_order_create":
                self._log_successful_transaction(
                    block_num=block_num,
                    account_id=authenticated_sender_id,
                    op_type=op_type,
                    params=op_params
                )
        except Exception as e:
            print(f"🚨[网关异常] {e}")
            #import traceback
            #traceback.print_exc()
            await self.call('replySignRequest', False, doc_id, f"网关异常中断: {str(e)}")

    async def oauth_handle(self, doc_id: str, fields: dict):
        """
        专门处理第三方商户的 OAuth / 扫码授权登录验证
        """
        print(fields)
        envelope = fields.get("rawTx", {})
        account_name = fields.get("account")
        clientIp = fields.get("clientIp")

        raw_payload = json.loads(envelope.get("tx_string", "{}"))

        op_params = raw_payload.get("params", {})

        print(f"🔐 [OAuth/扫码授权]: 收到用户 [{account_name}] 对商户的身份授权登录请求...")

        # 1. 审查第三方商户参数
        client_id = op_params.get("client_id")      # 提取商户的用户名 / 标识符
        token = op_params.get("token")    # 提取商户出具的临时会话挑战码
        site = op_params.get("site")    # 提取商户出具的临时会话挑战码
        ip = op_params.get("ip")    # 提取商户出具的临时会话挑战码

        if not client_id or not token or not site or not ip:
            msg = "授权登录参数不完整"
            print(f"x [授权风控拦截]: {msg}")
            await self.call('replySignRequest', False, doc_id, msg)
            return

        if clientIp != ip:
            msg = "BTSBots client 与商户 client IP 地址不符合"
            print(f"x [授权风控拦截]: {msg}")
            await self.call('replySignRequest', False, doc_id, msg)
            return

        try:

            # python_blockchain_sig = Your_BitShares_Sign_Logic(browser_pubkey)
            auth_payload = self._generate_auth_payload(self.account_name, site, token, ip)

            # 3. 组装准备推送到商户监控队列的完整的安全授权凭证包
            final_payload = {
                "client_id": str(client_id).lower().strip(),
                "verify": auth_payload.get("verify")
            }

            # =================================================================
            # 🎯 核心动作二：【通过 RPC 推送至 Meteor 服务端商家监控队列】
            # 调用钱包站服务端特有的 RPC 方法，由钱包核心服务器将数据安全写入 `login_requests` 集合
            # 供商户的 Python 机器人在后台抓取并进行最终的免信任密码学交叉核对
            # =================================================================
            print(f"📡 正在通过 RPC 向 Meteor 服务器推送授权凭证...")
            # 假设你在 Meteor 端注册的推送 Method 名字叫 'pushAuthToMerchantQueue'
            await self.call('pushAuthToMerchantQueue', final_payload)

            print(f"✅ [OAuth/扫码授权]: 登录站点 [{site}] 授权成功。token: {token}")

            # 4. 🌟 释放并通关 proxy_sign_requests 队列记录
            # 通过主站兼容的 Method 吐回成功回执，触发网页前端的 await 阻塞瞬间放行，提示用户授权签署成功
            await self.call('replySignRequest', True, doc_id,
                token)
            return

        except Exception as oauth_err:
            error_msg = f"授权背书签名或 RPC 推送发生故障: {str(oauth_err)}"
            print(f"x [OAuth/扫码授权失败]: {error_msg}")
            # 安全拒绝单子，防止前端无限打转挂起
            await self.call('replySignRequest', False, doc_id, error_msg)
            return

    def _check_fee_doc(self, op_types: list) -> tuple[bool, str]:
        global_coll = self.collections.get("global", {})
        if not global_coll:
            raise KeyError("本地内存中暂未接收到同步的费率数据。")
        global_doc = next((doc for doc in global_coll.values() if doc.get("id") == "2.0.0"))
        fee_doc= global_doc["parameters"].get("current_fees", {}).get("parameters", [])
        for index in op_types:
            item = fee_doc[index]
            fee = int(item[1].get("fee")) / 10**5
            if fee > self.config["fee_limit"]:
                return False, f"交易费用{fee}BTS, 超过限制: {self.config['fee_limit']}"
        return True,""

    def _verify_browser_envelope(self, envelope: dict) -> tuple[bool, str]:
        """
        【安全网络核验接口 - 授权公钥白名单】
        白名单里只存公钥的 50 位 SHA-256 哈希串。
        前端发送完整的 130 位公钥过来，后端计算哈希比对通过后，再用完整公钥验签。
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from binascii import unhexlify
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        import hashlib
        import json
        import time

        tx_string = envelope.get("tx_string")
        pubkey_hex = envelope.get("browser_pubkey")  # 前端传过来的完整 130 位原始公钥
        signature_hex = envelope.get("browser_sig")

        if not tx_string or not pubkey_hex or not signature_hex:
            return False, "解包失败：缺少标准 Web Crypto 鉴权参数。"

        try:
            # 计算 130 位完整公钥的标准 SHA-256 哈希值
            # 截取前 50 个字符作为特征指纹
            hasher = hashlib.sha256()
            hasher.update(pubkey_hex.lower().encode('utf-8'))
            computed_fingerprint_50 = hasher.hexdigest()[:50]

            # 匹配公钥白名单
            if computed_fingerprint_50 not in self.config["authorized_keys"]:
                return False, f"该公钥未授权，如需签名请加入白名单: {computed_fingerprint_50}"

            # 1. 还原公钥
            public_key_bytes = unhexlify(pubkey_hex)
            native_pubkey_object = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_key_bytes
            )

            # 2. 处理签名格式
            signature_bytes = unhexlify(signature_hex)

            # P-256 的 Raw 签名长度必须是 64 字节
            if len(signature_bytes) == 64:
                r = int.from_bytes(signature_bytes[:32], byteorder='big')
                s = int.from_bytes(signature_bytes[32:], byteorder='big')
                # 将 r 和 s 编码为 Python 预期的 ASN.1 DER 格式
                der_signature = encode_dss_signature(r, s)
            else:
                raise ValueError("Invalid signature length")

            # 3. 执行验证（使用转换后的 der_signature）
            message_bytes = tx_string.encode('utf-8')
            native_pubkey_object.verify(
                der_signature,  # 注意：这里换成 DER 格式
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            is_valid = True
            # print("签名验证成功")

        except Exception as crypto_err:
            print(f"x [风控警告]: 签名验证异常! 明细: {crypto_err}")
            is_valid = False

        if not is_valid:
            return False, "签名验证失败。"

        # 时钟同步与防重放安全审查
        try:
            raw_payload = json.loads(tx_string)
        except Exception:
            return False, "无法识别交易"

        if abs(int(time.time()) - raw_payload.get("client_time", 0)) > 10:
            return False, "交易已过期"

        if signature_hex in self.seen_signatures:
            return False, "重复的交易请求."
        self.seen_signatures.add(signature_hex)

        return True, "签名请求可信，已验证通过"

    async def _audit_security_strategy(self, op_type: str, params: dict, sender_id: str) -> Tuple[bool, str]:
        try:
            # 转账检查收款方白名单
            if op_type == "transfer":
                to_account_name = params.get("to_account")
                if to_account_name not in self.config["user_whitelist"]:
                    return False, f"收款账号 [{to_account_name}] 不在白名单，取消转账."

                return True, "可安全转账"

            if op_type == "limit_order_cancel":
                order_object_id = str(params.get("order_id", ""))
                return True, f"可取消限价单: {order_object_id}"

            # 限价单检查市场白名单
            sell_symbol = str(params["sell_asset"]).upper().strip()
            recv_symbol = str(params["receive_asset"]).upper().strip()

            market_pair_forward = f"{sell_symbol}/{recv_symbol}"
            market_pair_reversed = f"{recv_symbol}/{sell_symbol}"
            whitelist_matches = [m.upper().strip() for m in self.config.get("market_whitelist", [])]

            if (market_pair_forward not in whitelist_matches) and (market_pair_reversed not in whitelist_matches):
                return False, f"交易对 {market_pair_forward} 不在交易对白名单范围内。"

            # 限价单检查下单价格是否合理，防止被恶意低卖高买刷单盗窃
            sell_amount = float(params["amount"])
            recv_amount = float(params["amount"]) * float(params["price"])

            if not self._check_profitability_bounds(sender_id, sell_symbol, sell_amount, recv_symbol, recv_amount):
                return False, "该订单预期套利系数低于时间窗口内波动偏离下限！"

            return True, "完全符合交易安全策略"

        except Exception as err:
            return False, f"风控解析过程发生异常错误: {str(err)}"

    # TODO, need test
    def _check_profitability_bounds(self, account_id: str, sell_symbol: str, sell_amt: float, recv_symbol: str, recv_amt: float) -> bool:
        """Enforces sliding multi-timeframe geometric rolling arbitrage restrictions."""
        now = int(time.time())
        intervals = {
            "一小时内": (now - 3600, float(self.config.get("volatility_limit_1h", 0.97))),
            "一天内": (now - 86400, float(self.config.get("volatility_limit_1d", 0.95))),
            "一周内": (now - 604800, float(self.config.get("volatility_limit_1w", 0.90)))
        }

        # Proposed swap rate multiplier: Tokens Received / Tokens Expended
        proposed_rate = float(recv_amt) / float(sell_amt)

        with sqlite3.connect(self.db_path) as conn:
            for label, (cutoff_time, lower_bound) in intervals.items():
                # Locate historical transaction rows executing in the absolute reverse direction
                # (e.g. Current Receive Asset matches past Expended Asset, and vice versa)
                cursor = conn.execute("""
                    SELECT sell_amount, receive_amount FROM successful_orders
                    WHERE account_id = ? AND sell_asset_symbol = ? AND receive_asset_symbol = ? AND timestamp >= ?
                """, (account_id, recv_symbol, sell_symbol, cutoff_time))

                historical_trades = cursor.fetchall()
                if not historical_trades: continue

                for hist_sell, hist_recv in historical_trades:
                    historical_rate = float(hist_recv) / float(hist_sell)
                    # Arbitrage Equation: Total Swap Coefficient A = Proposed * Past_Inversed
                    arbitrage_coefficient = proposed_rate * historical_rate

                    if arbitrage_coefficient < lower_bound:
                        print(f"x [风控警告] 该下单违反了【{label}】时段的历史价格波动偏离约束！"
                              f"计算出的套利回报系数为 {arbitrage_coefficient:.4f}，"
                              f"低于用户设定的多时区最低底线容忍阈值 ({lower_bound})！拒绝签署私钥。")
                        return False
        return True

    def _log_successful_transaction(self, block_num: str, account_id: str, op_type: str, params: dict):
        sell_symbol = str(params["sell_asset"]).upper().strip()
        recv_symbol = str(params["receive_asset"]).upper().strip()
        # 限价单检查下单价格是否合理，防止被恶意低卖高买刷单盗窃
        sell_amount = float(params["amount"])
        recv_amount = float(params["amount"]) * float(params["price"])
        """Saves verified mainnet transaction receipts natively into SQLite data fields."""
        if op_type != "limit_order_create": return
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO successful_orders VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
                block_num, account_id, op_type,
                sell_symbol, sell_amount,
                recv_symbol, recv_amount,
                int(time.time())
            ))
            conn.commit()
