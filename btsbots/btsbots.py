from btsbots.bots_client import BotsClient

class BTSBots(BotsClient):
    #def __init__(self, ddp_endpoint: str, db_path: str = "bots.sqlite"):
    #    super().__init__(ddp_endpoint, db_path)

    async def run(self, passPath=""):
        await super().run()
        # 最新区块信息
        # update in collections "global_properties"
        await self.subscribe("chainBlockHeadStream")
        # 手续费
        # update in collections "global"
        await self.subscribe("chainGlobalProperties")

    async def make_transaction(self, raw_ops: list[dict], isSim: bool=False) -> int:
        """
        接受交易请求格式如下:
        {"type": xx, "params": xx}
        其中type可以为 "limit_order_create/limit_order_cancel/transfer"
        params 格式如下:
        {"to_account": "xxx", "asset": "BTS", "amount": 0.1, "memo": "test", "simulate": True}
        {"sell_asset": "BTS", "amount": 1.0, "receive_asset": "USD", "price": 5, "simulate": True}
        """
        try:
            # 1. build operations 
            ops = []
            for raw_op in raw_ops:
                op = await self._build_op(self.bts_id, raw_op)
                ops.append(op)
            # 2. fill fees
            self._fill_ops_fee(ops)
            # 3. sign and  broadcast
            block = await self._sign_and_broadcast(ops, isSim)
            return block
        except Exception as e:
            print(f"🚨[交易失败] {e}")
            raise

    def _get_ref_block_info(self) -> tuple[int, int]:
        import struct
        from binascii import unhexlify
        block_head_coll = self.collections.get("global_properties")
        if not block_head_coll:
            raise KeyError("本地内存中暂未接收到同步的高度状态数据。")
            
        block_doc = next(iter(block_head_coll.values()))
        head_block_num = int(block_doc.get("B", 0))       
        head_block_id_hex = str(block_doc.get("id", "")).strip()

        ref_block_num = head_block_num & 0xFFFF
        id_bytes = unhexlify(head_block_id_hex)
        ref_block_prefix = struct.unpack_from("<I", id_bytes, 4)[0]
        return ref_block_num, ref_block_prefix

    def _get_chain_time(self) -> int:
        block_head_coll = self.collections.get("global_properties", {})
        if not block_head_coll:
            raise KeyError("本地内存中暂未接收到同步的高度状态数据。")
            
        block_doc = next(iter(block_head_coll.values()))
        # mongo中的timedate对象，被meteor推送来的是毫秒时间戳
        block_time = block_doc["T"]["$date"] / 1000
        return block_time

    def _fill_ops_fee(self, ops: list):
        global_coll = self.collections.get("global", {})
        if not global_coll:
            raise KeyError("本地内存中暂未接收到同步的费率数据。")
        global_doc = next((doc for doc in global_coll.values() if doc.get("id") == "2.0.0"))
        fee_doc= global_doc["parameters"].get("current_fees", {}).get("parameters", [])

        for op in ops:
            self._fill_op_fee(op, fee_doc)

    def _fill_op_fee(self, op: list, fee_doc: dict):
        from binascii import unhexlify
        import math
        op_code = op[0]
        item = fee_doc[op[0]]
        calculated_fee = int(item[1].get("fee"))
        if op_code == 0 and op[1].get("memo"):
            cipher_bytes_len = len(unhexlify(op[1]["memo"]["message"]))
            # 还原 fc::raw::pack_size(memo) 的字节数累加
            # 33(from) + 33(to) + 8(nonce) + 1(长度标记) + 密文长度
            #varint_len = 1 if cipher_bytes_len < 128 else 2
            varint_len = 2
            total_bytes = 33 + 33 + 8 + varint_len + cipher_bytes_len
            calculated_fee += total_bytes * item[1].get("price_per_kbyte") // 1024
        op[1]["fee"]["amount"] = calculated_fee 

    async def _sign_and_broadcast(self, ops: list, isSim: bool=False) -> int:
        from datetime import datetime
        try:
            ref_block_num, ref_block_prefix = self._get_ref_block_info()
            # 从区块链获取时间，防止本地时间不准交易无法发送
            block_time = self._get_chain_time()
            dt = datetime.fromtimestamp(block_time+30)
            expiration = dt.strftime("%Y-%m-%dT%H:%M:%S")
            payload = {
                "ref_block_num": int(ref_block_num),
                "ref_block_prefix": int(ref_block_prefix),
                "expiration": expiration,
                "operations": ops
                }
            
            finalized_tx_json = self.active_key.sign_transaction(payload)

            # 投递广播
            if isSim:
                result = {"status": "SUCCESS", "blockNum": 1644}
            else:
                result = await self.call("broadcastTransaction", finalized_tx_json)
            if(result["status"] == "FAIL"):
                print(f"  交易广播失败：{result["message"]}")
                raise RuntimeError(f"  交易广播失败：{result["message"]}")
            block_num = result["blockNum"]
            
            print(f"  发送成功，交易区块号: {block_num}")
            return block_num
        except Exception as broadcast_err:
            print(f"  [!] 交易被节点拒绝，错误明细: {broadcast_err}")
            import traceback
            traceback.print_exc()
            raise

    async def _build_op(self, uid: str, raw_op: dict) -> list:
        op_type = raw_op.get("type")
        op_params = raw_op.get("params", {})
        _op = None

        if op_type == "transfer":
            _op = await self._build_op_transfer(uid, op_params)
        elif op_type == "limit_order_create":
            _op = await self._build_op_limit_order_create(uid, op_params)
        elif op_type == "limit_order_cancel":
            _op = await self._build_op_limit_order_cancel(uid, op_params)

        if _op is None:
            raise RuntimeError(f"未支持的交易类型{op_type}")
        return _op

    async def _build_op_transfer(self, uid: str, op_params: dict) -> list:
        if op_params.get("memo"):
            memo_payload = await self.encrypt_memo(op_params)

        _, to_id = await self.get_account_brief(op_params.get("to_account"))
        _, asset_id, asset_prec = await self.get_asset_brief(op_params.get("asset"))
        amount = int(op_params.get("amount") * (10 ** asset_prec))
        transfer_payload = {
            "fee": {"amount": 0, "asset_id": "1.3.0"},
            "from": str(uid),
            "to": str(to_id),
            "amount": {
                "amount": amount,
                "asset_id": asset_id
            },
            "extensions": []
        }
        if op_params.get("memo"):
            transfer_payload["memo"] = memo_payload

        return [0, transfer_payload]

    async def _build_op_limit_order_create(self, uid: str, op_params: dict) -> list:
        from datetime import datetime, timedelta

        sell_symbol = str(op_params["sell_asset"]).upper().strip()
        recv_symbol = str(op_params["receive_asset"]).upper().strip()

        _, sell_id, sell_prec = await self.get_asset_brief(sell_symbol)
        _, recv_id, recv_prec = await self.get_asset_brief(recv_symbol)

        raw_sell_amount = int(float(op_params["amount"]) * (10 ** sell_prec))
        raw_recv_amount = int((float(op_params["amount"]) * float(op_params["price"])) * (10 ** recv_prec))

        block_time = self._get_chain_time()
        dt_base = datetime.fromtimestamp(block_time)
        expiration = (dt_base + timedelta(days=300)).strftime("%Y-%m-%dT%H:%M:%S")
        order_payload = {
            "fee": {"amount": 0, "asset_id": "1.3.0"},
            "seller": str(uid),
            "amount_to_sell": {
                "amount": raw_sell_amount,
                "asset_id": sell_id
            },
            "min_to_receive": {
                "amount": raw_recv_amount,
                "asset_id": recv_id
            },
            "expiration": expiration,
            "fill_or_kill": bool(op_params.get('fill_or_kill')),
            "extensions": []
        }
        return [1, order_payload]

    async def _build_op_limit_order_cancel(self, uid: str, op_params: dict) -> list:
        cancel_payload = {
            "fee": {"amount": 0, "asset_id": "1.3.0"},
            "fee_paying_account": str(uid),
            "order": str(op_params.get("order_id")),
            "extensions": []
        }
        return [2, cancel_payload]

    async def encrypt_memo(self, op_params: dict):
        if not self.memo_key :
            raise ValueError("Need import memo key first")
        _info = await self.get_account_info(op_params.get("to_account"))
        payload = {
            "to": _info['k']['m'],
            "message": op_params["memo"]
        }
        return self.memo_key.encrypt_memo(payload)
