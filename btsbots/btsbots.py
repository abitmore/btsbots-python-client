from btsbots.bots_client import BotsClient

class BTSBots(BotsClient):
    async def run(self, passPath=""):
        await super().run()
        # 最新区块信息
        await self.subscribe("chainBlockHeadStream")
        # 手续费
        await self.subscribe("chainGlobalProperties")

    async def make_transaction(self, raw_ops: list[dict], isSim: bool=False) -> int:
        """
        接受交易请求格式如下:
        {"type": xx, "params": xx}
        其中type可以为 "limit_order_create/limit_order_cancel/transfer/account_create"
        """
        try:
            # 1. build operations
            ops = []
            for raw_op in raw_ops:
                op = await self._build_op(self.bts_id, raw_op)
                ops.append(op)
            # 2. fill fees
            self._fill_ops_fee(ops)
            # 3. sign and broadcast
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
        block_time = block_doc["T"]["$date"] / 1000
        return block_time

    def _fill_ops_fee(self, ops: list):
        global_coll = self.collections.get("global", {})
        if not global_coll:
            raise KeyError("本地内存中暂未接收到同步的费率数据。")
        global_doc = next((doc for doc in global_coll.values() if doc.get("id") == "2.0.0"))
        fee_doc = global_doc["parameters"].get("current_fees", {}).get("parameters", [])

        for op in ops:
            self._fill_op_fee(op, fee_doc)

    def _fill_op_fee(self, op: list, fee_doc: dict):
        from binascii import unhexlify
        op_code = op[0]
        item = fee_doc[op[0]]
        if op_code == 5:
            calculated_fee = int(item[1].get("basic_fee"))
            total_bytes = 143 + len((op[1]["name"]).encode('utf-8'))
            calculated_fee += total_bytes * item[1].get("price_per_kbyte") // 1024
        else:
            calculated_fee = int(item[1].get("fee"))
        if op_code == 0 and op[1].get("memo"):
            cipher_bytes_len = len(unhexlify(op[1]["memo"]["message"]))
            varint_len = 2
            total_bytes = 33 + 33 + 8 + varint_len + cipher_bytes_len
            calculated_fee += total_bytes * item[1].get("price_per_kbyte") // 1024
        op[1]["fee"]["amount"] = calculated_fee

    async def _sign_and_broadcast(self, ops: list, isSim: bool=False) -> int:
        from datetime import datetime
        try:
            ref_block_num, ref_block_prefix = self._get_ref_block_info()
            block_time = self._get_chain_time()
            dt = datetime.fromtimestamp(block_time+30)
            expiration = dt.strftime("%Y-%m-%dT%H:%M:%S")
            payload = {
                "ref_block_num": int(ref_block_num),
                "ref_block_prefix": int(ref_block_prefix),
                "expiration": expiration,
                "operations": ops
            }

            # 使用统一的 key_manager 签名交易
            finalized_tx_json = self.key_manager.sign_transaction(payload)

            if isSim:
                result = {"status": "SUCCESS", "blockNum": 1644}
            else:
                result = await self.call("broadcastTransaction", finalized_tx_json)
            if(result["status"] == "FAIL"):
                print(f"  交易广播失败：{result['message']}")
                raise RuntimeError(f"  交易广播失败：{result['message']}")
            block_num = result["blockNum"]

            print(f"  发送成功，交易区块号: {block_num}")
            return block_num
        except Exception as broadcast_err:
            print(f"  [!] 交易被节点拒绝，错误明细: {broadcast_err}")
            #import traceback
            #traceback.print_exc()
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
        elif op_type == "account_create":
            _op = await self._build_op_account_create(uid, op_params)

        if _op is None:
            raise RuntimeError(f"未支持的交易类型 {op_type}")
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

    async def _build_op_account_create(self, uid: str, op_params: dict) -> list:
        """实现 BitShares 账号注册 (opcode 5: account_create)"""
        account_create_payload = {
            "fee": {"amount": 0, "asset_id": "1.3.0"},
            "registrar": str(uid),
            "referrer": str(uid),
            "referrer_percent": 10000,
            "name": op_params["name"],
            "owner": {
                "weight_threshold": 1,
                "account_auths": [],
                "key_auths": [[op_params["owner_key"], 1]],
                "address_auths": []
            },
            "active": {
                "weight_threshold": 1,
                "account_auths": [],
                "key_auths": [[op_params["active_key"], 1]],
                "address_auths": []
            },
            "options": {
                "memo_key": op_params["memo_key"],
                "voting_account": "1.2.0",
                "num_witness": 0,
                "num_committee": 0,
                "votes": []
            },
            "extensions": []
        }
        return [5, account_create_payload]

    async def encrypt_memo(self, op_params: dict):
        if not self.key_manager:
            raise ValueError("Need import keys first")
        _info = await self.get_account_info(op_params.get("to_account"))
        payload = {
            "to": _info['k']['m'],
            "message": op_params["memo"],
            "my_memo_pub": _info.get('k', {}).get('m')
        }
        # 使用统一的 key_manager 加密 memo
        return self.key_manager.encrypt_memo(payload)

