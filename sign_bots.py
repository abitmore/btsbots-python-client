import asyncio
from btsbots.signbots import SignBots

async def main():
    bot = SignBots()
    try:
        await bot.run()

        def on_success(doc_id, tx_id):
            print(f"🌟[交易成功] 订单流水已被区块链安全打包: {doc_id} -> TX: {tx_id}")

        await bot.start_signature_queue_listener(on_broadcast_success=on_success)
        while True:
            await asyncio.sleep(1)

    except Exception as e:
        print(f"🚨守护进程运行异常退出: {e}", flush=True)
        #import traceback
        #traceback.print_exc()
    finally:
        await bot.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
