import asyncio
from btsbots.bots_client import BotsClient

async def main():

    client = BotsClient("wss://btsbots.com/websocket")
    try:
        await client.run()
        
        print("\n=== [RUNNING TEST: FETCH WEB OTP] ===")
        otp_code = await client.request_otp()
        
        print("======================================")
        print(f" ✓ Success! Returned 6-Digit Web Token: {otp_code}")
        print("======================================")
        print("[*] Test verification complete. Closing channel sessions safely.")

    except Exception as e:
        print(f"❌ OTP Retrieval Test Failed: {e}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
