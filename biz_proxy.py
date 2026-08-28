import os
import sqlite3
import uuid
import time
import requests
from fastapi import APIRouter, Query, HTTPException, Request, Response, Header
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import FastAPI
from contextlib import asynccontextmanager
from pydantic import BaseModel
import uvicorn

router = APIRouter()

# ─── 全局纯内存缓存，确保微秒级响应 ───
AUTH_CACHE = {}
TOKEN_CACHE = {}
PAYMENT_CACHE = {}
DB_FILE = "biz.sqlite"

# ─── B 端同步数据的 Pydantic 数据模型 ───
class LoginSyncItem(BaseModel):
    site: str
    token: str
    username: str

class PaymentSyncItem(BaseModel):
    order_id: str
    tx_id: str
    amount: str
    asset: str

def get_domain(url):
    import re
    # 匹配 https://、http:// 或直接开始，直到遇到第一个斜杠或结尾
    return re.sub(r'^(https?://)?([^/]+).*$', r'\2', url)

def get_real_ip(request: Request) -> str:
    """辅助函数：穿透反向代理获取客户端的真实公网 IP"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def verify_b_signature(payload) -> bool:
    from btsbots.graphene_light import verify_message as bts_verify_message
    if payload["pubkey"] != app.state.bts_pub_key:
        return False
    return bts_verify_message(
        payload["data"], payload["signature"], payload["pubkey"])


HTML_PATH = os.path.join("templates", "login.html")
JS_PATH = os.path.join("templates", "qrcode.min.js")

RAW_HTML_TEMPLATE = ""
RAW_QRCODE_JS = ""

@asynccontextmanager
async def lifespan(app: FastAPI):
    global RAW_HTML_TEMPLATE, RAW_QRCODE_JS

    if not os.path.exists(HTML_PATH):
        raise FileNotFoundError(f"❌ 严重错误：无法在路径 {HTML_PATH} 下找到登录 HTML 模板！")
    if not os.path.exists(JS_PATH):
        raise FileNotFoundError(f"❌ 严重错误：无法在路径 {JS_PATH} 下找到 qrcode.min.js 脚本！")

    with open(HTML_PATH, "r", encoding="utf-8") as f:
        RAW_HTML_TEMPLATE = f.read()

    with open(JS_PATH, "r", encoding="utf-8") as f:
        RAW_QRCODE_JS = f.read()

    # 启动时：初始化创建本地数据库（如果不存在）
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth (
                session_id TEXT PRIMARY KEY, app_id TEXT, username TEXT, login_at INTEGER, expires_at INTEGER
            )""")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                order_id TEXT PRIMARY KEY, amount TEXT, asset TEXT, tx_id TEXT, updated_at INTEGER
            )""")
        conn.commit()

        # 将本地数据库的历史数据全量恢复至内存
        cursor.execute("SELECT session_id, app_id, username, login_at, expires_at FROM auth")
        for session_id, app_id, username, login_at, expires_at in cursor.fetchall():
            AUTH_CACHE[session_id] = {"app_id": app_id, "username": username, "login_at": login_at, "expires_at": expires_at}

        cursor.execute("SELECT order_id, amount, asset, tx_id, updated_at FROM payments")
        for order_id, amount, asset, tx_id, updated_at in cursor.fetchall():
            PAYMENT_CACHE[order_id] = {
                "amount": amount, "asset": asset, "tx_id": tx_id, "updated_at": updated_at
            }

    print("🤖 BTSBots 接入网关代理，已完成初始化。")

    yield # ─── 上方为启动执行，下方为关闭执行 ───

    print("网关正在安全关闭...")

# 创建 FastAPI 实例并绑定生命周期
app = FastAPI(lifespan=lifespan)

@app.get("/biz-proxy/login", response_class=HTMLResponse)
def login_gateway(
    request: Request,
    redirect: str = Query(..., description="登录成功后最终要跳回的完整页面")
):
    # 获取用户在商户端发起的最初公网 IP
    client_ip = get_real_ip(request)
    site = get_domain(redirect)

    # 生成一次性的临时授权码凭证
    temporary_token = str(uuid.uuid4())

    # 在商户后端本地缓存中锁定：这个 Token 必须由 client_ip 在 5 分钟内完成签名
    # TODO, remove expired TOKEN_CACHE
    TOKEN_CACHE[temporary_token] = {
        "app_id": site,
        "initial_ip": client_ip, # 🔒 锁死第一道 IP 防线
        "username": None,
        "expires_at": int(time.time()) + 300
    }

    btsbots_oauth_url = (
        f"https://wallet.btsbots.com/oauth/authorize"
        f"?client_id={app.state.bts_account}"
        f"&token={temporary_token}"
        f"&site={site}"
        f"&ip={client_ip}"
        f"&redirect={redirect}"
    )
    btsbots_oauth_qrcode = (
        f"btsbots://oauth"
        f"?client_id={app.state.bts_account}"
        f"&token={temporary_token}"
        f"&site={site}"
        f"&ip={client_ip}"
    )

    final_html = RAW_HTML_TEMPLATE
    final_html = final_html.replace("__CLIENT_IP__", str(client_ip))
    final_html = final_html.replace("__OAUTH_URL__", str(btsbots_oauth_url))
    final_html = final_html.replace("__OAUTH_QRCODE__", str(btsbots_oauth_qrcode))
    final_html = final_html.replace("__TOKEN__", str(temporary_token))
    final_html = final_html.replace("__APP_ID__", str(site))
    final_html = final_html.replace("__SITE__", str(site))
    final_html = final_html.replace("__INLINE_QRCODE_JS__", RAW_QRCODE_JS)

    return HTMLResponse(content=final_html)

# 保存授权 token  的接口，供biz_bots使用
@app.post("/biz-proxy/sync-login")
async def sync_login(request: Request):
    import json
    try:
        raw_payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的 JSON 数据格式")

    if not verify_b_signature(raw_payload):
        raise HTTPException(status_code=403, detail="签名验证失败")

    data = json.loads(raw_payload.get("data"))
    token = data.get("token")
    username = data.get("username")
    client_ip = data.get("ip")  # 手机端/钱包端公网 IP

    if not token or not username:
        raise HTTPException(status_code=422, detail="缺少必要的 token 或 username 参数")

    # 4. 检查本地缓存
    temp_info = TOKEN_CACHE.get(token)

    if not temp_info:
        raise HTTPException(status_code=404, detail="未找到该登录凭证或已被钓鱼拦截")

    # if int(time.time()) > temp_info.get("expires_at", 0):
    #     raise HTTPException(status_code=403, detail="登录请求已过期")

    # 5. 反钓鱼 IP 比对
    initial_ip = temp_info.get("ip")  # 前端 React 页面记录的 PC 端公网 IP
    if initial_ip and client_ip and initial_ip != client_ip:
        print(f"🚨 [钓鱼拦截]: PC端IP({initial_ip}) 与 钱包端IP({client_ip}) 不一致！")
        raise HTTPException(status_code=403, detail="安全审查失败：检测到异地异网登录环境")

    # 6. 验证通过，更新缓存状态
    TOKEN_CACHE[token]["username"] = username
    TOKEN_CACHE[token]["expires_at"] = int(time.time()) + 300

    print(f"✅ [登录成功]: 用户 {username} 的 Token [{token}] 授权同步成功。")
    return {"status": "ok"}

@app.post("/biz-proxy/sync-payment")
async def sync_payment(request: Request):
    try:
        raw_payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的 JSON 数据格式")

    if not verify_b_signature(raw_payload):
        raise HTTPException(status_code=403, detail="签名验证失败")

    order_id = raw_payload.get("order_id")
    amount = raw_payload.get("amount")
    asset = raw_payload.get("asset")
    tx_id = raw_payload.get("tx_id")

    now = int(time.time())
    PAYMENT_CACHE[order_id] = {
        "amount": amount, "asset": asset, "tx_id": tx_id, "updated_at": now
    }

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("REPLACE INTO payments VALUES (?, ?, ?, ?, ?)",
                     (order_id, amount, asset, tx_id, now))
    return {"status": "ok"}

@app.get("/biz-proxy/callback")
def oauth_callback(
    request: Request,
    token: str = Query(..., description="主站回调带回的Token"),
    redirect: str = Query("/", description="最终要跳回的业务页面") # 默认回首页
):
    if not token:
        raise HTTPException(status_code=401, detail="缺少有效凭证")

    temp_info = TOKEN_CACHE.get(token)
    if not temp_info or int(time.time()) > temp_info["expires_at"]:
        raise HTTPException(status_code=403, detail="Token 无效或已过期")

    #  check initial ip with current ip
    client_ip = get_real_ip(request)
    if not (temp_info["initial_ip"] == client_ip):
        raise HTTPException(status_code=403, detail=f"检测到网络环境异常变更，拒绝颁发会话")
    if (temp_info["username"] is None):
        raise HTTPException(status_code=403, detail="未获得用户信息")
    bts_username = temp_info["username"]

    TOKEN_CACHE.pop(token, None)

    # 颁发长效 Session ID
    real_session_id = f"sess_{uuid.uuid4().hex}"
    expires_at = int(time.time()) + 86400 * 30

    AUTH_CACHE[real_session_id] = {
        "username": bts_username,
        "app_id": temp_info["app_id"],
        "expires_at": expires_at
    }

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("REPLACE INTO auth VALUES (?, ?, ?, ?, ?)", (real_session_id, temp_info["app_id"], bts_username, int(time.time()), expires_at))

    res = Response(
        status_code=302,
        headers={"Location": redirect},
        content="Login verified. Redirecting..."
    )

    res.set_cookie(key="bts_session", value=real_session_id, path="/", max_age=86400, httponly=True, secure=True, samesite="lax")
    return res


# ─── 授权查询接口：兼容 Nginx Header 查验 与 网站 URL 查验 ───
@app.get("/biz-internel/check-login")
def check_login(
    request: Request,
    session_id: str = Query(None, description="常规网站 URL 查询参数"),
    app_id: str = Query(None, description="常规网站 URL 查询参数"),
    # 后续正常访问 Linkding 时，由 Nginx 隐式塞入的 Header 凭证
    x_session_id: str = Header(None, alias="X-Session-ID", description="Nginx 隐式传入的长效 Session ID"),
    x_app_id: str = Header(None, alias="X-App-Id"),
):

    current_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "127.0.0.1")

    final_session_id = x_session_id or session_id
    final_app_id = x_app_id or app_id

    if not final_session_id or not final_app_id:
        raise HTTPException(status_code=401, detail="缺少有效会话ID")

    session_info = AUTH_CACHE.get(final_session_id)

    if not session_info or session_info.get("app_id") != final_app_id:
        raise HTTPException(status_code=403, detail="Session 无效或无权访问该应用")
    if int(time.time()) > session_info["expires_at"]:
        raise HTTPException(status_code=410, detail="Session 已过期")

    return Response(headers={"X-User": session_info["username"]}, content="OK")


@app.get("/biz-internel/check-payment")
def check_payment(
    order_id: str = Query(None),
    app_id: str = Query(None),
    x_order_id: str = Header(None),
    x_app_id: str = Header(None)
):
    final_order_id = x_order_id or order_id
    final_app_id = x_app_id or app_id

    if not final_order_id or not final_app_id:
        raise HTTPException(status_code=400, detail="缺少 order_id 或 app_id")

    pay_info = PAYMENT_CACHE.get(final_order_id)
    if not pay_info or pay_info["app_id"] != final_app_id:
        return {"amount": "0", "asset": "", "tx_id": ""}

    return {
        "amount": pay_info["amount"],
        "asset": pay_info["asset"],
        "tx_id": pay_info["tx_id"]
    }

@app.get("/biz-proxy/logout")
def logout(
    request: Request,
    # 从 Header（Nginx 模式）或者浏览器直连模式下提取当前会话 ID
    x_session_id: str = Header(None, alias="X-Session-ID", description="Nginx 隐式传入的长效 Session ID")
):
    session_to_delete = x_session_id or request.cookies.get("bts_session")

    if session_to_delete:
        # 清理内存缓存 (AUTH_CACHE)
        if session_to_delete in AUTH_CACHE:
            AUTH_CACHE.pop(session_to_delete, None)
            print(f"DEBUG >>> 成功从内存缓存中擦除 Session: {session_to_delete}")

        # 清理后端 SQLite 持久化数据库
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("DELETE FROM auth WHERE session_id = ?", (session_to_delete,))
                conn.commit()
        except Exception as e:
            print(f"ERROR >>> 退出登录时清理数据库异常: {str(e)}")

    # 如果用户是从 Linkding 的退出按钮点过来的，我们可以重定向回首页（此时因为没登录，Nginx 会再次拦截并送去登录页）
    redirect_target = request.headers.get("Referer", "/") # 优先返回上一页，没有则回根目录

    res = Response(
        status_code=302,
        headers={"Location": redirect_target},
        content="Logging out..."
    )

    res.set_cookie(
        key="bts_session",
        value="",
        path="/",
        max_age=0,
        httponly=True,
        secure=True,
        samesite="lax"
    )

    return res

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BTSBots 授权代理服务器")

    parser.add_argument("--host", type=str, default="127.0.0.1", help="监听地址")
    parser.add_argument("--port", type=int, default=9000, help="监听端口")
    parser.add_argument("bts_account", type=str, help="受信任的BTS账号名")
    parser.add_argument("pub_key", type=str, help="对应的BTS公钥")

    args = parser.parse_args()

    app.state.bts_pub_key = args.pub_key
    app.state.bts_account = args.bts_account
    print(f"🚀 BTSBots 网关代理启动 -> 地址: {args.host}, 端口: {args.port}")
    uvicorn.run(app, host=args.host, port=args.port, reload=False, workers=1)
