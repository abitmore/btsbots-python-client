### btsbots 用户指南

欢迎使用 **btsbots** 官方客户端！这是一个专为比特股（BitShares）用户打造的零信任、去中心化安全工具包。它能让您在网页端安全登录、一键完成代币转账、挂单交易，甚至通过邀请好友注册轻松赚取链上推荐分成，而您的私钥永远安全地保留在本地电脑中，绝不会泄露到云端。

---

### 🚀 准备工作

本项目采用现代 Python 开发并使用 **uv** 进行极速依赖和环境管理。开始前，请确保您的系统中已安装 `uv`。

为了您的账户资产安全和操作便利，**强烈建议使用标准的 Unix 密码管理器 `pass`（配合 GPG 加密）** 或项目生成的 **安全凭证文件 (`--keyfile`)** 来管理私钥。请避免直接在终端中手动输入私钥，以免留下明文历史记录。

---

### 🔑 附录：凭证文件 (`--keyfile`) 格式说明

当您通过注册工具成功创建一个账号后，本地会生成一个形如 `username_credentials.txt` 的凭证文件。其标准格式如下：

```text
myaccountname
Owner WIF: 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3
Active WIF: 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3
Memo WIF: 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3
```
* **第 1 行**：您的 BitShares 账号名。
* **后续各行**：智能多 Key 管理器会自动识别并导入所有以 `5` 开头的有效 WIF 私钥（支持单把或多把独立 Key）。
* 使用时只需通过 `--keyfile` 参数加载：`uv run sign_bots.py --keyfile myaccountname_credentials.txt`。

---

### 1. 网页端安全登录（获取 OTP）

为了登录 btsbots 网页端，您需要先在本地运行 Python 客户端以生成一次性密码（OTP）：

* **推荐方式（使用 pass 密码管理器）**：
  ```bash
  uv run get_otp.py --pass btsbots/my_account
  ```
* **便捷方式（使用本地凭证文件）**：
  ```bash
  uv run get_otp.py --keyfile myusername_credentials.txt
  ```

登录成功后，终端会输出一个 **6 位数的动态网页验证码（OTP）**。将其输入到网页端即可秒级安全登录。

---

### 2. 使用本地签名守护网关 (`sign_bots.py`)

签名网关允许您在网页端轻松触发交易操作（如转账、挂单、撤单），而本地的守护进程会自动进行安全策略风控、签名并广播到比特股区块链。

1. **启动签名守护网关**：
   ```bash
   uv run sign_bots.py --pass btsbots/my_account
   # 或者使用凭证文件：
   uv run sign_bots.py --keyfile myusername_credentials.txt
   ```
2. **首次授权设备公钥**：
   - 打开网页端并尝试执行一个操作。
   - 终端会提示该设备的公钥未授权并显示公钥指纹。
   - 打开根目录下的 `security_rules.json`，将该公钥映射至您的设备别名（如 `pc-market` 或 `Aphone-wallet`）中，网关即刻热加载生效。

---

### 章节二：sign_bots 网关风控策略与“联名信用卡”银行模式

为了让您的主私钥永远不暴露在网页端，同时满足多样化的日常转账与交易需求，`btsbots` 的签名网关 (`sign_bots.py`) 提供了一套企业级的**零信任风控策略引擎**。

您可以将这套系统类比为**“自己当中央银行，给家人、小孩或不同设备发放联名信用卡”**：主私钥锁在您最安全的保险箱（主服务器或本地 PC）里，而给不同的手机、平板或分身设备赋予不同的“额度与权限”。

#### 🛡️ 风控策略能实现哪些功能？
1. **设备权限隔离（Device Aliasing）**：不同的设备拥有截然不同的操作特权（如交易平板只能挂单撤单，核心钱包才能大额转账）。
2. **大额白名单转账（Unlimited Payments）**：只有授权的高级设备，才能向官方或受信的白名单收款账户（如交易所、固定的商业伙伴）发起大额转账。
3. **小额微支付与“联名信用卡”银行模式（Micro Payments & PIN）**：您可以给家人或小孩的手机设置小额联名卡权限，限制单笔、天累计、周累计上限。当小额支付触发安全阈值时，网关会要求在 App 弹窗输入 **PIN 码** 验证，输入正确即刻安全放行！
4. **防对倒刷单与价格偏离保护（Volatility Protection）**：自动比对历史滑动窗口的成交价格，防止手抖或网页被劫持产生恶意低卖高买。

#### ⚙️ 如何配置 `security_rules.json`？
网关支持热加载，修改后无需重启：
```json
{
    "description": "BTSBots Account and Asset Pricing Risk Control Strategy",
    "updated_at": "2026-09-01 21:25:00",
    "fee_limit": 10,
    "public_keys": {
        "c266a5528a64d93184e1f59ab65ee325bfe3f919cf6fe9300a": "pc-market",
        "db87c899a44b3197c5174c8c0d097fda8decf208e357407591": "Aphone-wallet",
        "d02396d17e7846bad306ff80bb97d0f7a6386d53f0b0aeaf7d": "Cphone"
    },
    "oauth_allowed_devices": [ "Aphone-wallet" ],
    "__comment_oauth": "允许执行动态OTP登录及第三方应用授权的设备",
    "trading_risk": {
        "authorized_devices": [ "pc-market" ],
        "__comment_trading_devices": "允许挂单、撤单、交易的设备",
        "market_whitelist": [ "CNY/USD", "CNY/BTS", "BTS/USD" ],
        "volatility_limit_1h": 0.97,
        "volatility_limit_1d": 0.95,
        "volatility_limit_1w": 0.90,
        "__comment_volatility": "限价保护: 卖单价/买单价 必须大于该阈值，防止手抖或被控对倒刷单",
    },
    "unlimited_payments": {
        "authorized_devices": [ "Aphone-wallet" ],
        "recipient_whitelist": { "exchange.btsbots": "1.2.33015" }
    },
    "micro_payments": {
        "base_limits": { "CNY": 50, "USD": 10, "BTS": 1000 },
        "device_rules": {
            "Cphone": { "single_multiplier": 0.6, "day_max_multiplier": 1, "week_max_multiplier": 7, "pin": 1664 },
            "Aphone-wallet": { "single_multiplier": 20.0, "day_max_multiplier": 100, "week_max_multiplier": 500, "pin": "" },
        "__comment_device_rules": "设备阶梯风控: 分别为(/单笔/天累计/周累计)额度倍数的限制。20CNY就是0.4额度，5USD又加上0.5的额度就是累计0.9"
        }
    }
}
```

---

### 3. 社区裂变与邀请码注册功能（含 BitShares 激励机制）

#### 💡 BitShares 推荐人与分红激励机制介绍
比特股（BitShares）底层区块链拥有非常独特的**原生裂变与推荐激励机制**：
- 当您作为**推荐人（Registrar / Referrer）**在链上为新用户注册账号时，新用户后续在比特股 DEX 进行交易所产生的所有交易手续费（Trading Fees），系统都会按照设定的比例（如 100%）自动返还给推荐人账号！
- 此外，通过 `btsbots` 的邀请码系统，不仅能帮朋友享受最低费率的极速注册，还能让您建立属于自己的 Web3 社区推广飞轮，躺赚长期的链上生态红利。

#### 🛠️ 如何操作：
* **步骤 1：生成邀请码**
  运行邀请码管理工具为自己生成一个专属邀请码：
  ```bash
  uv run invitation_tool.py --action generate --pass btsbots/my_account
  ```
  查看名下所有邀请码的使用状态：
  ```bash
  uv run invitation_tool.py --action list --pass btsbots/my_account
  ```

* **步骤 2：朋友使用邀请码注册账号**
  您的朋友拿到邀请码后，只需在本地运行注册引导工具：
  ```bash
  uv run registre_account.py --invite BTS-XXXX
  ```
  - 程序会引导朋友输入符合 BitShares 规范的最低费率用户名。
  - 自动在本地安全生成私钥对并提交至您的 `sign_bots` 网关。
  - 您的守护进程自动审核并代为在链上广播注册，同时将您设为推荐人和注册人。
  - 注册成功后，朋友的电脑上会生成专属凭证文件，引导其直接启动守护并登录 App！
