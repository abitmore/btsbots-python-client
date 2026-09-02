### btsbots User Guide

Welcome to the official **btsbots** client! This is a zero-trust, decentralized security toolkit designed for BitShares users. It allows you to log in securely, perform transfers and trading operations, and even invite friends to earn on-chain referral rewards—all while keeping your private keys safely stored on your local machine.

---

### 🚀 Prerequisites

This project uses **uv** for fast dependency and environment management. Make sure `uv` is installed on your system before proceeding.

For enhanced security and convenience, **it is strongly recommended to use `pass` (the standard Unix password manager with GPG encryption)** or the local **credential file (`--keyfile`)** generated during registration. Please avoid manual plaintext entry in the terminal.

---

### 🔑 Appendix: Credential File (`--keyfile`) Format

When an account is successfully registered via the tool, a credential file named `username_credentials.txt` is generated locally. Its standard format is:

```text
myaccountname
Owner WIF: 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3
Active WIF: 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3
Memo WIF: 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3
```
* **Line 1**: Your BitShares account name.
* **Following lines**: The intelligent multi-key manager automatically detects and imports all valid WIF private keys starting with `5`.
* Load it via `--keyfile`: `uv run sign_bots.py --keyfile myaccountname_credentials.txt`.

---

### 1. Secure Web Login (OTP Generation)

To log in to the web interface, generate a one-time password (OTP) locally via Python:

* **Recommended (via pass manager)**:
  ```bash
  uv run get_otp.py --pass btsbots/my_account
  ```
* **Convenient (via local credential file)**:
  ```bash
  uv run get_otp.py --keyfile myusername_credentials.txt
  ```

Upon success, an **OTP code** will be displayed in your terminal. Enter it on the web page to log in instantly.

---

### 2. Running the Local Signing Gateway (`sign_bots.py`)

The signing gateway intercepts web actions (transfers, limit orders), applies strict security policies, signs them locally, and broadcasts them to the BitShares blockchain.

1. **Start the Gateway**:
   ```bash
   uv run sign_bots.py --pass btsbots/my_account
   # Or using a credential file:
   uv run sign_bots.py --keyfile myusername_credentials.txt
   ```
2. **Authorize Device Public Key**:
   - Try an operation on the web app.
   - Your local terminal will log an unauthorized public key fingerprint. Map it inside `security_rules.json` under your device alias (e.g., `pc-market`), and the gateway will hot-reload instantly.

---

### Chapter II: sign_bots Risk Control & "Co-branded Credit Card" Bank Mode

To keep your master private key off the web while supporting flexible daily operations, `btsbots` provides an enterprise-grade **Zero-Trust Risk Control Engine**.

You can analogize this system as **"acting as your own central bank, issuing co-branded credit cards to family or secondary devices"**: your master private key stays secure in your vault, while secondary devices are granted specific spending limits and permissions.

#### 🛡️ Key Risk Control Features:
1. **Device Aliasing**: Grant distinct privileges to different devices (e.g., trading tablets can only place/cancel orders, core wallets handle transfers).
2. **Unlimited Payments**: Only authorized high-tier devices can make large transfers to trusted whitelisted accounts (e.g., exchanges).
3. **Micro Payments & "Co-branded Credit Card" Mode**: Set micro-payment limits (single, daily, weekly caps) for family devices. When triggered, the gateway prompts a **PIN code** prompt in the App to authorize instantly.
4. **Volatility Protection**: Automatically compares trading prices against historical rolling windows (1h, 1d, 1w) to prevent malicious wash trading.

#### ⚙️ Configuring `security_rules.json`:
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
    "trading_risk": {
        "authorized_devices": [ "pc-market" ],
        "volatility_limit_1h": 0.97,
        "market_whitelist": [ "CNY/USD", "CNY/BTS", "BTS/USD" ]
    },
    "unlimited_payments": {
        "authorized_devices": [ "Aphone-wallet" ],
        "recipient_whitelist": { "exchange.btsbots": "1.2.33015" }
    },
    "micro_payments": {
        "base_limits": { "CNY": 50, "USD": 10, "BTS": 1000 },
        "device_rules": {
            "Cphone": { "single_multiplier": 0.6, "day_max_multiplier": 1, "week_max_multiplier": 7, "pin": 1664 },
            "Aphone-wallet": { "single_multiplier": 20.0, "day_max_multiplier": 100, "week_max_multiplier": 500, "pin": null }
        }
    }
}
```

---

### 3. Community Referral & Account Registration

#### 💡 BitShares Registrar & Referral Incentive Mechanism
The BitShares blockchain features a native referral and revenue-sharing mechanism:
- When you act as the **Registrar/Referrer** to register new users on-chain, all trading fees generated by those users on the BitShares DEX are automatically rebated back to you at a preset percentage (e.g., 100%).
- With the `btsbots` invitation system, you can easily help friends register while building your own Web3 community growth flywheels and earning long-term on-chain rewards.

#### 🛠️ How to Use:
* **Step 1: Generate an Invitation Code**
  ```bash
  uv run invitation_tool.py --action generate --pass btsbots/my_account
  ```
  To check your invitation codes:
  ```bash
  uv run invitation_tool.py --action list --pass btsbots/my_account
  ```

* **Step 2: Friend Registers Using the Code**
  ```bash
  uv run registre_account.py --invite BTS-XXXX
  ```
  - Guides them to choose a compliant lowest-fee username.
  - Securely generates keypairs locally and submits them to your `sign_bots` gateway.
  - Your gateway automatically broadcasts the on-chain registration, setting you as the referrer.
  - A credential file is generated for your friend to start using immediately!
