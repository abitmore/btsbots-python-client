### btsbots Python Client

This is the official Python client for [btsbots.com](https://btsbots.com). It provides tools to log in to the web interface securely and run a local signing gateway for your BitShares operations. 

### Prerequisites

This project uses uv for dependency and environment management. Make sure you have uv installed before proceeding. 

### 1. Web Login (OTP Generation)

To log in to the btsbots web interface, you must first authenticate via this Python client to generate a one-time password (OTP). 

### Option A: Standard Login (Interactive)

Run the main script directly. The terminal will prompt you to enter your BitShares username, Active WIF, and Memo WIF: 

bash

uv run get_otp.py

Use code with caution.

Upon successful authentication, the script will output an **8-digit OTP code**. Enter this code on the web interface to complete your login. 

### Option B: Password Manager Login via pass (Recommended)

For enhanced security and convenience, it is highly recommended to use **pass** (the standard unix password manager). pass safely encrypts your secrets using GPG. 

1. **Create a new pass entry:** 

bash

pass insert btsbots/my_account

Use code with caution.
2. **Format your entry exactly like this:** 

  * **Line 1:** Your BitShares Username
  * **Line 2:** Your Active WIF
  * **Line 3:** Your Memo WIF
3. **Run the script with the --pass flag:**
Provide the path of the pass node you just created: 

bash

uv run get_otp.py --pass btsbots/my_account

Use code with caution.

### 2. Using the Signing Gateway

The signing gateway allows you to trigger operations on the web interface while keeping your private keys safe locally on your machine. 

### Step 1: Start the Gateway

Run the signing manager script (you can use the same --pass method if configured): 

bash

uv run sign_manager.py
# Or with pass:
uv run sign_manager.py --pass btsbots/my_account

Use code with caution.

Once logged in, the gateway will automatically start a local listening service. 

### Step 2: Authorize Your Client Public Key

1. Go to the btsbots web interface and attempt an operation (e.g., place a limit order).
2. Look at your local Python terminal. It will log a warning stating that the **client's public key is unauthorized**, and it will display that public key.
3. Copy this public key.

### Step 3: Configure Whitelists (security_rules.json)

Open the security_rules.json file in your project directory and paste your public key into the relevant fields. Define your whitelists for allowed operations and transfer destinations: 

json

{
  "authorized_keys": [
    "YOUR_COPIED_PUBLIC_KEY_HERE"
  ],
    "user_whitelist": {
        "angel": "1.2.1000",
        "dan": "1.2.2000"
    },
    "market_whitelist": [
        "CNY/USD", "CNY/BTS", "BTS/USD"
    ]
}

Use code with caution.

### Step 4: Hot-Reload & Complete

* **No restart required:** The sign_manager.py automatically detects changes to security_rules.json and applies them instantly.
* Go back to the web interface and re-submit your order or transaction. The gateway will now successfully intercept, sign, and broadcast it.
