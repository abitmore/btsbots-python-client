### btsbots Python 客户端

本项目是 [btsbots.com](https://btsbots.com) 的官方 Python 客户端。它为您提供安全的网页端登录工具，并可在本地运行签名网关，确保您的比特股（BitShares）私钥无需上传即可安全完成链上操作。 

### 前置要求

本项目使用 uv 进行依赖和环境管理。开始前，请确保您的系统中已安装 uv。 

### 1. 网页端登录（获取 OTP 验证码）

为了登录 btsbots 网页端，您需要先在 Python 本地端进行身份验证，以生成一个一次性密码（OTP）。 

### 方式 A：标准登录（交互式输入）

直接运行主程序，终端会提示您依次输入比特股用户名、Active WIF（活跃私钥）和 Memo WIF（备忘录私钥）： 

bash

uv run get_otp.py

Use code with caution.

登录成功后，终端会显示一个 **8 位数的 OTP 验证码**。在网页端登录页面输入该验证码即可完成登录。 

### 方式 B：使用 pass 密码管理器（强烈推荐）

为了更高的安全性和便利性，建议使用 **pass**（标准的类 Unix 密码管理器）。pass 使用 GPG 加密您的私钥，免去每次手动输入的麻烦。 

1. **新建 pass 节点**： 

bash

pass insert btsbots/my_account

Use code with caution.
2. **在节点文件中，请严格按照以下格式输入内容**： 

  * **第一行**：您的比特股用户名
  * **第二行**：您的 Active WIF
  * **第三行**：您的 Memo WIF
3. **使用 --pass 参数运行程序**：
后面跟上您刚才创建的 pass 节点路径： 

bash

uv run get_otp.py --pass btsbots/my_account

Use code with caution.

### 2. 使用签名网关

签名网关允许您在网页端触发交易操作（如交易下单），而私钥依然安全地保留在您本地的电脑中进行签名。 

### 步骤 1：启动网关监听

运行签名管理程序（同样支持 --pass 登录方式）： 

bash

uv run sign_manager.py
# 或者使用 pass 节点启动：
uv run sign_manager.py --pass btsbots/my_account

Use code with caution.

登录成功后，程序会自动启动并保持监听服务。 

### 步骤 2：获取并授权客户端公钥

1. 打开 btsbots 网页端并尝试执行一个操作（例如：下单）。
2. 此时观察您的本地 Python 终端，程序会提示**该客户端的公钥未授权**，并会在屏幕上**显示该公钥**。
3. 复制终端中显示的这段公钥。

### 步骤 3：配置白名单 (security_rules.json)

打开项目根目录下的 security_rules.json 文件。将复制的公钥粘贴到对应字段中，并根据需要配置您的交易和转账白名单： 

json

{
  "authorized_keys": [
    "这里粘贴您复制的客户端公钥"
  ],
  "allowed_operations": [
    "limit_order_create",
    "limit_order_cancel"
  ],
  "allowed_transfer_destinations": [
    "exchange-account",
    "trusted-friend"
  ]
}

Use code with caution.

### 步骤 4：自动生效与完成

* **无需重启**：sign_manager.py 具有热加载功能，会自动检测 security_rules.json 文件的修改并即时生效。
* 回到网页端，再次尝试执行刚才的下单操作，此时本地网关就会顺利通过验证、完成签名并广播交易。
