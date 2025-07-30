> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247506865&idx=1&sn=4ab467a93c57c8645bb7184e62bb1679

#  破解 JWT：漏洞赏金猎人指南（第七部分）——最终的 P1 Boss  
haidragon  安全狗的自我修养   2025-06-30 04:10  
  
#   
# 官网：http://securitytech.cc/  
##   
## 利用算法混淆漏洞绕过 JWT 身份验证，无需密钥泄露  
  
  
  
攻破系统并不需要私钥——只要逻辑上有个漏洞就行。真正的黑客不会猜测……他们  
  
****  
# 🧨 序言 — — 大结局 🗿💣  
  
经过数日紧张的实验室入侵、PoC 构建以及对 JWT 的疯狂钻研——我们终于成功了。这是我的“破解 JWT：漏洞赏金猎人指南”系列的最终章。  
  
在这篇终极文章中，我们探讨了 JWT 算法混淆问题——没有
```
kid
```

、没有
```
jwk
```

、没有
```
jku
```

，以及没有暴露密钥。纯粹的逻辑滥用、数学欺骗和 Burp 魔法，可以在没有私钥的情况下弹出管理员账户。这就是🔐安全与错误配置相遇的地方，我们将其转化为一个完整的漏洞利用。  
  
无论你是新手漏洞猎人，还是经验丰富的红队成员，这次攻击都会给你带来重击。让我们全力以赴吧。🧠⚡  
  
  
  
# 📚 完整系列 — 以防你错过任何内容 👇  
  
每个部分都处理一个独特的 JWT 错误配置场景，从基本缺陷到狂野的密钥注入技巧：  
  
1️⃣ 第 1 部分 ——通过 None 算法进行 JWT 令牌欺骗  
  
2️⃣ 第 2 部分 —通过 HMAC 暴力破解实现 JWT 密钥混淆  
  
3️⃣ 第 3 部分 ——通过 kid 参数进行 JWT 标头注入  
  
4️⃣ 第 4 部分 —通过 JWK 注入绕过 JWT 签名  
  
5️⃣ 第五部分 — JWT JKU 参数利用  
  
6️⃣ 第六部分 — JWT 算法混淆（公钥作为秘密）  
  
7️⃣🔥 最终 Boss — 你正在阅读。无需私钥，别再找借口了。  
  
  
  
JWT 索引  
  
  
  
  
# 🧠 简介：JWT，但不太安全……  
  
JSON Web Tokens (JWT) 是现代 Web 身份验证的支柱——快速、无状态且紧凑。但是，如果您不强制服务器验证 JWT 的方式……像我们这样的攻击者就可以扭曲这种逻辑。今天 PortSwigger 的实验展示了如何通过 JWT 算法混淆来绕过身份验证——无需密钥泄露。只需巧妙地利用公钥、alg 头和💣 HMAC 滥用即可。  
  
让我们打开引擎盖，重写规则。🔐🧠  
  
  
  
JWT 身份验证绕过最终  
  
  
  
  
# ⚠️什么是 JWT 算法混淆？  
  
JWT 可以使用以下方式签名：  
- 
```
RS256
```

：非对称（公共/私人 RSA）  
- 
```
HS256
```

：对称（共享秘密 HMAC）  
算法混淆发生在以下情况：  
> 为 RS256 配置的服务器错误地接受 HS256 并使用 RSA 公钥作为 HMAC 密钥。  
  
  
那么会发生什么呢？  
  
✅ 你可以伪造任何 JWT  
  
✅ 绕过身份验证  
  
✅ 获取管理员权限  
  
✅ 无需私钥  
  
只是一些扭曲的标头值和过度信任的服务器。💀  
  
  
  
# 🔬 漏洞摘要  
- **类型：** JWT身份验证绕过  
- **弱点：**算法混乱（RS256 → HS256）  
- **影响：**管理员访问、帐户删除  
- **CVSS 类比：**通过算法信任进行不当授权  
- **真实世界严重程度：** 🔴 P1 — 严重  
# 🔍 漏洞利用演练（分步 PoC）  
  
让我们重建实验室并了解确切的漏洞链。  
# 🔧 背景：安装 JWT 编辑器扩展（Burp BApp Store）  
  
  
  
  
  
  
# ✅ 1. 进入实验室  
  
访问：
```
https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key
```

使用以下方式登录：
```
wiener:peter
```

  
  
  
  
  
  
  
# 🧪 2. 尝试访问 /admin  
  

```
/my-account
```

将请求修改为
```
/admin
```

。您会看到：  
> “仅以管理员身份登录时才可使用管理界面。”  
  
  
  
  
  
  
  
# 🔄 3. 重新登录并收集 JWT  
- 注销，然后重新登录。  
- 从 cookie 中捕获两个会话的 JWT 
```
session
```

。  
- 保存它们以用于公钥派生。  
# 🔑 4. 运行密钥派生脚本  
  
使用Docker的
```
sig2n
```

工具来暴力破解公钥：  

```
docker run -- rm -it portswigger/sig2n <JWT1> <JWT2>
```

  
输出：  
- 可能的
```
n
```

值（模量）  
- Base64编码的X.509公钥  
- 使用该密钥签名的被篡改的 JWT  
# 🎯 5. 识别有效的 JWT  
- 将每个被篡改的 JWT 粘贴到
```
session
```

cookie 中。  
- 发送请求至
```
/my-account
```

。  
✅ 如果您得到
```
200 OK
```

→ 这是正确的密钥。  
  
🚫 如果您得到
```
302 Redirect to /login
```

→ 请尝试下一个。  
  
  
  
  
  
  
# 🧬 6. 创建对称密钥（JWT 编辑器）  
- 从有效的篡改 JWT 中复制 Base64 X.509 密钥。  
- 在 JWT 编辑器 > 密钥选项卡 → 新建对称密钥中。  
- 将
```
k
```

值设置为 Base64 公钥。  
# 🛠️ 7.修改并签名令牌  
- 在 Burp Repeater > JSON Web Token 选项卡中：  
- 
```
sub
```

将索赔变更为
```
administrator
```

  
- 设置
```
alg
```

为
```
HS256
```

  
- 点击签名 → 选择新创建的密钥  
- 确保选中“不要修改标题”  
# 🔓 8. 将请求发送至 /admin  
  
瞧！ 🪄 您现在拥有管理员权限了！  
  
  
  
  
  
  
# 💣 9. 删除用户 Carlos  
  
发送请求至：
```
/admin/delete?username=carlos
```

  
  
  
  
  
  
  
# 🎉 10. 确认实验室问题已解决  
  
右键点击 → 在浏览器中显示 → 粘贴响应 URL。实验已解决✔️  
  
  
  
# 💡 关键要点  
- 永远不要相信
```
alg
```

不受信任的 JWT 的字段。  
- 修复服务器端算法 — 不允许回退到
```
HS256
```

。  
- 公钥是公开的。不要将其视为秘密。  
- 像 RSA 这样的安全算法的安全性取决于其实现。  
# 👨‍💻 最后的想法  
  
这个实验让整个 JWT 之旅圆满结束。你不需要私钥就能破解应用程序——只要开发者做出一个错误的决定。  
  
至此，我们的 JWT 系列圆满结束 💥 但你的赏金之旅？这才刚刚开始。  
  
  
  
# 🧡 保持敏锐。保持好奇心。保持道德。  
  
下次漏洞利用，期待您的发现。****  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHNFLNQbv6QWUbnoWgoia6fefdWzpHtRJmjwYpmxnTLiasU5KzHoOJ3D4ofMtfPOOqRzLRSaicemSdpA/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
-   
- 公众号:安全狗的自我修养  
  
- vx:2207344074  
  
- http://  
gitee.com/haidragon  
  
- http://  
github.com/haidragon  
  
- bilibili:haidragonx  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
