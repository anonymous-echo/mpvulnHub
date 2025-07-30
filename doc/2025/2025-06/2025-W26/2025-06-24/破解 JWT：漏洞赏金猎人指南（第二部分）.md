> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247506770&idx=1&sn=b43532f3f972ae1cc74a3ac4cf9c3ff4

#  破解 JWT：漏洞赏金猎人指南（第二部分）  
haidragon  安全狗的自我修养   2025-06-24 04:45  
  
# 通过弱签名密钥绕过 JWT 身份验证以获取 Bug Bounty，通过在易受攻击的 Web 应用程序中强制使用弱 JWT 机密来伪造管理员访问权限。  
## 前 言：破解 JWT 系列  
  
欢迎来到我正在进行的“破解 JWT”漏洞赏金利用系列的第 2 部分——深入探讨不良加密实践和 Web 身份验证系统交叉点上的漏洞。  
  
JWT（JSON Web Tokens）无处不在——从现代 Web 应用程序到 API 身份验证——但如果实施不当，它们就会成为攻击者的金矿。本系列教程包含多个部分，将带您探索 7 个以上基于真实世界的实验，涵盖从存在缺陷的验证和算法混淆，到可暴力破解的密钥和公钥配置错误等各种问题。  
  
这是第 1 篇文章的链接。  
  
  
  
文章索引  
  
  
如果您是漏洞赏金猎人、安全研究员，或者只是渴望了解 JWT 是如何被攻破的 —— 那么这篇文章就适合您。🧠💣  
  
  
  
# ✨ 简介  
  
JSON Web Tokens (JWT) 在 Web 应用程序中用于维护会话和身份信息，非常流行。但与任何安全机制一样，JWT 的安全性取决于其实现方式。在本文中，我将带您完成一个动手实验，通过暴力破解一个弱对称签名密钥并伪造一个有效的管理员令牌来绕过 JWT 身份验证。💥  
  
是的，我又在这个实验室里把卡洛斯删掉了。卡洛斯永远是卡洛斯。😤  
  
  
  
破解 JWT：漏洞赏金猎人指南（第二部分）  
  
  
  
  
# 🔐 JWT 简介：快速复习  
  
典型的 JWT 由 3 个以点分隔的 base64 编码部分组成：  

```

```


```
<Header>.<Payload>.<Signature>
```

# 1. 标题  
  
包含有关所用算法的元数据：  
  
{  
  
"alg"  
:  
  
"HS256"  
,  
  
"typ"  
:  
  
"JWT"  
  
}  
# 2. 有效载荷  
  
存储有关用户的声明：  
  
{  
  
"sub"  
:  
  
"wiener"  
,  
  
"admin"  
:  
  
false  
  
}  
# 3.签名  
  
使用密钥以加密方式验证令牌是否被篡改。  
  
  
  
# 🧠 了解漏洞  
  
PortSwigger Academy 实验室向我们展示了一个经典漏洞：使用弱对称密钥 ( 
```
secret1
```

) 签名的 JWT。如果我们能够暴力破解该密钥，就能签署自己的令牌，并冒充任何用户，包括管理员。😎  
  
这种缺陷在现实世界的应用程序中极其常见，开发人员：  
- 硬编码秘密  
- 使用弱/密码式密钥  
- 不要旋转或安全存储签名材料  
让我们打破这个实验室并将那个弱密钥转变为完全的管理控制权。  
  
  
  
# 🧪 实验室概述  
  
实验室名称：通过弱签名密钥绕过 JWT 身份验证平台：PortSwigger Web 安全学院目标：暴力破解 JWT 签名密钥，伪造管理员令牌并删除
```
carlos
```

  
  
  
  
# 🧰 你需要的工具  
- 🧩 Burp Suite（带有 JWT 编辑器扩展）  
- ⚔️ Hashcat（暴力破解 JWT 秘密）  
- 🔐 Wallarm 的 jwt-secrets 列表  
# ✅ 漏洞利用步骤  
> ⚠️ 在我们开始之前，请确保在 Burp 中设置了 JWT 编辑器扩展。  
  
  
  
  
# 1️⃣ 进入实验室  
  
访问提供的实验室 URL 并使用以下方式登录：
```
wiener:peter
```

  
  
  
  
  
  
  
# 2️⃣ 尝试访问/admin  
  
尝试直接访问 — 您将收到 403 或重定向。目前尚无管理员权限。  
  
  
  
  
  
  
# 3️ 捕获 JWT  
  
在 Burp 中，拦截对 的请求
```
/admin
```

，然后将其发送到 Repeater。检查 Authorization 标头——这就是我们的目标 JWT。  
  
  
  
  
  
  
# 4️⃣ 暴力破解 JWT 密钥  
  
克隆秘密列表：  

```
git clone https://github.com/wallarm/jwt-secrets
```

  
运行 Hashcat：  

```
hashcat -a 0 -m 16500 <JWT_STRING> jwt-secrets/jwt.secrets.list
```

  
  
  
  
💥 Boom — 我们破解了秘密：  
  
secret1  
> 💡 运行
```
--show
```

即可揭示破解的秘密，无需重新处理。  
  
  
  
  
# 5️⃣ Base64 编码秘密  
  
使用 Burp Decoder 编码
```
secret1
```

为 base64：  
  
Result  
 → c2VjcmV0MQ==  
  
  
  
  
  
  
# 6️⃣ 在 Burp 中生成对称密钥  
  
JWT 编辑器 → 密钥 → 新建对称密钥  
- 生成新密钥  
- 将参数替换
```
k
```

为
```
c2VjcmV0MQ==
```

  
- 保存密钥  
# 7️⃣ 修改并签名令牌  
  
在 Burp Repeater → JWT 选项卡中：  
- 更改
```
&#34;sub&#34;
```

为
```
&#34;administrator&#34;
```

  
- 点击签名→选择对称密钥  
- 勾选“不要修改标题”  
- 点击“确定”  
# 8️⃣ 发送修改后的请求  
  
将签名的 JWT 请求发送至
```
/admin
```

🎉 成功 — 授予管理员访问权限。  
  
  
  
  
  
  
# 9️⃣ 删除卡洛斯  
  
发送此 GET 请求：  
  
/admin/delete?username=carlos  
  
🗑️ 抱歉，卡洛斯，你跑得很好。  
  
  
  
  
  
  
# 🔟确认实验室完成  
  
右键单击 → 在浏览器中显示 → 确认实验成功。🏁 大功告成！  
  
  
  
  
  
  
# 📌 关键要点  
  
✅ 弱 JWT 密钥 = 严重的身份验证绕过  
  
✅ 始终正确使用 base64 加密你的密钥  
  
✅ Hashcat + Burp 等工具 = 致命组合  
  
✅ 永远不要低估代币逻辑中的小疏忽  
  
  
  
# 🌍 现实世界的相关性  
  
JWT 是现代应用程序中的主要内容，但它们的实现通常很差：  
- 薄弱/可猜测的秘密  
- 移动应用中的硬编码令牌  
- 缺乏
```
alg
```

执法  
这些疏忽可能意味着全面入侵——账户接管、权限提升、数据窃取。在 VAPT 或赏金工作期间，务必对 JWT 进行批判性分析。🧠💼  
  
  
  
# 🙌 祝您黑客愉快！  
  
这就是我的 JWT 绕过系列的第二部分！从
```
alg: none
```

密钥破解开始，我们正在慢慢揭开错误配置的 JWT 的真正脆弱性。  
  
   
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW0h21TYuO94OrIGsD2aHGrUcUYiasibQS5AYJ4a95Ra3zIFIXQ4e8lkFA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW6iapnXQ3Wviaiaiap37xFRqNok6BymcTiacnk07OowXYFowAKYfa9zS6gSA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zWiaJkE3jZRR7znMJDXAlibBzibYaGLMlVvsa1xhlQFyv3viaARicSIII7a9A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
#   
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHWXCBzZk44eZOKvIGq0RZia2vfZVtmPodgjznTwlY7PXU40F5KQ8xiceJOhLktswpMhec0zQVz07Cw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
rust语言全栈开发视频教程-第一季(2025最新)  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFO4iaNJUiawzlicADlGjS6UCWtUt0Jaibcc4U8aM7H8pSmjNWZHzZC2ibEib1voX6Waqowyd0Mnfce48Hg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFO3lqcLOMSd2PQZ9GiblkFIKNw2LH9DMNEibhyxpUVNCd907wCN9NroUqTaJgquiapibArIRby4AGMoQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFO3lqcLOMSd2PQZ9GiblkFIRnBhWWFJXdzp516ibYibQsicDCzfq1MicKGdv9os1l2nyDAVNSR8b5cPow/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
# 详细目录  
# mac/ios安全视频  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFbBn3mydWukVkxb7u4ibpOneTvEKRymYhW9KMlUWP1RnaXLuZibvPMdGmrdWVV3AMJya9dNxszgOeA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
# QT开发底层原理与安全逆向视频教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGLucgfllJsyUEFRxtnUNkLfUhNeUCnH7x8VtPq0Q2zxZBdhjqiaibsx0rIbaYWMuIibmk5QtNPzsOSw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
linux文件系统存储与文件过滤安全开发视频教程(2024最新)  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHSM6Wk8NAEmbHHUS2brkROr9JOj6WZCwGz4gE4MlibULVefmhRw2dvJd8ZeYnDpRIm0AV1TmIsuEQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
linux高级usb安全开发与源码分析视频教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHCd9Qic4AAIQfFFD7Rabvry4pqowTdAw6HyVbkibwH5NjRTU4Mibeo4JbMRD3XplqCRzg4Kiaib3jchSw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
linux程序设计与安全开发  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGoVibbKav1DpliaTJ9icDrosqXeWyaMRJdCVWEG0VYLDibSMwUP1L5r9XmLibGkEkSZnXjPD6mWgkib9lA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEH4eXCW471pNuHpGPzUKCkbyticiayoQ5gxMtoR1AX0QS7JJ2v1Miaibv1lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- #   
  
-   
- windows网络安全防火墙与虚拟网卡（更新完成）  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERE5qcRgQueCyt3U01ySnOUp2wOmiaFhcXibibk6kjPoUhTeftn9aOHJjO6mZIIHRCBqIZ1ok5UjibLMRA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- windows文件过滤(更新完成)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmvkF91T2mwk3lSlbG5CELC5qbib3qMOgHvow2cvl6ibicVH4KguzibAQOQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- USB过滤(更新完成)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHv0vyWxLx9Sb68ssCJQwXngPmKDw2HNnvkrcle2picUraHyrTG2sSK7A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 游戏安全(更新中)  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHzEAlXtdkXShqbkibJUKumsvo65lnP6lXVR7nr5hq4PmDZdTIoky8mCg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ios逆向  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmjrTM3epTpceRpaWpibzMicNtpMIacEWvJMLpKKkwmA97XsDia4StFr1Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- windbg  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibv9VNhRI73qFehic91I5dsr3Jkh6EkHIRTPGibESZicD7IeA5ocHjexHhw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 还有很多免费教程(限学员)  
  
-   
-   
-   
- windows恶意软件开发与对抗视频教程  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFPap5AiahwlmRC2MGPDXSULNssTzKQk8b4K3pttYKPjVL4xPVu1WHTmddAZialrGo8nQB3dJfJvlZQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
