> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247506789&idx=1&sn=ac6c506a103f943a10d3556aaa61cd02

#  破解 JWT：漏洞赏金猎人指南（第三部分）  
haidragon  安全狗的自我修养   2025-06-25 04:09  
  
## 通过不安全的 jwk 标头注入来绕过 JWT 身份验证允许攻击者伪造令牌并获得未经授权的管理员访问权限。  
  
  
 前言  
  
JWT 让我着迷——不仅仅是因为它们紧凑的设计或无状态的强大功能，更在于当你修改正确的标头或签名时，它们会悄无声息地崩溃。如果你一直在关注这篇文章，那么你已经看到了第一篇文章：通过未经验证且存在缺陷的算法绕过 JWT 的惨痛教训，我甚至没有对令牌进行签名就绕过了身份验证。接下来是第二篇文章，我通过弱签名密钥暴力破解绕过了 JWT 身份验证。  
  
现在是时候进一步加大力度了。  
  
本实验深入探讨了一种更加优雅且险恶的漏洞——通过
```
jwk
```

标头注入绕过 JWT 身份验证。简单来说：我将自己的公钥注入JWT 标头，并使用相应的私钥对令牌进行签名。服务器呢？它直接接受，不会询问任何问题。解锁了完全管理员权限。🗿  
  
  
  
JWT 索引  
  
  
  
  
# ✨ 简介  
  
JSON Web Tokens (JWT) 在现代 Web 应用中随处可见——它支持登录、会话和安全数据交换。它们简洁、独立，但一旦被误用，就会非常危险。其中一种配置错误？信任直接嵌入在 token 头中的密钥。没错，这就是本实验室的攻略所在。  
  
输入
```
jwk
```

字段 — JSON Web Key 的缩写。它是 JSON 格式的公钥的结构化表示，通常用于验证 JWT 签名。理论上，它旨在通过适当的 JWK 端点进行可信密钥分发。但实际上呢？如果您的后端
```
jwk
```

直接从传入的 JWT 标头解析并信任某个值，那么您就已经失败了。  
  
在这个 PortSwigger Burp Suite 实验中，我利用了一个微妙但极具破坏性的漏洞：JWK 标头注入。通过在 JWT 标头中插入自定义公钥，我让服务器验证了我伪造的令牌——无需共享密钥，无需白名单，没有任何阻力。  
  
有什么影响？我解锁了管理面板，然后删除了那个用户，
```
carlos
```

就像周日例行公事一样。🔥  
  
  
  
JWT 身份验证绕过（第三部分）  
  
  
  
  
# 🧪 实验室概述  
- 
```
jwk
```

实验室：通过标头注入绕过 JWT 身份验证  
- 目标：获得管理员权限并删除
```
carlos
```

  
- 证书：
```
wiener:peter
```

  
- 漏洞：服务器盲目信任 JWT 标头中的公钥🤯  
# 逐步利用（PoC）🔍  
## 背景：在 Burp Suite 中安装 JWT 编辑器扩展  
  
  
  
1. 访问实验室网址：
```
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection
```

并使用凭据登录：
```
wiener:peter
```

👤  
2. 尝试访问 的管理面板
```
/admin
```

。响应显示：“仅以管理员身份登录后才能使用管理界面。” 🚫  
  
  
  
  
3.捕获
```
/admin
```

请求并将其发送到 Burp Repeater 进行进一步操作。  
  
  
  
  
4. 在 Burp Suite 中打开 JWT 编辑器选项卡。点击“新建 RSA 密钥”创建一个新的 RSA 密钥，然后点击“生成”即可生成新的密钥对。🔑✨  
  
  
  
  
5. 返回 Burp Repeater 并打开 JSON Web Token 选项卡。将
```
sub
```

声明从 更改为
```
wiener
```

，修改令牌有效负载
```
administrator
```

。点击“攻击”。🎯  
  
  
  
  
6.选择嵌入式JWK攻击选项。  
  
  
  
  
7.选择新生成的 RSA 密钥嵌入到 JWT 标头中。  
  
  
  
  
8. 请注意，JWT 标头现在包含一个
```
jwk
```

包含您的公钥的参数。🧩  
  
  
  
  
9. 发送修改后的请求。现在您可以访问管理面板，绕过身份验证检查。🚪🛡️  
  
  
  
  
10. 将请求 URL 更改为
```
/admin/delete?username=carlos
```

删除用户
```
carlos
```

，然后发送请求。💀  
  
  
  
  
11. 右键单击该请求，然后选择“在浏览器中显示”。复制并粘贴 URL 到浏览器中，确认实验已完成。🎉 恭喜！  
  
  
  
  
  
  
# 🔎 为什么这有效？  
  
让我们来剖析一下这个问题。缺陷在于一个错误的假设：信任客户端发送的内容。  
  
该实验室的后端不会使用已知的服务器端密钥来验证 JWT，而是直接从 JWT 的参数中解析出公钥
```
jwk
```

，并用它来验证签名。这就像把保险库的钥匙交给敌人，然后问他：“你是主人吗？”  
  
所以我：  
1. 生成 RSA 密钥对。  
1. 将公钥嵌入到 JWT 标头中
```
jwk
```

。  
1. 使用我的私钥对令牌进行签名。  
1. 
```
sub: administrator
```

在有效载荷中设置。  
1. 利润。  
# 🔐 如何缓解  
  
为了防止这种疯狂的行为：  
- ❌ 永远不要相信来自令牌头的密钥。  
- ✅ 仅针对已知的静态键集强制验证。  
- 🔒 在服务器端安全地存储您的公钥。  
- ⚠️ 避免动态 JWK 解析，除非与受信任的 JWKS 端点配对。  
- 🔁 实施分层防御：身份验证≠授权。  
# 💭 最后的想法  
  
本实验是一场大师班，它将向您展示如何在正确的地方信任错误的东西，从而瓦解您的安全堆栈。JWT 可以做到万无一失——但前提是您必须验证真正重要的内容。  
- 验证您的密钥。  
- 保护您的签名逻辑。  
- 永远不要仅仅因为令牌格式正确就假设它是值得信赖的。  
# 🧠 学习、破解、重复！  
  
这样的实验室能磨砺你的优势。它们不仅教授工具，更教授思维方式——发现假设并将其彻底颠覆。这就是你在竞争中保持领先的秘诀。  
  
在下一个漏洞出现之前：大胆入侵，谨慎验证，永远不要相信标头  
  
  
  
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
  
