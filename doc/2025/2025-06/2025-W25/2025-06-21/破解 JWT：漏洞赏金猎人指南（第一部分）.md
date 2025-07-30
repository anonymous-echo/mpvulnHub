> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247506752&idx=1&sn=a2fd5586e60447195a589c1eab942ce2

#  破解 JWT：漏洞赏金猎人指南（第一部分）  
haidragon  安全狗的自我修养   2025-06-21 00:40  
  
# 前言：文章索引和路线图  
  
在本系列教程中，我们将深入剖析大多数应用都忽略的 JWT 身份验证漏洞。下方列出了一系列漏洞，从简单的漏洞利用到一些高危漏洞，一一为您一一列举。🗿  
  
  
  
文章索引  
  
  
  
  
# 介绍  
  
如今，JWT 已成为无状态身份验证的主流。它们简洁轻量——但相信我，这种信任可能会让你功亏一篑。许多应用没有正确检查令牌，从而留下了漏洞。我们就是来帮你破解这些漏洞的。  
  
保持敏锐。🗿  
  
  
  
JWT 身份验证绕过  
  
  
  
  
# 🔐 JWT 简介：3 个关键部分  
  
在我们深入探讨这个疯狂的事情之前，请了解这一点：JWT 只是三个采用 base64 编码的信息片段，用点粘合在一起：  
  
<  
Header  
>  
.  
<  
Payload  
>  
.  
<  
Signature  
>  
1. 有关签名算法的标头元数据，没什么大不了的：  

```
{ “alg” ：“HS256” ，“typ” ：“JWT” }
```

  
2. 有效载荷用户声明，例如您是谁以及您可以做什么：  
  
{  
  
"sub"  
:  
  
"wiener"  
,  
  
"admin"  
:  
  
false  
  
}  
  
3. 签名：验证令牌合法性的秘诀。签名使用只有服务器知道的密钥对头部和有效载荷进行哈希处理后生成。  
  
  
  
# 🔓 实验 1：通过未验证的签名绕过 JWT 身份验证  
  
实验室链接：PortSwigger JWT 实验室 - 未验证的签名凭证：  
  
Username: wiener    
  
Password: peter  
## 实验室目标  
  
你的任务？翻开剧本，转为管理员，然后一锤定音
```
carlos
```

。行动起来！🗿  
## 您需要的工具  
- Burp Suite（代理和中继器）——经典  
- JWT.io（可选）——解码并征服  
## 漏洞概述  
  
这个应用？它直接信任收到的任何 JWT，根本不做签名检查。这简直就是在挑衅你，让你修改一下有效载荷，然后以管理员身份进入。  
## 分步 PoC  
1. 使用凭证登录。  
2. 尝试点击
```
/admin
```

。除非您是管理员，否则您将看到“禁止进入”的标志。  
  
在 Burp Suite 代理 > HTTP 历史记录中获取 JWT 令牌。那串字符串？就是你的票。  
  
  
  
  
3. 解码有效载荷：看到了
```
&#34;sub&#34;: &#34;wiener&#34;
```

吗？这就是你。  
  
  
  
  
4. 在 Burp Repeater 中更改
```
&#34;sub&#34;: &#34;wiener&#34;
```

→
```
&#34;sub&#34;: &#34;administrator&#34;
```

应用。  
  
  
  
  
5. 发送至
```
/admin
```

。如果服务器在签名验证方面出现问题，那就太棒了——你成功了。🗿  
  
  
  
  
6.查找
```
/admin/delete?username=carlos
```

并执行。  
  
  
  
  
**实验完成。胜利之舞。✅**  
  
  
  
# 🔓 实验 2：通过有缺陷的签名验证绕过 JWT 身份验证 ( alg: none)  
  
实验室链接：PortSwigger JWT 实验室 - 有缺陷的签名验证凭证：  
  
Username: wiener    
  
Password: peter  
## 实验室目标  
  
这次，告诉应用程序，去掉签名
```
&#34;alg&#34;: &#34;none&#34;
```

——这样它就不用费心验证了。然后，获取管理员权限并删除
```
carlos
```

。同样的老板级精力。🗿  
## 您需要的工具  
- Burp Suite（代理和中继器）  
- JWT.io（可选）  
## 漏洞概述  
  
当服务器接受时
```
&#34;alg&#34;: &#34;none&#34;
```

，它基本上说：“没有签名？没问题。”剧透：这是一个问题。  
## 分步 PoC  
1. 登录。  
2.拦截
```
/admin
```

请求。  
  
  
  
  
3. 发送到 Burp Repeater，检查 JWT 有效载荷：  
  

```
&#34;sub&#34;: &#34;wiener&#34;
```

  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFSib0fJ8ASk3X1RzJVRE2icEAOFlNic1DolLW4iaialsxEibO3QILiamS2UPpkRgmDZqdZUnQVZicLwAUeicg/640?wx_fmt=png&from=appmsg "")  
  
4. 更改
```
&#34;sub&#34;
```

为
```
&#34;administrator&#34;
```

  
  
  
  
  
5. 编辑 JWT 标头：  
  

```
{ &#34;alg&#34;: &#34;none&#34; }
```

  
  
  
  
  
6. 完全删除签名部分 — 保留尾随的点。  
  
  
  
  
7. 发送请求。管理员权限已解锁。🗿  
  
  
  
  
8.
```
carlos
```

照常删除。  
  
  
  
  
**实验完成。任务完成。✅**  
  
  
  
# 总结和安全课程  
  
漏洞原因修复建议未经验证的 JWT 签名服务器忽略签名始终验证 JWT 签名接受
```
alg: none
```

令牌服务器接受未签名的令牌拒绝
```
alg: none
```

，强制使用强算法  
  
  
  
# 下一步是什么？  
  
感受到那股力量了吗？接下来，我们将攻克弱密钥、狡猾的标头注入以及算法混淆攻击——赏金猎人的真正高手。敬请关注，保持警惕。🗿  
  
  
  
# 参考  
- JWT.io — 像专业人士一样解码  
- PortSwigger 网络安全学院——教授实际技能的实验室 https://portswigger.net/web-security/jwt  
- OWASP JWT 备忘单 https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html  
# 👋 一切就绪 — — 祝您黑客愉快！  
  
就是这样——两个经典的 JWT 配置错误变成了你漏洞赏金之路上的垫脚石。🎯 这些实验室不仅仅是练习；它们是你在野外发现的蓝图。  
  
不断磨练你的技能，质疑一切，并以合乎道德的方式打破常规。追寻永无止境——它只会不断升级。💻⚔️  
  
保持好奇心，保持危险性（以一种好的方式），最重要的是......  
  
**祝你黑客愉快，传奇人物。——**  
  
  
  
    
  
  
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
  
