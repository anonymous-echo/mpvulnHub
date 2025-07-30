#  大多数 Bug Hunter 忽略的简单漏洞   
hai dragon  安全狗的自我修养   2025-01-08 23:14  
  
图片由 StorySet Freepik 提供  
  
  
Bug Hunter 是一个迷人且具有挑战性的领域，它结合了技术技能、创造力和毅力。虽然有些漏洞有据可查且经常被利用，但有一类错误经常被忽视：简单但罕见的错误。这些漏洞相对容易利用，但很少遇到，使其成为精明的漏洞赏金猎人的宝贵目标。  
  
以下是其中一些隐藏的宝藏以及如何识别和利用它们的提示。  
  
  
  
# 1. 被遗忘的子域  
## 错误：  
  
许多公司托管不再使用但仍处于活动状态的子域。这些被遗忘的子域通常会运行过时或配置错误的应用程序，从而产生潜在的漏洞。  
## 为什么它很罕见：  
  
子域枚举很常见，但大多数猎人都关注主域。没有明确功能的子域通常会被忽略。  
## 如何利用：  
  
使用 Sublist3r 或 Amass 等工具进行子域枚举。  
  
检查未维护的服务、默认登录页面或忘记的测试环境。  
  
利用常见的漏洞，如过时的 CMS 版本或目录遍历。  
# 2. 罕见终端节点中的 CORS 配置错误  
## 错误：  
  
跨域资源共享 （CORS） 错误配置允许恶意网站与属于目标的 API 或 Web 服务进行交互。虽然 CORS 错误配置是已知的，但在非标准终端节点中很少发现。  
## 为什么它很罕见：  
  
大多数猎人会检查主 API 上的 CORS 问题，但会忽略辅助或内部 API。  
## 如何利用：  
  
使用 httpx 或 Burp Suite 等工具查找端点。  
  
测试宽松配置（Access-Control-Allow-Origin： * 或未经适当验证的特定白名单域）。  
  
制作恶意请求以提取敏感数据。  
# 3. 弱重置令牌实现  
## 错误：  
  
密码重置功能是一种常见的攻击媒介。一些网站会生成弱或可预测的重置令牌，从而有可能劫持帐户。  
## 为什么它很罕见：  
  
大多数现代系统都实现了强令牌生成，但旧系统或自定义实现可能容易受到攻击。  
## 如何利用：  
  
检查 reset 令牌的模式（例如，base64 编码的电子邮件地址或时间戳）。  
  
如果没有速率限制，请使用暴力技术。  
  
与帐户枚举相结合，实现精确定位。  
# 4. 不常见形式的服务器端模板注入 （SSTI）  
## 错误：  
  
当服务器端模板中的用户输入处理不当时，就会发生 SSTI，从而允许攻击者执行任意代码。  
## 为什么它很罕见：  
  
SSTI 漏洞经常被忽视，因为猎人认为所有输入都经过净化。  
## 如何利用：  
  
在管理面板或内部工具中查找输入字段。  
  
注入 {{7*7}} 或 ${7*7} 等有效负载并观察响应。  
  
使用 tplmap 等工具进行自动化测试。  
# 5. 敏感操作中的速率限制配置错误  
## 错误：  
  
速率限制可防止滥用终端节点，但在敏感操作（例如，密码重置或付款处理）中配置错误或缺少速率限制可能会导致漏洞利用。  
## 为什么它很罕见：  
  
大多数猎人专注于登录端点，但忽略了不太明显的操作。  
## 如何利用：  
  
确定执行关键操作的终端节点。  
  
使用 ffuf 或自定义脚本等工具测试高速请求。  
  
利用帐户锁定绕过或付款篡改等漏洞。  
# 6. 未探索参数中的不安全反序列化  
## 错误：  
  
不安全的反序列化允许攻击者将恶意对象注入序列化数据中，从而导致远程代码执行或权限提升。  
## 为什么它很罕见：  
  
序列化漏洞通常隐藏在晦涩难懂的功能或未记录的 API 中。  
## 如何利用：  
  
识别请求中的序列化数据（例如 JSON、Base64）。  
  
使用来自 ysoserial 等工具的有效负载进行测试。  
  
专注于具有管理或调试功能的终端节点。  
## 查找稀有 Bug 的提示  
> 1. 超越显而易见的思考：虽然其他公司针对流行的端点，但专注于鲜为人知的功能，如内部工具、调试页面或 beta 功能。  
> 2. 利用自动化：使用工具扫描大型范围，但手动分析结果以发现异常。  
> 3. 了解业务逻辑：了解应用程序的工作原理可以揭示扫描程序遗漏的漏洞。  
> 4. 保持好奇心：研究较少讨论的漏洞，并尝试创造性的有效载荷。  
  
  
简单但罕见的虫子经常隐藏在众目睽睽之下。虽然它们需要一些额外的努力才能发现，但它们可以产生可观的回报。通过扩大您的范围并专注于被忽视的领域，您可以找到这些隐藏的宝石，并使自己成为一名与众不同的漏洞赏金猎人。  
  
祝您狩猎愉快！  
  
  
  
其它相关课程  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW4Nlt9pZBgFYgFxfVZFxu83EQnESej7ydiblH1UfHqKX3hBfcm76JiaSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW0h21TYuO94OrIGsD2aHGrUcUYiasibQS5AYJ4a95Ra3zIFIXQ4e8lkFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW6iapnXQ3Wviaiaiap37xFRqNok6BymcTiacnk07OowXYFowAKYfa9zS6gSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zWiaJkE3jZRR7znMJDXAlibBzibYaGLMlVvsa1xhlQFyv3viaARicSIII7a9A/640?wx_fmt=png&from=appmsg "")  
#   
# 新课  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREAf7LpGLkacicc7QgrMu4m216yzE3ruLzWBK6ZCv1DOiaP2DtpFiavrC4aDwBl1aoibygicuMA2hq7BiaA/640?wx_fmt=png&from=appmsg "")  
#   
# 详细目录  
# mac/ios安全视频  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFbBn3mydWukVkxb7u4ibpOneTvEKRymYhW9KMlUWP1RnaXLuZibvPMdGmrdWVV3AMJya9dNxszgOeA/640?wx_fmt=png&from=appmsg "")  
# QT开发底层原理与安全逆向视频教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGLucgfllJsyUEFRxtnUNkLfUhNeUCnH7x8VtPq0Q2zxZBdhjqiaibsx0rIbaYWMuIibmk5QtNPzsOSw/640?wx_fmt=png&from=appmsg "")  
  
linux文件系统存储与文件过滤安全开发视频教程(2024最新)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHSM6Wk8NAEmbHHUS2brkROr9JOj6WZCwGz4gE4MlibULVefmhRw2dvJd8ZeYnDpRIm0AV1TmIsuEQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
linux高级usb安全开发与源码分析视频教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHCd9Qic4AAIQfFFD7Rabvry4pqowTdAw6HyVbkibwH5NjRTU4Mibeo4JbMRD3XplqCRzg4Kiaib3jchSw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**linux程序设计与安全开发**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGoVibbKav1DpliaTJ9icDrosqXeWyaMRJdCVWEG0VYLDibSMwUP1L5r9XmLibGkEkSZnXjPD6mWgkib9lA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**二进制漏洞**  
  
rust语言全栈开发视频教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERGLucgfllJsyUEFRxtnUNkLHbLZhPYWITVXTiablic0ZlDrc0uJkAvPnEcQHJI5qbtibk4EWqjZgAX8A/640?wx_fmt=png&from=appmsg "")  
- 更  
多  
详  
细  
内  
容  
添  
加  
作  
者  
微  
信  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-    
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEH4eXCW471pNuHpGPzUKCkbyticiayoQ5gxMtoR1AX0QS7JJ2v1Miaibv1lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- #   
  
-   
- w  
i  
n  
d  
o  
w  
s  
网  
络  
安  
全  
防  
火  
墙  
与  
虚  
拟  
网  
卡  
（  
更  
新  
完  
成  
）  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERE5qcRgQueCyt3U01ySnOUp2wOmiaFhcXibibk6kjPoUhTeftn9aOHJjO6mZIIHRCBqIZ1ok5UjibLMRA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- w  
i  
n  
d  
o  
w  
s  
文  
件  
过  
滤  
(  
更  
新  
完  
成  
)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmvkF91T2mwk3lSlbG5CELC5qbib3qMOgHvow2cvl6ibicVH4KguzibAQOQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- U  
S  
B  
过  
滤  
(  
更  
新  
完  
成  
)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHv0vyWxLx9Sb68ssCJQwXngPmKDw2HNnvkrcle2picUraHyrTG2sSK7A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 游  
戏  
安  
全  
(  
更  
新  
中  
)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHzEAlXtdkXShqbkibJUKumsvo65lnP6lXVR7nr5hq4PmDZdTIoky8mCg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- i  
o  
s  
逆  
向  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHmjrTM3epTpceRpaWpibzMicNtpMIacEWvJMLpKKkwmA97XsDia4StFr1Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- w  
i  
n  
d  
b  
g  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibv9VNhRI73qFehic91I5dsr3Jkh6EkHIRTPGibESZicD7IeA5ocHjexHhw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- 还  
有  
很  
多  
免  
费  
教  
程  
(  
限  
学  
员  
)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHhezg9PuKylWLTBfCjokEHDvveGEwLYBVsps1sH6rGrSnNZtjD2pzCk4EwhH3yeVNibMMSxsW5jkg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibR2Viaxgog8I2gicVHoXJODoqtq7tTVGybA8W0rTYaAkLcp8e2ByCd1QQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERECMA4FBVNaHekaDaROKFEibDwwqQLTNPnzDQxtQUF6JjxyxDoNGsr6XoNLicwxOeYfFia0whaxu6VXA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREEHMPaJ2RMX7CPES3mic42r1Wub102J6lAmEwKIicDfADiajsEReibfvSCbmiaRlGRCQibqfJJia0iak421Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- **windows恶意软件开发与对抗视频教程**  
  
-   
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFPap5AiahwlmRC2MGPDXSULNssTzKQk8b4K3pttYKPjVL4xPVu1WHTmddAZialrGo8nQB3dJfJvlZQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-    
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
