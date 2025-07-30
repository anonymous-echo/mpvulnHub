#  掌握现代红队基础设施第 3 部分 — 使用 DNS 记录和 OPSEC 绕过邮件安全网关保护邮件服务   
hai dragon  安全狗的自我修养   2025-01-17 23:20  
  
> 在“🔒掌握现代红队基础设施”系列的这一部分中，我们探讨了使用 SPF、DKIM 和 DMARC 等 DNS 记录为我们的域 **online-notifications.net**  
 域设置**和保护邮件服务**  
，同时实施**强大的操作安全 （OPSEC）**  
 措施来有效绕过邮件安全网关。本指南介绍如何将 **Zoho**  
Mail 与 **Cloudflare**  
上托管 online-notifications.net 域相关联，并创建邮件用户帐户来运行隐蔽的网络钓鱼活动或其他红队活动。  
  
  
  
  
  
  
  
# 目录  
1. 🔎 为什么 Secure Mail 服务对红队运营很重要  
  
1. 第 1 步：为 online-notifications.net 域设置 Zoho Mail  
  
1. 第 2 步：在 Cloudflare 上添加 MX、SPF、DKIM 和 DMARC 记录  
  
1. 第 3 步：实施 OPSEC 措施来绕过邮件安全网关  
  
1. 最后的思考  
  
# 🔎为什么 Secure Mail 服务对红队运营很重要  
  
电子邮件仍然是**社交工程、凭据收集和网络钓鱼**  
的最有效载体之一。为了确保此类活动的成功，必须：  
- 通过从经过验证的域发送电子邮件来建立**可信度**  
。  
  
- **避免**  
被电子邮件安全系统（例如垃圾邮件过滤器、DMARC 验证）检测到。  
  
- 通过保护基础设施来避免归因，**从而维护 OPSEC**  
。  
  
通过正确实施 SPF、DKIM 和 DMARC 记录并添加 OPSEC，您可以显著提高⬆电子邮件的送达率，同时⬇最大限度地降低暴露风险。  
# ⚙️第 1 步：为 online-notifications.net 域设置 Zoho Mail  
1. **创建 Zoho 帐户**  
打开   
Zoho Mail  
 并使用个人电子邮件注册帐户。  
  
  
  
  
选择一个计划（Zoho 提供免费计划，但现在他们改变了政策，所以我将选择 15 天免费试用）。（注意：您可以使用其他邮件服务，例如   
https://www.name.com  
 提供免费邮件服务）  
  
选择一个计划（Zoho 提供免费计划，但现在他们改变了政策，所以我将选择 15 天免费试用）。（注   
https://www.name.com  
 提供免费邮寄服务）  
  
  
  
  
**2. online-notifications.net 域与 Zoho 关联**  
  
添加 onlin-notificaions.net 域并继续  
  
  
  
  
已添加域，我将进行域验证  
  
  
  
  
Zoho 已识别出我的域由 Cloudflare 管理，并提供了以下 TXT 记录和值来验证域所有权。  
  
  
  
  
因此，我将此 TXT 记录添加到 Cloudflare DNS 设置中并保存  
  
  
  
单击 Add record（添加记录）  
  
  
**类型**  
：TXT.**姓名**  
：@.**值**  
：Zoho 提供的唯一验证字符串。  
  
  
返回 Zoho 并单击 验证 TXT 记录 将其添加到 Cloud Flare 中后  
  
  
  
  
**3. 创建 Mail 用户帐户**  
  
验证并链接域后，我将创建一个管理员用户。  
  
  
  
  
在下一页创建用户后，它会询问我是否需要更多电子邮件用户，我将单击继续设置组  
  
  
  
  
在组设置中，我将单击继续 DNS 映射  
  
  
  
# 🔧 第 2 步：在 Cloudflare 上添加 MX、SPF、DKIM 和 DMARC 记录  
1. **添加 MX、SPF 和 DKIM 记录**  
- SPF （Sender Policy Framework） 帮助邮件服务器验证我们的域是否有权发送电子邮件。  
  
- DKIM （DomainKeys Identified Mail） 为我们的电子邮件添加了数字签名，从而提高了真实性。  
  
创建**管理员用户**  
后，我将继续将以下记录添加到 **Cloudflare DNS 设置**  
中，就像前面的步骤一样。这一次，我将添加 **MX**  
和 **TXT**  
记录以及它们各自的主机、值和优先级。  
  
  
  
  
然后将它们添加到 Cloudflare DNS 中，如下所示。  
  
  
  
MX 提及 Zoho 邮件服务器  
  
  
SPF 和 DKIM  
  
  
然后点击 Verify all records on Zoho  
  
  
  
  
点击验证后，您将获得以下验证（有时您需要等待几分钟，直到 DNS 更新设置）  
  
  
  
  
单击“继续电子邮件迁移”，然后单击“继续移动”，最后单击“继续设置完成”。请务必保存提供的 SMTP 值，因为稍后在 GoPhish 中配置邮件时将需要这些值。  
  
  
  
  
之后，将使用我在 Zoho 注册过程中使用的相同密码创建 admin@online-notifications.net 用户。  
  
**2. 添加 DMARC 记录**  
- DMARC（基于域的邮件身份验证、报告和一致性）指定接收邮件服务器应如何处理 SPF/DKIM 故障。在使用 DMARC 之前，请确保您已设置 DKIM 和 SPF。  
  
将 TXT 记录添加到您的域：**type：**  
 TXT 和 **Name：**  
 _dmarc 和 **Value：**  
 v=DMARC1;p=无  
  
  
  
- 我们选择了**具有“无”**  
策略的 DMARC 版本 1，确保不采取任何行动，电子邮件送达不受影响。  
  
**DMARK 策略选项**  
- **none**  
：监控模式。不会对未通过 DMARC 检查的电子邮件采取任何措施。这通常在设置 DMARC 以监控电子邮件流量和收集报告而不影响送达时使用。  
  
- **quarantine**  
：建议未通过 DMARC 检查的电子邮件应标记为可疑并移动到 spam/junk 文件夹。  
  
- **reject**  
：指示电子邮件接收者拒绝未通过 DMARC 检查的电子邮件（不会发送）。  
  
# 🔒 第 3 步：实施 OPSEC 措施来绕过邮件安全网关  
1. **通过 mail-tester 服务测试电子邮件安全配置分数**  
我们将提供 Mail-Tester 服务，它不仅可以识别问题，还可以提供可操作的建议，以提高您的电子邮件送达率并避免垃圾邮件过滤器。  
  
Mail-Tester.com  
 通过检查以下内容来评估电子邮件的送达率：  
- **电子邮件身份验证：**  
验证 SPF、DKIM 和 DMARC 记录以确保正确身份验证。  
  
- **垃圾邮件内容：**  
分析垃圾语言或格式。  
  
- **黑名单状态：**  
检查您的域或 IP 是否在垃圾邮件黑名单中。  
  
- **HTML/文本平衡：**  
确保 HTML 与纯文本的比例正确。  
  
- **损坏的链接/图像：**  
验证所有链接和图像是否正常工作。  
  
- **嵌入图像：**  
确认映像已正确托管。  
  
- **服务器配置：**  
检查反向 DNS、HELO 和电子邮件标头。  
  
- **IP 信誉：**  
评估发送 IP 的声誉。  
  
- **HTML 质量：**  
确保您的电子邮件 HTML 代码干净且结构良好。  
  
- **电子邮件大小：**  
验证电子邮件是否过大。  
  
- **DNS 记录：**  
确保您的域已正确配置 DNS 记录。  
  
访问   
https://www.mail-tester.com/  
。该网站将提供一个电子邮件地址来发送测试消息。  
  
  
  
  
从您的邮件帐户发送电子邮件。在此示例中，我将从 发送一条空消息。为此，我将通过控制面板使用 Zoho Mail，或通过 https://mail.zoho.sa/zm/ 直接访问它。admin@online-notifications.net  
  
  
  
  
发送电子邮件后，返回 Mail Tester 站点并单击 **“Check your score”（检查您的分数）。**  
  
**以下是检查结果：**  
  
  
  
  
  
**2. 通过签名收集技术提高电子邮件可信度**  
  
为了提高电子邮件的可信度，建议使用**来自客户**  
的电子邮件**中的一些****签名**  
。一些获取签名的方法如下：  
- **向****不存在的地址**  
发送电子邮件，并检查响应是否有任何签名。  
  
- 搜索   
info@ex.com  
 或   
press@ex.com  
 或   
public@ex.com  
 等**公共电子邮件**  
，然后**向他们发送电子邮件**  
并等待回复。  
  
- **尝试联系**  
一些有效的发现电子邮件并等待回复  
  
**3. 其他绕过邮件安全网关的 OPSEC**  
- 通过向 **check-auth@verifier.port25.com**  
 **发送电子邮件**  
并阅读响应来检查您的电子邮件配置  
  
- 您还可以**将邮件发送到**  
您控制的 Gmail，并在 Gmail 收件箱中检查**电子邮件的标头**  
 dkim=pass  
  
- **如果发送垃圾邮件，则从**  
 **Spamhouse 黑名单**  
中删除 https://book.hacktricks.xyz/generic-methodologies-and-resources/www.mail-tester.com  
 并从 **Microsoft 黑名单**  
中删除   
https://sender.office.com/  
  
- 在此处检查域：   
https://malwareworld.com/  
  
- 通过随着时间的推移向多个受信任的收件人**发送良性电子邮件**  
来预热域，如果进入垃圾邮件，**则将其标记为非垃圾邮件。**  
  
- **定制内容**  
：避免在电子邮件主题和正文中使用可疑关键字，并尽可能为目标提供个性化电子邮件（例如，包含目标的名称或角色）。  
  
- **依恋技术;使用受密码保护的 ZIP 文件，其中包含电子邮件中包含的密码，或者**  
使用逃避检测的不太常见的文件扩展名（例如，.iqy、.iso）。（在接下来的部分中将向您展示通过 zip 和 ISO 交付并绕过 MOTW）  
  
- **域声誉：**  
定期轮换域和用户帐户以避免被发现。  
  
- **有效载荷交付：**  
在受信任的服务（例如 Google Drive、Dropbox）上托管恶意负载以避免怀疑。  
  
# 最后  
  
将我们域的邮件服务与 Zoho Mail 链接起来，并使用 SPF、DKIM 和 DMARC 进行保护，不仅可以提高送达率，还可以确保在红队参与中高度隐蔽。结合强大的 OPSEC 实践，这种设置使我们能够有效地绕过邮件安全网关，从而在执行网络钓鱼活动和其他社会工程攻击方面占据优势。  
  
  
  
其它相关课程  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW4Nlt9pZBgFYgFxfVZFxu83EQnESej7ydiblH1UfHqKX3hBfcm76JiaSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW0h21TYuO94OrIGsD2aHGrUcUYiasibQS5AYJ4a95Ra3zIFIXQ4e8lkFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zW6iapnXQ3Wviaiaiap37xFRqNok6BymcTiacnk07OowXYFowAKYfa9zS6gSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQEREkjoibjFst4F2YTlvkRG4zWiaJkE3jZRR7znMJDXAlibBzibYaGLMlVvsa1xhlQFyv3viaARicSIII7a9A/640?wx_fmt=png&from=appmsg "")  
#   
# 新课  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERFnNtHHDCr5QdssgMnq4biaMBbu8gMd43hicnWIuTfgVE7xTplq5JYkSCrh0lKCnClia4D3zbWmZPzGw/640?wx_fmt=png&from=appmsg "")  
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
  
