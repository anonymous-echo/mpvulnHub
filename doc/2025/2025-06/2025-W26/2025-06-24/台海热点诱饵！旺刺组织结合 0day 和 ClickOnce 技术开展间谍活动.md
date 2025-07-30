> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2MDc2MDA4OA==&mid=2247515203&idx=1&sn=aa65a6a18fdb558e811f8b9c1010a23c

#  台海热点诱饵！旺刺组织结合 0day 和 ClickOnce 技术开展间谍活动  
原创 红雨滴团队  奇安信威胁情报中心   2025-06-24 01:01  
  
概述  
  
旺刺组织（APT-Q-14）具有东北亚背景，与 APT-Q-12 (伪猎者)、APT-Q-15等组织存在重叠，均属于 DarkHotel 组织的子集，长期以来使用 CilckOnce 技术针对国内进行钓鱼活动，我们曾于 2023 年度 APT 报告[1]  
中对其进行过披露。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkOeHg4uIFTAJZRWCjBkOBBIa6TpJcjVhiaeS6LibNBRG4EzGDibiaM1jVtA/640?wx_fmt=png&from=appmsg "")  
  
  
由于 CilckOnce 技术需要与受害者交互的次数较多，所以钓鱼成功率并不太高，为了解决“用户交互”问题，旺刺组织挖掘了某邮件平台网页版的 XSS 0day 漏洞（目前 XSS 已经被修复），通过 XSS 漏洞触发 CilckOnce 的 js，当受害者打开钓鱼邮件的瞬间，浏览器进程会自动弹出 CilckOnce 钓鱼框，模仿邮件更新行为：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkQBb6OMXFCzBp8zDqiaojRAicCkl8iaqaUFFELZZglFI0Ipibpc6vxXO4hA/640?wx_fmt=png&from=appmsg "")  
  
  
完整攻击链如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkn1CljeGwaMVlGNymFx4Aib5EiaJaoYk43xP9mC7uy7MEuARG2icxuvwpg/640?wx_fmt=png&from=appmsg "")  
  
目前天擎 EDR 可以对该组织所有特马进行查杀，我们建议客户启用云查功能来发现未知威胁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkvJ76xX4MFhmXNMQWsZSwGHOyicCwMuiaib0x51Yv8OaViaRWJSy8gYWSgA/640?wx_fmt=png&from=appmsg "")  
  
  
  
技战术  
  
钓鱼邮件正文源自 Yahoo 时政新闻，与受害人员行业相吻合：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkSVf5qRXK56ibyLHX9PWCpuWPNA0kGHBgjh7FIA9H0bIq008jQxK2ibZQ/640?wx_fmt=png&from=appmsg "")  
  
  
CilckOnce 触发的 mail_5.0.7_update_detail.doc.application 内容如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOk6fTntOa9wC0BYnSTLh7ZoCp7dK5BCzmMPGL3icic1LbegR23ibT5473IA/640?wx_fmt=png&from=appmsg "")  
  
  
随后根据 mail_5.0.7_update_detail.exe.manifest 中的清单文件下载组件（ icon.ico、mail_5.0.7_update_detail.exe、tzuasd.std）并启动 mail_5.0.7_update_detail.exe，运行后会检测是否存在 tzuasd.std 并读取该文件内容并解密：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkvedot9eT0vwudjUVtcxqVHXyxSkTa9Zuw6c7XsKulHc9vTI0eDfIAA/640?wx_fmt=png&from=appmsg "")  
  
  
解密完毕后会向 TEMP 文件夹下释放两个解密的文件，一个是与样本同名的 word 文档，释放完毕后用 cmd 命令打开。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkPo6gfS8qCvew57YE9pAAztzDL6sIjpVlXOZOnYHNB1GIzguF8C9uFQ/640?wx_fmt=png&from=appmsg "")  
  
  
文档是邮箱操作手册，让受害者认为该流程为邮件的正常更新。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkwSpmH0RsPQzx9gzWsBZeO21KGNia4GVztutCX5qH2eWTxGlnv4ic8sbw/640?wx_fmt=png&from=appmsg "")  
  
  
释放恶意木马文件 csrss32.exe 并运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkrstxSOIsz2vObN5xkMibFibDzAKEUeZHUkb0MplN86fgt5VjroCfZAJQ/640?wx_fmt=png&from=appmsg "")  
  
  
csrss32.exe 会在内存中解密一个 dll 文件，并将其释放到 C:\Users\Public\cgfadb.pos。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOktY0O5fb9u0xVz5MCCalYAMlgTp32G4RyGfjXVoaPtLD8iaIcLchKQ4w/640?wx_fmt=png&from=appmsg "")  
  
  
之后会创建计划任务，使用 rundll32 执行 cgfadb.pos 中的导出函数 CreateObject  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkxYkOgl4mNtRlTPw5nCwrYBy5WTlYQOnNYLXsKg9llUTqrgicjng2sxg/640?wx_fmt=png&from=appmsg "")  
  
  
cgfadb.pos 的 CreateObject 函数中首先会解密其 shellcode 处的代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkyMmqNu3ofkaP8ODTicbH2GjJhfGsSdKmkoy1wniaXsICTiayRgkcncJVQ/640?wx_fmt=png&from=appmsg "")  
  
  
创建进程 svchost.exe，并将 shellcode 注入到进程 svchost.exe 中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkEWc7pRfblmeqKg8coXZEkb98tq3tKRyFBvFneyibo2MeLqkXKGt8r3Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOk2M320icZG9GLj9D0LTYAwO3UVCgJpZoibiapZfYlXwrcuq2wK2SKSaCIA/640?wx_fmt=png&from=appmsg "")  
  
  
之后修改 svchost.exe 入口点代码，让其指向 shellcode，最后 ResumeThread 执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkla8wwG0XD5Ov5DBvNrgD4Pvesic3RKDyhVQXx55R0Ex9l6QCOBD8raA/640?wx_fmt=png&from=appmsg "")  
  
  
该 shellcode 首先会解析一些 API。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOk6qKjPUdP00Vq0ialyWic3CPkNDelWqtDQhUXmmkHJgs4LHibCjAfxaOdQ/640?wx_fmt=png&from=appmsg "")  
  
  
之后同样会在内存中解密出第二阶段 shellcode，该 shellcode 是个 dll，加载完毕后会跳转到 dll 的入口点执行，在该 dll 中执行恶意行为。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkbmxQN5n6mEP1wf9KdEet9oIXD7ASo5CjCiaS855ojlprhW8Quciagazw/640?wx_fmt=png&from=appmsg "")  
  
  
首先会创建一个文件 C:\Users\All Users~.dat，该文件仅用于保持进程唯一，作用类似于互斥体。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkSMVsQPmc2IK8OX2ib87s9wCLAujIW5vxAeH82Lw4sOVGx7QxmOXm9UQ/640?wx_fmt=png&from=appmsg "")  
  
  
之后会在内存中解析出 C2：whocanis.com，通过 socket 连接 C2。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkcFUwTraSEnLPU3pPw40xtlZicqU8AaNAZy5byVw55PjlwHRamDgaQ9w/640?wx_fmt=png&from=appmsg "")  
  
  
连接成功后会收集系统相关信息，加密后发送到 whocanis.com/eu-uk/reent/tivma.php 页面上。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkPA2VqJOZVwCkVL7v4wRABZPRbyEseofI1EpynDpSUPmZMqmzpdhhfQ/640?wx_fmt=png&from=appmsg "")  
  
  
之后会接收来自页面的返回信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOku0DWLW6Y1hcgVWhmmbHicicIfqiadtj7k1Vhug8Dm1Tjd607svBIEpibFA/640?wx_fmt=png&from=appmsg "")  
  
  
接收完毕后会在内存中解密接收信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkNAv2sibYJ7icYkXaoViaTeiaFcKDN699qfVicklk9mCGxVzJ65glqy5ib4pw/640?wx_fmt=png&from=appmsg "")  
  
  
最后将接收到的内容写入 TMP 文件夹下的 wct586302 + 数字.dll 文件中，其中数字从 1 开始，最大可到 1000，直到遍历到 wct586302 + 数字.dll 文件不存在则写入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkBmlTc9WO9ziaCiaZQkBZdicAztNibicUuDKK7BrJUP3Rp8GsQUdCLcmKKqw/640?wx_fmt=png&from=appmsg "")  
  
  
之后会寻找进程 explorer.exe 用于提权和进程注入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkfqS0h5SF2oeVic7xh8bDp8mQLR0s6Fk54RseKiaYQvaMJ7embBS948AQ/640?wx_fmt=png&from=appmsg "")  
  
  
最后通过 CreateRemoteThread 向 explorer.exe 注入线程，其线程入口点为 LoadLibraryW函数，传递给线程的参数为之前写入的 dll 文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkCwRmvibXFEMfnxgibDB5FWfH0FzCHwl6fJslyAwnFuI8e3XpkqDhylkQ/640?wx_fmt=png&from=appmsg "")  
  
  
由于无法从 C2 中接收后续数据，无法进行后续分析。  
  
  
扩线  
  
APT-Q-14（旺刺）代表的东北亚情报机构除了拥有大量 win 平台的 0day外，安卓平台邮箱软件的 0day 漏洞也是其重点关注的目标，攻击者掌握大量国产软件未公开的内部接口。以我们目前捕获到的几起安卓平台邮箱软件 0day 来看，其漏洞成因大部分为 “ZipperDown”[2]  
，由文件名和符号链接引起路径穿越导致攻击者可以覆盖目标 so 或 dex 文件，相关技术细节我们会择期向开源社区进行公布。  
  
  
总结  
  
目前，基于奇安信威胁情报中心的威胁情报数据的全线产品，包括奇安信威胁情报平台（TIP）、天擎、天眼高级威胁检测系统、奇安信NGSOC、奇安信态势感知等，都已经支持对此类攻击的精确检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOk1Ihvxg5ZR16YYlCjAxOfEZtia3A4OIWIUNQdHCelRJ15VicBiam3bvQ6g/640?wx_fmt=png&from=appmsg "")  
  
  
IOC  
  
**FileHash-MD5:**  
  
241e18ad3beb6c0ce34060b186822503  
  
f07bc9e321c736eaa6e90fdfc1b2435a  
  
f0e0c028909c6c07120ff444ac56a8d8  
  
**C2:**  
  
whocanis.com(已过期)  
  
  
参考链接  
  
[1] https://ti.qianxin.com/uploads/2024/02/02/dcc93e586f9028c68e7ab34c3326ff31.pdf  
  
[2] https://www.secrss.com/articles/2927  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehicicib3RaYgEuk1wHtGFXW1MOkTYcrlempM2EAic2icUXzsdyQKJkr07yl6icnVGCFugM8EhPPfrp8v1zAw/640?wx_fmt=gif&from=appmsg "")  
  
点击  
阅读原文  
至**ALPHA 8.3**  
  
即刻助力威胁研判  
  
  
