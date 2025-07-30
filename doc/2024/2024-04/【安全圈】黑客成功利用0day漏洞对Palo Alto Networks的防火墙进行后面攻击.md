#  【安全圈】黑客成功利用0day漏洞对Palo Alto Networks的防火墙进行后面攻击   
 安全圈   2024-04-15 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
Volexity安全研究人员发出警告：疑似国家背景的不明黑客组织已成功利用 Palo Alto Networks 防火墙中的0day漏洞已有两周多的时间。  
  
Palo Alto Networks上周五披露了该漏洞，并警告称已发现有限的野外利用情况，并承诺将在接下来的两天内提供补丁。  
  
该安全漏洞被标识为CVE-2024-3400（CVSS评分10/10），被描述为一种命令注入问题，允许未经身份验证的攻击者在受影响的防火墙上以root权限执行任意代码。   
  
据供应商称，所有运行 PAN-OS 版本 10.2、11.0 和 11.1 且启用了 GlobalProtect 网关和设备遥测的设备都容易受到攻击。其他 PAN-OS 版本、云防火墙、Panorama 设备和 Prisma Access 不受影响。  
  
“Palo Alto Networks 已意识到有人恶意利用此问题。我们正在以“MidnightEclipse 行动”的名义跟踪此漏洞的初始利用，因为我们非常有信心地评估，迄今为止我们分析的已知利用仅限于单个攻击者。”该公司在博客文章中表示。  
  
Volexity 将CVE-2024-3400 漏洞归因于一个有国家背景的黑客，追踪编号为“UTA0218”，攻击者似乎能力很强，“有一个明确的剧本，说明如何进一步实现其目标”。  
  
“Volexity 评估认为，根据开发和利用此类性质的漏洞所需的资源、攻击者针对的受害者类型以及安装 Python 后门和所显示的功能，UTA0218 很可能是国家支持的黑客组织，意图进一步访问受害者网络。”该网络安全公司指出。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhL7AkAic8rrvibTc7lyAaIfhLSBNbgcXfHwLHo0MfvKibwgHXpYicIQAHSl0VwZCS7icaH2eMicNiaOcpgw/640?wx_fmt=png&from=appmsg "")  
  
该公司目前无法将该活动与先前已知的黑客组织联系起来。  
  
目前尚不清楚这种利用的范围有多广泛，但 Volexity 表示，“有证据表明，潜在的侦察活动涉及更广泛的利用，旨在识别易受攻击的系统”。  
  
该网络安全公司表示，自 3 月 26 日以来，UTA0218 已成功利用0day漏洞攻击多个组织。在两个实例中，攻击者还注入了一个名为 Upstyle 的基于 Python 的后门，并用它来执行其他命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhL7AkAic8rrvibTc7lyAaIfhm4MDsKSGbAIGeAfgoqiclkkZtF7lCOcRjyiapGiah81bPa78JIhtIcFFQ/640?wx_fmt=png&from=appmsg "")  
> “成功利用设备后，UTA0218 从他们控制的远程服务器下载了额外的工具，以便于访问受害者的内部网络。他们迅速在受害者的网络中横向移动，提取敏感凭证和其他文件，以便在入侵期间和之后可能进行访问。”Volexity 解释道。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhL7AkAic8rrvibTc7lyAaIfhlfVibakR3VX1YYicmtEDRMN2Srl9IObBbq8o8pIMsz41SWY8UZw2RjibA/640?wx_fmt=png&from=appmsg "")  
  
攻击链  
  
研究人员发现攻击在防火墙上创建了一个 cron 作业，以持续从远程服务器获取文件并执行其内容。我们看到攻击者手动管理命令与控制 (C&C) 服务器的访问控制列表，以确保只能从与其通信的设备进行访问。  
  
还观察到 UTA0218 部署了用 Python 编写的反向 shell 和开源 SSH 反向 shell，下载 GOST（GO Simple Tunnel）等反向代理工具，并从受感染的防火墙中窃取配置数据。  
  
在一次攻击中，攻击者使用帕洛阿尔托网络防火墙的高特权服务帐户通过 SMB 和 WinRM 横向移动。随后，UTA0218 窃取了 Active Directory 数据库、关键数据、Windows 事件日志、登录信息、cookie 和浏览器数据，并能够解密存储的凭据。  
> “没有观察到 UTA0218 在受害者网络内的系统上部署恶意软件或其他持久性方法。被盗的数据确实使攻击者能够有效地破坏所有域帐户的凭据。此外，攻击者获得了访问权限，并可能使用从浏览器数据中获取的有效凭据或 cookie 来访问特定的用户工作站。”Volexity 解释道。  
  
  
CVE-2024-3400 的补丁预计将于 4 月 14 日发布。与此同时，建议组织在其防火墙上禁用设备遥测，并应用 Palo Alto Networks 在其公告中详细介绍的其他缓解建议。  
  
建议认为自己因该0day漏洞而受到损害的组织收集日志、创建技术支持文件并保留取证工件。他们还应该寻找潜在的横向移动，并应考虑防火墙上的所有敏感数据受到损害。  
  
Palo Alto Networks 和 Volexity 警告称，UTA0218 和其他攻击者对 CVE-2024-3400 的利用可能会在未来几天内激增，这主要是由于补丁尚未推出。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/67ufDnLOiaDQOlamot2a41KdK4MQEqysnKxdYsvvGuBiaiczpicYGfTmntp6ylwB0iaicQ4sI7ZRqHgwttkIAIOpsjLQ/640?wx_fmt=png "")  
[【安全圈】腾讯云4月8日故障复盘及情况说明](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057945&idx=1&sn=7d4e58dc59b48007cf2f2b44725b4700&chksm=f36e1d19c419940fbdf8d97ceed0f0f0eae365243b1443574571f47385a2f36eb468872f3d5c&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhL7AkAic8rrvibTc7lyAaIfhcNDJfT5LEuSCKf9omwjgTxq8fvdoxZ9GEArthWUwjGmc34yxcTyLwQ/640?wx_fmt=jpeg "")  
[【安全圈】澳大利亚快递公司BHF被报 1920 万条数据记录泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057945&idx=2&sn=5d97c534958dc5991c0b82ec142cc254&chksm=f36e1d19c419940fe427070361a32632f5c6929440931968828be2ad5532c644dcae75934e4f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhjsWthx1pmxrXYap655WFBXBRBfVibXHJ1tiaRICIoNibmgibI9n2ywqTrrSQWWicNmV0flclF3mRIAqw/640?wx_fmt=jpeg "")  
  
[【安全圈】黑客疑似利用AI生成的恶意代码攻击德国企业](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057945&idx=3&sn=226b53efad7b4c3242ef662ae6d6db2e&chksm=f36e1d19c419940fa597869e343e2b5f67e19dc53bfac1decfd21567fa6795636e0cec3411be&scene=21#wechat_redirect)  
       
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhjsWthx1pmxrXYap655WFBzyCEmROCuBgtVvk07P3SphaHFnT9ncrZzfEibhdBbt0WEHgjRfVjoWg/640?wx_fmt=jpeg "")  
[【安全圈】超过 90000 台 LG 智能电视可能遭受远程攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057945&idx=4&sn=1c7a9479f516f7459b49cfcbc1efa98f&chksm=f36e1d19c419940faa138ed78ae1bea5caa1277016ac32fb0cc58606128ce3c8bef1e3ae32f7&scene=21#wechat_redirect)  
         
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
