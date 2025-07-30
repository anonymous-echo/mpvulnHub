#  知名防火墙厂商曝满分RCE漏洞，Palo Alto Networks警告漏洞正被利用   
看雪学苑  看雪学苑   2024-04-15 17:59  
  
网络安全巨头Palo Alto Networks警告客户，其防火墙工具中的0day漏洞正在被黑客利用。该公司在周五上午发布了关于CVE-2024-3400的公告（影响流行的GlobalProtect VPN产品），其严重性评分为10分最高分。Palo Alto Networks还表示，已经注意到有少数利用了这一漏洞的攻击。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FWsricwbTqvvdyR1mNySBVgE3Bv5zQCYIzI5icwFJxqYaKMU92e4g4SC5gNrqavnkpCgw0prpY9PFA/640?wx_fmt=png&from=appmsg "")  
  
  
这个命令注入漏洞源自GlobalProtect安全远程访问功能，可能允许远程未经身份验证的攻击者在PAN-OS防火墙设备上以root权限执行任意代码。美国网络安全与基础设施安全局（CISA）几乎立即将该漏洞添加到其已知被利用漏洞的列表中，表明联邦机构需要尽快修补此漏洞。与大多数漏洞给予的三周时间相比，CISA罕见地仅给予了联邦机构七天的时间来采取缓解措施。  
  
  
据悉，网络安全公司Volexity的研究人员发现并报告了这个漏洞，并称很可能利用此漏洞的攻击者背后有国家支持。之所以会做出这一评估，主要是基于以下几点——开发利用该性质漏洞所需的资源、所针对的受害者类型、以及安装Python后门并进一步访问受害者网络的能力。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FWsricwbTqvvdyR1mNySBVgRvm9ev18dR44iaC3qnLQwRSTy5vQ7uJOBloZ6Gzic22mda4Bdcib2XJHQ/640?wx_fmt=png&from=appmsg "")  
  
  
Volexity最初是在周三和周四注意到两个客户的防火墙存在可疑的网络流量，之后的进一步调查发现，黑客（称之为UTA0218）成功地远程利用了PAN-OS防火墙，创建了一个反向shell，并下载了其他工具到被攻击的设备上。攻击者从目标设备中导出数据，继而试图将其作为在组织内部横向移动的入口点。Volexity扩大调查范围后发现，从3月26日开始，多家客户和其他组织都受到了这个漏洞的攻击。  
  
  
攻击者似乎是在最初几天内测试了漏洞的可利用性，然后在4月7日开始尝试全面利用。攻击者于周三攻击取得了成功，在这之后，黑客迅速在受害者的网络中横向移动，窃取了敏感的凭证及其他文件，这些文件能为其在入侵期间甚至入侵后提供访问权限。  
  
  
Volexity警告称，由于漏洞的公开，未来几天可能会观察到利用的激增。Palo Alto Networks的公告中指出，补丁会在周日前提供给客户。此外，Palo Alto Networks还提供了几种缓解措施供客户采用：具有威胁预防订阅的客户可以通过启用威胁ID 95187来阻止攻击，并确保其GlobalProtect接口应用了漏洞保护。对于无法应用威胁预防缓解的客户，暂时禁用设备遥测也是一种解决方法。  
  
  
研究报告链接：  
https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/  
  
  
  
编辑：左右里  
  
资讯来源：Palo Alto Networks、Volexity、scmagazine  
  
转载请注明出处和本文链接  
  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
