#  【安全圈】苹果紧急修复两枚被用于定向攻击iPhone的零日漏洞   
 安全圈   2025-04-17 11:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
零日漏洞  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljuxnCBqbQIAXW9tRyOrn3ODDnquoDkUjRFR72lLoj5Y4WcPgQmyNNc6xQbggrMyibtKqSbgjrVBzA/640?wx_fmt=png&from=appmsg "")  
  
苹果公司已发布iOS 18.4.1和iPadOS 18.4.1更新，修复两个被用于针对特定iPhone用户实施高度定向、复杂攻击的关键零日漏洞。  
  
这两个漏洞存在于CoreAudio和RPAC组件中，攻击者可利用它们在受影响设备上执行任意代码或绕过安全保护机制。  
## 两个正被活跃利用的零日漏洞  
### CoreAudio漏洞  
  
第一个漏洞编号为**CVE-2025-31200**  
，存在于负责iOS和iPadOS设备音频处理的CoreAudio框架中。  
  
苹果公司表示，处理恶意构造的媒体文件可能触发内存损坏问题，最终导致代码执行。  
  
"处理恶意构造媒体文件中的音频流可能导致代码执行。苹果已收到报告，该漏洞可能已被用于针对iOS特定用户的极其复杂的攻击。"  
  
苹果与谷歌威胁分析小组合作确认，该漏洞已被用于针对部分iOS用户的高级攻击。  
### RPAC漏洞  
  
第二个漏洞**CVE-2025-31201**  
影响RPAC（面向返回编程攻击防护）安全机制，该机制旨在防范漏洞利用。  
  
该漏洞可能使具备任意读写能力的攻击者绕过指针认证（Pointer Authentication）功能，该功能可防止代码被篡改。  
  
"具备任意读写能力的攻击者可能绕过指针认证。苹果已收到报告，该漏洞可能已被用于针对iOS特定用户的极其复杂的攻击。"苹果表示。  
  
苹果指出，该漏洞在同一针对性攻击活动中被利用，目前已通过移除易受攻击代码得到缓解。  
### 受影响设备及修复措施  
- iPhone XS及后续机型  
  
- iPad Pro 13英寸  
  
- iPad Pro 13.9英寸（第三代及后续机型）  
  
- iPad Pro 11英寸（第一代及后续机型）  
  
- iPad Air（第三代及后续机型）  
  
- iPad（第七代及后续机型）  
  
- iPad mini（第五代及后续机型）  
  
## 针对性攻击凸显威胁升级  
  
虽然苹果未披露攻击具体细节，但将其描述为"极其复杂"且针对特定个人，暗示可能是国家支持或资源充足的威胁行为者所为。  
  
此类利用未知漏洞的零日攻击因复杂性和高成本，通常被用于间谍活动或针对性网络攻击。  
  
苹果强调其政策是在补丁可用前不披露安全问题。  
  
该公司于2025年4月16日发布的安全更新说明中提供了漏洞和受影响设备的详细信息。用户可访问苹果产品安全页面获取更多安全实践信息。  
## 如何更新系统  
  
要安装iOS 18.4.1或iPadOS 18.4.1，请前往设备上的**设置 > 通用 > 软件更新**  
。苹果强烈建议所有符合条件的用户尽快更新，确保免受这些漏洞影响。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljuxnCBqbQIAXW9tRyOrn3OWxmNCPW0acN35c6xQbYOrsu0PMkOxiaNTgFE6aYReVmywWf4Kdicwwbg/640?wx_fmt=png&from=appmsg "")  
  
随着网络威胁不断演变，苹果对这些零日漏洞的快速响应凸显了及时更新对保护用户隐私和安全的关键作用。  
  
**来源：2 Apple Iphone Zero-Day Vulnerabilities Actively Exploited in Extremely Sophisticated Attacks**  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】“五一”购票高峰，12306崩了：网友反映抢不到票](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069101&idx=1&sn=c8deb4b52b800fb059e1feec16b25688&scene=21#wechat_redirect)  
  
  
  
[【安全圈】公安局通缉3名美国特工！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069091&idx=1&sn=61ff7ab69c02f676c83ad79ff085ac3b&scene=21#wechat_redirect)  
  
  
  
[【安全圈】GitHub 主动屏蔽中国大陆用户，部分港澳用户同样受影响](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069060&idx=1&sn=1633fcbcb48a0517419c5896f8d44571&scene=21#wechat_redirect)  
  
  
  
[【安全圈】在校大学生滥用AI被抓](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069034&idx=2&sn=7ba359c368ee8d44043e1bf88bce7164&scene=21#wechat_redirect)  
  
  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
