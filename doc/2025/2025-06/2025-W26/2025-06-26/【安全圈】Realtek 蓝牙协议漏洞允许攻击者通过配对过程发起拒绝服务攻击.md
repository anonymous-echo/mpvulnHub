> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070375&idx=2&sn=43a610075b530001df1d12c917a221e3

#  【安全圈】Realtek 蓝牙协议漏洞允许攻击者通过配对过程发起拒绝服务攻击  
 安全圈   2025-06-26 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljo58Wg05iaUzeiaCgvy7RQpDfLKGic21UlrayfWTLqoojogKmDiamkozCic5UoCgohopdPKHn3GibVWNPQ/640?wx_fmt=png&from=appmsg "")  
  
近日研究人员披露，Realtek 在其 RTL8762E SDK v1.4.0 中存在一个严重安全漏洞，攻击者可利用该漏洞在蓝牙低功耗（Bluetooth Low Energy，BLE）Secure Connections 安全配对过程中发起拒绝服务（DoS）攻击。这一漏洞最初是在 Realtek 的开发平台 RTL8762EKF-EVB 中发现，根源在于协议状态机对配对阶段的数据验证存在缺陷。  
  
攻击者无需任何权限或认证，只需注入构造精巧的数据包，即可中断 BLE 安全连接配对流程，使设备无法建立加密连接，导致蓝牙服务持续失败。  
  
根据蓝牙核心规范 v5.3，BLE 的 Secure Connections 模式要求配对消息必须严格按照顺序进行，例如“Pairing Random”消息必须在“Pairing Public Key”交换成功之后才能发送。然而，Realtek 在 RTL8762E SDK v1.4.0 中的实现未能强制这一顺序，导致协议状态机在未完成公钥交换的情况下，错误地接受了提前到达的 Pairing Random 消息。  
  
该错误发生在 BLE 协议栈的安全管理协议（SMP）层，攻击者只需建立初始 BLE 连接，然后跳过公钥交换阶段，直接发送伪造的 Pairing Random 数据包，即可引发协议状态混乱，从而强制设备中止连接。这一漏洞允许攻击者持续阻断 BLE 连接建立，影响设备的稳定性和可用性。  
  
漏洞的 PoC 攻击脚本  

```
（pairing_random_before_pairing_public_key.py）
```

  
演示了攻击过程的简单性，说明攻击者只需发送时序错误的配对数据，即可复现漏洞行为。  
  
漏洞影响范围主要为使用 RTL8762EKF-EVB 开发板并运行 SDK v1.4.0 的设备。由于 Realtek BLE 协议栈广泛用于各类嵌入式系统、可穿戴设备、家居自动化设备及 IoT 模块，这一漏洞带来的潜在风险不容小觑。  
  
研究人员建议的修复策略是：在 BLE 安全协议栈中加强状态验证逻辑，确保 SMP 层严格按照状态机流程接收和处理消息，明确拒绝所有不符合预期顺序的消息，尤其是仅在完成双边公钥交换后才接受 Pairing Random 数据。  
  
此外，厂商应尽快发布安全补丁，使用受影响 SDK 的开发者和组织也应第一时间升级固件，强化对 BLE 连接流程的监控，以防止类似攻击在实际场景中被滥用。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】“银狐”木马新变种席卷全国：数千企业员工遭网络钓鱼诈骗](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070352&idx=1&sn=9573739f37e8a86bc0919cf885160204&scene=21#wechat_redirect)  
  
  
  
[【安全圈】WordPress 结账页出现高隐匿性恶意插件：伪装成 Cloudflare 窃取用户信息](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070352&idx=2&sn=5b413e9d66c7da07b4922b62d8ab1ba1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】TeamViewer 高危漏洞通报（CVE-2025-36537）](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070352&idx=3&sn=cc4501ba6fd8153a01376bad11487244&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Microsoft Exchange 邮件服务器遭大规模键盘记录攻击，全球逾 70 台被入侵](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070352&idx=4&sn=224922761dcc250ed7e36e3abd1dd1fb&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
