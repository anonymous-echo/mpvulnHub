#  锐捷网络云管理平台爆出严重漏洞，可从云端劫持WiFi热点   
 GoUpSec   2024-12-26 02:14  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbQot4tey7QwvtPeflfnf1djQRccjq5yLZrjJU3OrD9pbfbKcdDN2wUpuNhK8AUrpdswD9w3YkibWw/640?wx_fmt=png&from=appmsg "")  
  
  
近日，网络安全研究人员在锐捷网络的云管理平台中发现多个严重漏洞，这些漏洞可能使攻击者全面控制网络设备，进而对企业和个人用户的网络安全构成重大威胁。  
  
  
  
**从云端入侵WiFi接入点**  
  
  
  
来自工控安全公司Claroty的研究人员NoamMoshe和Tomer Goldschmidt指出，这些漏洞不仅影响锐捷的睿易云管理平台（Reyee），还波及基于Reyee OS的网络设备。  
  
  
研究团队不仅发现了多达10个漏洞，还设计了一种名为“Open Sesame”的攻击方式，可通过云端入侵物理附近的接入点，从而未经授权访问网络。  
  
  
**在发现的10个漏洞中有三个高危漏洞，如下：**  
  
****  
CVE-2024-47547  
- 评分：9.4（高危漏洞）  
  
- 问题：弱密码恢复机制，使身份验证机制易受暴力破解攻击。  
  
CVE-2024-48874  
- 评分：9.8（高危漏洞）  
  
- 问题：服务端请求伪造（SSRF）漏洞，攻击者可利用其访问AWS云元数据服务，渗透锐捷的内部云基础设施。  
  
CVE-2024-52324  
- 评分：9.8（高危漏洞）  
  
- 问题：使用高风险功能，允许攻击者发送恶意MQTT消息，导致设备执行任意操作系统命令。  
  
  
  
  
**攻击链条与破坏潜力**  
  
  
  
Claroty研究人员指出，MQTT协议的身份验证机制存在明显弱点，只需设备序列号即可破解（CVE-2024-45722，评分：7.5）。通过这一漏洞，攻击者可以获取所有连接至云端的设备列表，并生成有效的认证凭据。这些凭据进一步被利用执行以下攻击：  
  
- 拒绝服务攻击（DoS）：通过伪造认证中断设备连接。  
  
- 发送虚假数据：在云端注入错误信息，误导设备用户。  
  
此外，攻击者还可以拦截Wi-Fi信标，提取设备序列号，从而利用MQTT漏洞实现远程代码执行。这种“OpenSesame”攻击被分配为CVE-2024-47146（评分：7.5）。  
  
  
  
**漏洞修复与影响评估**  
  
  
  
在经过负责任披露后，锐捷网络已修复了上述漏洞，并更新了相关云服务。用户无需额外操作即可确保设备安全。据估计，约5万台云连接设备可能受到影响。  
  
  
Claroty的研究人员警告，这一事件再次表明，物联网设备（IoT）中的安全弱点对网络安全构成深远威胁。尤其是无线接入点、路由器等用户门槛较低的设备，却能为攻击者提供深入网络的路径。  
  
  
参考链接：  
  
https://claroty.com/team82/research/the-insecure-iot-cloud-strikes-again-rce-on-ruijie-cloud-connected-devices  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/INYsicz2qhvZRDUnojiaba5EGXQ7vEkEX8iar6wfVEW8pJj4v4XBgG48Lt1Ga5seakLRcfZJdGmq4yUsZXdLh2ZfA/640?wx_fmt=other "")  
  
  
  
END  
  
  
  
相关阅读  
  
  
  
[上线仅48小时翻车，苹果人工智能因造谣面临下架](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501895&idx=1&sn=4428507edfc93a1a6a95d8008e118d0a&scene=21#wechat_redirect)  
  
  
[MITRE公布最危险软件漏洞TOP25榜单](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501504&idx=2&sn=741da5d8dcc2e08936f21c432a3b1f0e&scene=21#wechat_redirect)  
  
  
[立即修复！五眼联盟公布最常被利用的15个漏洞名单](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501433&idx=2&sn=26dab7b46c410a8e7d56e6b78f742e15&scene=21#wechat_redirect)  
  
  
[25家跨国企业数据泄露，MOVEit漏洞引发重大安全危机](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501422&idx=1&sn=312c9acb659009fdafc7e2bd665d45ad&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/INYsicz2qhvbgcN4QY36lK2wjCavZiadQThpmM11FR4xkwyVG7K24lkpoLRcFHuZ7gAHgZEsr6Mia7BmKuwDJqX4g/640?wx_fmt=jpeg "")  
  
