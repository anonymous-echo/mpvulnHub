#  【安全圈】Tenda AC7 路由器漏洞使攻击者能够通过恶意负载获取 Root Shell   
 安全圈   2025-03-14 19:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliajjvdWakRvnUcaa8z3dOXP70I99MLTCvg4yicGPyPulic6yS08evtClcwXTxOPgCowJGP7Ot5Cn5yQ/640?wx_fmt=png&from=appmsg "")  
  
运行固件版本 V15.03.06.44 的 Tenda AC7 路由器中存在一个严重漏洞，允许恶意行为者执行任意代码并获得 root shell 访问权限。   
  
该漏洞源自路由器 formSetFirewallCfg 函数中的堆栈溢出漏洞。攻击者可以使用特制的 HTTP 请求完全入侵受影响的设备。   
  
这一发现凸显了消费网络设备中持续存在的安全挑战，并强调了制造商实施强大的输入验证机制的必要性。  
  
该安全漏洞存在于 Tenda AC7 路由器的 Web 管理界面的 formSetFirewallCfg 函数中。  
  
据 GitHub报告，该路由器在处理用户输入之前未能正确验证用户输入。   
  
具体来说，当路由器处理通过 Web 界面提交的防火墙配置数据时，它直接使用 strcpy 函数将用户提供的值复制到固定大小的缓冲区中，而不执行适当的边界检查。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliajjvdWakRvnUcaa8z3dOXPb4Xv6LibZe7RJTrIwgez6eiaI3giaibnPOqWlY69MwUuwzdFL24EKHiansw/640?wx_fmt=png&from=appmsg "")  
## Tenda AC7 路由器漏洞  
  
根本问题在于路由器如何处理“firewallEn”参数。当用户向“/goform/SetFirewallCfg”端点提交数据时，路由器会获取提交的“firewallEn”值，并使用不安全的字符串复制操作将其直接复制到缓冲区中。   
  
如果攻击者提交的数据大于分配的缓冲区大小，它会溢出到相邻的内存位置，可能会覆盖关键的数据结构，包括程序计数器寄存器：  
  
报告中写道：“该漏洞特别危险，因为攻击者可以控制程序的执行流程。”  
  
“通过精心设计有效载荷，可以将执行重定向到任意代码，从而有效地获得对设备的完全控制。”  
## 概念验证利用  
  
研究人员开发了一个概念验证（PoC）漏洞来展示此漏洞。   
  
该漏洞利用包含一个 Python 脚本，该脚本会向存在漏洞的路由器发送特制的 HTTP POST 请求。该脚本以“/goform/SetFirewallCfg”端点为目标，并带有一个超大的“firewallEn”参数，从而触发堆栈溢出条件。  
  
以下代码片段说明了该漏洞的核心：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliajjvdWakRvnUcaa8z3dOXP3dp4GY8ZYuTaV3p722zicRREowRtUXZcBKHWdock4c2zuBMIoHMjmoQ/640?wx_fmt=png&from=appmsg "")  
  
在初步测试中，研究人员证实，在“firewallEn”参数中提交过长的字符串会成功触发拒绝服务条件，导致路由器崩溃。   
  
然而更令人担忧的是，进一步改进有效载荷可以允许攻击者通过在受感染的设备上建立 root shell 来维持持续访问。  
  
该漏洞对于 Tenda AC7 路由器的拥有者来说具有重大的安全隐患。  
  
与存在漏洞的路由器位于同一网络中的攻击者可能会利用此漏洞来完全控制设备、拦截网络流量或使用路由器作为攻击网络上其他设备的发射点。  
  
强烈建议 Tenda AC7 路由器用户检查制造商提供的固件更新，并在可用时立即应用。   
  
在没有官方补丁的情况下，网络管理员应该考虑实施额外的安全措施，例如仅限于受信任的设备访问路由器的管理界面。  
  
随着连接变得越来越普遍，制造商必须通过实施适当的输入验证、使用内存安全的编程实践以及及时响应报告的漏洞来优先考虑安全性。  
  
来源:https://cybersecuritynews.com/tenda-ac7-routers-gain-root-shell/  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】PHP XXE 注入漏洞让攻击者读取配置文件和私钥](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=2&sn=8209e2048ee474d6b91f16029aa9c134&scene=21#wechat_redirect)  
  
  
  
[【安全圈】施乐打印机漏洞使攻击者能够从 LDAP 和 SMB 中获取身份验证数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=3&sn=a464bcdd8889a7e0e65921296df9fdd8&scene=21#wechat_redirect)  
  
  
  
[【安全圈】谷歌警告 Chromecast 用户不要恢复出厂设置](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=4&sn=7af960ec5a3791a46142d0250eee6895&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
[【安全圈】美国政府称 2024 年美国人因欺诈损失创纪录 125 亿美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=1&sn=7aa71495a16a8590c5a5dbaf2a299a09&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
