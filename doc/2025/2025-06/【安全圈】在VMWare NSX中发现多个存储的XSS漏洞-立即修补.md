#  【安全圈】在VMWare NSX中发现多个存储的XSS漏洞-立即修补   
 安全圈   2025-06-05 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![VMware NSX, XSS 漏洞](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljUotENZwoNatzNHyMChXkYLdIlRS2VyWarFvjAJnjrMv5gKHVqjjR7DukBx9cvfkTWHiaBCIERgRw/640?wx_fmt=other&from=appmsg "")  
  
Broadcom发布了重要的更新,解决了VMware NSX中三个新披露的漏洞,所有这些漏洞都使用户暴露于存储跨站点脚本(XSS)攻击。这些缺陷(如CVE-2025-22243、CVE-2025-22244和CVE-2025-22245)影响了一系列VMware产品,包括VMware NSX、VMware Cloud Foundation和VMware Telco Cloud Platform。  
  
根据Broadcom的咨询这些漏洞是私人报告的,并且源于NSX接口关键组件中的“不当输入验证”。这些缺陷可能允许经过身份验证的攻击者注入持久的恶意JavaScript代码,这些代码在毫无戒心的管理员或用户访问特定配置面板时执行。  
- **CVE-2025-22243 – NSX Manager UI 中的 XSS(CVSS 7.5 – 重要严重程度)**  
  
具有修改网络设置权限的威胁行为者可能会将恶意脚本注入管理器 UI。“具有创建或修改网络设置权限的恶意行为者可能能够注入在查看网络设置时执行的恶意代码  
,”该咨询解释说。  
  
- **CVE-2025-22244 – 网关防火墙中的XSS(CVSS 6.9 – 中度严重程度)**  
  
此漏洞允许通过网关防火墙界面内的 URL 过滤响应页面注入代码。“一个可以访问创建或修改响应页面以过滤URL的恶意行为者可能能够注入恶意代码,当其他用户尝试访问过滤后的网站时,这些代码会被执行。  
  
- **CVE-2025-22245 – 路由器端口中的XSS(CVSS 5.9 – 中度严重程度)**  
  
在路由器端口配置中存储的 XSS 可以允许在其他用户检查路由器设置时触发攻击。“具有创建或修改路由器端口权限的恶意行为者可能能够注入当其他用户尝试访问路由器端口时被执行的恶意代码。  
  
Broadcom列出了多个产品线中的所有易受攻击的版本。受影响的NSX版本包括4.2.x,4.2.1.x,4.1.x和4.0.x,固定版本可用于:  
- ①NSX 4.2.x → 4.2.2.1  
  
- ②NSX 4.2.1.x → 4.2.1.4  
  
- ③NSX 4.1.x 和 4.0.x → 4.1.2.6  
  
对于 VMware Cloud Foundation (v5.0–5.2) 的用户,Broadcom 建议使用 KB88287 中的指导,将 NSX 同步修补到 4.2.2.1 或 4.1.2.6 版本。电信云用户被转介到 KB396986 以获取升级路径。  
  
虽然没有公开利用报告,但敦促管理员立即修补受影响的系统,特别是因为缺陷需要特权访问,并可用于开发后或横向移动场景。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】曝黑客新型钓鱼攻击手法：利用虚假弹窗登录页 苹果浏览器风险最高](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069999&idx=1&sn=a209b07ffec898ff64ca31b5682c918b&scene=21#wechat_redirect)  
  
  
  
[【安全圈】高通紧急发布 5 月补丁，修复 3 个 Adreno GPU 零日漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069999&idx=2&sn=31032694ae0b355efabdb89fde5ebc02&scene=21#wechat_redirect)  
  
  
  
[【安全圈】“ Russian Market ”成为黑客进行盗窃凭证的首选应用商店](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069999&idx=3&sn=c0b6fc5079d25dc0e21619ac4cf85871&scene=21#wechat_redirect)  
  
  
  
[【安全圈】微软和 CrowdStrike 互通黑客识别数据，“去重” 80 余个威胁方](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069999&idx=4&sn=cfff29fabb6a70bf788e1d0fc8602042&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
