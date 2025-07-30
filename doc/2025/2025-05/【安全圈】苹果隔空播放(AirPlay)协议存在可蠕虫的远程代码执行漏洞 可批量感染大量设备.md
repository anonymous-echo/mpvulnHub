#  【安全圈】苹果隔空播放(AirPlay)协议存在可蠕虫的远程代码执行漏洞 可批量感染大量设备   
 安全圈   2025-05-01 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
安全研究团队近日披露，苹果AirPlay无线协议及其软件开发套件存在重大安全缺陷，可能引发全球范围内的大规模"蠕虫式"网络攻击。该漏洞集合被命名为"AirBorne"，涉及23个独立安全漏洞，其中17个已获得CVE国际通用漏洞编号，且部分漏洞可实现零点击远程代码执行（RCE）攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgYGRMlKMoeM5Q5EIMYnib1MpL5u1ae3b6VfcA0XbDhLzGV7qmYFMibwol6XNicUL1q45ThyAX3O6FMA/640?wx_fmt=jpeg&from=appmsg "")  
  
技术细节与攻击机制：  
1. 威胁范围：漏洞同时影响苹果原生系统（macOS/iOS）及采用AirPlay SDK的第三方设备，涵盖智能音箱、车载系统（CarPlay）、智能电视等数千万物联网设备。  
  
1. 攻击特性：通过组合利用CVE-2025-24252（权限提升漏洞）与CVE-2025-24206（交互绕过漏洞），攻击者可实现：  
  
1. 无需用户交互的静默入侵  
  
1. 同一Wi-Fi网络内的自动传播感染  
  
1. 受控设备成为企业内网渗透跳板  
  
1. 高危案例：CVE-2025-24132作为堆栈溢出漏洞，允许攻击者直接远程执行恶意代码，且无任何系统警告提示。  
  
安全现状与应对建议：  
  
• 苹果响应：官方已发布macOS 13.4.1、iOS 16.5.1等系统更新修补漏洞  
  
• 遗留风险：第三方硬件厂商因固件更新滞后，大量设备仍暴露于攻击风险  
  
• 防护措施：  
- 立即更新所有苹果设备至最新系统版本  
  
- 在公共网络禁用AirPlay接收功能  
  
- 检查网络设置中的"隔空播放"权限配置  
  
- 企业用户应部署网络流量监测系统  
  
据网络安全公司Oligo评估，全球23.5亿台活跃苹果设备及数千万第三方AirPlay终端均可能成为攻击目标。研究人员警告，该漏洞可能引发类似"WannaCry"的级联攻击事件，特别是在智能家居和车联网场景中风险系数最高。  
  
目前Oligo已向受影响厂商提交完整漏洞报告，并计划在未来数月公布更多攻击场景模拟。建议相关用户访问Oligo安全公告获取详细修复指南。  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】近年来我国十大网络安全事件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069369&idx=1&sn=cd14922c387723ce667822963de9e1bc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Apache Tomcat 漏洞可导致攻击者绕过规则并触发 DoS 条件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069369&idx=2&sn=f7f84aa2b4e350b27918d216e6977bc6&scene=21#wechat_redirect)  
  
  
  
[【安全圈】CISA 就 Commvault Web 服务器漏洞发布警告，称该漏洞可能被利用](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069369&idx=3&sn=ad648277b98ceb64dfd2d2ca0b6a1fca&scene=21#wechat_redirect)  
  
  
  
[【安全圈】吉利APP、领克APP突然崩了！有车主在路边苦等3小时，最新回应](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069352&idx=1&sn=db684cad13f694beef16dd9d35410ac6&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
