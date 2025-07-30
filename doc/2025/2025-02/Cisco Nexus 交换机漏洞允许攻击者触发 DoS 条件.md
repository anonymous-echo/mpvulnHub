#  Cisco Nexus 交换机漏洞允许攻击者触发 DoS 条件   
邑安科技  邑安全   2025-02-27 08:35  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8uG8iboql72V37wncP4M0cMD7UjhHTXJa9YqLibqFMkInUUhvkWbqeYjK1apILFzvFF5QQ45KvsTh6w/640?wx_fmt=png&from=appmsg "")  
  
Cisco 发布了一份安全公告，解决了其 Nexus 3000 和 9000 系列交换机中的一个漏洞，该漏洞可能允许攻击者触发拒绝服务 （DoS） 情况。  
  
在交换机的运行状况监控诊断中发现的漏洞可能会导致意外的设备重新加载。  
  
该漏洞源于对特定以太网帧的不正确处理。未经身份验证的相邻攻击者可以通过向受影响的设备发送持续速率的构建的以太网帧来利用此缺陷。  
  
成功利用此漏洞可导致设备重新加载，从而中断网络作。  
##   
## 受影响的产品  
  
如果以下 Cisco 产品运行的是易受攻击的 Cisco NX-OS 软件版本，则无论设备配置如何，此漏洞都会受到影响：  
- Nexus 3100 系列交换机  
  
- Nexus 3200 系列交换机  
  
- Nexus 3400 系列交换机  
  
- Nexus 3600 系列交换机  
  
- 独立 NX-OS 模式下的 Nexus 9200 系列交换机  
  
- 独立 NX-OS 模式下的 Nexus 9300 系列交换机  
  
- 独立 NX-OS 模式下的 Nexus 9400 系列交换机  
  
Cisco 已确认该漏洞不会影响其他 Cisco 产品，包括 Firepower 和 MDS 系列以及某些 Nexus 交换机。  
  
Cisco 的 Security Indicators of Compromise Reference Guide 详细介绍了如何识别可能受此漏洞影响的设备。  
  
成功利用该漏洞可能导致 Nexus 3100 和 3200 系列交换机的 L2ACLRedirect 健康监测诊断测试或 RewriteEngineLoopback 测试连续失败。  
Syslog   
消息（例如“L2ACLREDIRECT_LOOPBACK_TEST_FAIL”或“REWRITE_ENGINE_LOOPBACK_TEST_FAIL”）表示可能存在危害，然后设备重新启动，原因代码为“内核崩溃”。  
请务必注意，这些诊断测试失败也可能由于与此漏洞无关的原因而发生。  
## 缓解措施  
  
Cisco 已发布软件更新来解决此漏洞。签订服务合同的客户应通过其常规更新渠道获取这些修复。  
  
Cisco 建议客户查阅 Cisco 产品的安全建议，以确定风险并确定完整的升级解决方案。  
  
思科提供思科软件检查器工具，以帮助客户确定他们在思科 NX-OS 软件中面临的漏洞。此工具可识别影响特定软件版本的思科安全公告，以及修复所述漏洞的最早版本。  
  
思科产品安全事件响应团队 （PSIRT） 未发现任何公开公告或恶意使用该漏洞，这是在内部安全测试期间发现的。  
  
原文来自:   
cybersecuritynews.com  
  
原文链接: https://cybersecuritynews.com/cisco-nexus-switches-vulnerability-dos/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  
