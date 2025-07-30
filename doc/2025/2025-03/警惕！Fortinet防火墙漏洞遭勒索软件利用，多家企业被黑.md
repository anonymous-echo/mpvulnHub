#  警惕！Fortinet防火墙漏洞遭勒索软件利用，多家企业被黑   
安全内参编译  安全内参   2025-03-19 15:01  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7sMXyB0LNiawyjYlNYg8MN3q3SljmSYVrqpNTMqHnhMFD2VL4YBgEib9tyPpjO0U9CbbayhiakjRMzhA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**网络安全产品屡屡成为企业被黑入口。**  
  
前情回顾·**安全产品漏洞利用态势**  
- [Palo Alto防火墙又被黑：最新漏洞披露后第二天就遭利用](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247513752&idx=1&sn=39cc6a0e87b2d70d65cdc8731d42f1e2&scene=21#wechat_redirect)  
  
  
- [警惕！近期Fortinet防火墙频遭攻击，疑似零日漏洞被利用](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247513504&idx=1&sn=838af406a4e2aec5e99b37399b5f1a2e&scene=21#wechat_redirect)  
  
  
- [网安巨头Palo Alto全球数千防火墙被攻陷：因开发低级错误造成零日漏洞](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247513156&idx=1&sn=4ff7c148a1693c0de1be122e65851155&scene=21#wechat_redirect)  
  
  
- [抓紧修复！2022年最常被利用漏洞清单，Fortinet五年老漏洞位列第一](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247509423&idx=1&sn=34a6099e6da1476ed7f315831b3e2c7b&scene=21#wechat_redirect)  
  
  
  
  
安全内参3月19日消息，安全研究人员发现，与臭名昭著的LockBit团伙有关的黑客正利用Fortinet防火墙的两个漏洞，在多家企业网络中部署勒索软件。  
  
  
**已有多家企业因防火墙未打补丁被入侵**  
  
  
  
Forescout Research的安全研究人员在上周发布的报告中表示，他们正在追踪的一个名为“Mora_001”的黑客组织，正通过Fortinet防火墙入侵企业网络，并部署其自研勒索软件“SuperBlack”。这些防火墙位于企业网络的边界，承担着“数字守门人”的角色。  
  
其中一个被利用的漏洞为CVE-2024-55591。自2024年12月以来，攻击者已利用该漏洞对Fortinet客户的企业网络发起攻击。Forescout指出，Mora_001还在使用另一个漏洞CVE-2025-24472进行攻击。Fortinet已于今年1月发布了针对这两个漏洞的安全补丁。  
  
Forescout威胁狩猎高级经理Sai Molige表示，该公司已调查了三起不同企业遭遇的入侵事件，但他们认为实际受害者可能远不止这些。  
  
在其中一起已确认的攻击事件中，Forescout发现，攻击者会“有针对性地”加密存储敏感数据的文件服务器。  
  
Molige进一步解释道：“攻击者仅在完成数据窃取后才启动加密，这与近年来勒索软件运营的趋势一致。他们更倾向于窃取数据，而非单纯破坏系统。”  
  
  
**攻击者与LockBit勒索软件团伙关系密切**  
  
  
  
Forescout还指出，Mora_001这一威胁组织展现出了“独特的作战特征”，并且与LockBit勒索软件团伙“关系密切”。后者在去年已遭美国当局打击。Molige透露，SuperBlack勒索软件是基于LockBit3.0恶意软件生成器开发的，而该生成器此前已被泄露。此外，Mora_001组织在其勒索信中提供的联系方式，与LockBit团伙使用的完全一致。  
  
Molige进一步分析称：“这一联系可能意味着Mora_001要么是LockBit的附属组织，但采用了不同的作战方式；要么是一个与LockBit共享通信渠道的关联团伙。”  
  
网络安全公司Arctic Wolf的威胁情报负责人Stefan Hostetler也观察到，CVE-2024-55591曾被黑客利用。他表示，Forescout的研究结果表明，攻击者正专门针对那些未能及时打补丁或强化防火墙安全配置的企业发起攻击。  
  
Hostetler还提到，这些攻击中使用的勒索信，其风格与其他已知的勒索软件团伙（例如已解散的ALPHV/BlackCat）高度相似。  
  
  
**参考资料：techcrunch.com**  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
