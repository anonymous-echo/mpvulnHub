#  苹果0-Day漏洞被用于“极其复杂”的特性攻击中   
老布  FreeBuf   2025-02-11 10:59  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
近日，苹果公司发布了紧急安全更新，以修补一个0-Day漏洞，编号CVE - 2025 - 24200，由公民实验室 安全研究人员比尔·马尔扎克报告。该漏洞在有针对性的且“极其复杂”的攻击中被利用，“在设备锁定时禁用USB限制模式”。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38YrW11vyiab4Xf2Lib0vBIIzHx6dGt2WIeic6AsXD81CiaJYawXtFKqnZo9JbD6VZIM5eXIdw8RTm69w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
USB限制模式是苹果设备的一项安全功能，如果设备锁定超过一小时，该功能会阻止USB配件创建数据连接。此功能旨在阻止像Graykey和Cellebrite（执法部门常用）这类取证软件从锁定的iOS设备中提取数据。2024年11月，苹果还公司推出了另一项安全功能——闲置重启，即在长时间闲置后自动重启iPhone，以重新加密数据，使取证软件更难提取数据。  
  
  
受影响的设备包括iPhone XS及更新机型、iPad Pro 13英寸、iPad Pro 12.9英寸第3代及更新机型、iPad Pro 11英寸第1代及更新机型、iPad Air第3代及更新机型、iPad第7代及更新机型、iPad mini第5代及更新机型。  
  
  
尽管此漏洞仅在有针对性的攻击中被利用，但仍强烈建议立即安装iOS 18.3.1更新，以阻止潜在的持续攻击尝试。  
  
  
公民实验室曾在2023年9月的紧急安全更新中披露了另外两个零日漏洞（CVE - 2023 - 41061和CVE - 2023 - 41064），苹果公司对此进行了修复。这两个漏洞被用作零点击漏洞利用链（被称为BLASTPASS）的一部分，用于感染完全打过补丁的iPhone，使其感染NSO集团的Pegasus商业间谍软件。  
  
  
上个月，苹果公司修复了今年第一个被标记为在针对iPhone用户的攻击中被利用的零日漏洞（CVE - 2025 - 24085）。  
  
  
2024年，该公司修补了六个正在被利用的零日漏洞；即2023年，苹果公司修补了20个在野外被利用的零日漏洞，其中包括：  
  
  
11月的两个零日漏洞（CVE - 2023 - 42916和CVE - 2023 - 42917）；10月的两个零日漏洞（CVE - 2023 - 42824和CVE - 2023 - 5217）；9月的五个零日漏洞（CVE - 2023 - 41061、CVE - 2023 - 41064、CVE - 2023 - 41991、CVE - 2023 - 41992和CVE - 2023 - 41993）；7月的两个零日漏洞（CVE - 2023 - 37450和CVE - 2023 - 38606）；6月的三个零日漏洞（CVE - 2023 - 32434、CVE - 2023 - 32435和CVE - 2023 - 32439）；5月的另外三个零日漏洞（CVE - 2023 - 32409、CVE - 2023 - 28204和CVE - 2023 - 32373）；4月的两个零日漏洞（CVE - 2023 - 28206和CVE - 2023 - 28205）；以及2月的另一个WebKit零日漏洞（CVE - 2023 - 23529）。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
