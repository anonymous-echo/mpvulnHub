#  mySCADA myPRO中存在多个严重漏洞，可导致攻击者接管工控系统   
Ravie Lakshmanan  代码卫士   2025-03-20 17:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**瑞士安全公司 PRODAFT的网络安全研究员详述了影响 mySCADA myPRO 的两个严重漏洞，它们可导致恶意人员控制可疑系统。MySCADA myPRO是用于运行技术 (OT) 环境中的数据采集与监视控制系统 (SCADA) 系统。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMREnmv2ykWoK0kxjAXa1ib0h71CR2Po1U5Aadb1mNt9LHNiayM632YKDnFicCxmnIYLYso3XzIbfCG2w/640?wx_fmt=png&from=appmsg "")  
  
  
研究人员提到，“这些漏洞如遭利用，可导致攻击者越权访问工控网络，从而可能导致严重的运行中断和金融损失后果。”这些漏洞的CVSSv4 评分为9.3，如下：  
  
- CVE-2025-20014：操作系统命令注入漏洞，可导致攻击者通过包含一个版本参数的特殊构造的POST请求在受影响系统上执行任意命令。  
  
- CVE-2025-20061：操作系统命令注入漏洞，可导致攻击者通过包含一个邮件参数的特殊构造的POST请求，在受影响系统上执行任意命令。  
  
  
  
如其中一个或两个漏洞遭成功利用，可导致攻击者注入系统命令并执行任意代码。这两个漏洞已在如下版本中修复：  
  
- MySCADA PRO Manager 1.3  
  
- MySCADA PRO Runtime 9.2.1  
  
  
  
PRODAFT公司提到，这两个漏洞均由用户输入未清理造成，因而导致命令注入。该公司提到，“这些漏洞凸显了SCADA系统中的持久性安全风险以及更强大防御措施的需求。利用可导致运行中断、经济损失和安全危险。”  
  
建议组织机构应用最新补丁，通过将SCADA系统从IT网络隔离的方式执行网络分段，执行强有力的认证措施，以及监控可疑活动。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[工业互联网巨头 GE Digital 修复SCADA 软件中的两个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510703&idx=2&sn=1501b998aec477b0151e8ef9cb2b5b67&scene=21#wechat_redirect)  
  
  
[myPRO HMI/SCADA 产品被曝多个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509859&idx=2&sn=23248508de14b5f9c310a1d7fa72311f&scene=21#wechat_redirect)  
  
  
[SCADA 网络首次遭密币挖矿恶意软件感染](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486465&idx=4&sn=639fe3765334d747e994786d688b6235&scene=21#wechat_redirect)  
  
  
[研究显示修复SCADA缺陷的平均时间是150天](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485523&idx=1&sn=dc1c2fd9d1bc362aab6bac315f28edcd&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/03/critical-myscada-mypro-flaws-could-let.html  
  
  
  
题图：  
Pixabay   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
