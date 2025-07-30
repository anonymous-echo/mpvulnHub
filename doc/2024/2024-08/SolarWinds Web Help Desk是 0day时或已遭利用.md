#  SolarWinds Web Help Desk是 0day时或已遭利用   
Ionut Arghire  代码卫士   2024-08-19 17:26  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**美国网络安全局CISA在上周四提醒称，位于SolarWinds Web Help Desk 中一个新的严重漏洞已遭利用。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMR7fwO4wa9vkj7xic3kJvt1iaic86s5ibtY0cqZksksd3b1bs8m9tFVW3tsnOf6cOhgib5V1wricgOJN3gg/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞的编号为CVE-2024-28986（CVSS评分9.8），是一个Java 反序列化远程代码执行 (RCE) 漏洞，可导致攻击者在主机机器上运行命令。SolarWinds 公司宣布发布热修复方案解决该漏洞，表示成功利用需进行认证，但并未提及在野利用。  
  
SolarWinds 公司在安全公告中提到，“虽然该漏洞被报道为未认证漏洞，但 SolarWinds 无法在全面测试之后不经过认证的情况下进行复现。” 不过该公司确实建议所有客户应用补丁，而该补丁仅适用于 Web Help Desk 12.8.3.1813，该公司督促之前版本用户尽快升级。该漏洞影响 12.4至12.8版本。SolarWinds 更新其安全公告提醒称，如果使用了SAML 单点登录，则不应应用该热修复方案。  
  
就在 SolarWinds 公司发布该热修复方案的两天后，CISA “根据活跃利用的证据”，将CVE-2024-28986纳入“已知已遭利用漏洞 (KEV)”分类表。研究人员猜测，虽然CISA并未提供关于该利用的性情，但公开披露和纳入KEV分类表之间的短暂窗口说明，该漏洞可能在0day 漏洞状态已遭利用。另外，研究人员认为卫星通信公司 Inmarsat和Viasat（都出现在 SolarWinds 安全公告）或它们的一名客户可能因该漏洞遭利用而受陷。  
  
按照BOD 22-01的要求，联邦机构应在9月5日前在他们各自的环境中找到并修复易受攻击的 SolarWinds Web Help Desk 实例。虽然BOD22-01仅应用于联邦机构，但建议所有组织机构查看 SolarWinds公司的安全公告并尽快应用必要的缓解措施。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[SolarWinds 修复访问权限审计软件中的8个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520104&idx=1&sn=b5831c292df944c1998d2c0e89a80188&chksm=ea94be02dde3371465b0ad96095c0a03d607581b57af9afb87fd5ef76bdc9b79312b0f3468c7&scene=21#wechat_redirect)  
  
  
[SolarWinds 访问审计解决方案中存在严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517960&idx=2&sn=859ca4a50e7e9df4867d1973b7bba390&chksm=ea94b662dde33f74e25d02181f9fc202ee23b91008de4d26acf0d79bd3e0385d608d23bb1245&scene=21#wechat_redirect)  
  
  
[SolarWinds 事件爆发前半年，美司法部就检测到但未重视](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516392&idx=1&sn=03805ab2d377a6823689c8e9df44946b&chksm=ea94b182dde33894b955bb4519df38c455bcbfff727ec9d3034f4272590e649e51f90426748a&scene=21#wechat_redirect)  
  
  
[SolarWinds 平台修复两个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516335&idx=2&sn=7714c02477242110c20958d13327c558&chksm=ea94b1c5dde338d3aea7cd488e25f4d59825e633deebe43bb64963f20d6336a81cf4016641f1&scene=21#wechat_redirect)  
  
  
[SolarWinds 称将在2月底修复多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515647&idx=3&sn=e5d9ae1f0396aaa5c5eb758484fb760b&chksm=ea948c95dde3058339a2b4d43a851fdc2441afec55b15919595ce8d9f6b98ea46b38a0e06ae3&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/solarwinds-web-help-desk-vulnerability-possibly-exploited-as-zero-day/  
  
  
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
  
