#  Juniper Networks 修复多个严重的第三方组件漏洞   
Ionut Arghire  代码卫士   2023-04-17 17:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络、云和网络安全解决方案提供商 Juniper Networks 上周发布安全公告，详述了产品中出现的数十个漏洞，其中包括 Junos OS 和 STRM 第三方组件中的多个严重漏洞。**  
  
  
  
其中一份安全公告是和 stream 相关的第三方 XML 解析器库 Expat 中的多个严重漏洞。该安全公告详述了最新 Junos OS 版本中存在的15个 Expat 漏洞，其中7个是“严重”等级（CVSS评分9.8）。尽管这些漏洞是在近两年披露的，但并未遭恶意利用。  
  
相关安全更新已在 Junos OS 19.4 到22.2 版本中发布。Juniper 公司建议使用访问清单或防火墙过滤器降低与这些漏洞相关的风险。  
  
Juniper 还为 Security Threat Response Manager (STRM) 发布了CVE-2022-42889的补丁。该漏洞位于 Apache Commons Text 中，可导致远程代码执行后果。  
  
上周，Juniper 公司还修复了影响 Junos OS 和 Junos OS Evolved 的多个高危漏洞，其中最严重的漏洞可导致命令注入和代码执行后果。Junos OS Evolved 中的两个高危漏洞可分别导致低权限本地攻击者以root 权限修改文件或执行命令，或者执行管理员命令。另外，多个高危漏洞可触发拒绝服务条件。  
  
Juniper 公司还修复了位于 Paragon Active Assurance 中的一个严重漏洞，该漏洞可用于绕过现有防火墙规则和限制条件。  
  
Juniper 公司还修复了位于 Junos OS 中的多个中危漏洞，可导致攻击者引发 DoS 条件，发送被释放的数据包，访问敏感信息，绕过完整性检查，导致流量流入或者绕过控制台访问控制。  
  
Juniper 公司并未提到这些漏洞已遭利用。更多详情可见 Juniper Networks 安全公告页面。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Juniper 一月安全更新修复200多个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515307&idx=2&sn=bf20e1ace07e74a2657417caf4f0b6f6&chksm=ea948dc1dde304d73004888e52b7d0ac3b89bb748d42de28380055d0894a642c8b456bdb6652&scene=21#wechat_redirect)  
  
  
[Juniper Junos OS 高危漏洞影响企业网络设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514366&idx=1&sn=76a62227dec3a36c7b849a06adbeb4a4&chksm=ea948994dde3008220487af4d66da9e2fe0056dcbd1c25faa88e487e8c99b443702524fd34fe&scene=21#wechat_redirect)  
  
  
[Juniper Networks 修复开源操作系统 Junos OS 等中的多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494029&idx=3&sn=b6db3afe8845dee92efc83700819cf0f&chksm=ea94d8e7dde351f1a8ec5f666776a3afa7f1795e000ac8276e56d29c8e6d4a516155ee867fbf&scene=21#wechat_redirect)  
  
  
[Juniper Networks修复200多个第三方组件漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512960&idx=1&sn=0df41cf06e3efd8089ec6d6d6b03fc20&chksm=ea9482eadde30bfc407cd490459c7c947bbf2496475946f0379eb8e76c8f4e47f2063742ef87&scene=21#wechat_redirect)  
  
  
[严重漏洞可导致 Juniper 设备遭劫持或破坏](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247503558&idx=2&sn=a8552a0303feab0b57f89c10c50d338f&chksm=ea94ffacdde376ba053569e14a70d4fdb9c5994da61f492128945ec3363edb0731d826f97235&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/juniper-networks-patches-critical-third-party-component-vulnerabilities/  
  
  
题图：Pixabay License  
  
  
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
  
