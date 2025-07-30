#  CISA称SLP高危漏洞正遭活跃利用   
THN  代码卫士   2023-11-09 17:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**本周三，美国网络安全和基础设施安全局 (CISA) 将位于服务位置协议 (SLP) 中的一个高危漏洞增加到“已知已遭利用漏洞 (KEV)”分类中，指出已发现活跃利用证据。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS064eaUUuS9TUvEVnTYRMSibSE5aPwqh4eAQG8GhZsrcme0micM7x2lEtHug8rIDGopfJ69n8tN4sw/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞的编号是CVE-2023-29552（CVSS评分7.5），与可被用于发动大规模DoS 放大攻击的一个DoS 漏洞有关，由 Bitsight 和 Curesec 在今年4月初发现。  
  
CISA 提到，“服务位置协议 (SLP) 中含有一个DoS 漏洞，可导致未认证的远程攻击者注册服务并使用遭嗅探的 UDP 流量通过一个重要的放大因素执行 DoS 攻击。”  
  
SLP 协议可使位于局域网上的系统互相发现并建立通信。  
  
虽然目前该漏洞遭利用的性质尚无法知道，但 Bitsight 此前曾警告称该漏洞可被用于发动放大因素较高的 DoS 攻击。该公司指出，“这个极高的放大因素可导致资源不足的威胁行动者对目标网络和/或服务器通过反射型 DoS 放大攻击造成重大影响。”  
  
鉴于已存在利用该漏洞的真实攻击，联邦机构被要求在2023年11月29日前应用必要的缓解措施，包括禁用在不可信网络上运行系统的 SLP 服务，确保网络不受潜在威胁影响。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Adobe Acrobat Reader 高危漏洞加入CISA必修清单](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517855&idx=2&sn=5ea5455de3ad27bd027a363a4b11a95a&chksm=ea94b7f5dde33ee34cdfbb1253dab1a695f4138beb5de5e782328ecbbfdee7df7e80594a5429&scene=21#wechat_redirect)  
  
  
[NSA和CISA联合发布十大最常见的网络安全配置不当问题清单](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517792&idx=2&sn=26f5404af467b67c8aed30c37fbd4f2f&chksm=ea94b70adde33e1ce4f013e6b0674f3dd92751f5751befc98dba7a610fffd3373988026c0011&scene=21#wechat_redirect)  
  
  
[CISA “已知已利用漏洞”分类计划加快打补丁速度](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517736&idx=2&sn=3425c61c1f7349910eec3401ed3697cb&chksm=ea94b742dde33e546c960957e2e235031bcb2b96ad0872d9e1a991f1e02bdd4d0b3d8047af3b&scene=21#wechat_redirect)  
  
  
[CISA 发布开源软件安全路线图](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517654&idx=1&sn=7d8162734766c1f2b28308d2eb7a3ff4&chksm=ea94b4bcdde33daadaef6eb96bca05af2bc5cd7e02a3dd802bb942bb6631bcf8a9249c342094&scene=21#wechat_redirect)  
  
  
[CISA 将Adobe ColdFusion中的这个严重漏洞列入必修清单](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517437&idx=1&sn=561e8ad37f584120784a95e9ad1c33f4&chksm=ea94b597dde33c810a56421fadb562f0a4fbab00589ec4d11a1fb82d61b17dffcab841d4546a&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/11/cisa-alerts-high-severity-slp.html  
  
  
题图：  
Pexels  
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
  
