#  博通Brocade漏洞影响多家大厂的存储解决方案   
Eduard Kovacs  代码卫士   2022-07-01 19:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTMLMNkOBLg5PPq5XlaJWn53qxSglSuZl4XNicSqauibrrqaYicgNhHtb91ZALqDelU0iaJ4TqqXtzqTg/640?wx_fmt=png "")  
  
最近，博通 (Broadcom) 公司表示，其存储网络子公司 Brocade 提供的一些软件受多个漏洞影响，可能影响多家主流厂商的产品。  
  
博通公司表示，Brocade SANnav 存储局域网 (SAN) 管理应用受九个漏洞影响，目前补丁已发布。其中六个漏洞影响第三方组件如 OpenSSL、Oracle Java 和 NGINX，严重程度为中危或低危。在很多情况下，未认证攻击者可利用这些漏洞操纵数据、解密数据并引发拒绝服务 (DoS) 条件。  
  
余下的三个漏洞和 Brocade SANnav 有关，严重性和风险等级为“高危”，可导致攻击者从日志文件获取交换机和服务器密码，并拦截因静态密钥加密潜在的敏感信息。  
  
其中三个漏洞（CVE-2022-28167、CVE-2022-28168和CVE-2022-28166）是由内部发现的，目前尚未发现在野利用迹象。  
  
  
**多家合作厂商受影响**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTMLMNkOBLg5PPq5XlaJWn5f2fliaPvC0tqXzQlibKg5CC4ZiaXns3LgBpsfzuBxto1wTz6l14ytDdXw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTMLMNkOBLg5PPq5XlaJWn5r7UqyZpQmiacyianr8GMfp0A5ibP1EZOsLDFYBF5vgrh1kOLVXDiar6z1Q/640?wx_fmt=png "")  
  
  
  
然而，和 Brocade协作的多家公司的存储解决方案可受这些漏洞影响。  
  
HPE 在今天发布的一份安全公告中指出，“可从本地或远程利用这些漏洞泄露敏感信息、执行越权访问和修改数据并引发部分拒绝服务”。  
  
Brocade 的另外一家合作伙伴 NetApp 为SANnav 的多个漏洞分别发布安全公告。NetApp 自身产品并未受影响。  
  
Brocade 还与其它技术巨头达成存储解决方案方面的合作伙伴关系，包括戴尔、富士通、华为、IBM和联想。  
  
在本文成稿之时，Brocade 其它OEM合作伙伴并未发布关于 SANnav 漏洞的安全公告，因此目前尚不清楚它们的产品是否受影响。过去，至少其中某些厂商曾发布此类公告。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[博通芯片中间件被曝严重漏洞，数亿台电缆调制解调器易受攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492127&idx=2&sn=6f7791b8fdc89cb105374f0bd46f485a&chksm=ea94d375dde35a63b29a40c47bc0f74fe56f47edc647ad36d2a6911c8d9705c9cdb1d1f54523&scene=21#wechat_redirect)  
  
  
[华为苹果三星等均受影响：博通 WiFi 驱动被曝漏洞，可导致 RCE 和 DoS](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489762&idx=2&sn=74a7aa82de7def2e844ab6dff1b8d8ff&chksm=ea972988dde0a09ea4b42144f922c135a00541345ddaec391449eab29d100efd6db339677bfc&scene=21#wechat_redirect)  
  
  
[博通高通收购尚未达成 美国政府国安调查先行但意在中国？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486615&idx=2&sn=9b621111b19ab7d137cb964307dd8b34&chksm=ea973dfddde0b4ebd4f0e695d49573d4dfcc3183770fb4241dc4e61520bcf0f0a788e9b630d9&scene=21#wechat_redirect)  
  
  
[谷歌研究员发布攻破iPhone博通无线芯片的PoC利用代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485459&idx=6&sn=f657a72c91be83d2513cb21401cae1f6&chksm=ea973979dde0b06faba394923f27008862bbd704803fe5490c67d4e41a1e90e9af2dcb05a6b9&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/brocade-vulnerabilities-could-impact-storage-solutions-several-major-companies  
  
  
题图：  
Pixab  
ay License  
  
  
  
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
