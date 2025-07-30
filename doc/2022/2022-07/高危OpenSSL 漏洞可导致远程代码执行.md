#  高危OpenSSL 漏洞可导致远程代码执行   
Jessica Haworth  代码卫士   2022-07-07 18:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
OpenSSL 中存在一个高危漏洞，可导致恶意人员在服务器端设备上实现远程代码执行。  
  
  
OpenSSL是一款使用广泛的加密库，提供SSL 和 TLS 协议的开源实现，包括很多生成RSA密钥和执行加密和解密的工具等。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRAn9ibvpN9EniaJ2e72CSNLUOC6yfqRd0HoyxUTunBsicCmouH9IHEXDbOJtoFM9Gvg5fNlcs7H4J9w/640?wx_fmt=gif "")  
  
**内存损坏**  
  
  
  
安全公告指出，OpenSSL 3.0.4发布在支持 AVX512IFMA 指令的 X86_64 CPU的RSA实现中引入一个“严重漏洞”。该漏洞的编号为CVE-2022-2274，它使有2048个位的密钥的RSA实现不正确，即在计算过程中会引发内存损坏。  
  
OpenSSL 的维护人员指出，攻击者可利用该内存损坏漏洞在机器执行计算时触发RCE。研究员Xi Ruoyao在2022年6月22日将问题告知 OpenSSL 并开发了修复方案。  
  
该漏洞影响使用2048位RSA私钥的 SSL/TLS服务器或其它服务器，这些服务器在支持X86_64架构的AVX512IFMA指令的机器上运行。  
  
安全公告指出，“在易受攻击的机器上，OpenSSL测试失败，应该在部署前知晓。”OpenSSL 3.0.4版本的用户应当升级至OpenSSL 3.0.5、OpenSSL 1.1.1和OpenSSL 1.0.2版本。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[惠普Teradici PCoIP 受OpenSSL 漏洞影响，波及1500万个端点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511336&idx=2&sn=fc84814f3a81ed4219673479715a84a6&chksm=ea949c42dde315546e76c412e61dd9ba395e24a56d734d5be4251f9abec136b27ef1cbaefec8&scene=21#wechat_redirect)  
  
  
[OpenSSL 修复高危的无限循环漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510991&idx=1&sn=2b53393259a4ceb4be67d8a5d1c0b54a&chksm=ea949aa5dde313b3acddf64243c846a10c3a0af3430e2be6e83a27c25aa8815375fa64ac5ccf&scene=21#wechat_redirect)  
  
  
[OpenSSL 高危漏洞可被用于修改应用数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507483&idx=1&sn=3e9b55042cfcc7eaf5960a18157ba606&chksm=ea94ef71dde36667e9493590704bc5afacd44f1268659332107de51077bee9991d943bbd754e&scene=21#wechat_redirect)  
  
  
[速修复！OpenSSL 披露DoS 和证书验证高危漏洞，可导致服务器崩溃](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502718&idx=1&sn=87bfe3d3fc2396e28d950ccce10f2074&chksm=ea94fa14dde37302bc0ce58f4d3a09d6b107104dbdb0903e228042b9ad55f54c4a0b1a6503fb&scene=21#wechat_redirect)  
  
  
[“心脏出血”后，OpenSSL 起死回生靠什么？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492028&idx=2&sn=086dfceed7b069ce172b93d1dbad66a8&chksm=ea94d0d6dde359c04ffd98300ca54c586b443d62d84733a7f24ebfa362c4ff12c7c9d8b39712&scene=21#wechat_redirect)  
  
  
[OpenSSL将修复神秘的高危安全漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486003&idx=1&sn=03a33912fcdc13d8d7be214dd2a5d3ae&chksm=ea973b59dde0b24f8f63bac7395997b254d356b5743140386aedf8bc9c56a4dab5e924209674&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/high-severity-openssl-bug-could-lead-to-remote-code-execution  
  
  
题图：  
Pexels  
‍  
  
  
  
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
