#  Node.js 修复多个漏洞，可导致RCE和HTTP请求走私   
Jessica Haworth  代码卫士   2022-07-11 18:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Node.js 维护人员为JavaScript运行时环境中的七个漏洞发布修复方案。它们可导致任意代码执行和HTTP请求走私等攻击。**  
  
  
其中，三个漏洞可导致HTTP请求走私，分别是传输-解码解析有权限漏洞（CVE-2022-32213）、标头字段的限定不当漏洞（CVE-2022-32214）以及不正确的多行传输-编码解析漏洞（CVE-2022-32215）。  
  
这些漏洞均被评级为“中危”级别，影响18.x、16.x和14.x 发布。IIhttp v6.0.7和IIhttp v2.1.5包含的修复方案已在 Node.js 中更新。  
  
  
****  
**其它漏洞**  
  
  
  
该安全公告中还包含通过不合法的IP地址造成的 –inspect 中的一个DNS重绑定漏洞详情。  
  
该高危漏洞的编号为CVE-2022-32212，可导致任意代码执行。安全公告提醒称，“IsAllowdHost 检查可轻易被绕过，因为 IsIPAddress 未能正确检查IP地址合法与否。如果提供不合法的IPv4地址，则浏览器将向 DNS服务器提出DNS请求，为受攻击者控制的DNS服务器或可欺骗DNS响应执行重绑定攻击的中间人提供向量，连接至 WebSocket调试解调器，从而造成任意代码执行后果。这是对CVE-2021-22884的绕过。”该漏洞影响所有的 18.x、16.x 和 14.x的发布。  
  
该安全公告还详述了Windows上的一个DLL劫持漏洞（CVE-2022-32223）和中危漏洞CVE-2022-32222。后者可导致攻击者在系统启动时尝试从 /home/iojs/build/中读取openssl.cnf。  
  
此外，公告中还包括对 OpenSSL 中中危漏洞CVE-2022-2097的修复方案，在某些情况下可导致加密失败。使用AES-NI 汇编优化实现的32位 x86 平台AES OCB模式将不会完整加密数据，从而暴露了未被写的已存在内存中的16个数据字节。在 ‘所部署的’ 加密的特殊案例中，16个字节的明文文本可遭暴露。由于OpenSSL 不支持基于OCB的 TLS和DTLS 加密套件，因此TLS和DTLS并不受影响。  
  
以上所有漏洞均已在最新版本Node.js v14.20.0 (LTS)、Node.js v16.16.0 (LTS) 和 Node.js v18.5.0（当前）版本中修复。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Node.js 修复4个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510120&idx=2&sn=2248a9cd9eaeb4fa81633a61b0b3d0f2&chksm=ea949902dde310141c5bd5a8aefc398a63b2497388986cf845d66b84723e533bc689977e9ace&scene=21#wechat_redirect)  
  
  
[Node.js 沙箱易受原型污染攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508579&idx=2&sn=90cb9a086322e582c71840a9be1eed6a&chksm=ea949309dde31a1f9bb8a7531fe4ca9387412bb365f3feeee6120a1d1d036325458553104fa4&scene=21#wechat_redirect)  
  
  
[Node.js 易受两个HTTP请求走私漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508413&idx=1&sn=0a9ef2abb46ffa5197f25a0be4c0f144&chksm=ea9490d7dde319c140117f3c219c21ea90ca65cf65511d4d3a3851df0a02c33e9a2b8afc09b3&scene=21#wechat_redirect)  
  
  
[Node.js TLSWrap 实现中的释放后使用漏洞分析](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499986&idx=1&sn=4ab1b0ba496d7b6e6a8c455de048a393&chksm=ea94f1b8dde378ae75623cface57de18cedb85bb0ac90ca67cfc27713aacf183c5fa28bd7fc9&scene=21#wechat_redirect)  
  
  
[GitHub 在热门 Node.js changelog 开源库Standard Version中发现 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494159&idx=1&sn=21cf8e56cf600e34d1c467cd3e862d89&chksm=ea94db65dde352737e4e66bf42296a1d0be5a3f1ebafc633ae6545c45386455771464293b33a&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/node-js-fixes-multiple-bugs-that-could-lead-to-rce-http-request-smuggling  
  
  
题图：  
Pixabay License  
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
