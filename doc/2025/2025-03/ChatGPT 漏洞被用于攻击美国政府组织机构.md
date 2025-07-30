#  ChatGPT 漏洞被用于攻击美国政府组织机构   
Ionut Arghire  代码卫士   2025-03-19 18:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**网络安全公司 Veriti 报道称，威胁行动者们正在利用ChatGPT去年的服务器端请求伪造 (SSRF) 漏洞，攻击金融实体和美国政府组织机构。**  
  
该漏洞CVE-2024-27564是一个影响 pictureproxy.php 文件的中危漏洞，可导致攻击者在 url 参数中注入构造的URL并强制该应用提出任意请求。该漏洞在2023年浮出水面且在一年前公开披露，无需认证即可遭利用，而其PoC利用代码已被公开一段时间。  
  
Veriti 公司表示，至少有一个威胁行动者已将该漏洞纳入其武器库，并开始在互联网寻找易受攻击的应用。在一周内，该公司就发现来自单一IP地址的10000多次攻击尝试。大约三分之一的目标组织机构可能因其防护解决方案中的配置不当问题而面临利用风险。  
  
多数攻击活动针对的是位于美国的组织机构，主要集中在政府和金融行业。德国、泰国、印度尼西亚、哥伦比亚和英国的金融和医疗企业也遭攻击。Veriti 公司提到，“银行和金融科技企业依赖于受AI驱动的服务和API集成，使其易受SSRF攻击，可访问内部资源或窃取敏感数据。”  
  
尽管该漏洞属于中危级别，但已成为真实的攻击向量。组织机构应尽量修复该漏洞，同时应当检查自己的入侵防御系统和防火墙中出现的配置不当问题并监控日志，查找已知的攻击者IP地址。该公司指出，“忽视中危漏洞是昂贵的错误，尤其对于高价值的金融组织机构而言更是如此。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[OpenAI禁用朝鲜黑客的ChatGPT账号](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522340&idx=3&sn=b65a3d52caf2088d9510aff887ea70f8&scene=21#wechat_redirect)  
  
  
[ChatGPT 可导致访问底层沙箱OS和“工作指南”数据](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521498&idx=2&sn=d1ee6927e83d0198a631936e3f951bf2&scene=21#wechat_redirect)  
  
  
[Mozilla：十六进制代码可用于操纵 ChatGPT 写 exp](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521319&idx=1&sn=cbfae51c8facf463612f1507daddd94f&scene=21#wechat_redirect)  
  
  
[OpenAI：伊朗国家黑客利用 ChatGPT 密谋 ICS 攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521056&idx=2&sn=99545ebc43462c5f2e8b1617494b75b4&scene=21#wechat_redirect)  
  
  
[OpenAI 推出的 ChatGPT 数据泄露漏洞补丁不完整](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518467&idx=1&sn=e62b48f443aac09cc258fee8e9f2f03f&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/chatgpt-vulnerability-exploited-against-us-government-organizations/  
  
  
  
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
  
