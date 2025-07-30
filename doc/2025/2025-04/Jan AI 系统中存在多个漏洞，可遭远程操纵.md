#  Jan AI 系统中存在多个漏洞，可遭远程操纵   
Ionut Arghire  代码卫士   2025-04-03 18:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**安全研究人员提到，标榜为ChatGPT 替代品的开源工具 Jan AI中存在多个漏洞，可导致远程未认证攻击者操纵系统。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQr0CXoUIvN9qXrGWL7w9E0D7mMPiaPfSg4M7CEPo06ibaSWJJADes3t6vXRr6w2z7MjQEic0ucrZlhg/640?wx_fmt=png&from=appmsg "")  
  
  
Jan AI 是由 Menlo Research 开发的一款个人助手，可在桌面和移动设备上离线使用，包含热门大语言模型 (LLMs) 的模型库，支持用于自定义目标的多种扩展。  
  
Jan 在GitHub 上的下载量超过100万次，可使用户本地下载并运行LLMs，无需依赖云托管服务并从对AI的完全控制中获益。它受 Menlo 自托管的 AI 引擎 Cortex.cpp 的驱动，该引擎如同后端API服务器，并将 Electron 应用作为用户界面。用户可通过 Cortex 从专门的中心和HuggingFace 拉取模型，并导入以 GGUF 文件格式存储的本地模型。  
  
 an 和 Cortex 旨在本地运营，缺乏认证，这意味着它们易受来自恶意网页的攻击。Snyk 公司的研究人员分析发现，用于将文件上传到服务器的一个函数缺乏清洗，因此可被恶意页面用于向机器写入任意文件。进一步调查发现，Jan 的 GGUF 解析器中存在多个界外问题，其服务器上缺少跨站请求伪造 (CSRF) 的防御措施，因此在非GET 端点上遭利用，尽管 Cortex 执行了跨源资源共享 (CORS)。  
  
攻击者通过利用跨源任意文件写漏洞，可将构造的 GGUF 文件写入服务器，之后利用缺少 CSRF 防护措施的事实导入并处罚界外读，从而导致攻击者将数据读取到受其控制的元数据字段。  
  
攻击者可发送跨源请求，更新服务器的配置并完全禁用 CORS，之后通过将请求发送给该模型元数据端点的方式，读回被泄露的数据。研究人员提到，“通过GGUF 文件在网络泄露数据的做法非常利落，但也存在限制。我们无法在构造的模型文件后控制所映射的内容，因此也无法了解我们是否能够泄露敏感数据。”  
  
Jan AI 还易受远程代码执行 (RCE) 攻击，可通过 Cortex.cpp 对Python 引擎的支持实现。由于该引擎是C++的封装，执行Python 字节，因此攻击者可更新该模型配置，在字节注入 payload 并在模型启动时触发命令执行。  
  
研究人员在2月18日报送漏洞，Menlo 已在3月6日修复所有漏洞，它们是：CVE-2025-2446（通过路径遍历实现任意文件写）、CVE-2025-2439（位于GGUF 解析器中的界外读）、CVE-2025-2445（Python 引擎模型更新中的命令注入）和CVE-2025-2447（缺少 CSRF 防护措施）。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[微软利用AI从开源引导加载器中找到20个0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522638&idx=1&sn=15b5a925b5a9f1eecca2dc4a721a63a9&scene=21#wechat_redirect)  
  
  
[OpenAI 严重漏洞最高赏金提高至10万美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522605&idx=1&sn=d013414cab5f1de1d4ec9080c742585e&scene=21#wechat_redirect)  
  
  
[报告：89%的企业生成式AI使用不可见，或造成严重风险](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522363&idx=2&sn=30341de9895d38b4b0408b086cf54477&scene=21#wechat_redirect)  
  
  
[Mozilla：十六进制代码可用于操纵 ChatGPT 写 exp](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521319&idx=1&sn=cbfae51c8facf463612f1507daddd94f&scene=21#wechat_redirect)  
  
  
[OpenAI：伊朗国家黑客利用 ChatGPT 密谋 ICS 攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521056&idx=2&sn=99545ebc43462c5f2e8b1617494b75b4&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/vulnerabilities-expose-jan-ai-systems-to-remote-manipulation/  
  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
