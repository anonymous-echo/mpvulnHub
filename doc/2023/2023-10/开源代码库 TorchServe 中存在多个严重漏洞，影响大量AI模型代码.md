#  开源代码库 TorchServe 中存在多个严重漏洞，影响大量AI模型代码   
Bill Toulas  代码卫士   2023-10-09 18:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**开源的AI模型服务工具TorchServe 中存在多个被统称为 “ShellTorch” 的严重漏洞，影响数千个被暴露在互联网中的服务器，其中一些服务器归大型组织机构所有。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQlib8xW4DWtdQNeLNx139icWx4JWRSGlic9PvFibVtdII0pvHdl8JypIuITnQ80XAAdMZrjnwJrtBxUQ/640?wx_fmt=gif "")  
  
  
TorchServe 由Meta 和 Amazon 公司维护，是一款用于扩展生产中的PyTorch（机器学习框架）模型的热门工具。该库主要由从事AI模型训练和开发的群体使用，如学术研究员以及大企业如Amazon、OpenAI、特斯拉、Azure、谷歌和英特尔公司等。  
  
TorchServe 是由以色列公司 Oligo 的研究团队发现的，可导致越权服务器访问并在易受攻击的实例上实现远程代码执行后果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icWQibEYlpowrLXOAn4fHtC9rhxY1tofgI1qQdxwuJQb24ib7cazN7TQ7jA/640?wx_fmt=png "")  
  
  
**ShellTorch 漏洞简介**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icW8sAHjKornNsoibcicfDPrHdvPia4WmlocMR9YagV9G1zqibhhicklAQ2RdA/640?wx_fmt=png "")  
  
  
  
位于 TorchServe 中的三个漏洞被统称为 ShellTorch，影响 TorchServe 0.2.0至0.8.1版本。  
  
第一个漏洞是一个未认证管理接口API配置不当漏洞，可导致web面板默认绑定到IP地址0.0.0.0而不是本地主机，从而使其暴露到外部请求。由于该接口缺少认证，因此可导致任何用户获得不受限制的访问权限，从而使他们能够从外部地址上传恶意模型。  
  
第二个漏洞的编号是CVE-2023-43654，为远程服务器端请求伪造 (SSRF) 漏洞。如将其利用到漏洞链中，则可导致远程代码执行后果。虽然TorchServe API 对于从远程URL提取模型的配置文件具有一个域名允许清单逻辑，但所有域名默认全被接受，因此导致SSRF漏洞。这种情况可导致攻击者上传恶意模型，在目标服务器上启动时触发任意代码执行。  
  
第三个漏洞的编号是CVE-2022-1471，是可导致远程代码执行的Java反序列化漏洞。由于SnakeYAML库中存在不安全的反序列化问题，因此攻击者可上传具有恶意YAML文件的模型，触发远程代码执行。值得注意的是，Oligo 公司并未发现该SnakeYAML漏洞，而是将其用于利用链中。  
  
研究人员提醒称，如攻击者组合利用以上漏洞，则可轻松攻陷运行易受攻击 TorchServe 版本的系统。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icWQibEYlpowrLXOAn4fHtC9rhxY1tofgI1qQdxwuJQb24ib7cazN7TQ7jA/640?wx_fmt=png "")  
  
  
**漏洞修复**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icW8sAHjKornNsoibcicfDPrHdvPia4WmlocMR9YagV9G1zqibhhicklAQ2RdA/640?wx_fmt=png "")  
  
  
  
Oligo 公司表示分析师扫描web中易受攻击的部署后发现了数万个IP地址目前易受 ShellTorch 攻击，其中一些地址属于跨国大型企业。  
  
Oligo 公司解释称，“攻击者通过在 PyTorch 服务器上执行代码后可攻陷组织机构的网络，它们可将其作为初始立足点，之后横向移动到基础设施，以发动更具影响力的攻击，尤其是在没有合适的限制条件或标准控制的情况下更是如此。”  
  
要修复这些漏洞，用户应升级至于2023年8月28日发布的TorchServ 0.8.2版本。该更新向用户提示了SSRF漏洞，因此有效地解决了CVE-2023-43654带来的风险。之后，在congif.properties 文件中将management_address 设置为http://127.0.0.1:8081，正确配置管理面板。它可导致TorchServe 绑定到本地主题而非在服务器上配置的所有IP地址。最后，确保服务器仅从可信域名中提取模型，这就需要更新confiig.properties 文件中的allowed_urls。  
  
Amazon 公司还发布了关于CVE-2023-43654的安全通告，为在EC2、EKS或ECS中使用Deep Learning Containers (DLC)的客户提供缓解指南。  
  
Oligo 公司也发布了一款免费的检查工具，供管理员查看其实例是否易受 ShellTorch 攻击。  
  
Meta 公司回应称，建议开发人员使用TorchServe版本。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[微软AI研究员不慎泄露38TB 数据，内含密钥、密码和内部消息等](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517693&idx=1&sn=fb8dc494552143cd9a12960a1dc2e5f7&chksm=ea94b497dde33d81e6b6c776f96e7d41c2ba27376d68ee3179498f9a436a3f0418163ad6bb22&scene=21#wechat_redirect)  
  
  
[Meta 发布开源且可商用的 AI 模型 LIama 2](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517101&idx=2&sn=fed66598a1136b56ea3a7e3d25e4ce37&chksm=ea94b2c7dde33bd14a85c964ab99e4ebd1f3f5d81d7d12251e6fdae6be1845dbf3426bb2ad1b&scene=21#wechat_redirect)  
  
  
[AI管道的十大常见风险](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516856&idx=1&sn=81f685d276e19ea0e93ba9befbeb2dfe&chksm=ea94b3d2dde33ac4d753bda8abbce6b86997d62265916f67628d168d35da0e817753118cd775&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/shelltorch-flaws-expose-ai-servers-to-code-execution-attacks/  
  
  
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
  
