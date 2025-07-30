#  多个Kubernetes 高危漏洞可用于在 Windows 端点执行远程攻击   
THN  代码卫士   2023-09-14 18:10  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Kubernetes 中存在三个相互关联的高危漏洞，可用于以提升权限在集群的Windows 端点上实现远程代码执行。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRP1hraRFAHbebPicXLI53gAL0GODwaYSfMqeA0n1PYYknTqzfiaqZicuT1HpJ0Xmu6ZodgqXCJqkctg/640?wx_fmt=gif "")  
  
  
这些漏洞是CVE-2023-3676、CVE-2023-3893和CVE-2023-3955，CVSS评分为8.8，影响所有具有Windows 节点的K8s 环境。经 Akamai 公司在2023年7月13日报送后，修复方案已在2023年8月23日发布。  
  
Akamai 公司的研究员 Tomer Peled 发布文章表示，“该漏洞可导致具有系统权限的人员在K8s 集群的所有 Windows 端点上执行远程代码。要利用该漏洞，攻击者需要在集群上应用恶意 YAML 文件。”  
  
AWS、谷歌Cloud 以及微软 Azure 为这些漏洞发布安全公告，这些漏洞影响如下 Kubelet 版本：  
  
- kubelet < v1.28.1  
  
- kubelet < v1.27.5  
  
- kubelet < v1.26.8  
  
- kubelet < v1.25.13 以及  
  
- kubelet < v1.24.17  
  
  
  
简言之，CVE-2023-3676可使具有“应用”权限的攻击者注入任意代码，从而以系统权限在远程 Windows 机器上执行。Peled 提到，“CVE-2023-3676要求低权限，因此攻击门槛不高，攻击者所需的不过是访问一个节点并应用权限。”  
  
该漏洞和CVE-2023-3955的根因在于缺乏输入清洁，因此可导致特殊构造的路径字符串解析为 PowerShell 命令参数，从而导致命令执行。  
  
CVE-2023-3893 与 Container Storage Interface (CSI) 代理中的提权相关，可导致恶意人员获得节点的管理员权限。K8s 安全平台 ARMO 上个月表示，“这些漏洞中的重现主题是Windows 特定的Kubelet 端口缺乏输入清洁剂。具体而言，软件在处理 Pod 定义时未能正确验证或清洁用户输入，从而导致恶意人员通过环境变量构造 pod 并托管路径，而在处理路径时可导致非预期行为如提权等。”  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2023中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=1&sn=8154b433ae2be87ccbae15bc0fb09a00&chksm=ea94b543dde33c55c168c44e830d62b03e9b34ca072871d10156273a3f282cab7ccc42b9b430&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[OpenSSF发布4份开源软件安全指南，涉及使用、开发、漏洞报告和包管理等环节](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514034&idx=1&sn=51f02a3110acce0dbd53196876ef1fad&chksm=ea9486d8dde30fce4995e5734ad507e889b4c58c0d3ff8d777f66119f2d5fb3f1c7d0e064726&scene=21#wechat_redirect)  
  
  
[OpenSSF 发布NPM供应链最佳实践指南](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513843&idx=1&sn=33ab8f63db7079bb063295c6999a15e7&chksm=ea948799dde30e8f12d06337f2ee171ace7577dbd213e3c53699c56aeff4b34a18f02704fbcd&scene=21#wechat_redirect)  
  
  
[OpenSSF 获1000万美元投资，提升开源软件和软件供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508355&idx=2&sn=1f9e988dfdfb46799df3ef7cbc8a2760&chksm=ea9490e9dde319ffc5de5ca46d9fb8bb7df34958a285d13a62de51c1dcd25fb68230c09fef0d&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/09/alert-new-kubernetes-vulnerabilities.html  
  
  
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
  
