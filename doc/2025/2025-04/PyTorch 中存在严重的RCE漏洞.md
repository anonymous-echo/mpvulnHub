#  PyTorch 中存在严重的RCE漏洞   
Ddos  代码卫士   2025-04-21 09:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**最有名的深度学习框架 PyTorch 中存在一个严重的远程命令执行 (RCE) 漏洞CVE-2025-32434，CVSS v4 评分9.3，影响 PyTorch ≤ 2.5.1，位于 torch.load() 函数中。具体而言，当通过参数 weights_only=True 时可触发。**  
  
PyTorch 由 Meta AI 开发，目前由 Linux 基金会管理，是应用程序的“发电站”，用于构建智能计算机视觉系统、了解自然语言的细微差别。PyTorch 免费开源，拥有用户友好的 Python 界面，是全球研究人员和开发人员的心头好。  
  
该漏洞由研究员 Ji’an Zhou发现，他提到，“所有人都知道 weights_only=False 是不安全的，所以会用 weights_only=True来缓解该安全问题。但就在现在我证明了即使使用 weights_only=True，RCE仍可实现。”  
  
如恶意人员通过构造一个模型文件利用该漏洞，则可在目标机器上执行任意命令，就有可能导致数据泄露、系统攻陷，甚至在云托管的AI环境中横向移动。再加上很多开发人员将 weights_only=True 作为防护措施，该利用可能会在部署了安全实践的环境中获得成功。  
  
好在 PyTortch 团队已迅速修复该严重漏洞。已修复版本 2.6.0已发布。因此，用户应立即采取的最重要的步骤就是将 PyTorch 版本升级至2.6.0或更高版本。  
  
具体而言，用户可通过如下步骤进行更新：  
  
使用 pip：  
```
pip install torch torchvision torchaudio --upgrade
```  
  
使用conda:  
```
conda update pytorch torchvision torchaudio -c pytorch
```  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[PyTorch 严重漏洞可导致AI敏感数据被盗](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519716&idx=2&sn=df8e16d464e733a183fadfc8e360cc10&scene=21#wechat_redirect)  
  
  
[PyTorch 披露恶意依赖链攻陷事件](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515167&idx=1&sn=24c07a386819db63dc889fa9bfe7b382&scene=21#wechat_redirect)  
  
  
[速修复！Erlang/OTP SSH 中存在严重的预认证 RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522791&idx=1&sn=b726626262a08aef9a0f09bf3d3332e0&scene=21#wechat_redirect)  
  
  
[Ingress NGINX 控制器中存在严重漏洞可导致RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522579&idx=2&sn=df3fca1672e67390925fdec6d6a9c0b7&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://securityonline.info/critical-pytorch-vulnerability-cve-2025-32434-allows-remote-code-executio  
n/  
  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
