#  开源工具 PrivateBin 修复XSS 漏洞   
Emma Woollacott  代码卫士   2022-04-19 18:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J1TfC1KiaJk7cf6QAwOOQaqjLu1g8iatCpoGrC63KrUg28O1ia5ecf7VSTR9LjBicqbGyTavmo2Mzd4Eg/640?wx_fmt=png "")  
  
PrivateBin 是热门 ZeroBin 的一个分叉，它是一款在线工具，用于存储信息并通过 256位 AES 在浏览器中加密/解密，即服务器“不知晓所粘贴数据”。这款开源工具中存在一个跨站点脚本 (XSS) 漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J1TfC1KiaJk7cf6QAwOOQaqjJr0R3PWpichEeruLhlJ1ibosp4nC0PFo5t2tLy8phVfyibica0j298bH8g/640?wx_fmt=png "")  
  
  
  
Nethemba 公司的安全研究员Ian Budd 发现该XSS 漏洞可导致恶意 JavaScript 代码嵌入 SVG 镜像文件中，之后被附加到粘贴中。  
  
如果用户通过特殊构造的 SVG 附件打开粘贴并和预览镜像交互，而该实例未受到正确的内容安全策略保护，则攻击者可执行代码。Budd 指出，“创建payload 并发送给其它用户很容易。但问题是用户将不得不在新的页签中打开该镜像预览，成功执行后，将导致用户可访问运行在用一个域上其它应用的不受保护的 cookie、本地存储数据、会话存储数据等，其中可能包括认证令牌。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX7CVwP3ChLicpEFMN4RzYLOyAUpxON3YANQDBL3bxBaPOKBz3p58HcCZR6BsV5zQpvdgLictCLNkLHw/640?wx_fmt=png "")  
  
**攻击概率低**  
  
  
Budd 表示，攻击成功的概率相对较低，因为它明确要求进行用户交互，且潜在利用代码仅可在新页签中运行。他表示，“PrivateBin 在创建内容安全策略方面做得很好，从而缓解了该漏洞。如果用户使用的浏览器不遵守该内容安全策略或编辑默认内容安全策略的站点，则会触发该漏洞。”  
  
然而，Nethemba 在实例列表中发现，多个实例或者不遵守内容安全策略或者更改至不安全的设置，其中两个实例启用了附件，因此易受攻击。尽管如此，目前尚未发现该漏洞遭活跃利用的报告。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vnT4hbaLoX7CVwP3ChLicpEFMN4RzYLOyAUpxON3YANQDBL3bxBaPOKBz3p58HcCZR6BsV5zQpvdgLictCLNkLHw/640?wx_fmt=png "")  
  
**漏洞披露**  
  
  
2月22日，研究员上报该缺陷；4月9日，漏洞详情公开。  
  
Budd 指出，“漏洞披露过程很简单，我们和运行系列测试的 Simon Rupf 进行沟通，并了解了他的研究成果。我们讨论了缓解措施，PrivateBin 让我们了解了每一个步骤。”  
  
PrivateBin 指出，已经修复预览中的这个漏洞，并鼓励服务器管理员升级至已修复版本，或确保实例的内容安全策略设置正确。同时它还扩展了目录清单工具，纳入检查机制。  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2021中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505380&idx=1&sn=01d2f5af200abc6bb20411ee8f17b6b5&chksm=ea94e48edde36d98f20b66aecf9f359e49226b411872bcea527fcca0a5de018f407415313800&scene=21#wechat_redirect)  
  
  
[开源网站内容管理系统Micorweber存在XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511095&idx=3&sn=adbaf85a2b52fa28271d8650cc9f5e3a&chksm=ea949d5ddde3144b570cbe1d529895ae54cb07f1f1db4b3f8eb26622905360a3b6aa62e5c2b5&scene=21#wechat_redirect)  
  
  
[速修复！开源编辑器CKEditor 中存在两个严重XSS漏洞，影响Drupal 和其它下游应用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509349&idx=1&sn=e82d6a91637f37f30c81e3f1eb8d0fc7&chksm=ea94940fdde31d19c09a3f3f28cf387d5ad8a172d0cbbc393095582563b9a438989db51367a0&scene=21#wechat_redirect)  
[开源内容管理系统Drupal 修复信息泄露和 XSS 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247495080&idx=2&sn=62a0ad9712974813d2dd852f3c2f83f7&chksm=ea94dcc2dde355d4c612ac1a4bb1435e3744d89b3de131ddeaa82e6312ab1f8305618b88c74e&scene=21#wechat_redirect)  
  
  
[热门开源 WYSIWYG 编辑器 TinyMCE 被指存在严重的 XSS 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494613&idx=2&sn=7ab8578d79d645b6a0a4f6bd030c65fa&chksm=ea94dabfdde353a90b7dafcdd50b0ec0675f1bf39bfd8c09482159a72ad61c9f388cffb0a27b&scene=21#wechat_redirect)  
  
  
[开源 CMS Drupal 修复 XSS 和开放重定向漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493187&idx=2&sn=8ac5c62090bbee44166832232e092223&chksm=ea94d729dde35e3f802678198384d8ca46194058f56e4fd6e4590507ce5892ffdf214acf9046&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/xss-vulnerability-in-open-source-tool-privatebin-patched  
  
  
题图：Pixabay License  
  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMQjfQ8ZhaOGYOwiaOkCe6UVnwG4PcibqI6sJ3rojqp5qaJa0wA2lxYb0VKwria7pHqS9rJwSPSykjMsA/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
