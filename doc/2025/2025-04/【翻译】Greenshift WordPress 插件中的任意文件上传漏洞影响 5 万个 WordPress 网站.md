#  【翻译】Greenshift WordPress 插件中的任意文件上传漏洞影响 5 万个 WordPress 网站   
wordfence  安全视安   2025-04-23 14:24  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF7iaogicBCeR6fiaLVzkBpPsibO0YrNp1MBTHac6pBgiaFwE8M8tManstxbPsC1trQ9OLzgV5mqgicybsqw/640?wx_fmt=png&from=appmsg "")  
  
  
2025年4月14日，我们收到了Greenshift插件  
中存在的任意文件上传漏洞的提交。Greenshift是一款WordPress插件，活跃安装量超过5万次。经过身份验证的攻击者（拥有订阅者及以上权限）可以利用此漏洞将任意文件上传到易受攻击的站点，并实现远程代码执行，这通常用于完全接管站点。  
  
感谢  
mikemyers  
通过 Wordfence  
漏洞赏金计划 (Bug Bounty Program)  
发现并负责任地报告此漏洞。该漏洞在发布五天后就被报告给了我们的计划。这位研究人员因此次发现获得了 1,229.00 美元的赏金。我们的使命是通过深度防御来保护 WordPress，因此我们投资高质量的漏洞研究，并通过我们的漏洞赏金计划与高水平的研究人员合作。我们致力于通过检测和预防漏洞来增强 WordPress 生态系统的安全性，这是多层安全方法的关键要素。  
  
所有  
Wordfence Premium  
、  
Wordfence Care  
和  
Wordfence Response  
客户以及使用我们插件免费版本的客户都受到 Wordfence 防火墙内置的恶意文件上传保护，以防止针对此漏洞的任何攻击。  
  
我们于 2025 年 4 月 14 日向 GreenShift 团队提供了完整的披露细节。开发人员于第二天，即 2025 年 4 月 15 日发布了第一个补丁，并于 2025 年 4 月 17 日发布了第二个补丁。我们要赞扬 GreenShift 团队的迅速反应和及时修补。  
  
**此漏洞充分体现了 Wordfence漏洞赏金计划对 WordPress 生态系统的积极影响。该漏洞于 2025 年 4 月 10 日出现，仅四天后就被报告给我们的漏洞赏金计划，经过分类处理后发送给开发人员，并于第二天修复，这为攻击者在网站所有者获得保护之前发现并利用此漏洞创造了极其微小的机会。特别感谢研究员mikemyers如此迅速地发现此漏洞，也感谢 GreenShift 如此迅速地修复了此漏洞。**  
  
我们敦促用户尽快使用 Greenshift 的最新修补版本（本文发布时的版本为 11.4.6）更新其网站。  
## Wordfence Intelligence 的漏洞摘要  
  
**描述：**  
  
Greenshift 11.4 – 11.4.5 – 经过身份验证（订阅者+）任意文件上传  
  
**受影响的插件：**  
 Greenshift – 动画和页面构建器块  
  
**插件 Slug：**  
  
greenshift-animation-and-page-builder-blocks  
  
**受影响的版本：**  
 11.4 – 11.4.5  
  
**CVE ID：**  
  
CVE-2025-3616  
  
**CVSS 评分：**  
 8.8（高）  
  
**CVSS 向量：**  
  
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  
  
**研究人员：**  
  
mikemyers  
  
**完全修补版本：**  
 11.4.6  
  
**赏金：**  
 1,229.00 美元  
  
由于 11.4 至 11.4.5 版本中 gspb_make_proxy_api_request() 函数缺少文件类型验证，WordPress 的 Greenshift 动画和页面构建器模块插件存在任意文件上传漏洞。这使得经过身份验证的攻击者（拥有订阅者及以上权限）能够向受影响网站的服务器上传任意文件，从而可能造成远程代码执行。11.4.5 版本已充分修复任意文件上传漏洞，但 11.4.6 版本添加了功能检查，以有效阻止未经授权的受限文件上传。  
## 技术分析  
  
Greenshift 是一个 WordPress 插件，它包含许多 WordPress 块编辑器元素，以及多个可自定义的设置和动画。  
  
检查代码发现该插件使用该  
gspb_make_proxy_api_request()  
函数来处理多个 API 请求。  
  
在插件的11.4版本中，供应商引入了文件上传功能，以及之前已有的其他功能。其操作包含以下代码片段：  
```
```  
  
虽然该函数包含 MIME 类型检查，但这还不够，而且不幸的是，在易受攻击的版本中没有包含任何文件类型或扩展名检查。文件的 MIME 类型很容易被伪装成图像文件。这意味着不仅可以上传图像、PDF 和文本文件，还可以上传带有  
.php  
扩展名的文件。该文件会被上传到 WordPress 的上传文件夹，该文件夹默认为公开访问。这使得拥有经过身份验证的访问权限（例如订阅者）的攻击者可以上传任意恶意 PHP 代码，然后访问该文件以触发服务器上的远程代码执行。  
  
与所有任意文件上传漏洞一样，这可能通过使用 webshell 和其他技术导致网站完全被攻陷。  
  
还值得一提的是，一些块暴露了 REST 随机数，当这些类型的块在易受攻击的站点上使用时，这可能使攻击者能够在未经身份验证的情况下利用此漏洞。  
## 披露时间表  
  
**2025 年 4 月 14 日**  
– 我们通过 Wordfence 漏洞赏金计划收到了 Greenshift 中任意文件上传漏洞的提交。2025  
  
**年 4 月 14 日**  
– 我们验证了报告并确认了概念验证漏洞。2025  
  
**年 4 月 14 日**  
– 我们将完整的披露细节发送给了供应商。供应商确认了报告并开始着手修复。2025  
  
**年 4 月 15 日**  
– 发布了插件的部分修补版本 11.4.5。2025  
  
**年 4 月 17 日**  
– 发布了插件的完整修补版本 11.4.6。  
## 结论  
  
在本篇博文中，我们详细介绍了  
Greenshift 插件  
中一个影响 11.4 至 11.4.5 版本的任意文件上传漏洞。该漏洞允许经过身份验证且拥有订阅者级别或更高权限的威胁参与者在服务器上执行恶意代码，在某些情况下，未经身份验证的威胁参与者也可以执行恶意代码。该插件的 11.4.6 版本已完全修复该漏洞。  
  
考虑到此漏洞的严重性，我们鼓励 WordPress 用户尽快验证其网站是否已更新到 Greenshift 的最新修补版本。  
  
所有 Wordfence 用户（包括运行  
Wordfence Premium  
、  
Wordfence Care  
和  
Wordfence Response  
的用户以及运行 Wordfence 免费版的网站）都受到全面保护，免受此漏洞的侵害。  
  
  
原文地址：  
https://www.wordfence.com/blog/2025/04/50000-wordpress-sites-affected-by-arbitrary-file-upload-vulnerability-in-greenshift-wordpress-plugin/  
  
# 免费网络安全资料PDF大合集  
  
**链接：https://pan.quark.cn/s/41b02efa09e6**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF5xOsytm8HnicSzbLxpd8ftiayzOUDHO0ThH4c5u1nj0xL95BmAMgOfsc1d426a81FwEcpMYiazDBNRQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
