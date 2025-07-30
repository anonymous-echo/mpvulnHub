> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247497749&idx=1&sn=a8cd9dddb4ac27575e80a843c656aa16

#  如何升级Self-XSS  
 迪哥讲事   2025-06-19 09:30  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！请在授权的站点测试，遵守网络安全法！  
**仅供**  
**学习使用，****如若非法他用，与平台和本文作者无关，需自行负责！**  
  
在本文中，我将讨论我用来攻击反射型跨站脚本 (RXSS) 的技术。这是我之前遇到的全新体验，也让我学到了很多。让我们开始吧。  
  
在我们的目标 target.com 中，有一个“联系我们”表单，其中包含一个上传文件选项，用于提交问题的屏幕截图。像往常一样，我通过输入“mchkltxss”之类的随机字符串来检查反射，结果发现它确实存在反射。我尝试注入 XSS 有效载荷，但由于 HTML 编码问题，它们失败了。  
  
为了更好地查看请求，我切换到了 Burp Suite。我上传的文件名被放入了 filename 变量中。我尝试通过输入随机文本来修改这个变量，看看是否有任何反射，但最初没有任何结果。然后，我尝试输入一个随机扩展名，例如“helloworld.fakeext”。这反映了一条包含以下内容的错误消息：  

```
提供的文件扩展名“helloworld.fakeext”与预期的媒体类型不匹配。
```

  
所以，我们有反思。  
  
我尝试了 HTML 注入，成功了。然而，当我尝试 alert(document.domain) 时，它却失败了，因为该函数检测到 .domain 是一个扩展名。不过 JavaScript 很强大，它提供了一些不需要点的函数。我使用了 alert(document['domain'])，成功了。但到目前为止，它只是 self-XSS，因为文件上传使用了带有 multipart/form-data 编码的 POST 请求。  
  
我尝试了 Burp Suite CSRF PoC，包括多部分 PoC，它们都成功了，但文件上传部分却不行。所以，是时候开始写代码了。我编写了自定义代码来处理通过 POST 请求上传文件的操作，经过一些调整后，它终于成功了。  
  
  
关于他的文章向我展示了做事的方法。  
  
  
这段 js 代码动态地向表单添加隐藏输入，将 base64 编码的数据转换为文件，并将该文件附加到表单。之后，表单会自动提交。现在，我有一个完全可利用的 rXSS 漏洞。  
  
要阅读利用代码，请检查  
csrf-file-upload-poc  
  
它在两项资产中有效且不重复  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMEBKcGQvP8V1FiaY8HcTVuusBuCxBmkqtb55GELoXmuu03dq6wdr28DOmoBbsajpHibTamibuxar0C8Q/640?wx_fmt=png&from=appmsg "")  
  
总而言之，这次经历强调了彻底测试所有输入字段以及探索各种技术来检查反射、rXSS 或 HTML 注入的重要性。它强调了尝试不同方法和工具的价值。保持警惕，持续学习。  
  
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
  
  
  
  
  
  
  
  
