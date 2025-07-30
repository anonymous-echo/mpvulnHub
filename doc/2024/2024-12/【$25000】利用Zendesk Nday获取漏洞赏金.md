#  【$25000】利用Zendesk Nday获取漏洞赏金   
白帽子左一  白帽子左一   2024-12-16 04:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
在这篇博客中，我将分享如何在 Zendesk 客户的默认配置中发现模板注入漏洞。  
### 发现契机  
  
有一天，我看到了 Rojan Rijal dai 分享的一篇文章，他演示了如何在 Zendesk 和 Salesforce 等支持门户中利用动态占位符来窃取敏感数据。  
  
**参考文章链接**: https://www.ophionsecurity.com/post/abusing-dynamic-placeholders-in-helpdesks-to-extract-user-data  
  
在这篇博客中，他解释了如何使用 Zendesk 的占位符/模板创建工单。当工单被创建时，这些模板会被渲染，从而实现数据外泄。  
  
Zendesk 提供了一系列占位符模板，例如：  
  
{{ticket.ccs[0].name}}  
  
{{ticket.ccs[0].phone}}{{ticket.ccs[0].custom_fields}}{{ticket.ccs[0].notes}}  
  
更多占位符参考: https://support.zendesk.com/hc/en-us/articles/4408886858138-Zendesk-Support-placeholders-reference  
### 漏洞影响  
  
攻击者可以创建包含恶意模板的支持工单，并将受害者用户添加为 CC（抄送）对象。  
  
当模板被渲染时，攻击者可以窃取 CC 用户的电话、姓名、内部备注、定制字段等信息。  
  
**例如：** 窃取 CC 用户的定制字段和用户备注可能使攻击者访问内部数据，包括用户地址、账单信息，甚至个人身份信息（PII）。  
  
这是一个极具吸引力的攻击向量，我也想在私人漏洞奖励项目中测试它。  
### 关键点  
  
Rojan dai 在文章中强调了一个关键点：  
  
**此漏洞只能针对自定义支持门户进行利用。**  
  
例如：https://support.gitlab.com/hc/en-us 是一个默认的 Zendesk 门户。  
  
默认的 Zendesk 门户使用 Zendesk 提供的表单 https://support.gitlab.com/hc/en-us/requests/new 来创建工单。  
  
而 https://support.github.com是一个后台使用 Zendesk 的自定义支持门户。  
  
自定义门户是带有自定义表单的网站，其表单数据通过 API 传递到 Zendesk。因此，如果程序使用 /v2/tickets.json API 在后台创建工单，注入便有可能。  
### 开始猎捕漏洞  
  
在尝试在我的大多数项目中测试此漏洞时，我很快意识到，识别这些“自定义表单”是一个挑战，需要大量手动检查。  
  
相反，识别默认的 Zendesk 门户却仅需几分钟。  
  
我所需要做的就是收集目标项目的子域，然后通过 CNAME 解析，我找到了大量默认 Zendesk 门户，例如 target.zendesk.com。  
  
由于原文章中对默认门户的攻击较少探索，我决定从这条路径进行测试。  
### 测试门户  
  
以下是一个普通 Zendesk 门户（默认配置）的示例，其所需字段如下：  
```
email, subject and description
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1UbvlwuiaoxiblmWKPtuPleXmVNHUBZZpMkqUPGa68ficL9PDRRlhsuPeXHZR3vBlS4hw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**我在主题/描述中提交了带有恶意模板的表单。**  
  
在工单创建后，尽管用户输入可以被反映出来，但由于存在数据清理（sanitization），无法实现注入攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1UbvlwuiaoxiblHYXBdA0ImJ2qepG2d0dnREoaYwvagsjzNA7VJzRylDUvaytcDtttjQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**Zendesk正在对主题内容进行清理。**  
  
那么，如果我创建一个没有主题的工单会怎样？仅在描述正文中包含有效负载（payload）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1Ubvlwuiaoxibl5zGSmLc84zspzGeRR9YcwqqWkJFA9Focdnh2VDIF5yl5Orru7DibhYw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
主题字段不能为空！  
这感觉像是刚开始就走到了死胡同。  
  
然而，当我继续检查一些默认的Zendesk门户时，我注意到了一些有趣的现象。  
其中一个项目的Zendesk门户在创建工单时**不需要主题字段**  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1UbvlwuiaoxiblObBuN9ujvuABWFDPmduqSpXU6KsFbSuFXB29XV3xjJw2OOPNNCz5zg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这次我只需要在描述中插入一个恶意模板并提交表单,模板成功被渲染了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1Ubvlwuiaoxibl5cicyDTG1xZNXd2ktHOyANtybWbA5cXr6FDyibyoot7wokkaIkKF7elw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
因此，尽管Zendesk对**原始主题字段（subject field）**进行了清理，但如果创建的工单没有主题，Zendesk会使用描述字段（description body）作为主题。而这种描述 <-> 主题的引用操作缺乏必要的清理。  
  
我们现在有了一个Zendesk中的占位符注入漏洞。  
  
但有一个小问题，这种漏洞仅对那些Zendesk表单中没有主题字段的项目有效，而这样的项目并不多。  
  
鉴于这个漏洞的奇妙之处，我必须绕过这个“**主题**”字段的强制性要求，并能够创建没有主题但在描述中包含有效载荷的工单。  
  
**基于电子邮件的工单创建**  
  
除了通过API或表单创建工单之外，Zendesk还支持基于电子邮件的工单创建。  
  
我们可以发送一封电子邮件到support@target.zendesk.com，电子邮件的内容将被处理为一份支持工单。  
  
我们还可以在电子邮件中添加其他用户为工单的抄送（CC）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1UbvlwuiaoxiblCegQ55peyu3VzJTspMe8xXZYyOIQFQaiaMlQq6nu7GsIMGlkd1JlvSA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
由于我可以在发送电子邮件时控制主题字段和正文字段，因此我向 support@target.zendesk.com 发送了一封没有主题的电子邮件，在电子邮件正文中包含了恶意模板，并将受害者的电子邮件地址添加为抄送（CC）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1Ubvlwuiaoxibl7g55lP1AKLIhSHSicq0icIL1ic2JY0UbOHc21rOK0Cwy9FCQqUFfiaicE5g/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我们收到的邮件回复是什么？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1UbvlwuiaoxiblO9NEdStFCWibG9YccLSXDOT2icSjJJljrGbM3PhqcIWEj4x19w8MEQrQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
一个模板注入漏洞，使我能够通过将受害者信息（如姓名、电话、角色、自定义字段等）添加为抄送（CC）来泄露信息。  
  
**报告**  
  
该漏洞的影响范围取决于具体的程序。  
  
一些程序已经禁用了Zendesk的电子邮件抄送功能，因此无法提取信息。  
  
而一些程序则使用了**静态主题行**，由于没有处理攻击者的输入，因此根本无法进行注入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1UbvlwuiaoxibleqtVHZq4Zn3dy86lT4v0xzSQoRXADHcY2sF5RdhYvgaVyuyxhv0bew/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1Ubvlwuiaoxibl5pLxjQfsvgiajo7X83zuTrbibu4iam0drUNFOpnP1B969MpsX36v3aOkA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
Zendesk 还具有模板抑制/激活规则。  
  
因此，程序确实采取了一些措施，可以对抗这种攻击。  
  
**厂商回应**  
  
该漏洞的处理被视为低到高影响的漏洞，具体取决于我能够泄露的数据信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1UbvlwuiaoxiblJsIfjicpwjp3KqTTITQ9XEDTKgtS6BHpIeX7LoFrb4lDDC8ocqGUgvw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
几乎所有厂商都对这个漏洞都非常积极，并采取了迅速的措施来解决它。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFRtYUDgCSN1UbvlwuiaoxiblAEsISL4rFSq8nWKk4RKIRvNM6EmQaFibsVdLtFZkk443ia69ypFfNfOQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
与此同时，一些厂商要求我将此漏洞报告给Zendesk，并且也从他们那边进行了沟通。该漏洞随后报告给了Zendesk。被评为“中等——业务逻辑漏洞"。  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
