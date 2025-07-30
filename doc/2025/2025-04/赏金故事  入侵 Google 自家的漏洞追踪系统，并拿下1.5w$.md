#  赏金故事 | 入侵 Google 自家的漏洞追踪系统，并拿下1.5w$   
白帽子左一  白帽子左一   2025-04-14 04:01  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
你听说过 Google 的 Issue Tracker 吗？大概没有，除非你是 Google 的员工，或者是最近在使用 Google 工具时提交过漏洞的开发者。我之前也从未听说过，直到有一天我发现我提交的漏洞报告，除了收到常规的邮件通知之外，还会在这个平台上新建一个工单线程来处理。  
  
于是，我立刻开始尝试去攻破它。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibC2qRRIzNjHbbrNHXxMxibrlUGEfcUk80ZaBBiaT7MB556vntJiaQ65VBg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
那么这个网站到底是什么呢？根据官方文档，Issue Tracker（在内部被称为 Buganizer System）是 Google 内部用于在产品开发过程中跟踪漏洞和功能请求的工具。它也对外部公众用户和合作伙伴用户开放，用于在特定项目中与 Google 团队协作。  
  
换句话说，当有人对某个 Google 产品遇到**问题**  
时，这个问题就会被记录进**问题跟踪系统**  
。听起来挺合理，对吧？作为外部用户，我们看到的其实只是冰山一角：只有一小部分预先批准的分类，以及那些 Google 员工明确将外部账号加入的工单，例如**漏洞报告**  
。  
  
但在水面之下，还藏着多少信息呢？  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzib4guiaS4zwCb3srGRD6FlWttmD8lo59MCsB1nuhjmDZ4icE5YwrHmobiaA/640?wx_fmt=png&from=appmsg "null")  
  
  
通过观察最新公开线程所分配的数字 ID，我们可以很容易地估算出这个工具在内部的使用频率。在山景城（Mountain View）的工作时间内，每小时大约会新建 **2000–3000 个问题**  
，而其中只有 **0.1%**  
 是对外公开的。看起来，如果这个系统发生数据泄露，影响将会非常大。那我们来“搞搞它”吧！  
# 尝试一：获取一个 Google 员工账号  
  
我在接触到 Issue Tracker 后，最先注意到的一件事是：你可以通过发送邮件来参与讨论，邮件地址格式如下：  
```
buganizer-system + componentID + issueID@google.com
```  
  
（其中   
componentID  
 是代表类别的数字，  
issueID  
 是你要回复的线程的唯一标识符）  
  
这让我想起了一个最近的发现，叫做 Ticket Trick（票据欺骗），它允许攻击者通过类似的邮件系统渗透进入企业的聊天系统。考虑到这是一个 **@google.com**  
 的邮箱地址，我试着用它注册 Google 的 Slack 团队，结果进入的确认页面看起来非常有戏：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibyrCnB8WBZgtt5Qibk6FhR5iaic6uZnUEE9kCRzLbBPpzoQ1mDrm0TKULA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
可惜，Slack 的确认邮件始终没有收到。  
  
接下来我想到的一个备选方案是，设法搞到一个主邮箱地址为 **@google.com**  
 的 Google 账户，希望这样可以让我在 Buganizer 上拥有更多的权限。不过，正常情况下，外部人员是**不应该**  
能够注册这种账号的：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibT5vgvBc1ichpuAlz3WiaopSGfx1dDKE25btfGR0FsqP3CPN9WSQRI8aw/640?wx_fmt=png&from=appmsg "null")  
  
  
然而，我发现了一个绕过这个限制的方法：如果我用一个假的邮箱地址注册账号，但**不**  
通过邮件中的链接完成确认，那么我就可以**无限制地修改**  
这个账号的邮箱地址。利用这个方法，我把一个新注册的 Google 账号的邮箱更改为了 buganizer-system+123123+67111111@google.com  
。  
  
不久之后，我就在对应的 Issue 页面上收到了这封确认邮件的内容：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibG2us5dKSJbWULS6yzyBWib0VoQhBDugXIc17uJLd1vKRVv59zppoicww/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
太棒了！我点击了确认链接，登录了 Issue Tracker，然后……  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibOAQaBxPibfLR9LNCosslcRORZWEwuribVK9J43nA6oPh2TBf1QOA2foQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我被重定向到了谷歌的企业登录页面。而很遗憾，我的 Google 账号凭据在这里并不起作用，白激动一场。  
  
尽管如此，这个账号在互联网上的其他地方仍然带来了不少额外的权限，比如可以访问   
谷歌内部的叫车系统  
（或许还能免费用？）。因此，这仍然是一个安全隐患，给恶意用户打开了不少“门”。  
  
审核通过时间：**11小时内**  
 | 赏金：**$3,133.7**  
 | 漏洞等级：**P1**  
# 尝试二：获取内部工单的通知  
  
当我熟悉 Issue Tracker 的界面时，另一个引起我注意的功能是“加星”。  
  
“加星”某个问题，意味着你对该问题感兴趣，并希望在有人评论时收到邮件通知。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibNW53jAKw5S7uicRVCjfWjprqHK1I7ugvjuwua9bsffoahXydzBd3QPQ/640?wx_fmt=png&from=appmsg "null")  
  
  
这个功能最让我感兴趣的一点是：当我尝试对**我无权访问的问题**  
使用“加星”操作时，系统竟然**没有返回任何错误**  
。这个接口似乎**完全没有做权限控制**  
。  
  
于是我登录了我的第二个账号，尝试通过修改请求中的 Issue ID，把我主账号的某个漏洞报告加星。随后，我看到了这样一条提示信息，说明操作成功了：  
> 有 1 人关注了该问题。  
  
  
难道就这么简单就能**旁观 Google 的未公开漏洞**  
？我立刻在这个漏洞工单里发了一条评论，看看我的“攻击者账号”是否会收到通知。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibdicUPoNAKRJRHjW5vTM5A5icGibeJQ3t4OiaRuwGQoOPsK4tiaj1XJiaOPog/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
但结果是——我又一次**没有收到任何邮件通知**  
。  
  
出于某个我现在已经记不清的原因，我决定在这个点上再深入测试一下。于是我找了一个**最近的问题 ID**  
，推算出一段范围内的几千个 ID，这些 ID 理应对应数据库中**最新的问题记录**  
。然后，我把这些问题**全部加了星标**  
。  
  
几分钟之内，我的邮箱就变成了这样：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzib2KaC8AHUxosIH9bwgHLRngSVM3icxDQC3TKesCgT1X0QaOf1xwsLibHQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
我打开邮箱的第一反应是：“中大奖了！”  
  
然而，仔细检查后，我发现那些线程里并没有什么特别有趣的内容。显然，我只能偷听到一些与翻译相关的对话，人们在讨论如何用不同的语言传达短语的含义。  
  
我甚至考虑过不报告这个漏洞，等了几个小时，希望能找到办法提升漏洞的严重性。最后，我意识到，Google的安全团队可能会对找到潜在的跳板方法和变种感兴趣，于是我还是将详细信息发了出去。  
  
**审核通过时间**  
: 5小时 | **赏金**  
: $5,000 | **优先级**  
: P0  
# 尝试三: 游戏结束  
  
当你作为外部用户访问 Issue Tracker 时，大部分功能都会被限制，只剩下非常有限的权限。如果你想看到 Google 员工可以做的所有酷事，可以在 JavaScript 文件中查找 API 端点。有些功能完全禁用了，而有些功能则仅仅在界面中被隐藏了。  
  
在设计这个有限版本的系统时，有人非常贴心地保留了一种方法，让我们可以将自己从 CC 列表中移除，防止我们对某个问题失去兴趣或不再希望接收相关的邮件。这可以通过发送如下的 POST 请求来实现：  
```
POST /action/issues/bulk_edit HTTP/1.1{   "issueIds":[      67111111,      67111112   ],   "actions":[      {         "fieldName":"ccs",         "value":"test@example.com",         "actionType":"REMOVE"      }   ]}
```  
  
然而，我注意到这里有一些疏漏，导致了一个巨大的问题：  
1. 1. **不当的访问控制**  
：在尝试执行给定操作之前，系统没有明确检查当前用户是否实际有权限访问 issueIds  
 中指定的问题。  
  
1. 2. **静默失败**  
：如果你提供的邮箱地址当前不在 CC 列表中，端点会返回一条信息，表示该邮箱已成功移除。  
  
1. 3. **响应中包含完整问题详情**  
：如果操作过程中没有发生错误，系统的另一部分会认为用户具有适当的权限。因此，给定问题 ID 的每一个细节都会在 HTTP 响应体中返回。  
  
我现在可以通过替换上述请求中的 issueIds  
 来查看数据库中每个问题的详情。中了！  
  
我仅尝试查看了几个连续的 ID，然后用一个无关的账户进行攻击，确认了这个问题的严重性。  
  
是的，我可以看到关于漏洞报告的详细信息，以及 Buganizer 上托管的其他所有内容。  
  
更糟糕的是，我可以在一个请求中提取多个工单的数据，因此，实时监控所有内部活动可能根本不会触发任何速率限制。  
  
我迅速将漏洞细节发给了 Google，他们的安全团队在一小时后禁用了受影响的端点。响应速度令人印象深刻！  
  
**审核通过时间**  
: 1小时 | **赏金**  
: $7,500 | **优先级**  
: P0  
  
当我最初开始寻找这个信息泄露时，我以为它会是 Google 漏洞中的“圣杯”，因为它泄露了关于所有其他漏洞的信息（例如，HackerOne 对类似漏洞的奖励最低为 $10,000）。  
  
但在发现它后，我迅速意识到，这个漏洞的影响会被最小化，因为所有危险的漏洞在一小时内就会被中和。  
  
我非常满意这笔额外的奖金，并期待在其他 Google 产品中发现更多漏洞。  
  
   
  
获取更多精彩内容，尽在Track安全社区~：  
https://bbs.zkaq.cn  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
  
