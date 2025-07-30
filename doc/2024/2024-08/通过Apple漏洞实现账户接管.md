#  通过Apple漏洞实现账户接管   
原创 白帽子左一  白帽子左一   2024-08-07 12:02  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**前言**  
  
大家好，今天我将与你们分享一个漏洞挖掘过程，该漏洞会导致任何查看我的Apple账户的个人资料的用户，其账户被接管，当然，该漏洞早已提交并得到修复。  
  
**正文**  
  
我在 Apple 上搜索了几天，尝试使用多种工具进行子域名枚举，以获取所有可能的子域名。我能够获得大约 20K 个活动子域名，这是一个很大的列表，但我有很多时间，所以我继续逐一测试它们。  
  
我发现了一个有趣的东西，它是一个社区子域名，你可以用你的 iCloud 账户登录它，所以我在想，如果我在那里获得一个账户接管权，我就能接管 iCloud 账户。  
  
我搜索了好几天，终于找到了一个有趣的端点，它是一个位置端点，我可以在个人资料上添加位置信息，但我无法手动执行此操作。  
  
位置地址是通过输入地址自动添加的，它是从苹果地图中选择这个自动位置，下面是它的一个例子  
  
maps.apple.com/?&q=Test&address=Test  
  
它将我重定向到谷歌地图并输入 Test/Test  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGdeYyf1ZbVozf0Cq5yGvkLs7icYWqxpEfNRJoJMiavxrbDdXgPg1C8AeS3NZpw1b3GRpf8tEoCCz7A/640?wx_fmt=png&from=appmsg "")  
  
这是一件有趣的事情，接着我去添加一个谷歌地图中未列出的新地图，然后使用我找到的端点分享它：  
  
maps.apple.com/?&q=Test&address=Test  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGdeYyf1ZbVozf0Cq5yGvkLMaSibGfrjR7o1SUuX2BOJ4VjQDzqHOHnzX1BulqDmJicNmElWEQHpv5w/640?wx_fmt=png&from=appmsg "")  
  
在添加地图后，我在谷歌地名中放置了一个盲 xss payload，然后发送它，它被接受了，但肯定不会在谷歌中执行  
  
但在我将其与maps.apple.com链接后，因为苹果地图从谷歌地图获取了地图，我能够制作最终的有效载荷并将其添加到我的个人资料位置中，并且它位于（Lieu，法语：地方），即您在屏幕下方看到的位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGdeYyf1ZbVozf0Cq5yGvkLSg0eA6ibeLvn79Vmnv8JErkzUXX2tmMcP0RNeCibx8BeFnoyfs4TQMyQ/640?wx_fmt=jpeg&from=appmsg "")  
  
最终，它被执行了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSGdeYyf1ZbVozf0Cq5yGvkLlMO5oH7iacfmYG07x0geJw1C2qzQRtCLr2rm8YxNQG3tZWI6oBJNupw/640?wx_fmt=jpeg&from=appmsg "")  
  
然后我在 Map 中添加了一个盲 Xss Payload，并打开了新账户，尝试查看包含盲 Xss 的个人资料，然后它被触发了，我在我的 Xss Hunter 账户中获得了账户的 cookie，这使我能够直接接管该账户。  
  
以上内容由白帽子左一翻译并整理。  
原文：  
https://hamzadzworm.medium.com/how-i-got-a-bug-that-leads-to-takeover-accounts-of-any-user-who-view-my-profile-913c8704f6cd  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前言漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，只需25，即可加入，如不满意，72 小时内可在 App 内无条件自助退款。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE3xxjQrLXjiaAWoqibdM1AFZ0uePzzUOG049bSjeEkbft1NfIm833fQ0ibIbW5IoE2ftnWoS3YxRPLg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
