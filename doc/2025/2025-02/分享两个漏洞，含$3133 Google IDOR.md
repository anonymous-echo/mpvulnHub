#  分享两个漏洞，含$3133 Google IDOR   
原创 玲珑安全  芳华绝代安全团队   2025-02-13 06:22  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0KnkqaXglicqFIVS5OgBzr7tkvR1Awes6RbHS27L144QMPEl5FPgBicWPWMt4xzB8DcuBTyRgNxOz2nRiag/640?wx_fmt=png "")  
  
关注公众号，阅读优质好文。  
  
漏洞1  
  
在对某目标系统进行安全测试时，发现其运行着两个独立的域名——一个用于司机用户，一个用于开发者/企业用户。表面上看，这两个域名各自独立管理账户，但测试表明它们在处理电子邮件变更时存在严重的逻辑漏洞。  
  
  
正文  
目标系统存在两个子域：  
- example.com（司机门户）  
  
- dev.example.com（开发者门户）  
  
在司机门户中，电子邮件更改功能缺乏验证，无需确认邮件即可完成更改。  
  
  
漏洞步骤  
1、创建两个账户  
  
User1（司机账户）：使用 driver@gmail.com 在 example.com 上注册。  
  
User2（开发者账户）：使用 developer@gmail.com 在 dev.example.com 上注册。  
  
由于测试需要，两个账户均未启用 2FA。  
  
  
2、请求密码重置链接  
  
在 example.com 上，针对 driver@gmail.com 请求一个密码重置链接。  
  
  
3、更改司机账户的邮箱地址  
  
登录 example.com 司机账户。在账户设置中，将 driver@gmail.com 更改为 developer@gmail.com（即开发者账户的邮箱）。变更立即生效，系统未发送任何确认邮件或进行任何验证。  
  
  
4、利用旧密码重置链接进行账户接管  
  
使用之前获取的密码重置链接，针对之前的邮箱执行密码重置。由于该链接未失效，重置成功，攻击者可直接设置新密码。  
  
  
5、开发者账户失效  
  
尝试在 dev.example.com 使用 developer@gmail.com 登录开发者账户时，发现该账户已无法访问。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0Knkq1TIia2o0JkibB8Z0CWw7ZYPskX4ibpHR5FYtclnQNmpTc0cFUxJuG82V4fHibqsL8UsnoxTticmZ5lGQ/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞成因  
1、邮箱变更无需用户确认，攻击者可随意更改账户邮箱。  
  
2、邮箱更改后，已有的重置链接仍然有效，允许攻击者在邮箱变更后继续利用旧链接重置密码。  
  
3、系统在尝试强制邮箱唯一性时，可能会错误地删除或禁用原账户。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0Knkq1TIia2o0JkibB8Z0CWw7ZYPcwJpEYWzaU1f2RzjIwhIiauhohBhSIthHb3jf2QTia4Bux62RL5UC7aQ/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞2  
目标URL：REDACTED.google.com。  
  
  
为了深入了解其功能，我查阅了 developer.google.com 上的相关文档，并开始进行测试。  
  
  
在测试过程中，我发现了一个 XSS 漏洞，但它触发的域名是经过正确沙盒化的 *.googleusercontent.com，这符合 Google 的安全策略，因此不被视为有效漏洞。  
  
  
接着，我偶然发现了一个功能，该功能允许用户从 Google Drive 导入文件，并且能够正常工作。当我使用 Burp Suite 拦截该请求时，我注意到请求中使用了 docId 作为参数，用于标识用户选择的 Google Drive 文件 ID：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0Knkq1TIia2o0JkibB8Z0CWw7ZYPkm9wnWTc2sbiaBQaonq8MFj7RtEjnAg86ibYkBNPhYuBeW5su4wHf0Kg/640?wx_fmt=png&from=appmsg "")  
  
  
我注意到 docId 出现在 Google Drive 文件的 URL 中，大致如下：```
https://drive.google.com/open?id=18TrUTt3SI3fmKNut8SREDACTED
```  
  
该请求会返回一个 JSON 响应，其中包含一个 token 和我们选择的文件的 标题。我将其发送到 Repeater 并开始尝试修改请求。  
  
  
那么，如果我修改 docId，使用其他用户的私有文件 ID，会发生什么？  
  
  
在Drive中，我们可以通过更改权限设置，使 Google Drive 文件变为私有。如果其他用户想要访问该文件，他们必须向文件所有者请求访问权限。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0Knkq1TIia2o0JkibB8Z0CWw7ZYPJILianNWhYxLw4dIGNFOYiaKYssd442wOtRm1vTMlkGg94iclNtLgIrCg/640?wx_fmt=png&from=appmsg "")  
  
  
于是，我在另一个账户上创建了一个**私有文件**  
，然后将其文件 ID 填入 **docId**  
 参数中。  
  
服务器返回了 **200 响应**  
，并附带了 **token 和文件名**  
，即使请求者**本不应该**  
拥有该私有文件的访问权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0Knkq1TIia2o0JkibB8Z0CWw7ZYPRnFU3icrOwNDATRqxZzPTrSXDcOZK5yYh16QxicfyuTag8MHeAye8fsg/640?wx_fmt=png&from=appmsg "")  
  
说实话，我并没有指望能拿到赏金，毕竟这个漏洞相对简单。要利用它，我必须事先知道文件 ID，而这个 ID 本身是一个较长的随机令牌。此外，我最多只能获取文件名和文件类型，无法直接访问文件内容。  
  
三周后，我的报告被评估为 $3,133.70。我想，他们可能在内部发现了更严重的问题。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/sz_mmbiz_png/1AoMVy0Knkq1TIia2o0JkibB8Z0CWw7ZYPBAialWkbyiaWTyVhhh0ZXucjKujWpIq1dNnatO1T4r3bm3ib8ic7iaGCAlA/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**培训咨询v**  
  
bc52013 或  linglongsec****  
  
****  
****  
**SRC漏洞挖掘培训**  
  
****  
玲珑安全第一期SRC漏洞挖掘培训  
  
  
玲珑安全第二期SRC漏洞挖掘培训  
  
  
玲珑安全第三期SRC漏洞挖掘培训  
  
  
玲珑安全第四期SRC漏洞挖掘培训  
  
  
玲珑安全第五期SRC漏洞挖掘培训  
  
  
****  
**往期漏洞分享**  
  
  
[通过监控调试模式实现价值$15k的RCE](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247500709&idx=1&sn=dae16f5afd1d6144250a8b8a6dff65e8&scene=21#wechat_redirect)  
  
  
  
[【万字详析】HubSpot 账户接管全流程](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247500698&idx=1&sn=042ce70d5163f34267ca9e2f7be485be&scene=21#wechat_redirect)  
  
  
  
[某教学平台支付逻辑漏洞](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247500670&idx=1&sn=12cd707e76414099093fc21cf65e7a9e&scene=21#wechat_redirect)  
  
  
  
[通过模拟功能实现提权（Bugcrowd）](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247500656&idx=1&sn=8cd3d32e7a74ea7a64d7e7932730f768&scene=21#wechat_redirect)  
  
  
  
[JS Review+GraphQL滥用实现管理面板访问](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247500644&idx=1&sn=63921757c037e412027b192cf9e83038&scene=21#wechat_redirect)  
  
  
  
[绕过电子邮件确认实现预账户接管](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247500627&idx=1&sn=ae5186aac454cc70ff0c842856bf986c&scene=21#wechat_redirect)  
  
  
  
[价值$3000的Google Slides IDOR漏洞](https://mp.weixin.qq.com/s?__biz=MzI4NTYwMzc5OQ==&mid=2247500618&idx=1&sn=4c4a94d321a4f44795de9c7ec943e774&scene=21#wechat_redirect)  
  
  
  
通过有趣的逻辑漏洞实现账户接管  
  
  
一个漏洞让我年入数百万  
  
  
  
**玲珑安全B站公开课**  
  
https://space.bilibili.com/602205041  
  
  
  
**玲珑安全QQ群**  
  
191400300  
  
  
