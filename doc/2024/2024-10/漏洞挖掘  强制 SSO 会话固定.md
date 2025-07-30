#  漏洞挖掘 | 强制 SSO 会话固定   
原创 白帽子左一  白帽子左一   2024-10-02 12:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
在最近的一个项目中，我遇到了一个有趣的小问题，该问题允许通过固定会话标识符并强制受害者的浏览器启动单点登录 (SSO) 流程的第一步来实现一键式帐户接管。由于缺乏反 CSRF 令牌验证，因此可能存在此漏洞。  
## 登录页面  
  
登录页面展示了“使用SSO登录”功能：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHcichL2TSYVYvTsoU8jWNh1icYqPADf7aamBV0cMashH2ZiawT6CC7BEU0PXoBh54lYsiatyyOX3MG4Q/640?wx_fmt=png&from=appmsg "null")  
  
## 研究 SSO 流程  
  
在研究 SSO 流程后，我发现了以下步骤顺序：  
  
  
1.**单击按钮启动 SSO 流程：** 向 /idp/auth/mid-oidc?req=[UNIQUE_ID]&redirect_uri=[REDIRECT_URI] 发出**GET**请求  
  
2.**SSO 服务提供商流程** 在服务提供商域上发出多个请求，类似于登录 Google，其中请求被发送到 google.com。如果用户之前已登录，则会自动执行操作。  
  
3.**点击回调 URL** 服务提供商端授权后，会向回调 URL 发出请求： **GET** /idp/callback?code=[STUFF]&state=[STUFF]。 **然而，这不是返回会话令牌的最后一步，还需要一个额外的步骤。**  
  
4.**发出会话令牌** 请求获取会话令牌。 **获取 /idp/approval?req=[UNIQUE_ID]** UNIQUE_ID值与第一步中的值相同。这意味着，如果您知道这个值，您可以点击此方法并获得会话。由于不存在csrf 保护，因此可以执行会话固定。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHcichL2TSYVYvTsoU8jWNh1B7cTqWUojMribyQUyrdSdE8ibibb6BhNHRDuRHnibkU7LVP0hwaaHn3TLw/640?wx_fmt=png&from=appmsg "null")  
  
## 漏洞利用场景  
  
“攻击者”在其计算机上打开 URL 并提取“使用 SSO 登录”按钮链接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHcichL2TSYVYvTsoU8jWNh1icMYa3N3lhme5NEeMJADnVXo0qWOMMicWBOGoZc8nd5kBBH6Fjr0SjIQ/640?wx_fmt=png&from=appmsg "null")  
  
攻击者从复制的链接中提取“req”参数并启动漏洞利用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHcichL2TSYVYvTsoU8jWNh1jfw3ucq0txJRZUg0P0WOia9msIJhRibavcnnNSpOVa78pMnPYjJZVXbQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHcichL2TSYVYvTsoU8jWNh1X8IpTZ25h2GSzr9jWYU7GnSaLp5GIibczh6dx7T7F1kicNYUpwQNH4kQ/640?wx_fmt=png&from=appmsg "null")  
  
然后，攻击者将包含“req”参数的链接发送给“受害者”。  
  
在浏览器中打开链接后，“受害者”遇到一条错误消息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHcichL2TSYVYvTsoU8jWNh1cX5kApntQz7NHtrwXROLic6IXVFb8WicR69LA7P7EXgHZiaLv60CLkjRQ/640?wx_fmt=png&from=appmsg "null")  
## 该漏洞是如何发挥作用的？  
  
攻击者执行的恶意脚本利用10个线程向**/idp/approval?req={req}发出多个请求。**  
  
最初，服务器对这些请求的响应是**500**错误。但是，当受害者启动 SSO 流时，但在处理对“approval”URL 的请求之前，对上述端点的所有后续请求都会返回**带有会话令牌的有效链接。**  
  
利用该漏洞，“攻击者”获取会话 URL 并可以完成登录流程，有效地以“受害者”身份登录：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHcichL2TSYVYvTsoU8jWNh1akziayqoKeOCD8pPmj0wfbxpFKJob1nzvchFX3ax7hZb926MF5WSjibA/640?wx_fmt=png&from=appmsg "null")  
  
**通过直接访问返回的 URL，攻击者完成登录流程并以“受害者”身份登录。**  
## 修复/防御措施  
  
问题修复可以通过以下方式完成：  
  
  
1.实施CSRF 保护。  
  
2.在 SSO 流程的每个步骤中验证会话标识符以防止固定。  
  
3.在 /idp/approval 端点上应用速率限制，以防止对会话令牌的快速和未经授权的请求。  
  
  
以上内容由白帽子左一翻译并整理。原文：https://infosecwriteups.com/forced-sso-session-fixation-5d3b457b79cb  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前言漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，只需25，即可加入，如不满意，72 小时内可在 App 内无条件自助退款。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
