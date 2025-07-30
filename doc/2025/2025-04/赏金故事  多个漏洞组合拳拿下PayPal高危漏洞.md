#  赏金故事 | 多个漏洞组合拳拿下PayPal高危漏洞   
白帽子左一  白帽子左一   2025-04-16 04:00  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
在寻找安全问题时，许多研究者往往会把注意力集中在未公开的资产和隐蔽的端点上，而忽略了一些明显却同样关键的功能点。  
  
如果你将目标当作是第一次接受安全测试的系统，并对每一个环节进行彻底检查，我相信你一定会发现一些新的问题 —— 尤其是当你测试的代码已经持续开发了一段时间。  
  
这是一个高危漏洞的故事，它影响的页面可能是 PayPal 被访问最多的页面之一：登录表单。  
## 初步发现  
  
在分析 PayPal 的主身份验证流程时，我注意到一个 JavaScript 文件中包含了看似是 CSRF 令牌和会话 ID 的内容：  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibibqlZfCudauluH58GIYYPtCOf9ZdfeGfpibh4BtP9WTfKvBibfOODH6vQ/640?wx_fmt=png&from=appmsg "null")  
  
这立即引起了我的注意，因为在有效的 JavaScript 文件中提供任何形式的会话数据，通常会使攻击者能够轻松获取这些数据。  
  
在所谓的跨站点脚本包含（XSSI）攻击中，恶意网页可以使用 HTML <script>  
 标签跨域导入脚本，从而获得文件中包含的任何数据。  
  
果然，经过快速测试确认了 XSSI 漏洞，尽管使用了 JavaScript 混淆器来随机化每个请求的变量名，但有趣的令牌仍然被放置在相对可预测的位置，使得只需稍作努力就能将其提取出来。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibAicbYUFuqKNwicMghJDY9o9Wk8409l0odwBsGH23npH1hgjZkbXvtxaA/640?wx_fmt=png&from=appmsg "null")  
  
然而，一个秘密的价值仅取决于你能用它造成多大的损害。我立即开始探究 _csrf  
 和 _sessionID  
 到底是什么，并且它们是否真的可以在实际攻击中被利用。  
## 深入挖掘  
  
经过无数次尝试将 PayPal 平台上经过身份验证的请求中的常规 CSRF 令牌替换为 _csrf  
 的值，我得出结论，使用这个特定的令牌无法发起经典的跨站请求伪造（CSRF）攻击。同样，不幸的是，受害者的 _sessionID  
 也不足以在 PayPal 网站上冒充他们。  
  
接下来，我回到脆弱的脚本，追踪这些令牌，看看它们到底是用来做什么的。这导致我深入研究了 PayPal 用来防止暴力破解攻击的主要保护机制之一 —— **安全挑战**  
。虽然这个功能在许多地方都有使用，但我将重点关注主要的登录表单。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibjLdQWoibaVKCC19CLrlN4iceRIYvicCZ0vm44eBuAQboiaQsTyWZDEZ8RQ/640?wx_fmt=png&from=appmsg "null")  
  
这个想法非常简单：在几次登录失败后，你需要解决一个 reCAPTCHA 挑战才能继续尝试。然而，具体的实现可能会引起一些关注。  
  
当检测到可能的暴力破解尝试时，下一次认证请求的响应是一个页面，页面上只有一个 Google 验证码。如果用户成功解答验证码，就会发起一个 HTTP POST 请求到 /auth/validatecaptcha  
。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzib1xfmib6QvBQ27NUibxCzOuibQiaoPTJDZ3k6ydswJDBr1ibufRVFbp72WOg/640?wx_fmt=png&from=appmsg "null")  
  
请求体中包含了熟悉的 _csrf  
 和 _sessionID  
，以及另外两个值，我们稍后会提到。  
  
验证码验证请求的响应旨在将用户重新引入认证流程。为此，响应包含了一个自动提交的表单，表单中包含了用户最新登录请求中提供的所有数据，**包括他们的电子邮件和明文密码**  
。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibpIMRyIibSEeeEZDdlAlJjzFcse2d0y47ArZ8eSs564icV0C3YYFbph6Q/640?wx_fmt=png&from=appmsg "null")  
  
我意识到，在正确的时机和一些用户互动下，知道请求中使用的所有令牌就足以获取受害者的 PayPal 凭据。在现实攻击场景中，唯一需要的用户互动就是访问一个由攻击者控制的网页。  
  
于是我回去尝试找出缺失的参数。这比预期的要容易：  
- • jse  
 的值根本没有被验证。  
  
- • recaptcha  
 是 Google 在解决 reCAPTCHA 挑战后提供的令牌。它与特定会话无关，因此任何有效的令牌——例如来自自动解答服务的令牌——都会被接受。  
  
## 利用  
  
将所有这些信息结合起来，我创建了一个概念验证，展示了整个过程，除了集成验证码解答服务。  
  
首先，概念验证会利用最初的 XSSI 漏洞获取一组在受害者会话中有效的令牌。然后，它会使用受害者浏览器中的随机凭据发起一些认证请求，模拟暴力破解尝试，从而触发安全挑战流程。  
  
一旦受害者使用同一浏览器登录 PayPal，缓存的随机凭据将被用户自己的电子邮件和密码替换。最后一步是获取新的 reCAPTCHA 令牌，之后通过服务器端请求 /auth/validatecaptcha  
 端点来获取明文凭据，并在页面上显示。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFZ7LDicZ6KmicTBVuNwUjibzibtu4icGwufpy1alTssqGiaJ8xcBvymBAWyNz57yvicqfHuqR81DCQIA2Jg/640?wx_fmt=png&from=appmsg "null")  
  
我的概念验证代码展示的最终页面包含了您的电子邮件和密码。  
  
后来我发现，使用相同的漏洞流程，在一些未经身份验证的结账页面上也被使用，从而通过相同的技术泄露了明文信用卡数据。  
## 修复和预防建议  
  
/auth/validatecaptcha  
 端点现在需要一个额外的CSRF令牌，防止通过跨站脚本引入的方式泄露。  
  
虽然这一修复正确解决了漏洞，但我认为在设计系统时，遵循信息安全领域最古老且最重要的建议之一就能避免整个问题的发生：**绝不要以明文形式存储密码。**  
  
获取更多精彩内容，尽在Track安全社区~：  
https://bbs.zkaq.cn  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
****  
  
   
  
