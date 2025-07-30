#  【漏洞实例】某咖啡站点通过IDOR接管6k美元的账户   
 EnhancerSec   2024-07-06 18:01  
  
前言  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKVibeL72YzLH79T4AjdRH13DzX1avCNqbSeU0Xb1nicv59X6oLLh7kDFEvYM8xzc2FNaTyUeuPNejw/640?wx_fmt=png "")  
  
声明：本文仅供学习参考使用，如若造成其他不良影响，均与本公众号无关！  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
  
在浏览某咖啡站点时，我注意到一个页面加载了来自第三方网站的内容。让我们称此网站为example.com  
，以免披露。当我在这个网站上做一些研究时，我在  
example.com/starbucks  
目录中看到了card.starbucks.com.sg  
上的相同登录页面，此时我有两种可能性。  
  
      
1.  
  
此应用程序可以是一个制作和测试card.starbucks.com.sg  
当前开发的环境。  
  
      
2.  
  
或者它可能被用作旧的测试环境，并且处于空闲状态。  
  
这两种可能性都增加了这里出现错误的概率，但主要问题是，我不知道我在这里发现的错误是否会影响生产环境。为了理解这一点，我在  
card.starbucks.com.sg  
上创建了一个用户帐户，并尝试使用此帐户登录  
example.com/starbucks  
。我能够使用我刚刚创建的帐户成功登录。两个应用程序似乎都使用相同的身份验证机制。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESWGpOxmUAa968uVx2MBYv2mBUyjibDP3e42M2wg2FgWHcRx5AF5xVFBg/640?wx_fmt=png&from=appmsg "")  
  
  
从这一点开始，我浏览了  
example.com/starbucks  
，并发现了一个生产应用程序中不存在的端点。该端点收到的  
POST  
数据如下。  
  
    email=hacker@hacker.com  
  
当我在这里的电子邮件参数中写下我想接管的帐户的电子邮件地址并发送请求时，我在我的个人资料页面上看到了属于该电子邮件地址的帐户的部分信息。我还无法完全接管帐户，并且由于此应用程序中生成的  
CSRF  
令牌无效，我的密码更改请求没有成功。  
  
为了解决这个问题，我将  
PHPSESSID cookie  
值从  
example.com/starbucks  
复制到  
card.starbucks.com.sg  
我能够看到生产环境中属于受害者的所有信息，这里生成的有效  
CSRF  
令牌允许我更改密码，并且我能够完全接管一个我知道其电子邮件地址的帐户。  
### 影响  
  
除了查看属于用户的所有个人信息并完全接管帐户外，如果用户帐户中有加载的信用，这些信用可以通过移动应用程序在星巴克商店消费。  
我在  
example.com  
上遇到了另外两个测试环境。我们称它们为example.com/starbucks2  
和example.com/starbucks3  
。使用我在  
card.starbucks.com.sg  
的帐户，我无法登录任何测试环境。  
example.com/starbucks2  
不允许我创建新帐户，所以我在  
example.com/starbucks3  
上尝试了运气，并成功创建了一个新帐户。  
  
我认为应用程序  
example.com/starbucks2  
和  
example.com/starbucks3  
正在使用测试表，因此生产用户无法登录这些应用程序。  
  
使用我在  
example.com/starbucks3  
上创建的帐户，我能够登录  
example.com/starbucks2  
，但不能登录  
card.starbucks.com.sg  
。然而，我从  
example.com/starbucks2  
复制的  
PHPSESSID  
在  
card.starbucks.com.sg  
上是有效的，我可以使用该帐户。考虑到所有场景，我在这里创建了一个链，如下所示：  
  
1.  
  
在  
example.com/starbucks3  
上用受害者的电子邮件地址创建一个虚拟帐户。（添加到测试用户表中。）  
  
2.  
  
在  
example.com/starbucks2  
上，通过同一端点将该电子邮件的帐户与您自己的帐户相关联。（将  
PHPSESSID  
与  
testusers  
表中的电子邮件相关联。）  
  
3.  
  
将  
PHPSESSID  
复制到  
card.starbucks.com.sg  
并接管。（接管生产用户表中同一电子邮件地址的真实帐户。）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESwFhoYUM3HxlXTiclRVlyroRcMrHBVAicdAGFX53FewJgdrfnGSmqjxlQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
关注不迷路  
‍  
‍  
‍  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLC22Wa3B8Lb3AkPOhcfqzORXBdEyiajPX2GJd1patuUzlhgOZia7X11licPvQvJviakdHTDt0NWxjicOw/640?wx_fmt=png&from=appmsg "")  
  
关注本微信公众号，点击下方微信群，扫码加好友，备注“微信群”，拉你进交流群，后面会在群里抽奖！群里会不定期给大家分享国内外高危严重小技巧  
‍  
‍  
‍  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESIntAQKdnibCOF6NXl5ziaqupHVgRP1jh7Opk6N3XIbskCL0LykGQlj0g/640?wx_fmt=png&from=appmsg "")  
  
  
  
**【网安智汇】知识星球介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ES6UAWJficFjEVKMkcXkeK80uK2sI2PhFfrrEEm9OBX7HJlrltgHRzgGA/640?wx_fmt=png&from=appmsg "")  
  
创建知识星球的初衷就是为了分享学习资料，同时也是为了清理电脑和网盘的缓存，知识星球目前已经分享了安全运营、SRC漏洞实例、电子书籍、攻防红蓝紫方资料。可以自行扫码加入。  
‍  
‍  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESGORMj3bw9OicpNGxZTdQ9p3O2MQu69rHQjPQpLmiayaXklchDTdB0ibeQ/640?wx_fmt=jpeg&from=appmsg "")  
  
或者在微信公众号后台点击微信群，添加微信，备注来意（微信群），加入交流群参与后续的抽奖活动免费进入知识星球。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLC22Wa3B8Lb3AkPOhcfqzOgPVvZS2m3yFq0p9LSPmyFxlyEYVJQibItTiaWNiakooek4s6dV5tZCDEQ/640?wx_fmt=png&from=appmsg "")  
  
  
**END**  
  
  
  
