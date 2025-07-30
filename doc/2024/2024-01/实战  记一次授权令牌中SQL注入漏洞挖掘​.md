#  实战 | 记一次授权令牌中SQL注入漏洞挖掘​   
 迪哥讲事   2024-01-23 23:43  
  
# 记一次授权令牌中SQL注入漏洞挖掘  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicSoAyXYHib8YzDsmib6IonBzo6MXbRmUL1WibOATT5JtfaHgCLUDlRvs15C11vog40ibulZdqswbD49g/640?wx_fmt=png "")  
  
今天在这篇文章中，我将分享一篇关于使用授权Header（Authorization Headers token）的 SQL 注入的文章。  
  
Authorization Headers token的一些介绍，  
  
=> 授权令牌由服务器生成和签名，用于通过唯一令牌验证用户。  
  
=> 登录成功后，服务器会发送一个授权令牌，Web 开发者通常会将其存储在浏览器的本地存储或会话存储中。  
  
=> 现代网站使用 JWT（JSON Web 令牌）进行用户授权。这并不意味着每个授权令牌都是 JWT。这取决于网站使用的后端和框架，  
# 渗透过程  
  
我是一个季节性的 Bug 赏金猎人。我尝试通过google dorks搜索一些私人的bug赏金计划，并随机选择了一个程序进行狩猎。  
  
当我从主要目标开始时，我没有做像子域枚举或任何 Dorking 这样的基本侦察。  
  
对我来说，这是平凡的一天。我刚刚启动了 BurpSuite并打开了目标站点。根据公司政策，我不能透露目标。  
  
在 Wappalyzer 插件的帮助下，我注意到目标在 PHP 上运行。  
  
对我来说，PHP 本质上是易受攻击的。作为一名 Web 开发人员，我有丰富的 PHP 构建网站和修复漏洞的经验。  
  
在攻击目标时，我会在侦察过程的初始阶段对目录进行暴力破解并检查 robots.txt 文件。  
  
我使用 Dirsearch 查找隐藏目录，但没有运气。除了管理页面，我没有得到任何可疑的东西。  
  
我尝试通过访问 target/admin/ 打开管理页面  
  
但是没有成功，它会引发错误403 Forbidden  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicSoAyXYHib8YzDsmib6IonBzft3daXfZo2KM749ujNxjFjKvSPVNPneibQWIMT69vlIZGbygKlog2cQ/640?wx_fmt=png "")  
  
我并没有太快放弃，再次尝试使用Dirsearch 在管理页面内进行 Fuzz。这次活动页面收到了200状态码。  
  
没有任何延迟，我已经打开了页面 www.target.com/admin/events/  
  
我注意到这个页面是一个普通的登录页面，它有两种登录方式，一种用于用户，另一种用于超级管理员  
# 发现SQL注入  
  
正如我所说，登录页面有两个链接，一个用于用户，另一个用于管理员，我选择了第一个，并将我重定向到  
```
www.target.com/admin/events/?classic_login=true
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicSoAyXYHib8YzDsmib6IonBzCmpESJ0lR9PYCLE3EmfhGg9zuB9SicGr1EJV6Cu50LsZsEn12u5o5dw/640?wx_fmt=png "")  
  
它弹出用户名和密码，我开始提供错误的凭据并观察服务器的响应，测试了一段时间后，我提供的用户名和密码为1'  
  
幸运的是，它出现了SQL报错。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicSoAyXYHib8YzDsmib6IonBzicZicLo8cLDMHJayE4xkF4eVzIED8RiaZuD4XevRZbMicOLcUtIUxOLwEg/640?wx_fmt=png "")  
  
我试图重现它，但它不起作用，并且登录弹出窗口完全消失了。  
  
即使刷新页面后，错误消息也会显示在那里，因为我认为这可能是一些后端错误。  
  
我查看了 Burp代理历史记录，发现没有发送常规的 POST 表单数据或 JSON 数据。  
  
我有一段时间空白，后来在隐身模式下打开了链接，然后出现了用于登录的弹出窗口。再次观察请求和响应。  
  
后来，我注意到带有令牌的 Header Value Authorization。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicSoAyXYHib8YzDsmib6IonBz5wFWOoOic3rvYm2aaHx3MCwqWWhGKSSEFKtpfrYUhnaPPKVictWhdUgg/640?wx_fmt=png "")  
  
作为一名 Web 开发人员，我知道授权令牌是如何工作的，并且我对 PHP、MERN 堆栈和一些 Django 框架有很好的了解。我可以很容易地猜到开发人员使用的标记化  
```
Authorization: Basic Base64Values
```  
  
您可能经常在 Web 应用程序中看到此 Header。  
  
专业提示：在后端，在大多数情况下，Bearer 被忽略，开发人员将令牌与发行的令牌匹配。  
  
如果那是 JWT，那么开发人员通常会对其进行解码，而不是验证这就是不正确的访问控制、帐户接管发生的地方。  
  
我已将请求发送到Repeater，选择了令牌并使用 Burp 解码器对其进行解码，因为我通过长度和性质猜测了加密类型。它不是 JWT，而是 1':1' 的 base64 值  
  
我很快想起了 Sqlmap 工具，捕获了整个请求，并将其保存到一个文本文件中。  
  
并尝试运行sqlmap，但问题出现在base64编码。虽然 sqlmap 支持 base64 编码，但场景是值之间有一个冒号 :。  
  
因为应用程序的行为如下  
  
它接受用户名和密码，并使用 base64 对值进行编码，其中用：分隔  
  
虽然我擅长手动 SQL 注入利用，但有一种 base64 编码的实时模式，并在转发器中应用有效负载。为此，我试图找到目标的列数。  
  
并将用户名和密码的payload：  
```
1' Order By 1 — -:1' Order By 1 — -
```  
  
Base64后 Auth的payload如下。  
```
Authorization: Basic MScgT3JkZXIgQnkgMS0tIC06MScgT3JkZXIgQnkgMS0tIC0=
```  
  
base64 编码发送，无 SQL 错误，显示常规未授权错误  
  
试图增加这些列，但抛出错误。我知道只有一列并尝试注入联合语句。  
  
注入payload：  
```
1' Union Select 1 — -:1' Union Select 1 — -
```  
  
编码后  
```
Authorization: Basic MScgVW5pb24gU2VsZWN0IDEtLSAtOjEnIFVuaW9uIFNlbGVjdCAxLS0gLQ==
```  
  
我已成功登录管理面板并能够修改内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicSoAyXYHib8YzDsmib6IonBzChBkHic0Zs9WEmoUcvGTiaVvblH37wfKmvxvRT3g7xdITAzg5gtFxVRg/640?wx_fmt=png "")  
  
下面是没有打码的POC演示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicSoAyXYHib8YzDsmib6IonBzqOT70KRkOJxFhPxRaw0DXoo8icspHGEv3hFmg874nHSibsfdm9Nc8NeQ/640?wx_fmt=png "")  
  
****  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
