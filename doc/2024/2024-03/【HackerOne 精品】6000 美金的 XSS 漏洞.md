#  【HackerOne 精品】6000 美金的 XSS 漏洞   
 迪哥讲事   2024-03-27 20:49  
  
### 【HackerOne 精品】6000 美金的 XSS 漏洞  
> 本系列专注 hackerone 平台披露的高质量报告  
  
  
本篇介绍  yelp.com 价值 6k 美金的XSS漏洞  
  
漏洞标题: **yelp.com XSS ATO (via login keylogger, link Google account)**  
  
漏洞奖励: 6k  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrL4Qk23u2qYxAC5cV01VIc0zjicO2a7AHkrvzhQxbKQqKr0YaDq4trcFdmg63cmwGtvzMlZgVuxiaQ/640?wx_fmt=png "")  
  
### 漏洞概述  
  
yelp.com域下的页面会将 Cookie 字段中的guvo字段内容返回到HTML页面中，在一些特定的域下可以造成XSS漏洞，这种情况通常来说是Self XSS的危害，但可以通过结合其他漏洞并通过一些特殊的Cookie混淆手段将其转变为一个在浏览器持久化的存储型XSS，造成如下危害:1）在漏洞页面 biz.yelp.com/login 通过XSS引入Keylogger.js手段劫持用户在输入框进行输入时的明文密码2）在https://yelp.com/profile_sharing 页面通过伪造绑定google账户的POST请求实现将受害者的账号与攻击者的谷歌账号进行三方绑定，从而劫持用户的账号。  
### 漏洞细节  
  
**1）XSS via "guvo" cookie**Cookie guvo的值在一些页面上反映出来（未经转义），最引人注目的是在www.yelp.com的首页以及https://biz.yelp.com/login的登录页面上。这种未经转义的反映发生在window.ySitRepParams对象和window.yelp.guv属性中。只需在浏览器或Burp中的请求中添加该cookie，并观察响应即可看到这一点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrL4Qk23u2qYxAC5cV01VIcKvtgU5c59k2wx5QROSwdvNtRIX4pW4LalCJx7z3hRzQRRTYP0Yz7dg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrL4Qk23u2qYxAC5cV01VIcwiazRtr8Vd93wUOnZRSwx94YXzJicPDUD5ib5P1PkkOYCXfrQC2ziaRKDA/640?wx_fmt=png "")  
  
  
**2）Setting the "yelpmainpaastacanary" cookie**  
  
在yelp.com上有一个功能，通过在请求中添加查询参数 ?canary=asdf，响应将包含一个HTTP标头：  
```
```  
  
这为我们提供了一种设置cookie "yelpmainpaastacanary" 为任何我们想要的值的方法。但我们需要一种方法来控制 "guvo" cookie。事实证明，我们可以将 "guvo" cookie 嵌入到 "yelpmainpaastacanary" cookie 中。  
  
**3）Broken cookie parsing and cookie smuggeling**  
> 比较有意思的一个点，值得学习。  
  
  
Yelp后端将解析用户的Cookie，通过空格而不是分号来进行分割。通常，浏览器发送的Cookie会用分号分隔，就像  
```
```  
  
正常情况下，这将被解析为两个Cookie a 和 b。但如果我们设置一个Cookie，像这样：  
```
```  
  
这应该被解析为一个名为a的Cookie，其值为"1 b=2"，但Yelp会将其解析为2个Cookie，分别是a和b。我们可以利用这一点，通过向以下请求中添加 guvo cookie 来将其伪装在 yelpmainpaastacanary cookie 内：  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrL4Qk23u2qYxAC5cV01VIcYVFORZhrqP9tDRIiaEpdfbs3oMcZJOEsD0PnCYCERLZicAyCtGHV52DQ/640?wx_fmt=png "")  
  
  
返回的Cookie设置如下  
```
```  
  
这会导致我们的XSS（跨站脚本）有效负载在每次访问www.yelp.com的首页时触发：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrL4Qk23u2qYxAC5cV01VIcd7EILVH3YGxxGGtHquJQ4Pao7h3MibV5pkRmSdaIGga3NZnKAfbnr7Q/640?wx_fmt=png "")  
  
  
作为额外的Buff，我们还可以注入一个Max-Age: 99999999属性，这样我们的Cookie不会过期，它将一直存在于受害者的浏览器中，等待我们的XSS注入发生：  
```
```  
```
```  
  
**4）POC**  
  
**biz.yelp.com/login 上的键盘记录器**  
  
以下JavaScript片段将在用户输入或提交登录表单时泄漏https://biz.yelp.com/login上电子邮件和密码字段的内容。凭据将泄漏到我拥有的calc.sh域：  
```
```  
  
我们创建一个链接，它会将guvo cookie设置为在登录页面触发这个有效负载。请查看这个 CyberChef 以了解如何完成这个操作并轻松进行修改：  
```
```  
  
我们的最终链接如下所示：  
```
```  
  
任何访问该链接的人都将安装我们的键盘记录器。这是一段简短的视频，展示了它的实际运行情况：  
  
  
**通过关联 Google 账号进行账号盗用**  
  
将Google账户链接到Yelp账户的请求是从https://yelp.com/profile_sharing发出的。  
  
Google链接流程中的最终请求是一个POST请求，它被发送到https://www.yelp.dk/google_connect/register，包括CSRF令牌csrftok和一个名为id_token的令牌，该令牌用于将Google账户与Yelp账户关联。  
  
我们可以为自己的Google账户生成一个令牌，然后使用XSS将其链接到受害者的账户。要生成令牌，我们只需将一个Google账户链接到我们自己的Yelp账户，然后在Burp中拦截最终请求即可：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrL4Qk23u2qYxAC5cV01VIcSBJq5Pj2n6KaXUT5g1ELR4ibrdsiaYCq494zuQnC2VrVL55SOhoZ3FvA/640?wx_fmt=png "")  
  
  
现在我们已经获得了用于Google账户doodaduguc@gmail.com的令牌，我们可以为受害者创建一个XSS有效负载。在这段代码中，我们向/profile_sharing发出请求，并使用正则表达式提取CSRF令牌。然后，我们使用我们准备好的id_token向受害者的账户链接我们的Google账户  
```
```  
  
同样，我们使用这个CyberChef配方创建一个链接，以感染受害者：  
```
```  
  
最后的链接是这样的：  
```
```  
  
这个视频展示了攻击过程。左边是受害者，右边是攻击者。受害者已登录他们的Yelp账户。然后，受害者登出，然后在某个时刻访问了我们恶意链接。当受害者以后再次登录他的Yelp账户时，我们的有效负载触发，我们的Google账户doodaduguc@gmail.com与受害者的账户关联。攻击者现在可以使用Google账户登录，并进入受害者的账户。  
  
### 漏洞影响  
  
这种攻击可以被用来完全接管商业账户，并对yelp.com上的普通账户进行接管。由于Cookie不会过期，唯一需要的是受害者在某个时候访问我们的链接，然后当他们以后尝试登录yelp.com时就会被攻击。这个链接可以通过Yelp论坛、评论或私信传播给其他用户，从而轻松地针对其他Yelp用户。  
### 漏洞点评  
  
漏洞点所在的位置处于核心的主站登录页面且可以持久化是高赏金的关键，其他方面比如漏洞利用思路常规但胜在POC链条详细完整，在实际环境有参考价值，国内 SRC 一般来说当存储型或者反射型交就好，如果有社交场景可以参考这个利用思路，尝试将漏洞定级为高危级别。POC所用到的编码器网址如下: https://gchq.github.io/CyberChef/  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
