#  通用0day挖掘思路   
 迪哥讲事   2024-03-25 21:23  
  
**No.0**  
  
**前言**  
  
  
一直以来都想写一篇挖通用漏洞的文章，但是因为种种原因（懒得很），但是总不能一直不写吧，因为每天都在挖洞，每天都会有新的不同的思路，自己也很努力的在学php、java基础，想为以后学代码审计做准备，但是在此之前，还是想给大家一些不会代码审计怎么挖掘通用漏洞的思路，每挖到一个漏洞都要看看这个漏洞是不是通用的，养成良好的习惯。我之前也不会挖通用漏洞，但是有一天就是开窍了一样，或者就是运气好吧。  
  
**No.1**  
  
**0day和通用漏洞的理解**  
  
  
0day，就是未被公开的安全漏洞，被称为零日漏洞，可能已被攻击者发现并使用了一个小时、一个月，甚至更长时间。  
  
姑且来说0day就像CVE一样，是一个之前未被发现，直到被人提交到CVE平台后才被公开，被大众所知。CVE一般来说比较容易成功提交，审核时间在1周到一个月，可能我提交的漏洞都是比较简单的，也不是什么代码审计审出来的，所以通常审核时间在一周就给我发编号了。像CMS、CVE计划中、开源软件、系统的漏洞。用寻找到的目标，来发现漏洞。  
  
CVE提交流程：  
  
1、提交地址  
  
https://cveform.mitre.org/  
  
选择CVE ID进行申请  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfFmgVIhA61QcibRtrtnibFoGkpIXqwdy84vcevah2m6FibjiaqjJQp66oQw/640?wx_fmt=png&from=appmsg "")  
  
  
2、页面填写规范  
  
在Email处，填写接收CVE官方的通知邮件的收件箱  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAf4pfC3qI8umuHicDNPQXIIdEb0WJ5Cxbd7erhePuSryR9JexLWoicaNFQ/640?wx_fmt=png&from=appmsg "")  
  
  
选择提交的CVE数量，同时确认此漏洞没有被CVE发布编号进行  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfiaAEftLLhcnKrxXicyibj48V3iajyjxafvRKSMsU9kU5ZoQopIJNQicw7Zg/640?wx_fmt=png&from=appmsg "")  
  
  
选择所提交漏洞的类型  
  
一般我都是交反射存储型XSS，因为这种简单的漏洞或者资产少的漏洞，CNVD是不收的，所以我一般是能交CNVD就交CNVD，CNVD不要的，我再交到CVE上来，混一个编号  
  
  
首先是选择一个漏洞类型，这个大家只要翻译一下，看着选就好了  
  
因为没有那么多的漏洞类型，所以大家选择差不多的就可以了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfHOj91fgLicd9hqMen6w96HGHuW84Wz1fASKTtH6qkaqEv3xpMVicw4Cg/640?wx_fmt=png&from=appmsg "")  
  
  
发现漏洞的平台，可以是github，也可以是CMS或者是电商系统那种的官网  
  
产品的名称一定要了解清楚，同时版本号如果实在是不知道就填null  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfVyrduWobmMBtEAsOGEPvpniaGXibMPV0hicjiatIuKpR6kzU9AOWCDFKpA/640?wx_fmt=png&from=appmsg "")  
  
  
厂商可以去发邮件告知，也可以在github的源码评论区中发送告知  
  
漏洞复现的类型是看本地复现还是公网复现的  
  
攻击手段有代码执行其他等等，一般选择代码执行就可以了  
  
受影响的组件，比如是评论区呀，收货地址呀，这些都要通过翻译进行填写上去  
  
POC这个不用多说，怎么复现的，怎么写  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfWO34q3iaUC8FXCgZfqSicsa205Pm6BP8GXO8wicASf8m3Up11ov43dcww/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞描述一下有什么危害，代号写一下  
  
最后两个可以填一样的，就是github上发布跟此漏洞相关的就行  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAf4hFqfW0ib6ySXtlm3SG4I0Kppkpo9sHyibZRqfQIJGh0mNWnQsys8CbQ/640?wx_fmt=png&from=appmsg "")  
  
  
最后就是看清楚验证码进行提交即可，过几分钟CVE就发邮件给你，告知分配下去了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfOCbZEMcYvfMFIqgFtxFd9OAUCgkM3JVAVsoLXxMghYzw9dDt7HA3eQ/640?wx_fmt=png&from=appmsg "")  
  
  
通用漏洞，就是通用型，POC通通都适用，类似于0day的概念。  
  
CNVD平台的收录条件很严，收录标准更是苛刻形容  
  
通用型漏洞得十个网络案例以上  
  
事件型漏洞必须是三大运营商（移动、联通、电信）的高危漏洞，或者党政机关、重要行业单位、科研院所、重要企事业单位（如：中央国有大型企业、部委直属事业单位等）的高危事件型漏洞才会颁发原创漏洞证书。  
  
  
**No.2**  
  
**通用漏洞的挖掘方法**  
  
  
通用是你自己挖到的从未没公开过或者有细节的漏洞叫通用  
  
我觉得挖掘通用漏洞是从点到面，我都是发现了某个漏洞点，后面发现不对劲，感觉这站点是CMS，或者还有其他网站在用这种感觉。不管是渗透测试还是代码审计还说，都是唯手熟尔。没有捷径可走，都是遇到的问题多了，下次就能记住，并且能成功发掘出来，我觉得技术这种东西就是比昨天多一点，比明天少一点。  
  
真的想挖掘通用漏洞的方法还是要有针对性的目标和漏洞挖掘，首先来给本章定一个基调，那就是挖掘一个通用的漏洞。  
  
首先看这样一个页面，判断为邮箱登录账号密码，本来目的是测试有没有sql注入，万能密码绕过，再不济看看网站有没有弱口令爆破的，没成想测出来反射型的XSS漏洞，而后又因为一些比较明显的特征发现了通用性  
  
已知此处有漏洞，该如何发现是通用漏洞？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfTs5mXKfkqAYEdjU8OpIxTDjWKI8CnDmebpPtoibP5McqMfaH4KV6JSg/640?wx_fmt=png&from=appmsg "")  
  
三个点：  
  
1、logo，也被称为icon  
  
2、模板，也被称为标识符  
  
3、特定的title  
  
看一下这个页面，可以直接插入payload测试出是否会包含在html页面中  
  
```
locks@qq.com<script>alert('XSS')</script>
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfeTgzULHTdYCvLcIJPBwUJlUNVgLicJkecPDAS8gaEOLZ2yzu6meZahg/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到在XSS中的单引号转义，这种情况我一般直接去掉单引号  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfAKe8Xlaa37V1CO3aDnBD7JrNDWXupvXUa28tSAZ9fV6b7AQ5KhNC7w/640?wx_fmt=png&from=appmsg "")  
  
  
发现还是被上面参数包裹，现在就是要闭合上面的，跳出来进行执行语句  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfV2tgXvFBxCrBK383rGpWMtlFD7DpZ4eKoHfela6hdibAyCSIkzqCicCQ/640?wx_fmt=png&from=appmsg "")  
  
  
locks未弹窗  
```
"<zzz><script>alert(locks)</script>
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfImtpSibAJNPP1IjxUbUZdd7D8mMpXSR1Wiaiau0ibIXX4Nu72TPMaISoUg/640?wx_fmt=png&from=appmsg "")  
  
  
数字却弹窗了  
  
```
"<zzz><script>alert(666)</script>
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAftUD6jS8LTlLp7weE7IcxNM9HL2WoKibIfoT2nqCiaHzrK7jJyibwicKQhw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfibGmuaibBYbVNMykH2FA7piahAC5O86vt5MpV8Xw2ApDd3fBe2NP5E2rQ/640?wx_fmt=png&from=appmsg "")  
  
  
用document.cookie弹出cookie  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfxibNfXibUkeym94OaRUhElfu9XMDic0ZEiaFCFqOsKU9zic3t2Snmz5tOaQ/640?wx_fmt=png&from=appmsg "")  
  
  
分析为什么字符不弹，数字却弹窗了  
```
<input type="text" name="email" value="testing@example.com\" <zzz=""><script>alert(666)</script>" class="input-block-level" placeholder="E-Mail address" /&gt;
```  
  
将payload插入到元素的value属性中。这种情况下，脚本并不会执行，因为value属性的值不会被解释为JavaScript代码。  
  
使用  
```
`<script>alert(locks)</script>
```  
  
，但浏览器不会将其视为有效的JavaScript代码，因为它被包含在value属性中  
  
使用  
```
<script>alert(666)</script>`，
```  
  
，同样，浏览器也不会将其视为有效的JavaScript代码，因为它也被包含在value属性中。然而，在某些情况下，浏览器可能会尝试进行一些自动的HTML修复，而且这种行为可能因浏览器而异。这就是为什么它可能触发了警报框的原因。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfGAF9g75Fl1Jo5Y9xf2wibj6rgz0zGytcR89licPhOBMgOOFXYYfM8ajQ/640?wx_fmt=png&from=appmsg "")  
  
  
**No.3**  
  
**通用漏洞案例研究**  
  
  
实际通用漏洞案例分析  
  
看见这个聊天框发送，一开始是想测这个发送到页面是否存在XSS或者SQL注入的  
  
经过测试发现没有  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfvBcuGobeeCwBHGems1tw8jJqN7mdmIcADv78ibsfQtY3tkXxqjIJ4Kw/640?wx_fmt=png&from=appmsg "")  
  
  
后面转移思路，发现这个可以捕获到IP地址  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAf43DROyaQpMq55UHaumicXVgcJ0ib1CmhvF6iauVVkm4AnPP2D9CVgTdkA/640?wx_fmt=png&from=appmsg "")  
  
  
成功打出XSS，SQL注入不存在  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z3L9iccnsUsIIwUkhF2xwAfPDLRwa2s6TZtnBsqAbUibiaiawHSFWib1HkbzbuTTNB62eX5lRjXHjFL5g/640?wx_fmt=png&from=appmsg "")  
  
发现漏洞后，进主页看logo和title用hunter或者fofa查就行  
  
  
**No.4**  
  
**挖掘通用漏洞结论**  
  
  
简单来说就是黑盒测 然后用logo title 关键字上hunter等工具查是不是通用的就行  
  
可以再进一步搜索这个公司乃至这个系统历史漏洞。  
  
参考链接：  
  
https://mp.weixin.qq.com/s/1YZ3NqT3vRjnys8pTcESgQ  
  
  
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
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
