#  记一次EDU漏洞挖掘   
ddwGeGe  迪哥讲事   2024-02-27 22:10  
  
**前言**  
  
以下提及的漏洞都提交到edusrc平台进行修复，大佬勿喷。  
  
**信息收集**  
  
在外网进行系统测试，发现大部分都需要统一身份认证，瞅瞅该目标单位的统一身份认证要求，可以看到初始密码的规则是 xxxx@SFZ后六位，用户名是学号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBruWib0Dy81TRdgiccKCbco7iceV0IFyhkCaCLeiaA2lwzyEicqXgmUvA80Tg/640?wx_fmt=png&from=appmsg "")  
  
利用相关语法 site:xxx.edu.cn "学号|SFZ|密码"等，未找到有效信息，想到用类似 "助学金、奖学金、补贴"等关键词，发现一处敏感信息泄露，及时保存下来，没准就成为后面突破的一个节点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBrIDLkPyicr5iaKLGaYHkTAxssk8KLUaoZHduLRibc93z2HDH83A2yBej9A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBribOoB8d7pVLRXScpMpoLm7fVUDASd2chzsvNluChnWP6fs8YJ7MxcDw/640?wx_fmt=png&from=appmsg "")  
  
**信息整合**  
  
从统一身份认证登录的条件来看，我们可得出以下几点  
  
1、用户是学号2、SFZ后六位3、已知部分用户的SFZ后五位  
  
学号可以利用相关语法找到 site:xxx.edu.cn "姓名"等等，举例  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBrgicQ5hibXp79giaibAfYxHGBsM9d3f8brTTOa0aIl6kAe83NcTnGibx3d4A/640?wx_fmt=png&from=appmsg "")  
  
由于SFZ倒数第六位+第五位是生日的日，那最高不超过31，而且倒数第五位已经确定了，可以构造如下（默认密码的规则是 xxxx+@+SFZ后六位，以下是举例 非真实）  
  
xxxx@020101xxxx@120101xxxx@220101  
  
最终在尝试第二个的时候，成功以默认密码登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBrLnicicIRM6x5abtpYibGqaWwKSLto0mZh2dvSWuj3HkCXvIsTnlxjuX9A/640?wx_fmt=png&from=appmsg "")  
  
**突破**  
  
可以看到需要更改密码，但前提是需要输入完整的SFZ号码，将当前的信息继续整合，已经知道某个用户的SFZ前七位+后六位，中间的数字是打码，其实不难猜出，只剩下年份的后三位(1999的999) + 月份(01 且不超过12)，其余的就交给Burp了，肯定有小伙伴问，年份如何确定了，毕竟还是很多的。其实是根据用户当前的年段（如大三），再结合自身，进行反推，大概是在 199x，最终成功修改密码。  
  
锁定年份 199X(X是数字)、爆破月份  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBrvF12ibJ1a7PCsnjl24jM2p6baCbA4HnUkpcZUqTohf3Z7mo2EIakW3Q/640?wx_fmt=png&from=appmsg "")  
  
继续X+1，爆破月份  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBr1o9kVia2dYVPGcZ5zbkkiaN7DyxVkIfCtdbrLSpmdxfDchBiaZ3LsL2Kw/640?wx_fmt=png&from=appmsg "")  
  
由于统一身份认证和VPN绑定，成功拿到VPN权限，可通过多个内网段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBrRqOK0pLuw360Jq5icbibLmKg58qMdmYV6VI8ibwkB6hmKvEyopBAl1GRQ/640?wx_fmt=png&from=appmsg "")  
  
拿到统一身份认证平台，就可以跳转到多个系统进行测试（不在后续深入 点到为止）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4iatf66KNgW5rbBWE41DSBrrwN4QicmHmvbr9O61DMl2TAeibibpyyIfK7rOpremFVrJCCMHKzxcVp7g/640?wx_fmt=png&from=appmsg "")  
  
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
  
  
