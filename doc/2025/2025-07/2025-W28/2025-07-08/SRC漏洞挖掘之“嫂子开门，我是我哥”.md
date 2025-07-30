> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247497828&idx=1&sn=3edecf58ac99722cc6db88b124495ed3

#  SRC漏洞挖掘之“嫂子开门，我是我哥”  
 迪哥讲事   2025-07-08 12:43  
  
**No.0**  
  
**前言**  
  
  
在一次日常的漏洞挖掘过程中，在一个微信小程序中本来毫无头绪的时候，在巧合之下点开了另外一个小程序，结果两个小程序竟存在联系，经过不断测试，挖出水平越权漏洞。  
  
成功达成成就“嫂子开门，我是我哥”  
  
**No.1**  
  
**正文**  
  
  
开局就是这样一个小程序（我们称之为小程序A）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnal0BJB5cZpOwgTVs5rygHISAt0yicu0FDibicr7icuibX19Lz5SDyfhfbdw/640?wx_fmt=png&from=appmsg "")  
  
  
随便输入一个手机号13111111111之后，会显示如下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnu3VxjTBt2VOeF8abyZLcJicYQWv3VxgLAZU5VK3v3QZxtPqpFlrcPQg/640?wx_fmt=png&from=appmsg "")  
  
  
可以知道13111111111这个手机号绑定的用户名、学号以及学校，但是用户名被打码了，抓返回包也是打码数据，这也构不成敏感信息泄露，只能先放在一边。  
  
  
然后我又点开了另一个小程序（小程序B），在小程序B的个人中心处有一个添加学员的功能点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnsz4ictudAHFpNYszph8OFNrx42czOOd2yqsomERpgOOzU9X8AOm4wqg/640?wx_fmt=png&from=appmsg "")  
  
  
有两个方式添加：手机号绑定和学员号绑定  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLns1Xb46oTrHETdbdwWV0qn4rlQkecTInxjLcDZ5m71ddkkkCEcWzt8Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLn5fYHkfsW2owr4rn8dw0wecKxXibbzjh8DxlTetQ242o4pdQzz2vEakQ/640?wx_fmt=png&from=appmsg "")  
  
  
等一下，这个学员号看起来好眼熟啊，会不会是小程序A中的学号呢？试试呗，反正又不会怎么样  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLns2ibjAOvic2JJUg1cgCiaoXVUhUCGvx215UBO7PUTsWv8StSB3qECboXw/640?wx_fmt=png&from=appmsg "")  
  
  
好家伙，这明文信息就这么轻松得到了，事情变得有趣起来了呢。当时我看到了信息名片下面有一个获取验证码，想着会不会有验证码回显导致的任意用户绑定，于是bp抓到如下数据包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnhuZWTQbhXPyNqgAbJQtFgQ3HoMLaEh6IsKPCxYq2vK9FwROWAYSiaTg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLn8c1aelYHGgxX0OPGZmeRQTV8XjBKiae0CHxUGh0qb9rdia6diaBKbXdhQ/640?wx_fmt=png&from=appmsg "")  
  
  
遗憾的是，该发送短信的接口不存在验证码回显，但数据包携带的数据引起了我的注意。“userId”经测试是自己账号的身份id，而“studentId”就是用户名为“家长”的账号的身份id。这样一来我首先想要去测试的就是水平越权漏洞。  
  
  
仍旧在当前小程序的个人中心，来到个人信息修改处  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnb0YpyC0Ay6O4mTVBZTYcAOAFYA8aMmytGicZ9dsaibCvxCgiaYJRbibQrQ/640?wx_fmt=png&from=appmsg "")  
  
  
点击“修改”时bp抓包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnTPX6CIwCIuTA3YKLkC3ErMTZjZNXAr5pEtZfTpKdDKujfJ0iaq6aBtQ/640?wx_fmt=png&from=appmsg "")  
  
  
数据包如下  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnNEEXWZDgWcM7XbvyqicY9ojegqWRkBAAXZicgCS4dZVc8ibBadFMYpicrA/640?wx_fmt=png&from=appmsg "")  
  
  
哟？！，改成我们之前说到的id试试  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnEiaBVekCBfJTv1W8Wl5wzLLEu0fckfkspD7Dy9chFsuaCNDjVM0Nl2w/640?wx_fmt=png&from=appmsg "")  
  
  
再次去查那个账号时，发现已经被越权修改了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34z27aOjKIs2R1F4Vva1bgLnbCUyNzkicgYIHvYAMe9LxRIAsuGq3qRmOIdpmLLAELstu3JjyAMjXzA/640?wx_fmt=png&from=appmsg "")  
  
  
好的，得吃！直接写报告提交。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，本星球日日更新，绝非简单搬运，包含号主大量一线实战,全网独一无二，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
  
  
部分更新内容展示:  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5uQHTeibMu5Vo2yrJJcCaKUCgPhwGsEp5nRKI0HC4ayT2MRN7icUED9WqsTMIgCutGmSCiauj8FVEbg/640?wx_fmt=png&from=appmsg "")  
  
## 往期回顾  
#   
# 如何利用ai辅助挖漏洞  
#   
#   
# 如何绕过签名校验  
#   
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
  
