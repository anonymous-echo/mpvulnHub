#  实战：一次Src越权漏洞挖掘   
 迪哥讲事   2023-12-30 22:11  
  
**No.0**  
  
**前言**  
  
  
无需登录就可以获取****申请信息，包括但不限真实姓名，手机号，简历，公司等铭感信息。可通过遍历获取所有已申请用户的敏感信息（几千条）  
  
发现上万条企业信息泄露，请见文章最后步骤7，（可以批量申请加入企业，对审核人员造成负担）  
  
**No.1**  
  
**实战经过-未授权**  
  
  
发现方式  
  
1. 浏览器打开url  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoB0iagEGiaMiaj5iaRQm4lVttDYg37Kc5dzXmAgn08h28Q8gjsrJ7wuqxzQ/640?wx_fmt=png&from=appmsg "")  
  
  
2. 使用burp工具抓取请求数据包，发现有请求列表的数据包，可以获取申请列表信息  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvo992pickIYaEGvsT6Qvg8yic5IHdPBZ1wAZpoKmXsGkXQvt82ju7dTjeg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvo9Frop9VoPXcScvdibGXJU3Via4ntBCxxwTtw8rEvPJgWTNqlqdyQj1Pg/640?wx_fmt=png&from=appmsg "")  
  
  
3. 登录一个正常账号，尝试申请一个企业  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvodc8ADIeTj2xDSaPlLGrUzrRvrUvwMpvjEfVLdQnvZ8EaEmRmE32RAg/640?wx_fmt=png&from=appmsg "")  
  
  
4. 用浏览器抓取查看详情数据包。发现铭文的铭感数据，真实姓名，联系方式，简历链接等  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoh19icZibyRjytx1CVyxbvCau9e4PyQlrOHYExq51cGiciaM1O1gxicLh3Rg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoxlnjXaayxLsrFc7ZWRtW4yn3q1CuX8mficriaM9ZbFHn17RT4IZXatOg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoDPBaMzFjWCAwFqibXJAl4iaK1RbtkZD1JdUFjgrDWPGG5JM2dd8umTmA/640?wx_fmt=png&from=appmsg "")  
  
  
5. 尝试用burp构建请求包。发现可以获取到明文的敏感信息  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvofiayHp9kVLYWR2S5NKMBPnAxrb64kcbwfQ8M97NWMFT4icVDAnzfXWbg/640?wx_fmt=png&from=appmsg "")  
  
  
6. 尝试替换请求包中的ApplyId，可以用步骤2中的返回包里的Id值进行替换  
  
可以通过遍历id进行恶意获取信息。  
  
（这里仅测试3条数据）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvo8JB7rC5I05KYqIeI6ObG9nIDPbX5pmPiafFBGYCKOmCibDpSbRMQTdAQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoou03Wiaoiam2EYaX18un0uNugAcqo2KU3T9cKXSBTmK84kCVt23me5Gw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoou03Wiaoiam2EYaX18un0uNugAcqo2KU3T9cKXSBTmK84kCVt23me5Gw/640?wx_fmt=png&from=appmsg "")  
  
  
（没有cookie也可以请求成功）  
  
**No.2**  
  
**实战经过-任意用户登录**  
  
  
  
某SRC小程序存在任意用户登录漏洞  
  
点击某小程序后，点击同意的瞬间开启抓包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvomxlclJnxUOGqXCoicT76T9jwF6fh3u4QTj7KEf6qqyxxcW0AGDGILibA/640?wx_fmt=png&from=appmsg "")  
  
  
在{}中随意填上code值  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoQOf6bzMAgTJttRH2ZzeC79uZwibkn4ZrvIYuR1o6icicct0pCKt69DAXA/640?wx_fmt=png&from=appmsg "")  
  
  
拦截返回包并来到修改返回包步骤  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoO8VFR0p1gmsqicnia0OdGRJHEEeFcIExDJ9NU9QewKCvtoT6Y06ticU3Q/640?wx_fmt=png&from=appmsg "")  
  
  
mobile处填写想要登录的手机号，点击放包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoMZbIlknyPdnBYib3enatCDGx2ibFiby0FxgQibEkfnWX5zibg1ecw8kFNSw/640?wx_fmt=png&from=appmsg "")  
  
  
发现已经返回code值了，不做修改继续放包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoZibG6a9rVMmhae7dvpUCfPGXArl3fVvM03kvaDRb3Ya9ic5uKOZRWXcQ/640?wx_fmt=png&from=appmsg "")  
  
  
继续放包  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoliakibrVttFOkqibKl1shoyWQXtkMEkPFyzkIk8bTn8kKV8A0jVWItp9g/640?wx_fmt=png&from=appmsg "")  
  
  
此时返回小程序发现已经登录成功，且该账户的任何功能都可以，信息都可以查看，成功接管  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvo2hSZYWkJYvibhC7HhFLEJzg9Nnog38LicNic40vVqGXDPmYAc6pkZJksw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34wwzd3LYDKhl0QzBUeibibKvoMPwP6rZtyQqSluNpjW7XHsPW0Sn849MMCAcBG4u7CLHM1VIiaEYN4cw/640?wx_fmt=png&from=appmsg "")  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
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
  
  
****  
  
