#  (SRC漏洞挖掘四)短信发送功能点   
 迪哥讲事   2023-09-12 22:32  
  
# 短信轰炸  
## 并发短信轰炸  
  
在发送验证码中有图形验证码或者其他验证时并发手段是常用的一种绕过思路，不仅仅在短信发送能够利用并发手段，领取优惠券、签到等功能点都能够利用并发手段。点击发送验证码并抓包![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5ibkiaK3cdRQ8I7a35uvVUNo5eD8f4WSvMwVyv6jJbfFSPUiasS1CW5icew/640?wx_fmt=png "")  
安装并发插件![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5Y7biaxNVHRFppkEDzBK9mmMKpejljmWf7QkOcFkp40zruGkbT5NNgsA/640?wx_fmt=png "")  
先不要放掉该数据包，把发送到burp插件turbo intruder里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5G2YnxpjA6GNB4a9MB4GW87PD2ZfbMoWLNicKmZhVz1MRqeGJq6pEOUg/640?wx_fmt=png "")  
然后选择race.py这个专门的测试并发漏洞的脚本，并且自行手动在请求包里添加req: %s字段后，就可以开始攻击了：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5SohYUa61c6czenia4ib8FbcibPpGLe1uvYS0qzGAxict1j5TiaAbOqro9Tw/640?wx_fmt=png "")  
  
成功并发  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5CTeMF4SydTjbpY1TNF1Mx7u7Ewyiad1Hape9cnuSI8FEAeTTg5WonMw/640?wx_fmt=png "")  
  
造成短信轰炸![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5jDYCascSIBoRqpOViaaAPBR3zVcJI60biaNicUB2OPRqfNLW16rpK2zqA/640?wx_fmt=png "")  
  
## 时间戳绕过  
  
很多发送短信验证码的时候都会出现time类似这个参数对于这类参数有什么作用。对于这类参数大多数都是使用时间戳来进行验证，我们只需要将时间提前即可绕过，比如抓到的包的时间是08:09，我直接更改为08:20，这边我也挖过非常多这类漏洞。![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5rjvPsibKKbeGubKbprjg6wlSer0MtWL1XSHvXnWibnYsNHz4BI2EXngw/640?wx_fmt=png "")  
还有就是他会比时间戳多出一两个数字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5LXiaYPncon8IVibOtUWFcpqFZd068967ySsOkRianR3iaQXbbJsWibGZ6mA/640?wx_fmt=png "")  
  
时间截在线转换地址：  
  
https://www.matools.com/timestamp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5yhgHcAnMwSoZKhEVfxsg0MCWQH72MrSBQYnvaCc6WINK87u9NmCdpg/640?wx_fmt=png "")  
## 加一些数据绕过  
  
+86
不知道你是否会发现很多发送短信验证码的前面都会有+86这个，+86是中国国际区号，用于拨打国际电话，而我们可以利用这一点在+86的后面再添加+86来实现绕过
加空格  
## 删除cookie  
  
有的是对cookie进行验证，还有就是你得观察一下数据包中的其他参数如type之类的，有的在type参数后面随便加一个数字字母同样也能绕过，这些得跟实际数据包进行观察与尝试。  
## 逻辑绕过  
  
对于网站将数据加密或者签名的短信验证功能点，在无法获取签名和加密密钥的情况下我们要如何来造成短信轰炸呢？这边是研究的一个新思路就是在正常情况下我们使用下面的数据包无论是用上面的哪种方式都不可以造成短信轰炸，并且每次点击发送验证码并抓包数据包都在发送变化。这边可以利用以下方式：点击发送验证码并抓包![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5jNBwq2SNJExZEOCnMiaHQUQ9kYdE2CyDFOib75afrcN2tgibOiawnZOt2w/640?wx_fmt=png "")  
将数据包放到reperter模块，并丢弃该数据包（一定不要放包forward），然后再次回到网站使用该手机号进行发送验证码并重复刚刚的步骤  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC50KhOCwyGRkRvqZK3beU9beLibgZm8oIOOGsTnvuicVjl7mQjekL8smaw/640?wx_fmt=png "")  
  
这样就获取到多个进行了签名或加密的数据包，一次快速点击go，看能否发送多条短信，如果能够就说明存在短信轰炸漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5c0mI1ETibM4ef8Wrtibr65zwCoUBake4aSUjApQNr8icJlrmX1AcQlfSA/640?wx_fmt=png "")  
# 四位验证码爆破漏洞（高危）  
  
对于发送的四位验证码可爆破的话那就是高危可以实现任意用户登陆注册，普通四位验证码爆破我就不说了，这里我遇到了一个有时间限制爆破的漏洞，这类漏洞提交的时候要怎么说是很关键的（在我们提交漏洞时要善于用详情说出自己漏洞的危害，对一些限制条件进行有利说明，这样漏洞才能高危严重呀）  
  
**「漏洞说明：」**  
  
发送的验证码只有四位，并且在输入验证码错误次数没有限制，只有时间限制，在两分钟内最少都可以爆破一千次以上（那么只要攻击者一直尝试总有一次在自己的爆破范围内，并且时间不会太长，最多一个小时就可以修改一个用户的密码）造成任意用户登录  
  
成功爆破![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5Sx4FZwytAs2pa7FyGhqMBA0bm00iaWacwJIbicExg95S1D0KA2xz0DPw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5Cm9aaibuRQF4ANMp5qfqib2EDia63LR8b9ZwN2Uzlp8IiagpDwibd9YxWGg/640?wx_fmt=png "")  
生成四位验证码和六位验证码脚本如下：  
  
python四位手机号验证码生成  
```
for i in range(10000):
    if i<10:
        i = '000'+str(i)
    elif 10<=i and i<100:
        i ='00'+str(i)
    elif 100<=i and i<1000:
        i ='0'+str(i)
    else:
        i=str(i)
    with open('4位手机验证码.txt', 'a') as f:
        f.write(i+"\n")

```  
  
python六位手机号验证码生成  
```
for i in range(1000000):
    if i<10:
        i = '00000'+str(i)
    elif 10<=i and i<100:
        i ='0000'+str(i)
    elif 100<=i and i<1000:
        i ='000'+str(i)
    elif 1000<=i and i<10000:
        i ='00'+str(i)
    elif 10000<=i and i<100000:
        i ='0'+str(i)
    else:
        i=str(i)
    with open('6位手机验证码.txt', 'a') as f:
        f.write(i+"\n")

```  
# 逻辑漏洞（高危）  
  
登录点输入手机发送验证码并抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5plNd6w4xpJB4swRghoZ9vFOUvN3jTc9YToUUxRdXa8rjVsWoxV7FjQ/640?wx_fmt=png "")  
在该手机号后再添加,（逗号）和一个手机号（抓包修改phone的参数值为"phone=手机号1,手机号2"）![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC54JSN6v2CngD3Vnhyq5qUYCsrhzj28hExqrRS47qHicXlvh9WLUGCtzg/640?wx_fmt=png "")  
此时攻击者就能同时收到他人手机号的验证码，从而实现任意用户登录，同理在邮箱验证功能点也可能存在该漏洞，还有一种思路是将整个参数和电话号码再添加一遍："phone=手机号1&phone=手机号2"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5H64Oc2ZLOJr7dKmq1G7RsuZtQU6HiaKib5FccjkzaPF5KfLfMiaaChfiag/640?wx_fmt=png "")  
# 验证码复用  
  
在正常逻辑下登录一个系统需要一个手机验证码，该验证码用过后就不能用了，但是换个浏览器使用这个验证码依然能够登录说明存在验证码复用漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC552PibNEVd5Zs5eEQEodWbPKj5P62OwicS1OI5dMlSrsrw7pApZLFDMww/640?wx_fmt=png "")  
输入手机号点击获取验证码、手机收到验证码如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5fMO21SRLlbO81z4c26rdxTL5g6Gt42Pgvdfj28op6ZBaY7FchqKGpg/640?wx_fmt=png "")  
输入验证码登录成功后换个浏览器，再次使用该手机号验证码登录、发现发来的验证码还是上次使用的验证码、且输入该验证码也能登录、正常情况下验证码用过是不能再用的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5micvUicN9wDeOal2hXMZPX7Dt9TqZg5myWSAvYrHABABnV8gFm44c9qQ/640?wx_fmt=png "")  
# 验证码前端显示和验证码内容可控漏洞  
  
填写个人信息后点击发送验证码并抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5OmXepKttys1dHVKAYDg0FIbp1hiaBao0matiao84ZNib7AtRmxFc6zAoA/640?wx_fmt=png "")  
  
发现验证码在前端显示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5obLqtRfdUVGU7tXha26a7OLlq7hHTBlWNcwRoiaewgdAsLOPddbwZIA/640?wx_fmt=png "")  
  
并且验证码内容可控  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC59erbXr9j2YWNmPib7A5WfI9Kl63jqNtdPlFYFJAv12FdmOBiaicogoHmw/640?wx_fmt=png "")  
  
收到短信如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsnvOqazeMELlHWAD0UCO0MSUzR3cDC5qeoy62Ob1DibFqtkQXPY6F3RY24RJHoWjictrJ0k8BVJ5Ulo8CHPbJ6A/640?wx_fmt=png "")  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 往期回顾  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  
