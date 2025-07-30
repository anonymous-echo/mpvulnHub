#  寻找IDOR漏洞：Key Endpoints and Resources   
 迪哥讲事   2024-09-23 23:12  
  
# 寻找IDOR漏洞：Key Endpoints and Resources  
  
# bugbounty笔记 知识星球优惠券放送  
  
今天，在这篇文章中，我将分享一些常见的可以用来寻找IDOR漏洞的端点。我已经对这个主题进行了深入研究，并将分享一些优秀的资源库，这些资源库可以帮助你发现并利用IDOR漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/cxf9lzscpMrGp8Rfkiar2t5Iolgribwna9YwEKkxYQRiaq15Qx0baoic7hFS9YgjtNEoHa5A1Ar9a14h5GGrLqicMUA/640?wx_fmt=jpeg&from=appmsg "")  
  
不安全的直接对象引用（IDOR）是一种常见的Web应用程序漏洞，如果未得到妥善管理，可能带来严重的安全隐患。  
  
它的发生是由于Web应用程序允许用户访问内部对象（如文件或数据库条目），而没有检查用户是否具有相应的权限。  
  
这意味着，如果有人发现了这些对象的引用或链接，他们就可以在未经授权的情况下访问或修改这些对象。  
  
IDOR漏洞属于访问控制问题的一种。  
  
当应用程序未能正确验证用户是否被允许访问某个资源时，就会出现这种漏洞。  
  
这可能导致严重的问题，如数据泄露、未经授权的数据更改以及用户账户的安全受损。  
  
根据Bugcrowd的漏洞评级分类（VRT），IDOR问题的严重程度取决于暴露数据的敏感性和未经授权访问的潜在影响，范围从高危（P1）到低危（P5）不等。  
  
现在，你已经了解了什么是IDOR。那么，我们接下来讨论一下可以在哪些地方找到这种漏洞吧。  
  
利用哈希/编码值：  
- 如果你发现任何ID参数是编码的，那么尝试对其进行解码，看看如何利用它。例如，如果存在一个参数userId=MTIzNA==，你会发现这个参数是用Base64编码的。现在，你可以解码它并尝试进行利用。为了更好地理解，你可以观看这个视频：https://youtu.be/xsIi-YMMiBA?si=BGWFX_U9CAq0gM8c
https://www.youtube.com/watch?v=EyoVsS75cLE  
  
- 另一种方法是，如果请求头中没有包含任何授权Bearer Token，或者应用程序没有验证正确的Cookie，那么你可以简单地将攻击者的userId更改为受害者的userId。  
  
上传头像：  
- 上传头像时，确保拦截并检查请求体，如果其中包含任何ID，尝试更改该ID，你可能可以将头像上传到其他用户的账户中。为了更好地理解，你可以参考以下视频：https://youtu.be/xg3zjcw2F98?si=FdVGZJ2ceYIb-_Tw
https://youtu.be/8IjznzLr03U?si=9OSw_7HhJXfS1shH  
  
尝试更改邮箱/用户名：  
- **案例1**如果你能够更改其他用户的邮箱地址，这就是一种账号接管漏洞，属于P1级别的高危漏洞。以下是如何利用它的解释：攻击者尝试更新手机号和邮箱，之后拦截请求，发现其中有一个ID参数。他将ID更改，然后发现可以更改不同用户的邮箱。接着，他进入注册页面，点击“忘记密码”，输入自己的邮箱，收到密码重置链接，然后更改密码并登录到该用户的账户。你可以参考以下视频进行了解：https://youtu.be/zxDmYWzLqJE?si=6amlNB1VFazvOMuE
https://youtu.be/q6pVmNAMVmg?si=1KKk3VN9sOJA758W  
  
- **案例2**攻击者尝试更改自己的用户名，在更改时拦截请求，然后简单地将攻击者的ID更改为受害者的ID并转发请求。如果他能够更改用户名，那么这也是一种IDOR漏洞。这种漏洞的影响因组织而异。视频演示参考：https://youtu.be/4vSjfL_kcUs?si=qkay58Iv1TUdL4lg  
  
不要忘记下载内容：  
- 请求可能类似于GET /attachment/1234，只需更改ID就可以下载任何附件。视频演示：https://youtu.be/1vAXT1_46Kk?si=rwfmWjqWBG8wzmps
在某些情况下，这可能导致重要文件的下载，进而可能导致个人身份信息（PII）的泄露。  
  
取消订阅受害者：  
- 攻击者将邮箱更改为受害者的邮箱，然后点击“取消订阅”，结果是受害者的邮箱被从所有产品中取消订阅。文章和视频参考：https://medium.com/@Dhamuharker/unsubscribe-any-users-e-mail-notifications-via-idor-7de76e2b036b
https://youtu.be/5IbHmDlnEJ4?si=lCs1Qk3LDUmORWWr  
  
以上是一些你可以用来寻找IDOR漏洞的主要攻击点。我还提供了一些可能对你寻找IDOR有帮助的资源。  
  
https://github.com/Dishant4081/All-about-IDOR?tab=readme-ov-file  
  
注意：我在前面提供的所有演示视频链接都已包含在此资源库中。  
  
这个仓库汇集了所有关于IDOR的主要资源，包括50多个演示视频、HackerOne报告、Medium文章、各种绕过方式，以及IDOR的各个关键部分。如果你喜欢这个资源库，别忘了给它点颗星。  
  
通过这些资源，你将对IDOR有充分的了解。参考这些内容后，你一定已经准备好去寻找IDOR漏洞了。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
Thanks for:  
  
https://medium.com/@dsmodi484/finding-idor-vulnerabilities-key-endpoints-and-resources-b9b4084edf34  
  
  
