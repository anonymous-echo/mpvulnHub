#  一个简单的越权漏洞成功拿下Admin权限   
 迪哥讲事   2023-09-07 23:14  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>#   
# 文章首发于个人博客：https://mybeibei.net，点击最下方“阅读原文”可直接跳转查看。  
#   
#   
# 背景介绍  
  
国外一名白帽子（Bharat Singh）在渗透测试过程中发现一处 IDOR 漏洞，该网站因为未验证请求正文中的用户输入，从而导致可以获得超级管理员的访问权限，让我们开始今天的故事分享。  
# 漏洞故事  
  
这位白帽子在实习期间要求测试客户的网络应用程序，这对于他来说是一次用来测试自身技能的绝佳机会，说不定可以在整个测试过程中获得一些有价值的东西。  
  
该应用程序有不同用户角色的邀请功能，如管理员、营销人员、营销主管等等……  
  
白帽小哥首先创建了一个管理员帐户，并通过他的第二个电子邮件地址向自己发送了具有营销人员角色权限的邀请，然后通过其它浏览器窗口中接受该邀请，然后开始在管理员的窗口页面上尝试寻找有趣的东西。  
  
首先发现只有管理员可以更改用户角色和其它配置文件详细信息。当去辑受邀用户个人资料选项时，发现该请求数据包很有趣，POST请求像下面这样：  
  
POST /user-management/update/123  
  
如果通过修改这个“123”用户 ID 来更改其他人的个人资料数据会怎样呢？响应结果显示错误，果断失败。  
  
再次进入用户配置文件编辑选项：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnibY68xW6dcoZJ8ErVAMF7dxwsLRACBUHHP0gunHoGGgLRVO4R10vS4Yia769aFDM9Psic05ibAVuedw/640?wx_fmt=png "")  
单击保存按钮然后在 Burp 中拦截该请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnibY68xW6dcoZJ8ErVAMF7dAVQobbxNsmPic8LTObhFDWmYqRjFQazzMTia5fwVlUIK6icE15ZJ3O9tg/640?wx_fmt=png "")  
  
白帽小哥决定将请求中的“role_id”参数值改为“1”，期望它将被邀请的用户提升为管理员权限。  
  
再次打开受邀用户（营销人员）窗口并刷新页面，果然现在的权限是超级管理员了！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnibY68xW6dcoZJ8ErVAMF7dHNtwIV6mBcqiaHYYvib2spXQfoyLTvAzP1Y1SyMBibibOvOvVCPe87FUjQ/640?wx_fmt=png "")  
# 漏洞影响  
  
攻击者可以获得超级管理员访问权限，这意味着攻击者可以访问、修改或删除应用程序中的任何数据，包括用户信息和敏感数据。  
  
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
  
  
  
原文出处：https://bharat-singh.medium.com/privilege-escalation-to-super-admin-22cb6a09c1d9  
  
  
