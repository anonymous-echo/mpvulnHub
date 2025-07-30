#  如何将LFI漏洞从高危升级为严重   
 迪哥讲事   2023-09-23 23:08  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>#   
# 文章首发于个人博客：https://mybeibei.net，点击最下方“阅读原文”可直接跳转查看。  
  
# 背景介绍  
  
一位国外白帽子正在测试一个VDP程序，经过前期侦查后，他选择了对一个子域进行搜索。  
  
打开Burp拦截请求，其中一个请求成功的引起了白帽小哥的注意。  
  
https://target.tld/api/whitelabel/getFile?file=favico  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWG9uChWF85Iev5rNibP3k51ABicmHR1JFHBn2WGwAIZepPIRIN9JSmaaw/640?wx_fmt=png "")  
  
白猫小哥开始尝试 LFI 并获取 /etc/passwd 文件，但响应均为空。  
  
然后白帽小哥开始使用Seclists进行Fuzz：  
  
https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIW8XdiadEMOSw7lT9m5XuzUUIeorB7nVVFKnYJfib3zEZ74JfhuAmp2ueA/640?wx_fmt=png "")  
*/etc/hosts  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWS4SEtxeMCClHTvyEymK19fp3HXPCKxURhHD2T1qcX8Xm9KrIZ2TichQ/640?wx_fmt=png "")  
*/etc/ssh/ssh_host_dsa_key  
  
虽然没有大的影响，但LFI也算高危漏洞了，那么能否将漏洞级别提升至“严重级”呢？  
  
hackerone上有不少这样的案例，比如以下这些：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWqIUJm2Y4ibia73LLiaPxUpCVaLibfoic0SmMh2Dh9h7qbUy5dSnf3Hg7d9w/640?wx_fmt=png "")  
  
根据这些案例报告，如果想将漏洞级别提升至“严重级”，需要找到一些‘特别’的东西，通过暴力破解似乎有点困难。  
  
于是白帽小哥用特殊字符和 unicode 对内部端点进行Fuzz，并发现了一些有趣的东西。（ * 字符可以返回每个目录中的所有文件）比如下面这个请求：  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWYlhsTkPQEibzic3IT4hMoiajiaF0LrB5zdawZTIhgpSPT0j8ibEvxvIZCRw/640?wx_fmt=png "")  
*数据库账号及密码  
  
尝试登录看看，Bingo！![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWjnzGDULZtM99E24dMuR3XAiaPulJjuzII2kvrTB5oRrk9MetsVYYgRg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWE33ib1iciaGRwNTb95wOTwEFnJWNv1v63iaPtQicoDcj1aDqfQGnjv5k5Wg/640?wx_fmt=png "")  
  
源码泄露：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWlzp74WtJotvib9DJaeBXyEzg5mickXIGI0B85GHrL4tCGqnsZTDWsLpw/640?wx_fmt=png "")  
  
这下漏洞的级别妥妥的“严重”了～  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWbIKMI6K00ewBlTx322z8bMQ7AGcQfIPTnSdUbmdP8PHhiaHtD3Oz1MQ/640?wx_fmt=png "")  
  
结果也确实没有令白帽小哥失望。  
  
**PS：**关于 * 的用法，还可以这样使用：/etc/apache2/*SOME-STRING如果该字符串与该目录中的文件名的一部分匹配，则返回该文件。像下面这样：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWu19Wtln9KIMt5BI712MychYibWGQICMuC9VQVRhjNWz3XcYxqKuDxrg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnYzazlvlvttPYrajmwWKIWLvLB4EvvgWhhE6uPZWaJpSkDOI3bXwQNxJJYvicVo7pqibhbibXUNYErA/640?wx_fmt=png "")  
  
****  
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
  
  
  
