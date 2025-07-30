#  第80篇：Weblogic上传漏洞在不知绝对路径情况下拿shell方法   
 迪哥讲事   2024-02-15 23:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450ATcz6jUJnFNeOxRzVZ9Lbc0INLwTJTZT1GaNutZrfDn6csvjBoS2ox0efLUEexXqPEcVbYfbLo8w/640?wx_fmt=png "")  
##  Part1 前言   
  
**大家好，我是ABC_123**  
。Weblogic曾经爆出一个上传漏洞，漏洞编号是CVE-2018-2894，这个漏洞利用起来稍微有点麻烦，很多朋友由于不知道绝对路径而没法上传shell，从而放弃对其的进一步利用，ABC_123曾经搭环境尝试了各种方法去解决这个问题，接下来给出自己的研究成果。  
****  
  
##  Part2 技术研究过程   
- **上传漏洞利用步骤及分析**  
  
首先复习一下weblogic上传漏洞利用过程，一般情况下，存在上传漏洞的页面是**/ws_utc/config.do**  
，在“**Work Home Dir**  
”处会自带一个绝对路径，一般是  
/u01/oracle/user_projects/domains/base_domain/tmp/WSTestPageWorkDir  
，然后可以结合上述路径更改为如下路径，接着上传jsp文件获取一个webshell。  
  
/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiaQ9P5LiagXxCwHAHfPwibt7ZKOmias7jj4fA4yUhxpMtE1ejAvhhVOJRqg/640?wx_fmt=png&from=appmsg "")  
  
  
上传成功之后，根据返回的网页源码，将jsp的webshell的时间戳与相对路径结合，就可以得到webshell的完整URL地址了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiaEpt5vytMlpeLdqcRZx20icNs8t2z5vTbPR8DKfcwQ1NXSCBy53Ksn2A/640?wx_fmt=png&from=appmsg "")  
  
  
但是我们经常遇到的情况是“**当前的工作目录**  
”是空的，或者是被其它攻击者给随意更改成错误的路径，导致不知道绝对路径导致上传webshell失败，那如何解决这个问题呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiaz3xED5ePeTnJv04cq6Wy9heTyrMuJTQelmlTNIXNpcWClkC5Kc8WZg/640?wx_fmt=png&from=appmsg "")  
  
  
首先我们做一下尝试，将绝对路径更改为以  
**servers/**  
开头的相对路径，发现也是可以上传成功的。通过试验我们发现，此处仅需要知道  
**servers/**  
开头的相对路径即可，这在一定程度上，降低了getshell的难度。  
  
servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiaCYibsYhheadSUjrm0x4X8K8DUSDRv9wASKo4dx4y0jyfggz0SuevTibw/640?wx_fmt=png&from=appmsg "")  
  
  
这里需要注意的是，上述路径中**/AdminServer/**  
在不同的weblogic安装环境中可能不一样的，它可能是/Server-0/或者/app_server1/，它可能是管理服务器名称，也可能是被管服务器(MS)名称  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjia4ellWpoAvEOTuAwIfFavhF11TB2exZArjEVHhEicicAFQEMI6oxdoRuw/640?wx_fmt=png&from=appmsg "")  
  
  
路径中的**/4mcj4y/**  
值也不是固定的，它是由/AdminServer/结合另一个变量计算出来的，所以我们只需要知道/AdminServer/处的值就好办了。如下图所示，github上有很多通过当前weblogic服务器名称计算出该值的脚本程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjia4SW8OPBBjNIGoKTD2FWf7aF5CX4C6EfcdSJcrjvxwzCYAC5ont9oFg/640?wx_fmt=png&from=appmsg "")  
  
- ### IIOP协议获取相对路径  
  
经过研究发现，如果目标weblogic端口的iiop协议开放的话，直接向iiop协议端口7001或者其它端口发送一个数据包，在返回数据包中就会有获取相对路径最关键的服务器实例名称（此处是  
AdminServ  
er）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiavpL0u14e1UYYatcPdFOM5r5qlby2e73l0sibACoShs4DhMp2Szl10oA/640?wx_fmt=png&from=appmsg "")  
  
  
知道了AdminServer这个值，就可以使用脚本计算出完整的相对路径了，就可以上传webshell了。  
  
- ### 通过报错泄露路径  
  
通过报错的方法，也可以不断获取完整的绝对路径，  
这种方法有时候能成功，有时候不能成功，我也没深入研究为什么。这个方法实测效果不太好，但是有时候可以作为探测目标绝度路径是否存在的一种方法。在“  
**Work Home Dir**  
”处填入“**servers**  
”，然后点击提交，会弹出一个报错页面，其中就会泄露一部分绝对路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiaHmVxlYjHEK61zRqb9DFbuzsELqjxvrVGaUq4JhRXP9LPo234lxKFzg/640?wx_fmt=png&from=appmsg "")  
  
- ### XXE漏洞获取weblogic的绝对路径  
  
经过仔细观察发现，此上传漏洞的编号是CVE-2018-2894，在CVE-2018-2894编号附近，有一个XXE漏洞CVE-2018-3246，因为两个漏洞编号相近，所以两个漏洞理论上会同时存在。因此如果目标环境出网的情况下，我们通过这个XXE漏洞获取到weblogic的路径，然后再利用上传漏洞获取webshell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjia8Ett5s2JfMQD8CzyBibWDiaBMJUVIfFslmF9TTnN9hKibpW0x8icbMGKIg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiaQyiblaUYUSV7agF8lmrKyDKZQz8uNHnc3tvxCHSxFr58MgmvKmxTg4Q/640?wx_fmt=png&from=appmsg "")  
  
##  Part3 总结   
  
本文中ABC_123给出了3种方法，各有优缺点，实战中结合起来用，基本上可以搞定这个上传漏洞的利用。  
  
**方法1：**  
报错获取绝对路径，缺点是不一定每次都能报错，而且有时候报错出来的路径不全。  
  
**方法2：**  
IIOP协议可以获取AdminServer，但是目标weblogic端口必须没有屏蔽IIOP协议。  
  
**方法3：**  
XXE漏洞获取绝对路径，但是目标weblogic必须得能够出网。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
****  
  
