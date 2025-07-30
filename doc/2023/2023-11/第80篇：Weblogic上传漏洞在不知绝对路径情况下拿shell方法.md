#  第80篇：Weblogic上传漏洞在不知绝对路径情况下拿shell方法   
 湘安无事   2023-11-26 09:25  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450ATcz6jUJnFNeOxRzVZ9Lbc0INLwTJTZT1GaNutZrfDn6csvjBoS2ox0efLUEexXqPEcVbYfbLo8w/640?wx_fmt=png "")  
##  Part1 前言   
  
**大家好，我是ABC_123**  
。Weblogic曾经爆出一个上传漏洞，漏洞编号是CVE-2018-2894，这个漏洞利用起来稍微有点麻烦，很多朋友由于不知道绝对路径而没法上传shell，从而放弃对其的进一步利用，ABC_123曾经搭环境尝试了各种方法去解决这个问题，接下来给出自己的研究成果。  
  
**建议大家把公众号“希潭实验室”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OAz0RNU450Dq1Q8s4COc7InkMO0jIGjiaGho1fcJicpibWB4vzvIM1wAib9TiakVECbIM5S0mHCTTeGJJibWtCe25vXw/640?wx_fmt=jpeg&from=appmsg "")  
  
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
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450A5qqg2iaK6KIYYR8y6pF5Rh3JHDibOKOop204nXz618iawdRb8dABicMPtHb2PkJE8x6koJO5HyuwZJQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**公众号专注于网络安全技术分享，包括APT事件分析、红队攻防、蓝队分析、渗透测试、代码审计等，每周一篇，99%原创，敬请关注。**  
  
技术交流可加下方wx  
  
****  
****  
**|**  
**知识星球的介绍**  
  
不好意思，兄弟们，这里给湘安无事星球打个广告，不喜欢的可以直接滑走哦。添加下面wx加星球可享优惠  
  
1.群主为什么要建知识星球？  
```
很简单为了恰饭哈哈哈，然后也是为了建立一个圈子进行交流学习和共享资源嘛
相应的也收取费用嘛，毕竟维持星球也需要精力
```  
  
2.知识星球有哪些资源？  
```
群里面联系群主是可以要一些免费的学习资料的，因为群里面大部分是大学生嘛
大学生不就是喜欢白嫖，所以大家会共享一些资料
没有的群主wk也有,wk除了不会pc,其他都能嫖hhh
```  
  
一些实战报告，截的部分  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtODwbOOp88vXJ5mXX9NSIvA7UUtTDHJDhDCOrbSnT7UAsyyTlY1FyJhA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtOWwAWoiaibCM3ibleLWSAKnsLREnwa09BkFZXfm5lRWtfbVwgKf0j3ISaw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtO3qicwjmWdRCB5UxWt1jfnSfKBwD6yIyveRa3ENZ0KXVa9BtRRzD8GicA/640?wx_fmt=png "")  
  
一些1day的poc,这些也就是信息差，不想找可以让wk帮你们嫖,群主也会经常发  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtO0QGwS7xuY4vKe6X9SZCa87DMEEJJ68fnBiadQSQTDdfqgVQiaGZz9NbA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtOdSLtwUia1EA2xEubNgTf3UYervduLFz4LWw33ic6fPw7vv1UQyLBEbrQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtO4Sq6oGicP66MiaBT1o8YcVKQNLPytG0yB79mVmuXicA2foVBk3Ud5sfvw/640?wx_fmt=png "")  
  
一些共享的资源  
```
1.刀客源码的高级会员
2.FOFA在线查询与下载，key使用、360quake、shodan等
3.专属漏洞库
5.专属内部it免费课程
6.不定期直播分享（星球有录屏）
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYvS1u1PKCurEmuM61nGSElnNalHCy4YicPa9bZ23vMDPHzQPDxybG50b760tL8KcAYTGjBicGocsdXw/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYuCJm1WAIhc9XAa6OLI3ryvT32RpoHYTibSMVnsTh875E0Jk4XPduRqDicRQGMWHDD4RnueHudPHI3g/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYslWA5vxdHdKvewGdoWN924dObAfdfNmtTDhYH3CY4QshUibO2wZe4VuJmPjke7KJabuCJIIP69iaZQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
