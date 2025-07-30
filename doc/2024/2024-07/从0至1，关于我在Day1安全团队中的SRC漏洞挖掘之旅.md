#  从0至1，关于我在Day1安全团队中的SRC漏洞挖掘之旅   
卡冈图雅  Day1安全团队   2024-07-04 17:18  
  
- **时间线：******  
  
---我于2024年4月12日加入**Day1**  
  
---2024年6月24日完成**0-1**  
  
---截至2024年7月1日，挖洞收入突破  
**1.6W**  
，超额完成**0-2**  
。  
  
简单自我介绍，我的ID为”卡冈图雅”，目前是某高校通信工程专业，大一在读，出于对计算机技术的热爱，我走上了网络安全的学习之路。我在大一的第一个寒假开始自学Web安全，因为  
**缺乏大佬指导，所以踩了不少坑，学到的知识也是一知半截**，这就导致我的安全基础非常的差，只会一些简单的常规漏洞，可以说是”天崩开局”。  
  
随着学习的逐步深入，开始听说了 **EDUSRC**这种教育漏洞挖掘平台，于是开始在**CSDN**中刨屎，搜索 “如何挖掘SRC漏洞”，  
**文章”铺天盖地”，内容”千篇一律”，都是互相抄袭的毒文章，都说要先使用谷歌语法进行信息搜集，然后就可以挖到了，****省略了真正有价值的挖掘思路和手法****，导致我这种初学者掉进大坑****，**一顿操作“照猫画虎”，一个漏洞都没有挖到，直接内心受到10000点暴击伤害。  
  
于是，某天在 CSDN中刨屎的过程中，发现了一篇难得的好文章，内容由浅入深，那篇文章的作者就是庆尘哥：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrUJjaxnWmcGicndYiatanHQkibgjmAKwvUUJXtoUsZvhS6Bq3ukAuVoTPsQ/640?wx_fmt=png&from=appmsg "")  
  
于是果断加了庆哥的微信，听庆哥讲述了他在 Day1安全团队中的成长经历，**也听闻了王老师和师兄们的辉煌战绩，果断决定加入Day1，开始走出自己的舒适区**。  
  
当晚立即就加了王老师的微信，手头当时只有4000块，于是当晚就和家里要了4500块，没有任何犹豫就报名加入了 Day1，感觉  
**犹豫一点都是对自己没信心**。  
  
当时很清楚第一节课是教安装灯塔，当时灯塔的安装就把我给难住了，可谓”天崩开局”，还是多亏了师兄指导才把灯塔安装好：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrUia60GOxECVzAAcBicwvGlqKyskGBvRiaO2libM0HeY8OjSZSHJ9kPqDJ2A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrUS4u6xiasfr5cZbUEHGIOHpzniaIiaya5GMIHAx1icGJibxxFMc27GdkzY1A/640?wx_fmt=png&from=appmsg "")  
  
急急匆匆地用了一周不到，把所有的课看了一遍，当时真的就是一有时间就打开录播软件看视频。  
  
终于在4月24日，挖到了人生的第一个漏洞，中危1000元，因为  
**这个漏洞就是王老师讲过的经典漏洞，一摸一样，所以当时才能测的出来**，1000元对于一个月生活费只有2000块的学生党来说，可以称得上天价了，当时兴奋了一整个下午：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrU8HvkRu5oXtBtGtS41X8KxaMlVsNwmlL6ZeXiaaB2zUNCuEpsUS8ib6HQ/640?wx_fmt=png&from=appmsg "")  
  
因为掌握的不够多，那之后只会挖一些并发、短信/邮箱轰炸这种低危垃圾洞，不出意外的全部被忽略，刚学会用灯塔，灯塔信息泄露扫出来的文件，只要能打开就交，光漏洞盒子就交了数十个文件信息泄露，不出意外，全部重复了，于是就有了几十连忽略：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrUVEeRGsVjpeLWyUGZSESjZNsUWzicdibic7a85v3D3UddlsN9wBxpXy38g/640?wx_fmt=png&from=appmsg "")  
  
5月19日，Day1安全团队沈阳线下，来了好多大佬，当时作为小白听王老师和师兄们讲一些漏洞的知识，也是这次线下，学习了很多新思路和新的手法，也学到了王老师  
**独家的0day通杀手法**，迫不及待地回去尝试，于是线下之后一周不到，5月24日，我用  
**线下学到的技巧直接”二连中危”，挣到了1400块**。  
  
得到正向反馈后，感觉洞感提升得非常快，  
**从 “挖几天没一个洞” 到 “只要打开bp就出洞”**的转变。  
  
终于在6月17号下午，挖到了人生中第一个  
**严重漏洞**：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrUoy6AugadUshWibwSVjMbHWL263ozGTVPdcp5fHEryy43wDDatxg2T4w/640?wx_fmt=png&from=appmsg "")  
  
喜提8100元，单洞几乎0-1  
。  
  
最后狠狠地吹一波  
**Day1的师兄们，人超级好，实力+颜值+人品共存，有问题真的非常耐心地给你解答，一点不藏着掖着**，话不多说，直接上图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrUWu7Satd1tBmbTVsYgWnTqtrEU55TJWmBx4b8O1ZUu0RUT5Mo7TJVuA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrUHjaAcErQ8bzNXbC8gqTSlpxnYHZUsRT5hzUNLm4GOGBDlMpt0fKDGg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9ic98WRD8icicrJW5Pia5CPYiaiceNofK6xmrUGjXxMlvstzy2ajqAJ85gWIsuahymicPAynzvm2ddjnkxicu7ddjGvXGg/640?wx_fmt=png&from=appmsg "")  
  
在Day1安全团队，  
一周最少两节的直播课，师傅们的0-1分享，各种大佬解答问题，项目资源的内推，为新人小白准备的航海计划，每一期都是血赚，还有不定期的线下面基小聚，各种0day技巧分享，还有专门为大学生准备的关于未来工作的答疑解惑，这氛围谁不爱。  
  
下面是我自己的公众号，取名为 "Sowordholders Security"，对应我最喜欢的小说《三体》中"执剑人"一词，公众号平时会分享一些真实的企业SRC中的赏金漏洞案例以及思路：  
  
  
  
有问题可以在公众号菜单联系我，SRC漏洞挖掘培训认准  
**Day1安全团队**  
，联系我咨询的话可以领取**内部特价优惠**  
哦  
  
- **我的网络安全核心价值观：**  
  
**It's always**  
**day 1**  
**永远保持第一天接触网络安全的热情**  
  
****  
  
  
  
  
  
  
  
  
  
  
  
