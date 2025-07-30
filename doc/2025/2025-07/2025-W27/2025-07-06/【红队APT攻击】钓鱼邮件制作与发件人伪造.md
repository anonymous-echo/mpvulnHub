> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247492677&idx=1&sn=fb5ac1b6ebcef89e31f993f306a48abd

#  【红队APT攻击】钓鱼邮件制作与发件人伪造  
zero1234  神农Sec   2025-07-06 05:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：zero1234  
  
文章来源：https://www.freebuf.com/articles/system/427576.html  
  
  
**钓鱼邮件制作与发件人伪造**  
  
## 前情提要  
  
前面我们学习了如何快速的搭建一个钓鱼服务器，如何进行快速的钓鱼。但还不够，因为对于钓鱼来说，每个的细节都需要我们尽可能的把握，从而增加成功率。而之前的钓鱼邮件，虽然伪造了邮件部分，但却无法伪造发件人。第一篇的制作成果：  
  
红队APT基础 | 钓鱼邮件的制作与SPF绕过（一） - FreeBuf网络安全行业门户﻿  
  
目标邮件  
  
![1744704075_67fe124b8ff5427627e70.png!small?1744703984275](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J2Tib5Oyr2q9tt1a7gtfJLF3vOwPIia2W22icxeu8gOurcFgcwOKVKrDLw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744704120_67fe127824322d5d5be7e.png!small?1744704028845](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JD1AYKnJgEuhTEAwZG5ZTvRKYyKbb7IfSxlTXQnysMWksDndjCLbmTA/640?wx_fmt=jpeg&from=appmsg "")  
  
伪造结果  
  
![1744704161_67fe12a15a285654792bf.png!small?1744704069957](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jh2X6icjjtntHaa9IOjicsyK4EL1SYKoNs64DpYnibcx8GnibcfM0Qu0A1A/640?wx_fmt=jpeg&from=appmsg "")  
  
区别显而易见了，发件人是不同的，并未完成真正的伪造。  
## 你能收获什么？  
  
获得一封近乎无暇的钓鱼邮件~，因为这个方法也不是完美的，废话不多说，直接展示成果：  
  
目标邮件  
  
![1744704120_67fe127824322d5d5be7e.png!small](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JD1AYKnJgEuhTEAwZG5ZTvRKYyKbb7IfSxlTXQnysMWksDndjCLbmTA/640?wx_fmt=jpeg&from=appmsg "")  
  
伪造邮件  
  
网易  
  
![1744704374_67fe13769cc4945a8b398.png!small?1744704283404](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JfFRfiaBqYBeQdibfKjN5ejibqf2DdiaNB8qrvcHz8AZVYD2Uf8oNS9OByQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744704368_67fe13707d06958249696.png!small?1744704277324](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JSQavTF1E3iaqoLM1pDCaBOVkz0zawTia9lcMqB9p41dAGThWvCB8HrFQ/640?wx_fmt=jpeg&from=appmsg "")  
  
QQ  
  
![1744704712_67fe14c8dd6ef728267a0.png!small?1744704621255](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JNjibglqibLkMicmyKQx8azsGBSiaUnGiaP71vxn77HsRWAZibkR5cdJqemBA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744704374_67fe1376a82765d4897aa.png!small?1744704283404](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JuTmskuLwevGyOvXQdLBicMsB9ujkPY8augY59zSDDSfCABTpKODSfNQ/640?wx_fmt=jpeg&from=appmsg "")  
## 正式开始  
  
我们今天涉及的服务器：香港服务器_香港云服务器_海外服务器租用托管商-恒创科技  
  
我们今天涉及的工具是：EwoMail开源邮件服务器软件  
  
为什么选用这两个呢？  
  
关于服务器有三点讲究：  
  
1.免费~嘿嘿，最重要的嘛，演示不选一个免费的那不是坑大家吗  
  
2.服务器没有封闭25端口，阿里云、华为云、腾讯云这些都是会封闭25端口的，你说解封？你想吃紫蛋了我看，哈哈，开玩笑。  
  
3.需求centos7/8 64位系统，CPU：1核，内存：2G，硬盘：40G，带宽：1-3M  
  
4.香港服务器，或者海外的服务器，为什么？因为这两类服务器域名不用备案。什么？你说你要去备案，我看你是没被溯源过~  
  
![1744705529_67fe17f9b550f6b980430.png!small?1744705438162](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jz5JOHUicPibv69oGg4vpk6oInv1FyEtpViaFfNauBNDKrWCw79icJic3FLQ/640?wx_fmt=jpeg&from=appmsg "")  
  
首先看看免费服务器怎么领取  
  
![1744705656_67fe1878ed0582d0d0559.png!small?1744705566412](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jo8ZjIMpicQKAMGfozo3VatN1Pyy3HbLibRueXD6EvhJSYzBa4G1UtibGA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744705668_67fe1884f39b06943725d.png!small?1744705578086](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JBdHnaSPgCNjEreERQnjD6eXq3TPgu5Ar2gDp8kJRaZNzhElYr9ctTw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744705714_67fe18b20725c4e334ae0.png!small?1744705622498](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J1ufeHnK6JAia4NtSXWjdLyicP2cye45Ag09WF7sHlFUNjNHMN5AZv7wA/640?wx_fmt=jpeg&from=appmsg "")  
  
然后自己申请吧，需要实名认证，手机号绑定。  
  
申请好后，使用工具（MobaXterm_Personal）连接即可。  
  
什么你说你不懂什么叫MobaXterm_Personal，那你可以去看看：  
  
不会有人2025了还不会反弹shell吧？让你的反弹shell从0到1！ - FreeBuf网络安全行业门户  
  
这篇文章的知识点一有提到（照顾小白师傅~）  
  
那么准备好服务器我们就去申请域名  
  
![1744705927_67fe1987aded5879152d9.png!small?1744705837534](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JQsRAkudT48zVviaIPlmX0nMCZZuiaG1msibsiaw28ygNdibfTE0eEo28ajQ/640?wx_fmt=jpeg&from=appmsg "")  
  
那么我们就以这个目标为例嘛，需要申请的一个域名肯定要和他相似  
  
如何申请呢，简单复制粘贴  
  
![1744705942_67fe1996c777cbaa33ad6.png!small?1744705851697](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JerFPzqCvZMJbN912s5TxD9MBemK5jDtHqovGsC6v2SGpB4sLBGVt7A/640?wx_fmt=jpeg&from=appmsg "")  
  
诶可以发现为什么没有  
info.sendcloud.me  
这样的域名。  
  
因为  
info  
其实是子域名，是前缀，等等也会讲到如何复刻  
  
![1744705965_67fe19ad3b9f67ed3abae.png!small?1744705873880](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jeuoocic993q2xkicTIC80TRo0V2dkv17icZyIYTRA9xVicKGlXkeoFoCUA/640?wx_fmt=jpeg&from=appmsg "")  
  
那么为了实验环境，我肯定是买个便宜的  
  
![1744705977_67fe19b9db781ae687e2b.png!small?1744705886335](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JcrzPPLcD4LCWH7qJbXlJjibciccRWPG2CB8IVXse48zibnQ5T3zcIpEjA/640?wx_fmt=jpeg&from=appmsg "")  
  
买完后审核要一段时间，可以顺便去搭建  
~  
  
![1744705991_67fe19c7b5a19f36d4e91.png!small?1744705901536](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JzTTYz3Db2RwQaqtDHzXDJuIic6Yv3HrV2hPS8cRnNMl2B7nppDyzERQ/640?wx_fmt=jpeg&from=appmsg "")  
  
根据它的安装命令，我们一步一截图，这个步骤都是实测过的，  
2025  
实测可用  
~  
  
建议打开手册，从手册上面复制命令（不整虚的，保证大家的复现成功率  
~  
）：  
  
http://doc.ewomail.com/docs/ewomail/install  
  
![1744706108_67fe1a3ce6f45eefa9e1f.png!small?1744706023940](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JNNiaSdFYv3We43BWibkTLtjKXrUgibt46rghyPjGdRkibiacTnUxnw0DBbw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706011_67fe19dbdbd3ae7ccc81f.png!small?1744705920424](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J2IITPYbsYYhwrzk8yrUcnLLy8wxqcovYV7k45JXMOD8qUwbLs7k5Bg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706015_67fe19dfd81d23626f4aa.png!small?1744705924448](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JKwSRIm4PkXALzIib2gB8lUw96Gg4q5kosywVOLl5Xdj5ylO89e2BPtQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706023_67fe19e71fe45a0e4008d.png!small?1744705931705](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JRvolgyric5rzdwL6ObIRg5Ehf1XQ4Yts0YbfNxfAGMSz87xQxMrW3BQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![1744706141_67fe1a5d83ffbb930334f.png!small?1744706049941](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Joo3aPVa2S2dwFGJnNv8icmibCzbrcA1GpPewmskCE1qQOibhBxZl5Cx8g/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706148_67fe1a645f58b5fed798c.png!small?1744706056983](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JFXJaxPpAKAibaIPiaATI384x71ZVloQUiajX6w3oYuqTgH59ibQmSiasoeQ/640?wx_fmt=jpeg&from=appmsg "")  
  
这里完成以后就可以下载命令了  
~  
  
![1744706162_67fe1a72cc5a7e4d16bd9.png!small?1744706071241](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J5Ge5tyZQ3asQCMCWzpQ0s2fQU9twWQL1ZSg1mZ3GMvn528HPQczBnQ/640?wx_fmt=jpeg&from=appmsg "")  
  
记得下面的下载要把ewomail.cn替换为你自己的域名！  
  
![1744706200_67fe1a98c2c7331b162d8.png!small?1744706109383](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JcOqN5UNZOiawicHibbM9KGwEU0M8wsHKD72R42Yt9icax9hOlvYqvjfhrw/640?wx_fmt=jpeg&from=appmsg "")  
  
实测用  
Gitee  
的访问不到，那么我们就用  
GitHub  
的。  
  
一直到git clone https://github.com/gyxuehu/EwoMail.git这个命令输完就停手  
  
![1744706215_67fe1aa750a8a1f6e05fe.png!small?1744706123713](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JFC7uic2wagG3iaj9BibXMffwCRibPSCABpwGO9EsfbTiaeef6ZCSuznrkAg/640?wx_fmt=jpeg&from=appmsg "")  
  
就是有点慢，耐心等待吧，下载过程中查看你申请的域名  
  
![1744706227_67fe1ab31f56ad6a44176.png!small?1744706135623](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JIiav4jLYkOIBGzlia4jjEib0wX6VMEX53qsnUUsV8ECE67OEyDBGGMlww/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706230_67fe1ab6aec5642d9e6eb.png!small?1744706139707](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JGjs8Fiag3TSyVKVCm4uWSE0bYgLFhe4e6aLqe5t3E4X7T7lxz8UqLVA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706300_67fe1afc78c5d9be95a06.png!small?1744706209147](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JoWBskj6W9bSngtYCibQEZU2AVoFa6VS2Z96nq8IV9yzYOGhqyxNgz1g/640?wx_fmt=jpeg&from=appmsg "")  
  
然后点击解析设置，可以查看到官网文档里有表格，当然不会的可以看我一步一步做  
  
![1744706316_67fe1b0cc83eb5e4888e0.png!small?1744706225314](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JazMxwjq4pNSUpCR1jp4mMDusVF8MlnqVR14zcLOBwbNKgcDDnGJ9yA/640?wx_fmt=jpeg&from=appmsg "")  
  
第一个  
  
![1744706350_67fe1b2ef358b5c163911.png!small?1744706259788](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JSZibU12N0XvvFuD7vU62P5CDmU5Xickj1cKEty5Jb6SiacTuXdfkh5dfA/640?wx_fmt=jpeg&from=appmsg "")  
  
第二个  
  
![1744706354_67fe1b32ec14cf9379ed4.png!small?1744706263548](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J0icZ8rxWeopicC8PRrOXYoc1teWtW3xiaic6PibmOFiaYfJS0L1PI8OZr5DQ/640?wx_fmt=jpeg&from=appmsg "")  
  
第三个  
  
![1744706361_67fe1b39562ee226c973a.png!small?1744706270270](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JYObTIv3VKLicApvTHTM1rnIOHd4rwzxPWuYeV75SyDlKLoQHvMlic6zg/640?wx_fmt=jpeg&from=appmsg "")  
  
第四个  
  
![1744706365_67fe1b3d44768cbdcf5e2.png!small?1744706274734](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J3ekdvoIaJNWv2iam7icPqzFa08YSL4ycAJ4dy59Bzicq1c7Zu9CMiblE2A/640?wx_fmt=jpeg&from=appmsg "")  
  
第五个  
  
![1744706370_67fe1b420e32ccf271d58.png!small?1744706278996](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J4r7ibAF609zT5evdXSDY2xyWfQCCR9wDd2mDrXoPCCKZkdnAqwiaicuFQ/640?wx_fmt=jpeg&from=appmsg "")  
  
第六个  
  
![1744706374_67fe1b46c42d681f9d1b9.png!small?1744706283628](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JVqUoCqXUTsCvmKvlM5Mia1WUFlr0v45J6SiaKjApgAibdL6kHRicANia9fg/640?wx_fmt=jpeg&from=appmsg "")  
  
第七个  
  
![1744706383_67fe1b4f122763c50ad10.png!small?1744706291628](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jgf2UYNUhU2lQIM45mQJnXkk2ylDbFbibSgZh7J9urIkwueDWV1MIjfA/640?wx_fmt=jpeg&from=appmsg "")  
  
第七个是不是没配，因为需要你安装好后再进行配置。  
  
继续做上面没做完的安装操作，复制域名，粘贴命令 sh ./start.sh 域名  
  
注意：这里不一定每个人都会报错，我用的这个服务器会报错，所以如果全程跟我用一样的东西，涉及到的报错都能解决。  
  
如果没有解决，请回头看看自己是不是那一步做错了或者没做。  
  
不出意外会报错：那么你就输入sudo rm -f /etc/yum.repos.d/epel*.repo  
  
然后再运行  
  
![1744706434_67fe1b8224f4b1fd4fb4c.png!small?1744706342590](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JAFthc3Xl9QHVsvtqcHC1S0CS2icYldKL4640f0RZJsQNeQpYpRibBp1Q/640?wx_fmt=jpeg&from=appmsg "")  
  
就会出现新的报错，没关系  
  
继续输入解决报错命令  
  
yum install ca-certificates  
  
![1744706445_67fe1b8d55405a793aab6.png!small?1744706353951](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JTiaaEgsXzYsdiaFKFNICU893Ww8efLibKNpN9TnHQ2WiaEhsLBXLGsAnmA/640?wx_fmt=jpeg&from=appmsg "")  
  
update-ca-trust force-enable  
  
update-ca-trust extract  
  
wget -O /etc/yum.repos.d/epel.repo https://mirrors.aliyun.com/repo/epel-7.repo  
  
![1744706457_67fe1b99ee7a4992f5c9f.png!small?1744706366501](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JQtcaeG8XuataMicA8HFlZgloRUAqDfa9pawtlQeYONDmntMyhnVsRCA/640?wx_fmt=jpeg&from=appmsg "")  
  
然后再输入安装命令，这次就能成功了  
  
![1744706498_67fe1bc2a4dbff7ff6b4b.png!small?1744706407394](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JFFeQEZzKhwgV63dHw605mMvUtPqiaW6a0jeibItDUWKriateAWXBShiaicQ/640?wx_fmt=jpeg&from=appmsg "")  
  
看到这里的回显，恭喜你基本上就已经成功了  
~  
  
![1744706518_67fe1bd671a6a3c27f17b.png!small?1744706427155](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J6FmB0wsqGqeRmDjECgqZpIcHohIWFLv1wxERfhRo0LWUDbHPKbXLsA/640?wx_fmt=jpeg&from=appmsg "")  
  
最后这样就是成功啦！别急，还记得上面第七个还没配置  
  
所以根据文档  
  
![1744706530_67fe1be27fb57f5734621.png!small?1744706439048](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jlzib9MChdONQVZutQVXf6qzcXIPIRw5M2BcfcJ2FdcfNHwCpb7Ch1JA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
amavisd -c /etc/amavisd/amavisd.conf showkeys使用这个命令  
  
![1744706543_67fe1bef8098caebefbc8.png!small?1744706452120](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JK0CCFqAgUU3HK2TXZSibbSm1dV5Dslfj6DXicvWp713licIz47oZ4ZQ8w/640?wx_fmt=jpeg&from=appmsg "")  
  
然后复制这一段  
  
![1744706555_67fe1bfb7b6f84cf9e8dd.png!small?1744706463957](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jfib1SR47UNIfafrzVq4CC3JTSmnt7Ot4xHRZscPC7F7QGcicRiaJmCZuQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706559_67fe1bfff202f2b468a57.png!small?1744706468514](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JBxRBhvNmvVPaymVZAelugicxibXAUFibDRNAklfroV7FVSVrY0gbEDSCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706569_67fe1c09d3f8d3238d40d.png!small?1744706478675](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JS7ojibicvlC4uuZYAia0Hia5yQK0Q3BknSSrDkfNIJqwR1IlSrzBhpX8Ug/640?wx_fmt=jpeg&from=appmsg "")  
  
然后就需要去到刚刚阿里云配置的地方进行配置了  
  
![1744706582_67fe1c1621bcbd184642f.png!small?1744706490757](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JD0u6lWGLVdep17GQF2DzQCxBxg09YKuLrOB3hGNEozuEeVmOdVic9Lg/640?wx_fmt=jpeg&from=appmsg "")  
  
配置完成后，我们就可以使用  
  
http://45.207.39.114:8000/  
邮件发射服务器，记得替换为你的服务器  
ip  
地址！  
  
![1744706600_67fe1c288a6156624f595.png!small?1744706509080](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JJuU4riaAHWibFuRpestch9ZJEeAxvzmicGgicyOxXjw3aLLFV4YDxtM0iaw/640?wx_fmt=jpeg&from=appmsg "")  
  
http://45.207.39.114:8010/  
邮件管理服务器！  
  
![1744706639_67fe1c4fbd810af22dabd.png!small?1744706548518](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J5cnz4TKjNL8KwSibw4vTiaXYqDE3cl2azGGUmaoq6U8vM1FoUU4GCciaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
首先登录邮件管理服务器  
  
默认密码  
  
![1744706651_67fe1c5b1369cda663b90.png!small?1744706559566](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JMA4jsIjXEbr0AS7KDUUiab0NpJ5WyIA4TrXWdh16IiaAsMCkicCFn9q6Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
进去后记得更改密码（因为在公网，小心被别人攻击了~），然后就可以创建了  
  
![1744706682_67fe1c7aa04fba87eecd8.png!small?1744706591224](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JdsRVHG60Lm7YbuJX37Zh7OkA4FzQtQibcibupIl9WIZXRcXLdzDMJXlw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706687_67fe1c7f07c29aa838bb8.png!small?1744706595566](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JKJouLMEDgjkxhnE4HVHicuXYI1owIyqaP6u6gcCss3qSN0KLsRbxM4g/640?wx_fmt=jpeg&from=appmsg "")  
  
创建完邮箱，然后去到  
8000  
端口  
  
![1744706698_67fe1c8aac2f9d7e37917.png!small?1744706607325](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J9TT4h79IZ13YVCzv6tuxde5F6BniaKHtnyPMPqh9p3AsOhiaurNo3pHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
用刚刚创建的邮箱和密码  
  
![1744706716_67fe1c9c558c6ca177aab.png!small?1744706627080](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J87WwXOk6gFdXwGSt9oFoSOvtnKlTC4SyWsThk5epmqOsJ4ymZCFebQ/640?wx_fmt=jpeg&from=appmsg "")  
  
发送一封邮箱测试一下  
  
![1744706728_67fe1ca8dc488d0a1c275.png!small?1744706637327](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jm87bBGl5ibCfcLRumdhEXEqYiaib4OUM7KGwEHUq20EhCKQ1KC6cU1qBQ/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到发送域名  
admin@sendcloud.asia  
，稳啦。  
  
那么我们前面有一个坑，目标的域名不是  
info.sendcloud.com  
吗。这个  
info  
怎么办？  
  
简单呀，看文档  
  
![1744706746_67fe1cba995b125d1cc0d.png!small?1744706655496](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JYYARQtxOmjiarHiayPrYHLbDA86qhhqUu4aUIcLPDd9FX4ic2jiaxs7c2Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706752_67fe1cc089475a7d499c2.png!small?1744706661010](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JIVWlO5nnlr3uftibnCEqpjFI7NTHIBfcyibmkhv596fCxTUA1icrJjXMg/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744706756_67fe1cc463fbeab91e2cc.png!small?1744706664932](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J9XyYJBeGgSz1NGicpMB4eqibuKGymSWJ1KrpHFJJClrHWK9oDhAzntZw/640?wx_fmt=jpeg&from=appmsg "")  
  
重复刚刚的操作，是不是就得到了一个一模一样的  
~  
  
![1744706776_67fe1cd867f41a95692cf.png!small?1744706685006](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J6jMib97kIibLysaVkWCtEcaNenXXkYvZuKDTOjFHzJz78z4jDaqMK9Yg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
那么我们回到  
gophish  
中。  
  
![1744706790_67fe1ce6584e450b7e92d.png!small?1744706699020](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jiadu5WfXP5wcibGSLaKpbbrhmPLRvzQDuT20OiacQrrJald4k7pULCX6w/640?wx_fmt=jpeg&from=appmsg "")  
  
配置其实很简单啊，将自己创建的服务器填上去。  
  
smtp.  
替换为自己的域名  
:25  
  
密码就是自己刚刚创建的那个邮件服务器密码。  
  
然后就可以测试一下发送  
~  
  
往后就很简单啦，和第一篇文章是一模一样的。  
  
![1744706803_67fe1cf320741f845658b.png!small?1744706711650](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JLVyWiardHHicQw2PRB4nbaYWcePmvJud91bHNahh6hcUPe7NqicVNUGUA/640?wx_fmt=jpeg&from=appmsg "")  
  
导出这个，复制后粘贴  
  
![1744706814_67fe1cfe0d1efd816fdb3.png!small?1744706722533](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JfBrKRo3x1vOkp6h4AeugSNHbUZdhiaYB1UT83qIaW6owL0yXG4TfShA/640?wx_fmt=jpeg&from=appmsg "")  
  
最终效果  
  
![1744706833_67fe1d1176a4c0298b6b8.png!small?1744706742365](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JuTmskuLwevGyOvXQdLBicMsB9ujkPY8augY59zSDDSfCABTpKODSfNQ/640?wx_fmt=jpeg&from=appmsg "")  
  
咋样，牛逼不牛逼厉害不厉害  
~  
  
当然还有坑点没有解释  
~  
## 所有的域名都可以伪造吗？  
  
理论上可以，但实际上呢？  
  
看两个对照实验，比如我想伪造admin@qq.com这个域名  
  
我发到QQ邮箱，你会发现  
  
![1744707113_67fe1e298a54608a17cbc.png!small?1744707022134](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JCKeBibyx1E63oesxgrQWtYGuCqe3RPSXlKYJN66Aic7nnQxX5eQEfwVg/640?wx_fmt=jpeg&from=appmsg "")  
  
它会被退回，而如果我发送到网易邮箱中呢？  
  
![1744707157_67fe1e553b2bda25cafa1.png!small?1744707065737](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JOVUSgXQpvLhLwoCpYibl7V5wrDYlrQ5Wle8BCr6NF2eZML8O7KDttAw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744707189_67fe1e7524d0b9fdb4ca3.png!small?1744707098973](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JnCPCPSMehaNdfsB6UuqNKG490bP0YtZNKzDmucZiaibjXRWuFN1oWh9g/640?wx_fmt=jpeg&from=appmsg "")  
  
就成功伪造了。  
  
再看一组，肯定因为有人好奇，我为什么不用info.sendcloud.asia域名做示例，因为我懒，这里补一个截图先。  
  
![1744707506_67fe1fb28a90fc2632150.png!small?1744707415267](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1J9fQ7OMYOjZu9sx4CcEC0cYLI7FBpA6QhpyiciaGI3uiblhAibn4arTfYBw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1744707564_67fe1fec03222aca62b9c.png!small?1744707472877](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1JqjasdlcRFAWjMQXicPAxZPbEetqHpZicEB2Vgk5Iy9TFkh4quHY1BE9w/640?wx_fmt=jpeg&from=appmsg "")  
  
你看QQ的第一封邮件会出现在垃圾箱里，而第二封就不会了。  
  
而网易邮箱  
![1744707633_67fe20312436dc03f7e32.png!small?1744707542007](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWVwR9NmqF4ia3hsC6ygGBT1Jr9ZmdlXEKv3fjjNxeBIDRL8kXA0xPaxrNQ5p3MmhDYfmSQSkicFqLiaA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
一个垃圾邮件都没有。  
  
综上所述，这表示什么？表示每个邮件系统的策略其实是不一样的，而我们在操作过程中，应该首先弄明白每个邮件各自的策略，从而更好的进行钓鱼邮件攻击。  
  
好啦，今天就差不多到这了，最后祝大家天天开心、快快乐乐~  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于900人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWU0bsia0ju14OCUfVMSnyJJX4SAHwM2uxfzyQ99oMpk5ib5iavqd6nQicUWV26KKYYvm9e9AkIXKBYFBg/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满900人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWWVED9b2pQcIicYSpecBvsgjoKVqQwoTMrP4ib6NKzia8NLsUo6Z1ykmp2rpHPyNNgKeoKWpzOrgZQ0Q/640?wx_fmt=jpeg&from=appmsg "")  
  
    

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
