#  记录一个src挖掘的骚思路   
原创 深潜sec安全团队  深潜sec安全团队   2025-03-01 00:06  
  
## 前要  
  
    现在入行src的人太多了，很多思路已经陷入闭环不是那么好挖，我在很久以前在国外众测挖掘的时候，经常见到不要的漏洞里面有一个SPF，我就比较好奇，然后深入了解后，发现确实也有一些危害，而且国内确实没有人交过一方面的东西，结果一交，确实收获了一些赏金，这里大概是在24年初的时候，只交了4家src吧，过了两家，基本都是中危左右吧，当然我这里也只是简单的利用，有一家给的中危一级因为没过网关。  
  
    附带一提，地图api key去年过年挺火的，但是这个思路在国外平台最早是19年以前就有人交过这种了，所以说很多东西，可以多关注关注国外平台，说不定学到一些思路就在国内通杀了是吧。  
  
这里推荐几个平台自己学习一下。  
  
1.  
https://medium.com/  
2.  
https://hackerone.com/hacktivity/overview  
（多关注关注老的漏洞，真的有不少骚思路）  
3.  
推特 这个就不用说啥了吧  
## 使用方法  
### 1.检查txt记录  
  
    通过dig检查txt记录，这里我们可以看到这里是设置SPF策略，**include:spf.staff.mail.aliyun.com**，表示将spf.staff.mail.aliyun.com的SPF记录包含在当前的SPF记录中，这意味着spf.staff.mail.aliyun.com的SPF记录中所列出的邮件服务器被授权发送与该域名相关的电子邮件。然后其中关键的**-all**，代表拒绝其他所有邮件服务器发送过来的邮件，很多人为了方便会将其设置成**~all**(软拒绝)，这种其实也不是很安全的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdy0H0EuuicHEWjybA8dIoW5DUG0zzAic4ROJSVgG5L3uV1t5U0SyalB4vJzpZzxvHNHDdNiaLznC3AxA/640?wx_fmt=png&from=appmsg "null")  
  
### 2.检查mx记录  
  
然后讲讲MX记录，有MX记录的就证明存在该邮件域，假设evil.com存在MX记录，我们就可以向  
test@evil.com邮箱用户发送邮件，这里举例一个没有的MX记录的域名这里可以看到是没有任何MX记录的，然后向其域发送邮件就会失败  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdy0H0EuuicHEWjybA8dIoW5D9SyAQiaRIRaiakns84JCvRHiaaHcKqjUamSXyIqql7Jz8O9yUdU5Pq4QQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdy0H0EuuicHEWjybA8dIoW5Dac2ziaoT7msWtCTmmaAjVJDvBziakxc9FRTOGuG0IDiaOlbEyjnXWKHxA/640?wx_fmt=png&from=appmsg "null")  
### 3.漏洞利用  
  
如果发现没有设置SPF或者是设置的有问题，而且存在MX记录，那么我们就可以尝试利用，比如下列这个，存在MX，但是没有设置SPF  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdy0H0EuuicHEWjybA8dIoW5DBWZhfV7clcQkPQdVGy6l8uCx1NDicicP0haSPyB7aDuphtp21Cbsy1hQ/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdy0H0EuuicHEWjybA8dIoW5DxccT4Qibb6A24pP5iaLgUDo50TMnbKNAbcHq0ewibLUszdZuLNgBHg5uw/640?wx_fmt=png&from=appmsg "null")  
  
这里为了方便先使用网站，恶意利用通常都是使用swaks工具配合脚本，这里使用  
https://emkei.cz/[4]网站进行测试，网站的效果有限，还是推荐使用swaks工具进行高级的伪装  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdy0H0EuuicHEWjybA8dIoW5DRpxIgyOQDnVicIibibYiaQuWJRyUS1cfBrmXmB2nGEBn75QyV9PLaSFcyw/640?wx_fmt=png&from=appmsg "null")  
  
这里打开邮件，可以看到发送过来了，通常都是收集邮箱，向内网人员发送给邮件，这里使用自己的邮箱进行示例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6Qpdy0H0EuuicHEWjybA8dIoW5Dut53ib2z7acVpj1fKV2X8ojibAxa8DNBMRWUsFY2pDWKQxcZI6pOAF7w/640?wx_fmt=png&from=appmsg "null")  
  
### 4.危害介绍  
  
存在未配置SPF，而且存在mx记录，证明存在该邮件域，导致可以任意伪造该邮件域邮箱用户，对内网邮箱用户发送欺骗邮箱、木马文件、勒索病毒等，也常常用于红队钓鱼方面，是一种较为主动的AParget  
  
假如存在内网邮箱用户  
test@target.com，我们可以伪造成 "产品部<  
admin@target.com>"，向内网邮箱用户当作让你测试新产品，发送一份木马文件、勒索病毒，对内网进行破坏等，，也常常用于红队钓鱼方面  
  
### 5.危害升级  
  
1.需要伪装的更好一些，如果能过审核复现的时候能过网关，估计能算高危  
  
2.看看能不能尝试渗透他的stmp邮件结合利用，但是这个就看运气啦  
### 6.注意点  
  
部分src认为有危害，而且挺大，有一些认为没危害。  
  
  
