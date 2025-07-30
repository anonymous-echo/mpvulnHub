> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMTY1MTIzOA==&mid=2247484688&idx=1&sn=266aba204fedbfcfeb75f0291b0e9cea

#  【应急响应】记修复某品牌打印机FTP匿名访问漏洞  
 剁椒Muyou鱼头   2025-06-23 01:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
**阅读须知**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
  
****  
**本公众号文章皆为网上公开的漏洞，仅供日常学习使用，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把**剁椒Muyou鱼头**  
“设为星标”，否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD01hM2Bw8oTpcNCZl68Bj8T0aLpOHAMFCv9Qd6KeeQgTscOURdQUDbLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4Z7hc6oGV6C6IwibzfQUM1oq1yUciadAKQ3Ap29o8GGnBU52wXgSSicBxQ/640?wx_fmt=gif "")  
  
  
****  
**2025/06/23 星期一**  
  
**晴·西风3级**  
  
  
//01 前言  
  
  
      
最近收到一堆FTP匿名访问的安全漏洞，大体看了一眼百分之90都是打印机自带的FTP服务。各种打印机型号大多数都存在开启FTP服务的功能，先处理了立思辰LANXUM GA9540CDN这款打印机。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA0ozYt0g1366kv2gswZ3tKicIicIbwoAOy44XEparxooUjPjpF6EtpGhPnCDT9ibEmk88mNlIWBnlINQ/640?wx_fmt=png&from=appmsg "")  
  
  
//02   
FTP匿名访问漏洞  
  
  
      
FTP即文件传输协议，是在网络上进行文件传输的一套标准协议。当FTP服务器配置为允许匿名访问时，任何用户都可以无需身份验证即可登录到服务器，并可能访问、上传或下载服务器上的文件。这种配置方式存在极大的安全风险，因为黑客可以利用这一漏洞直接登录FTP服务，上传恶意文件，从而获取系统权限，并可能造成数据泄露。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA3wycbuUIxIWzic2AYgt4MKQIbiaicTuSelkLDu2yWX49T9mkh798nyic4FSicicM0qEjI8HMc0MQ3tysJg/640?wx_fmt=png&from=appmsg "")  
  
  
//03   
打印机漏洞修复  
  
  
      
直接跑去打印机物理位置看一下，发现需要账户密码登录才能关闭FTP服务，于是打了400客服转人工问到密码是Admin/Admin。并且可以直接访问443端口的WEB服务进行登录。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1P3Q7gqlFib6PpSm5EOJm5KvwbM2KIxcPibrXl9b3KS0nwgUkb3icTMPuLmOu06LsaCTW3IL3I0r8JA/640?wx_fmt=png&from=appmsg "")  
  
  
      
登录成功后在网络设定模块协议功能处，选择关闭FTP接受服务即可关闭打印机FTP问题。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1P3Q7gqlFib6PpSm5EOJm5K8dtaVC3mJk59Uy5w2RibbKOSeGuFUCLjA0c25ZR72lA0xtaGP8aGw1A/640?wx_fmt=png&from=appmsg "")  
  
  
//04 结尾  
  
  
    实际上该漏洞在内网环境下属于非常烦人的一种漏洞，不修吧，也造不成多大危害，但是又怕有的人会使用FTP服务打印一些敏感文件，就会造成信息泄露的问题。并且这种打印机自带FTP和ICMP服务产生的漏洞多达几百个，并且打印机厂商型号还不一样，还需要登录进去才能关闭服务，因为它默认是开启的。原来考虑禁掉FTP服务，但是考虑到有的人是真的需要这个服务的，也就没有实施，现在也是看一眼有没有敏感文件，没有则不管，有的话协助修复一下。  
  
  
  
    
END   
  
  
   
作者 | 剁椒Muyou鱼头  
   
  
I like you,but just like you.  
  
我喜欢你，仅仅如此，喜欢而已~  
  
  
  
  
**********点赞在看不迷路哦！**  
  
  
