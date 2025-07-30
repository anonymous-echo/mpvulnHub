#  漏洞挖掘 | 某证书站Bypass sql   
原创 zkaq-不是川北  掌控安全EDU   2024-04-04 12:03  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
本文由掌控安全学院 - 不是川北 投稿  
# 信息收集  
```
 edu证书站这么多年已经被各种大佬轮了不下几十遍了，所以各种思路也是被玩烂了。现在无非这几种方法:
找账号进统一系统----->找各种洞
子域名，ip旁站
搞vpn账号打内网
公众号小程序（也是本人目前搞的最多的方法
）.
```  
# 定位目标  
  
1、搜索证书站的名字，然后找去一个一个寻找公众号和小程序，这种方法只能慢慢来。之后就定位到了某个公众号（目前已修），公众号也是另一种的web形式，所以这里公众号的选项可能是参数点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrtyYASTdCpBJdvI1RnLaRshEToHeYQQEibhNYTBJsjReTibolIhYjDDy6WHibwLeLAz9aE2TIZpWDqA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrtyYASTdCpBJdvI1RnLaRsia2wRlgUVpRKJEemRf02J8SQosztmF9sH6bnVEjkhGAU1ynWwcWbNKg/640?wx_fmt=png&from=appmsg "")  
  
2、进行抓包处理（打个厚码），这里就是能看到各种参数值![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrtyYASTdCpBJdvI1RnLaRsOrOLeRQEfPdZ5ia9hnIdIMvskbDvC8oCB4hKib5YickMia0wqbmjurJNIw/640?wx_fmt=png&from=appmsg "")  
  
  
3、对于这种参数值，按照我的习惯，不管什么参数都试一试，试一试不要命的。单引号两个单引号进行测试，看看闭合不闭合。这里也是有一个报错页面,直接放payload。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrtyYASTdCpBJdvI1RnLaRs985ibz2bsqY2X9C2kicic3tKRMtBhS8QIIKrIlbTX3whFrOjspRwyBuQA/640?wx_fmt=png&from=appmsg "")  
  
4、对于上面的我解释一下，首先respond包里面有一个.net，那么就可以证明这是一个aspx站点，那么根据经验判断，aspx站点配mssql数据库或者access数据库。判断语言和数据库，这里的order是一个排序注入点，这里的asc可控，所以可以进行注入，至此，一枚SQL注入漏洞就到手了~  
```
数据库语句类似：select * from user order by asc
```  
  
