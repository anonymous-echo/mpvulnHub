#  Springblade JWT身份伪造漏洞与SQL注入解析   
原创 chobits02  C4安全团队   2024-03-02 01:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJRLLtYBSPZSrvHpKCMpR33fZXDsFfCUiaMUEFNjwibYVCIEMh5nHZ64C3ic4obBScxEJqbEdP461QGAg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1 "")  
  
springblade框架（又称为BladeX）是基于spring微服务二次开发的框架，广泛应用于java后端的开发中，比如哈尔滨新中新公司的慧新e校系统就是基于springblade开发的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWCkT68aMuQjYwuIiaWZqq6ZOZMibwA9DSzMLmly47oSVZqvaibfwarOS6g/640?wx_fmt=png&from=appmsg "")  
  
  
**1.JWT身份伪造解析**  
  
springblade有个jwt加密signkey默认值的漏洞，就是项目如果不指定signkey值，就会使用代码中默认值来加解密jwt。下面根据代码来分析下：  
## springblade的Gateway服务用于接受和分发请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWss7uc09TWX8KhVyIkTvdaHBPSDKI3t6XQflsUmbReOdgzo86e1nlLQ/640?wx_fmt=png&from=appmsg "")  
  
当请求到达gateway，会进入AuthFilter方法中  
  
此处headerToken为读取请求头中的jwt值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWo6icUD93Wt9O5nsodFGxib34aRoxnEyW6EU4YF0lUl8U9VQSI4aWSwdA/640?wx_fmt=png&from=appmsg "")  
  
跟踪进入AUTH_KEY  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWBTVPy3UweibDLZvnN91VbHwgFU6LypCnUEEvnYtwFHuGa5hAcS3DpiaQ/640?wx_fmt=png&from=appmsg "")  
  
再跟踪进入HEADER  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWVuwszbsNTkBT8Ch9k6fM9CiaziaS5Kf0ztGSAJl2O8tMl0d0RDHlESvw/640?wx_fmt=png&from=appmsg "")  
  
所以headerToken值为读取请求体中的Blade-Auth请求头  
  
此处headerToken非空，paramToken为空，因此不满足“缺失令牌，鉴权失败”的条件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWQNez6g9XXYvhUSGBZH2LuOdBZ41wceP7ELST5FiaN5WrnAEPJa0RR3Q/640?wx_fmt=png&from=appmsg "")  
  
追踪到getToken方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWW0k6RMXsvtiaYtiad1wiabcXTq1yKrIFqoZfokMXkGwhv1YH58Lc09t88w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWkRcMCY2a32sv4639zV9qxnvQ6Rrt3JsbRhMEibT29OMRE0WwcKPBg3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWVkl7P2IbQbayNaqelT1icKN2bCGxBJk3qZysViaofeJk98iaMPibDVojNg/640?wx_fmt=png&from=appmsg "")  
  
此处需要满足auth长度大于7，headstr为截取前6位字符串，即bearer，判断前6位满足bearer，则截取剩下的字符串作为token值  
  
再追踪parseJWT方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWMS8mW0rdE0iaYpVNOicPp1CkubjWqibicja9a0DSFbLo1y6J2osicIMCEZA/640?wx_fmt=png&from=appmsg "")  
  
跟踪进入方法，此处parseJWT解析token值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWCANwnqpYwTKhUwibrDWZbRUhB5FG3UaQNJLH36974iaCKicHL1QanWHoA/640?wx_fmt=png&from=appmsg "")  
  
设置signkey值为getBase64Security()方法返回值的base64解码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWqUZHIkFYjIXN24wkbCShjrXJGSr3QnFV1VsYAODPaE2aFGLYkCNWAg/640?wx_fmt=png&from=appmsg "")  
  
如下图追踪到getSignKey()方法，可以发现此处使用了默认的signkey值  
```
bladexisapowerfulmicroservicearchitectureupgradedandoptimizedfromacommercialproject

```  
  
所以此处是为了验证JWT的完整性和真实性，需要使用签名密钥对签名部分进行验证，如果签名密钥signKey不一致，则claims为空，返回请求未授权（  
JWT身份伪造漏洞就出在这一步，JWT的密钥为默认的值，可以让攻击者伪造身份）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWCbMJCgDEwCJ7csJAjKq2k29XbibIkk41FnEUeQZNN9Lfucgr3K5vmAg/640?wx_fmt=png&from=appmsg "")  
  
  
**2.export-user接口SQL注入解析**  
  
这个SQL注入本质上是个后台注入漏洞  
  
因为外部输入未经过滤直接拼接到SQL语句中，危险传参了如下SQL语句：  
```
${ew.customSqlSegment}
```  
  
允许用户自定义sql语句拼接到查询语句中  
  
查看漏洞所在的blade-user模块，可以发现export-user接口中就带了这个危险语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWACCgxam4eLJ2A9T6VkN73aiaXwsn6kqSzobUDS2uErzPibzosblysSGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWvYky9iaicDIHhOGsEJoKkntJkrGX2r9DRqfibSK43hJn8SeJmx2qMMV8w/640?wx_fmt=png&from=appmsg "")  
  
之后就造成任意登录用户使用该接口都能造成SQL注入  
  
如下图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWW7caLQlvqjtxy9HVrNaWvyebHibIAH0Zd0KxjZFJJw7Gj3D73xIMVbdQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTtibvw004iaePw5TbxbryzWWXHhMNmPv1qkRic9O6tyJVXwj8qrtERAsHFv0XYT1o4xu8aOYrZNXV5A/640?wx_fmt=png&from=appmsg "")  
  
  
  
END  
  
  
关注HackingWiki漏洞感知  
  
了解更多安全相关内容  
  
  
  
  
  
