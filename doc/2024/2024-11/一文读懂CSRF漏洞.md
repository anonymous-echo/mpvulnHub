#  一文读懂CSRF漏洞   
simple学安全  simple学安全   2024-11-25 06:38  
  
目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzIUPBl1F3hZk17KqG2NxgUrLR7zic08MBTwicG9qyrIj2POcNzhPaALdg/640?wx_fmt=png&from=appmsg "")  
  
简介  
  
CSRF漏洞全称跨站请求伪造漏洞，攻击者利用目标用户的身份，以目标用户的名义执行相关操作。在目标用户登录了网站的前提下，点击攻击者发送的恶意url，才能触发漏洞。  
  
常见的修改密码、分享文章、点赞、发信息等功能处，都可能存在CSRF漏洞。  
  
漏洞利用  
  
测试CSRF漏洞，主要是使用BurpSuite自带的Generate CSRF PoC功能，这里以DVWA靶场的CSRF漏洞为例。  
  
1）这是一个修改密码的功能，输入新密码，点击change即可修改密码，这里进行抓包如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKz8bAXj02djy0heyDsL7pQ5YpMUWpJD24WMs7C8CsmFG9hlhyHBmxRAA/640?wx_fmt=png&from=appmsg "")  
  
2）直接右键单击请求包，选择Engagement tools->  
Generate  
 CSRF PoC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKz0tfY8VyXnPqzQVjtEYXRf0GNylY0ECh1X82omlJstvpFRhO50V8Ubw/640?wx_fmt=png&from=appmsg "")  
  
3）在弹出的窗口中点击Copy HTML，将复制的内容保存为change.html文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzn13a9YcMicpr2sDonzY4DmtbW7n9Yp7a4iccPkAQeD4vvAXicS4gXrC6A/640?wx_fmt=png&from=appmsg "")  
  
4）模拟受害者在登录的情况下访问了该html，点击Submit request，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzNUR1dc8ia1DL4j1rbrJwXElFCV0KEichM0SFoULFqPpN8J6GOg7uYmnA/640?wx_fmt=png&from=appmsg "")  
  
5）可以看到受害者密码被成功修改  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeU9QD61S9PKSqEcjVjSNztKzYnwJoImicsfx4mNq0ick8r09AdSot32edTZhT2uuEzmoYJpwsDrY4QoQ/640?wx_fmt=png&from=appmsg "")  
  
CSRF绕过  
  
1、**绕过Referer限制**  
  
1）若验证referer字段是否包含网站域名a.com，可以尝试自己申请一个域名b.com，然后添加子域名：a.com.b.com 尝试绕过  
  
2）若验证referer字段是否包含host，也是同样的方法，添加子域名：192.168.1.1.b.com  
  
3）直接将referer字段删除  
  
2、**绕过token限制**  
  
1）将token字段删除或者置空  
  
2）使用固定的csrf_token，若服务器只检查csrf_token是否有值，而不与当前用户做匹配，则可能绕过  
  
修复建议  
  
1、验证请求的referer值  
  
2、使用token验证，服务器端验证该token，与用户一致方可通过  
  
3、添加二次确认，比如修改密码时需要验证码  
  
END  
  
**查看更多精彩内容，关注**  
**simple学安全**  
  
  
