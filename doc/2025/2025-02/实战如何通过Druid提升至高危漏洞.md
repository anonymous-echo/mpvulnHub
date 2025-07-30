#  实战如何通过Druid提升至高危漏洞   
 实战安全研究   2025-02-09 09:06  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9evFcNH31Pjh0f83GEqsibSQsGS8uUrBPLU6VJbjw8CTibOgsYYOhqqKpaQHb9BicrJcCOYhZG0tYOg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6mG6TyJornrhz9JticBo3Nx4zhzUFXcggEDw1lkfzMI0KuLp7dW4dDCvbfgAKlLSX3yGmYg0gtXcw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
```
本公众号“猎洞时刻”旨在分享网络安全领域的相关知识，仅限于学习和研究之用。本公众号并不鼓励或支持任何非法活动。
本公众号中提供的所有内容都是基于作者的经验和知识，并仅代表作者个人的观点和意见。这些观点和意见仅供参考，不构成任何形式的承诺或保证。
本公众号不对任何人因使用或依赖本公众号提供的信息、工具或技术所造成的任何损失或伤害负责。
本公众号提供的技术和工具仅限于学习和研究之用，不得用于非法活动。任何非法活动均与本公众号的立场和政策相违背，并将依法承担法律责任。
本公众号不对使用本公众号提供的工具和技术所造成的任何直接或间接损失负责。使用者必须自行承担使用风险，同时对自己的行为负全部责任。
本公众号保留随时修改或补充免责声明的权利，而不需事先通知
```  
  
  
  
Druid是阿里巴巴开发的号称为监控而生的数据库连接池。  
  
Druid常见的就两个漏洞，一个是未授权访问，也就是不需要密码就可以登录，另一个是弱口令，也就是弱密码登录Druid。  
  
但是这两个漏洞危害很低！那么如何提升危害？请看下面内容！  
  
  
  
如何快速发现Druid？  
  
下面这个界面大家经常遇到吧，是Springboot的默认报错界面，而Springboot的项目，经常使用Druid作为数据源，因此遇到这个报错页面可以扫一下Druid路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kUGyIJqpBPLt8oRmpJEor5hN9ia6qCWOy1UsDv2YCJURwLW7XJlpOjVg/640?wx_fmt=png&from=appmsg "")  
  
可以使用Springboot-scan直接进行目录扫描。  
  
-u 是进行敏感信息扫描的，一般-u http://xxx.com就可以。  
  
下面红色的就是扫描发现了Druid  
```
https://github.com/AabyssZG/SpringBoot-Scan
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kuxZRf3lkK09xxbKa3mzlic3GZn8BNdeM0u2dKibNC2B3Ksmh8qAPiasWQ/640?wx_fmt=png&from=appmsg "")  
  
扫描Druid，一般就下面这几个常见路径。  
```
/druid/login.html
/druid/sql.html
/druid/weburi.html
/druid/websession.html
/druid/weburi.json
/druid/websession.json
/webpage/system/druid/index.html
/druid/index.html
/druid/login.html
/prod-api/druid/login.html
/prod-api/druid/index.html
/dev-api/druid/login.html
/dev-api/druid/index.html
/api/druid/login.html
/api/druid/index.html
/druid/datasource.json
/admin/druid/login.html
/admin-api/druid/login.html
/druid/submitLogin
/system/druid/websession.html
/webpage/system/druid/websession.html
```  
  
  
Druid的两个常见漏洞  
  
Druid未授权漏洞  
  
不需要密码，访问druid，直接就是已经登录的界面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kicfY3hD1b8ZNJtgKiabz04dPN2Y5t40lI1tooC9Dicran0hrPGOhv2IoA/640?wx_fmt=png&from=appmsg "")  
  
  
Druid弱口令漏洞  
  
访问后需要输入账号密码才能登录。  
  
一般就以下这几个常见默认密码。  
```
ruoyi 123456
ry 123456
ruoyi admin123
dy admin123
admin admin
admin 123456
admin admin123
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kI57OZMMgDXG3Wwe5JIVvJSWX0DmIEsGZicbVp29wLht4kpPvcrMV5MA/640?wx_fmt=png&from=appmsg "")  
  
输入密码成功后，才能进入这个页面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kC18sBA38gcbuDUl1n3mWgTGyWBZZTRmZKEp6ltBk5OzO83hsKYRGmw/640?wx_fmt=png&from=appmsg "")  
  
  
Druid怎么提升危害？  
  
下面就是一些实战案例：  
  
druid有些比较有危害的，比如路径、接口和可能有效的session  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0k3ot0YRtoPFL7OsqArFrqJ1ibmroAcMtJbMv27tvm0Epmmp9QJVtFRaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0koyRpSHuicdU89c3qmKTooUR9l5uznJXTgJD9ia7TJTAyozPaIxWFTOHQ/640?wx_fmt=png&from=appmsg "")  
  
下载这个工具，填写url和账号密码，如果是未授权访问的druid，可以不用填写账号密码。  
```
https://github.com/yuyan-sec/druid_sessions/releases/tag/1.2
```  
  
一次性给你提取session，路径和sql语句，然后方便你去进行爆破。  
  
如果需要登录的drud，记得填写账号密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kl6nZgiaIqVJcMSXiajYVM0leA0hmnfz9POd3jDxFoynGxU6ibNK0t8XqA/640?wx_fmt=png&from=appmsg "")  
  
获得了session和路径，下面就需要你去抓包，然后去爆破，看看哪个session是有效的，这里面大部分都是无效的，如果有一个是有效的，那你就直接进后台了，或者直接使用后台接口了。  
  
像这种Druid后台，他只是一个网站的小组件，一般还有另一个真正的网站，需要你去找一下，如果实在找不到，就直接使用Druid监控中记录的接口，拼接访问一下，也是可以的。然后再填写session，看看session是否有效！  
  
手动替换慢，还可以使用burp的Intruder模块进行爆破！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kxAv0wpFwpnyWBPib9iaFvtZ0cyl77XEiaDpbdqvVZoaseIwUicNWm1jAsg/640?wx_fmt=png&from=appmsg "")  
  你可以使用burp的intruder模块，去爆破通过工具复制下来的seesion，这样找到生效的session更快！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kCYHnIpXKiaG9yUO56NO5xRWicJibt2DKU66uIHDRXGpsU0BicM56z0bKPA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0k69f9icoIZdVe4IEFbGAnA5ib1eNVOrdiaKzMmu85HMYGgVpNeJVrbgVOg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kOdsmO96nuXhR5YvNMwt1fR0eaLUsAy9hdyAFIKYJoibgIQhFOKGcr3w/640?wx_fmt=png&from=appmsg "")  
  
下面的就是成功的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kicG1btxfqDibg2j2Zicb1em5vWdOjHTzXZrriaTQ0MMn7FRs7Kgefzkf5g/640?wx_fmt=png&from=appmsg "")  
  
  
  
如果获得可以使用的session，那么就找到他的前台服务网站，直接替换本地session，刷新一下，就可以保持登录了！  
  
之前成功过一次，通过爆破找到可以使用的session，找到他们的后台，然后直接F12替换session，再刷新一下，就直接进入了后台。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0k4aGfVa4XIRRcBJiabIk3yMzMjlOMEHanqA5FEgOVX7qfKAoLgcic11BQ/640?wx_fmt=png&from=appmsg "")  
  
替换session后，刷新一下，就直接步入后台，不会掉线。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kukLbWEatfSuZYlnicaXGlnicBicj6PRicZoQhsrbAj58beCGfowlfNZRBg/640?wx_fmt=png&from=appmsg "")  
  
  
  
对于这种漏洞，实际上有三种漏洞打法，和一种前后端分离打法，Druid只是其中之一，如果师傅想要看完整视频，欢迎看B站的公开课视频，直接全部扫盲！让你爱上挖洞！  
  
  
公众号文章链接：  
  
https://mp.weixin.qq.com/s/_FFhmgVrH74AXpmsqEFVFw  
  
  
B站直接视频链接：  
  
https://www.bilibili.com/video/BV1a1w5exEXX/?spm_id_from=333.1387.homepage.video_card.click  
  
  
  
  
**第二期漏洞挖掘培训课表**  
  
  
  
目前猎洞时刻漏洞挖掘第二期已经刚开课，涉及企业赏金SRC，众测赏金，线下项目渗透和安全行业工作能力提升、EDU、CNVD，目前价格仅需1299，每期都可以永久学习，并且赠送内容200+的内部知识星球，保证无保留教学,不搞水课! 酒香不怕巷子深，可以打听已经报名学员，我这边是否全程干货!绝对对得起师傅们花的钱! （课表内容持续增加，以内容最多的课表为主！）  
目前第二期还能低价上车，后面第三期即将涨价！从来没让报名的师傅觉得价格不值得，倒是学员催我涨价的不少，感谢各位师傅观看！  
  
            公众号后台回复：  
课表   
--->可以获得完整课表图  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9rz2h7EdTiapo8icicnKnF3zKXC3PYKZGajoq7TRI0wKKoAPTgSRr9km41vZITictTM9exsu90cTriabQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8IK7lTriaciaD9Jz6siafgogqsBovYj6aGNMhfVBJtdSX7XB8VgibqpFzZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8nnyWiaW43JwDgSEv6WAwkA7Szg4uNlHncMTxSDtVaibrVas5I8SyWeww/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
一句话，一千出头的价格，绝对最强的性价比，绝对是我无保留教学，童叟无欺，全靠真实无保留教学，才能快速吸引这么多学员的信任!  
  
有师傅之前被割韭菜课程坑怕过，来我这里报名后，不仅价格便宜，内容全程干货教学，直接逐帧学习，无论是赏金挖掘还是工作项目，都进步神速!还提供全天的技术咨询服务!  
  
以下均为师傅们真实反馈!!无任何造假内容!  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8RFpUED5Ox4Nocu5GASads3Mhdm86RMptNFevoIFQoLgW4hQIrBuNPQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8I3SjoIKD3QdFBMGKlGllQQce8D64LYMaRTNNLF9LXOhOWiciaBycT9Vw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU88f4jWu80cQCLic1yicQzsnfkibkEtibHN6Jp0aEXicAnvYGnricbbM7WoSsg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8ObbxibDzLDAic2ODAR59RZia6BXGNzIrGkkwLeFTLOg55pVudmuPl2d6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU87QULMuS41F7esLUDfzfKiaRmF4bHTovEtJd9WNkiaJw7wMlkowX01Lxg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
**报名联系方式**  
  
  
  
不仅仅课程报名可以加我，加入交流群，和好友列表扩充都可以加我  
  
(如果师傅被高价课程坑怕了，不妨来我这一试，不会让师傅失望的！只挣良心钱！随叫随到的技术指点服务。)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8LWspGGBUhKQiaf6SCPKRibs95dhiaibzxHd9icnticCsWXSnuzYvOP5jJ8Ng/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU86qIeicfIgQFlQSWdMF69dGJIZaGkGAyrtBh5RzbiaoJSmqxoG4GicHiaBg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic230QsrImn2pA0AAptUq0kIzJMm6ibuoUsmXDpkZjFIDcr4wyRd1aTq66ibEicXvAlZTiaBz76hZHjXg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibt43kfA610bXOcfdUianCU8bD2LeIUHOYgnOxPv9QMTe58cP7XtwfQhlibIUib4te4f19wiafCmv40Jw/640?wx_fmt=png&from=appmsg "")  
  
  
  
