#  记某src通过越权拿下高危漏洞   
小*咔  安全之眼SecEye   2024-08-12 21:54  
  
点击上方「蓝字」，关注我们  
  
因为公众号现在只对常读和星标的公众号才能展示大图推送，建议大家进行星标  
。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76k4fD8m0rkPrAict2lkdiaUHasZshA7Yibv0OpnNzpPKLRbGBC8ib7Fngn81sYBPpOaObsyU2iceZ4XPicQ/640?wx_fmt=png&from=appmsg "")  
  
  
01  
  
# 免责声明  
  
  
**免责声明：**  
该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。  
  
  
02  
  
# 文章正文  
  
  
在挖掘某SRC时，遇到了一个社区网站，社区站点是我在挖掘SRC时比较愿意遇到的，因为它们可探索的内容是较多的，幸运地，通过两个接口构造参数可进行越权，从而获得整个网站用户的信息。  
- 图片以进行脱敏处理。  
  
- 在登录网站后，查看产生的数据包，发现了一个特定的API接口：/gateway/nuims/nuims?Action=GetUser  
  
- 通过返回包的内容判断该接口用于获取当前用户的登录信息，包括用户名（UserName）、加密后的密码（Password）、绑定的邮箱信息、绑定的电话信息以及用户的IP地址等敏感数据。  
  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvP3jtCVx4RXP1oGg6ztJRakjI1wMP1GW4u52J2Mqsia1Q4l9L1iaoMWOQ/640?wx_fmt=png&from=appmsg "")  
  
- 此时看到返回包的信息十分激动，这接口要是能越权，就可以看到这个站点其他用户的个人信息了，漏洞这不就来了吗。  
  
- 可回头去看请求包头，发现是get请求包，参数只有Version可以修改，但是修改后没有任何效果，尽管接口返回了敏感信息，但目前看来它并不能越权到其他用户。  
  
- 会不会存在其他的参数可以进行修改，回去翻了js文件，想查看下有没有泄露的参数信息，查看后js的一些参数并不能进行构造。  
  
- 再次查看返回包时，想到该网站会不会通过userId进行权限校验的，然后在接口构造userId进行测试。  
  
- 构造参数接口，在接口/gateway/nuims/nuims?Action=GetUser&Version=2020-06-01加上UserId参数的值，UserId参数填上其他用户即可越权查看其他用户的个人账户敏感信息。  
  
- 构造后的接口：/gateway/nuims/nuims?Action=GetUser&Version=2020-06-01&UserId=xxxxxxxxxxxxx。![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvPvxMqEhctzgHg8xmdT641OicKyAvaKAYfQazhJw1jicmCJsWpDCicdyOQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvia6YVyRyexGiaqTg0c1HdJQrlCHEyAmkZ4nIUTUPKBqiaEuj5hUnv9SLQ/640?wx_fmt=png&from=appmsg "")  
  
  
- 此时我们可以看到，替换了userId参数后，可以查看到其他用户的个人信息，成功进行了越权  
  
- 继续对该站点进行测试，看看还能不能发现其他漏洞。  
  
- 通过插件findsomething获取到了另一处接口：/gw/nuims/api/v1/nuims/LcpGetUser，该接口和上一个接口返回的内容相同![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvoiaNcMBnIH8a2qIoObxNzLK0dO8iaGRBWK7RwxAxBHPicPZLKbDJnREDg/640?wx_fmt=png&from=appmsg "")  
  
  
- 那会不会和上一个接口存在同一个参数越权呢，继续构造参数进行测试，成功越权查看用户信息。![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvCoIoCnG6nOKIGACiafYUCU4nBPXtmIDqqicmiaKAE5YhwuWPteMBhJPDg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvQmzpnwADALROgz9CN5jibrl2PvrFqBRQqPDBx010cLcmfNcdXsTfOqg/640?wx_fmt=png&from=appmsg "")  
  
  
- 已经成功找到可以越权的漏洞，但是此时又出现了问题，userId参数并不是可以遍历的，不可遍历的参数，一般审核是不认可的，有可能都不给通过，更别想拿到高危了。  
  
- 所以还需要进一步挖掘，看能否获取到其他用户的userId信息，如果能拿到其他用户的userId参数，那我们不就可以拿到更多的用户信息了。  
  
- 返回首页，查看论坛界面。![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvlcXPtz2j4hbdt9cT2kcibxMISMnZddWgDGG8rxa9GYdC7fopribDzrqg/640?wx_fmt=png&from=appmsg "")  
  
  
- 查看数据包，可以发现数据包中出现的communityUserId和之前的userId的值是一样的。  
  
- 但是communityUserId是如何获取的呢，通过点击论坛里面的帖子，可以获取不同作者的communityUserId信息，这时我们就可以获取到其他用户的userId值了，再将该值进行替换，可以越权看到他人的个人账户信息了。![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvZibkquDKlKYvnicibQfFmu7D5f6WBPayBGCicUnlWZYTUcLdGzhlNAAKTA/640?wx_fmt=png&from=appmsg "")  
  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nXic3X7v5iaWg83wWWjlZaxvOSoPckMibhNraiauBsUFibqyahoc90kwViaXlcDfGVpVOXTLVYiahkNiaeuA/640?wx_fmt=png&from=appmsg "")  
  
测试完，就可以去写报告提交了，坐等高危的到来。  
  
```
来源：https://xz.aliyun.com/t/14493
```  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**星球介绍**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
高质量漏洞利用工具、漏洞POC/EXP、实战tips分享社区，日常更新0Day/Nday/1day及对应漏洞的批量利用工具，内部POC分享，星球不定时更新内外网攻防渗透技巧、src挖掘技巧等。  
同时，内部的交流群有很多行业老师傅可以为你解答学习上的疑惑  
，实战或者攻防中遇到的技术、非技术难题我们也可以通过自己的途径帮你一起解决。  
  
**【星球服务】**  
  
1，Fofa永久高级会员  
  
2，常态化更新最新的漏洞POC/EXP，未公开、半公开漏洞POC  
  
3，不定时更新SRC挖掘小技巧、SRC挖掘报告  
  
4，安全圈兼职、全职工作内推途径；职业生涯发展路线答疑解惑  
  
5，各种漏洞利用工具，渗透工具、学习资料文档分享  
  
6，加入内部微信群，认识更多的行业朋友（各大安全厂商以及互联网、金融行业甲方安全师傅），遇到任何技术问题都可以进行快速提问、讨论交流；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76nCng18dyM5JHBugAZhk667q3pyYQYNtOtIXwPd8zuDeTBrTkWRgBiaQibCibH6UTtLYNzr0C80yIHQg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
点个「在看」，你最好看  
  
