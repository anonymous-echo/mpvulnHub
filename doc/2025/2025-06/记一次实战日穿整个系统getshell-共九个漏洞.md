#  记一次实战日穿整个系统getshell-共九个漏洞  
原创 猎洞时刻  猎洞时刻   2025-06-09 12:12  
  
```
                              免责声明
本课程旨在培养具备合法合规网络安全技能的白帽子安全研究人员，专注于网络安全漏洞挖掘与防护技术。任何参与本课程的学员，均需承诺遵守国家法律法规，严格遵守网络安全行业的道德规范。
严禁黑灰产及违法行为：本课程严禁任何从事黑灰产、非法入侵、攻击他人系统或从事任何违法行为的人员参与。如果学员在学习过程中有任何违法行为，本课程及相关机构将不承担任何责任。
学员行为与本课程无关：课程内容仅供学术研究与技术提升之用，任何学员的行为与本课程无关，学员需对其行为负责，并承诺仅将所学用于合法的网络安全防护和技术研究。
参与本课程即表示您已充分理解并同意以上免责声明。如有任何疑问，欢迎与我们联系。
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9evFcNH31Pjh0f83GEqsibSQsGS8uUrBPLU6VJbjw8CTibOgsYYOhqqKpaQHb9BicrJcCOYhZG0tYOg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
# 前置说明  
  
首先在如下  
url统一身份认证,使用课程中的方法获取到账号密码，这方面并不难，方法有很多。  
  
统一身份认证处  
:  
  
https://xxxx/portal/main.html  
  
漏洞url:  
  
https://xxxxx/Login/login.html#  
# 漏洞详情  
## 站点一: 虚拟仿真系统  
  
url:  
  
https://xxxx.cn/  
### 1.弱口令  
  
门户登入后点击WEBVPN  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st3ic4ziaF9eexIaLwV9ic1DBYH6ItsLsXyupLKCYSK68XicxFo0ztvZ329g/640?wx_fmt=png&from=appmsg "")  
  
点击虚拟仿真实验  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stmp77Se00BZTNFT0oUDSc7FYLHKxKjmy3UoYNkWPG3pHobZeQXaTHJg/640?wx_fmt=png&from=appmsg "")  
  
验证码存在复用，不影响爆破，进行抓包burp跑出弱口令账密为  
  
test  
  
000000  
  
像这种测试账号，在实战中也是很常见，而且经常拥有admin的高级权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7std38elUJwatb3GT0mGibOcZBKtMrBMznicqL0FteibX4MtK2YVibAFt9vtg/640?wx_fmt=png&from=appmsg "")  
  
成功登入系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stic4Zp3VGMy2FfuMTkjTxCFxOWzNRWMdicWHr2XrhxQNRI4UBhQ9KzMbA/640?wx_fmt=png&from=appmsg "")  
### 2: sql注入  
### 进入系统后进行抓包测试，发现某个数据包存在order关键词，这种我建议写在自己的hae匹配规则，发现SQL注入关键词自动高亮。数据包中出现order、orderby等关键词要着重注意测试排序注入，排序注入无法直接被预编译防护，因此出现漏洞概率很高。  
  
漏洞url:  
  
https://xxxxScheme/Ajax/GetTrainingList?paper=1&type=1&rows=10  
  
数据包:  
  
POST /xxxxScheme/Ajax/GetTrainingList?paper=1&type=1&rows=10 HTTP/2  
  
HOST: XXXXX  
  
name=1&start=2025-03-31&end=2025-04-15&order=&ordertype=1&time=undefined&schemetype=t0  
  
  
丢入sqlmap发现order处存在注入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stjk0RxahIRJPHxRkOiazUoppQb69vtBh1IjNo8ETT7BXuNyeYNMB9t3Q/640?wx_fmt=png&from=appmsg "")  
### 3.存储型XSS  
  
点击个人信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stgMIuEwdmA7WZ8p755brIOEMrkYBR2TgQ705wFE6RibsiaKN5aQdNjUQg/640?wx_fmt=png&from=appmsg "")  
  
点击编辑  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stZEJTnmxwgbUOfcPGQKhicEZsgD7AwIxJuxgEZfSryaiaCabCLkOuzSGg/640?wx_fmt=png&from=appmsg "")  
  
姓名处写入如下payload:  
<table><tbody><tr><td data-colwidth="553" width="553" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-style: solid;border-color: windowtext;"><p style="margin-bottom:0.0000pt;"><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><font face="宋体"><span leaf="">&lt;img src=x onerror=&#34;\u0061\u006c\u0065\u0072\u0074(1)&#34;&gt;</span></font></span><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
成功弹框，打出XSS漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stooiaMYPE5cPRpOwaCt6annmHGDalvU8GRQLa4pRHYxWtKvWYyXfRy3g/640?wx_fmt=png&from=appmsg "")  
## 站点二: 财务管理系统  
### 4.存储型xss  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stkNf3fic0oCfibhSorYiaGlqMDwROUpXaQKBOTS5XZv7mI80icaSb7iaw1rQ/640?wx_fmt=png&from=appmsg "")  
  
  
点击账号设置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stzzheJDesgPZnO7XeiaTJOvicW6rgNEWwVORW81hVAwXRRVlDOWdicREXA/640?wx_fmt=png&from=appmsg "")  
  
修改昵称,输入在课程中用到的小小payload:  
<table><tbody><tr><td data-colwidth="553" width="553" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-style: solid;border-color: windowtext;"><p style="margin-bottom:0.0000pt;"><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><font face="宋体"><span leaf="">&lt;object data=&#34;data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=&#34;&gt;&lt;/object&gt;</span></font></span><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stDCj5zQnfWsL1MFra4fia56eTdPUErE4b1KZmLO9GVVqXiafhONWuD4Tg/640?wx_fmt=png&from=appmsg "")  
  
重新点击账号设置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st8QaXBRA49H03bicxR4WAq62EcDwBOkOoYjkV4cibryosPtbeOw0Ful5Q/640?wx_fmt=png&from=appmsg "")  
  
成功弹框，打出XSS漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7strficdvF1Wibs8NlSicQOicx4OaoEkyTNR12sia8mNkzz00l3YvzmYAYGZ2Q/640?wx_fmt=png&from=appmsg "")  
  
## 漏洞5: shrio反序列化RCE  
  
漏洞url:  
  
点击如下功能  
  
直接浏览器访问会跳转403,不用管,直接burp拦包获取到cookie即可,为后续工具利用提供方便，毕竟这是一个VPN内部系统，外面工具没法直接访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stM8stia0VShuyJeQQ7rFibdfgAEuWvygINCJLCqnrjsVEqUKShqtr0S0A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st1seMvebQe7N2ia87G8duCPB0w3gpL9ZAz2gUicSCLnIkbyaxOvlh6WHw/640?wx_fmt=png&from=appmsg "")  
  
经过插件+人工查看发现存在shrio特征rememberMe=deleteMe。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7styGJsd8I2LeQVp7rkN5hRq8PkSsVpmZmWkrSKpGniaDkvCvFd4z9l1kA/640?wx_fmt=png&from=appmsg "")  
  
  
点击响应复制cookie及其以下header放入放入一把嗦工具中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7sttfVKmfuKRTxwkT7aHAhbtmx1abvbnovrq4D2FOUWZv6FNwJfQMEEmA/640?wx_fmt=png&from=appmsg "")  
  
  
  
工具网址:  
  
https://github.com/SummerSec/ShiroAttack2  
  
爆破出shrio秘钥为:  
  
kPH+bIxk5D2deZiIxcaaaA==  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stiafQ5f1dYwvQ2sLKBKztxTPLS1KFfZGzrlp4JrbPD6KkBTLVJHzDSqw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stbfUgvrmrsUicJSSDod1cUbGUlRWEbQQ9pnhk6cDXNeBiaEuuu5LQm5yQ/640?wx_fmt=png&from=appmsg "")  
  
成功执行命令  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stpoD19bGbj6SG6DTXNdrAI03ibD4FaASQlRp2w091gzlL53NEayLAHsg/640?wx_fmt=png&from=appmsg "")  
  
内网主机能出网,不打了,点到为止。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stzVcSX8E2ibPC9VlqIDYt8F1mUV6Wbb4D1LFYlUUoCwad72ejYicldia1A/640?wx_fmt=png&from=appmsg "")  
##   
## 站点三:互联网+在线实验平台  
### 6.弱口令  
  
统一身份认证后点击互联网+在线实验  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st6WlrrPhiaxg4JpVxyWXaiblKr4Tl97NR2EmOwRVVkGibkTcicrp0zrSEXg/640?wx_fmt=png&from=appmsg "")  
  
弱口令账密如下(斜杠为分隔符)，该系统不仅仅admin弱口令，仍然存在测试账号弱口令，扣鸡腿！  
  
admin/admin  
  
test/test  
  
admin登入为管理员权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stCoewia4Wqj2SlPUwYJpict3fgoMlLgez22rVeibKZUBg74gcLRgYSMkTQ/640?wx_fmt=png&from=appmsg "")  
  
test用户只有少量权限，但是也可以正常使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stx9GPC0rpHKexQ0ceHKRMPmeTxaAFpS6x92djFQ5MtTrE5QnLZgb2Fw/640?wx_fmt=png&from=appmsg "")  
  
登录系统后，进行后续的测试操作。  
### 7.存储型xss  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stybZQA1vEgE1jGDtc4ibJwprsic6ID6djUaaGE7WibrzsyV35QF7Kk7uXA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stfFMpwgDpPJ7rFwNoS7WzZLxAcz0LIRSQ6trJEMt5MxgZFuia4lKmSgA/640?wx_fmt=png&from=appmsg "")  
  
备注处填入小小的payload:  
<table><tbody><tr><td data-colwidth="553" width="553" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-style: solid;border-color: windowtext;"><p style="margin-bottom:0.0000pt;"><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><font face="宋体"><span leaf="">&lt;img src=x onerror=&#34;\u0061\u006c\u0065\u0072\u0074(1)&#34;&gt;</span></font></span><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stbOEtJnQ4mwkWMVcpVnQ1C0CoSmI0rWcUwFRtVXmtSRg6HnVyaj8tKg/640?wx_fmt=png&from=appmsg "")  
  
成功弹框，打出XSS漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stc2ZXbC9aRMxY2JLicbS6hlXqB7co7Rv2c1oakuJU7raMYicuqpcZm48Q/640?wx_fmt=png&from=appmsg "")  
### 8.存储型xss  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st1ptXUdHbYco30yag3JXfVzSjvDlUHRdwzC92Pf9eZXiaQ3iaMqWkibGrQ/640?wx_fmt=png&from=appmsg "")  
  
新建一个组织进行测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stXZ1Gk4DwOmWoEbaGGwUjaBSPrzUWibwau28eOdAXATnFYprBib3QaUCg/640?wx_fmt=png&from=appmsg "")  
  
经过测试这两个地方都可以弹,payload为:  
<table><tbody><tr><td data-colwidth="553" width="553" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-style: solid;border-color: windowtext;"><p style="margin-bottom:0.0000pt;"><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><font face="宋体"><span leaf="">&lt;img src=x onerror=&#34;\u0061\u006c\u0065\u0072\u0074(1)&#34;&gt;</span></font></span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stYScD6nnpZib94UpaicVlVlYGXY0BUy1tU619uPBpvlQp4ykkiaRwqj41w/640?wx_fmt=png&from=appmsg "")  
  
成功弹框，打出XSS漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stQESCTCpo1oeghlaa9NMwrUGHusA9Q3QJ1yiavVibkYjg1EU3yXp0iar2A/640?wx_fmt=png&from=appmsg "")  
### 9.存储型xss  
  
添加课程进行测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stBPPIibscU8QeQygojWNbiclyToBcOkfRXIEOPiaavcTVXd81L8rria60EA/640?wx_fmt=png&from=appmsg "")  
  
payload:  
<table><tbody><tr><td data-colwidth="553" width="553" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-style: solid;border-color: windowtext;"><p style="margin-bottom:0.0000pt;"><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><font face="宋体"><span leaf="">&lt;img src=x onerror=&#34;\u0061\u006c\u0065\u0072\u0074(1)&#34;&gt;</span></font></span><span style="font-family:宋体;mso-bidi-font-family:&#39;Times New Roman&#39;;font-size:11.0000pt;mso-font-kerning:1.0000pt;"><o:p></o:p></span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stOwntEwhwN2qk6OrExlfqiaicm4YGxfKkCoHa9EfuE4sW7HAicJA2nk3gA/640?wx_fmt=png&from=appmsg "")  
  
成功弹框，打出XSS漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stDicRGHKcnGAG6eHeSAzKX5icn9IEfYwkbJn7SXSficbjL3DQlV44QbLNg/640?wx_fmt=png&from=appmsg "")  
## 总结：  
## 像这种内部VPN系统总是有着各种各样的漏洞，尤其是弱口令有很多，不要总盯着admin账号，像test这种测试账号也经常出现。进入系统后，各种sql注入、rce、xss、越权、未授权等漏洞就多了很多。 以上漏洞均已提交漏洞平台进行修复。  
## 感谢各位师傅观看！！祝各位师傅一路长红！！！  
##   
##            往期内容：  
## Edu实战记录 | 四个漏洞打包提交  
## 记一次无需Burp也能拿下Edu证书站  
## 记一次拿下全校信息的漏洞+垂直越权  
## 记一次非常严重的全校越权信息泄露  
## Edu证书站 | 某票据系统JS提取未授权通杀  
## XSS 如何乱杀企业SRC -公开课视频  
## SRC第二期公开课！！超全信息收集！不听白不听！  
## [收费公开课] 前后端分离渗透和三个突破口  
## Edu双一流证书站 |  github密码泄露导致的越权漏洞  
## Edu985证书站 |  一次VPN 系统内SQL注入  
## 一次越权信息泄露扩散到全校任意密码修改  
## Edu证书站嘎嘎乱杀 (三) 全校密码任意修改  
## Edu证书站嘎嘎乱杀（二）  
## Edu证书站嘎嘎乱杀（一）  
## &lt;干货&gt;微信小程序特有通用漏洞&小程序强开F12开发工具&小程序反编译&Accesstoken泄露  
##   
  
**技术交流和咨询课程加我微信**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6eD0pXNbsvuELZ16CtzibM3uL5nhCm7oicNfmjkWHGpZVDPN3TsDlatGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6wkBASUnGtVTLJFdwLRiafq5oc8QjqibWWogTsgtJQdlJlODzq0nbtUXQ/640?wx_fmt=png&from=appmsg "")  
  
(课程咨询，加群聊，好友扩列均可加我~)  
  
****  
****  
      
  
**猎洞时刻第三期漏洞挖掘培训**  
  
  
  
      目前猎洞时刻漏洞挖掘第三期正在开课中，  
覆盖企业赏金SRC，众测赏金，线下项目渗透和安全行业工作能力提升、EDUSRC、CNVD，目前价格仅需1千多  
，每期都可以永久学习，并且赠送内容200+、成员500+的内部知识星球，保证  
无保留教学  
,不搞水课!   
众多学员入职CT、LM、QAX、AH等安全大厂。 酒香不怕巷子深，可以打听已经报名学员，我这边是否全程干货!  
   
绝对对得起师傅们花的钱! (以下课表内容并非全部，经常在上课期间添加新的技能方向!)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYnKghloAvKFVA1XCTZb7icsSd5MfMibwAqEQYHyLrd9IYI9U9rRcuNhOA/640?wx_fmt=png&from=appmsg "")  
  
也是终于赢得了自己的口碑，众多学员报名后强推“  
涨价  
”的课程，我始终坚信，服务好大家，才能越走越远，越做越强。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicFpowf1mKe20qfMpLBcVUV3GNlUgJqeaXJeNbIzwcDy9Ida8A1CSxspGmFsxvvD8Lic0A0oZTTtQg/640?wx_fmt=png&from=appmsg "")  
  
  
下面是来自学员的EDUSRC挖掘成果，一个人三个月八百分，将近30本证书。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYPgLWriacNzyAksQdXYKsQD7jtMjSF7Y25IBicTG27RfiatM8ic3mbB8WbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALY74flREur5Db0xDhQQNkhPwOQa5m0TMlSYYw6A9df8DaRucXxkalafw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYrO3pcEQavRY72PWs1iahoibBuHYCibm4dicwFVgOWpicZcL0JfxXdhYSTvg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALY0yI2I0ENze3361KDnO6LoSOO8cibXQoA4qrODniayeWmMicnTpcoj5KxQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stg4yibGuRqZjASFb9MwV0mD8p50Jw034ZJictwIL03grzS3GHoWSD5uSg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
来自学员企业赏金SRC、众测赏金挖掘反馈。  
  
低价一千多的课程并不代表内容比市面上几千块的差，打破一分钱一分货的观念！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHib8yZ3NhhWwLtaxkWNkcegE3RvEoAXXpRU8bGiao5OMyTQ7KgWLiaUoPkEvp7U5taCln3WR4Eev9jIQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHico4s7YfpmcHmWDlhInfXQ3onZicYXP4Uj0ouTBT5XjibfTpA5kiaZzewcDnlKhicLxy12Oa2lm7jhU0g/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYzWcagp19avqg68yMJXCg9StedSvztuxtGT6WGBHBiaibHIYEckicljtdQ/640?wx_fmt=png&from=appmsg "")  
  
  
学员获取万元赏金，一次性回本几倍。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYq4mHFyFHQUTQQicUGGnS8DGd6Jbedpz2liaF96icgXhCIDfCeozmuHrcA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYWLzgrwhMOKM4oibbxP1JtZtQIJFAL9hfayESyzYWcUXPyqNMIEE3b6A/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
来自学员报名后的真实评价和反馈。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6ExiaaJbSDqQ9FamicjOoN4aVVwjQveKGicwNjicNe87FTDdB7P98yM44qQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
  
从一开始的疑惑不信任，怕跳入另一个培训的坑，到最后的逐帧学习！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6pZc2LXREMNIpdRNlNGwTLeasLyoPpfJ7XFy1SNRrAVOSA5VXVT0vuA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6MqcwfLpquPZVpCn91la3icYKcEFjaGMLqx4kjG25icSd8yh3n6YgnveQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
  
每节课都是花费大量时间进行撰写，不仅仅课程全程干货，针对于学员的入职、简历修改、实习和职业规划、工作内推、在线技术解答这些售后服务也一直在认真做。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6wIz6wQlIl3dRCMgYAD4PSfDuAKDWhWRyLiboPFlpmdjFwmI9Gj3MWkQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6eD0pXNbsvuELZ16CtzibM3uL5nhCm7oicNfmjkWHGpZVDPN3TsDlatGQ/640?wx_fmt=png&from=appmsg "")  
  
课程加量不加价、上述课表中的内容，不代表第三期的全部内容，实际上课会比课表多更多。  
  
课程中还会有更多  
其他师傅的技术分享  
，比如溯源反制、edu通杀挖掘、企业src挖洞新技巧等等...  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHicsfiaZKESbNhgIqu5tfwALYwIGqmltkLxbXpaLLEzu6tvafJO5Dms4WGGGtghnKFELWlIPs7VtzRQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
除此之外，包括什么HW和入职简历修改、安全厂商内推等资源、内部众测项目我们团队都是具有资源的！然后还会赠送一个永久的安全圈子(原收费圈)，有大量漏洞实战报告、各种实用工具和安全圈资源！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
  
**报名课程赠送永久纷传圈子**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6eD0pXNbsvuELZ16CtzibM3uL5nhCm7oicNfmjkWHGpZVDPN3TsDlatGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6FLfpsSWbNzwzQJza2ibjh5l0t3uicD8DeibFlUfgLvXmn2ZRiadKlnAc6g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6k8MJLUSTKbCwbEwE2yejib6SYER4uY4BtrtZUnb6SeSvuRt3AjLwLvA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6rjNT659oVt15pR0AtT7JlmpPbBUs7867ticTdKV1mG1J7Uc6u7Krukg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6DJ5I3VEY7k9SF6SUquUR3YJclSqSdNUCpjSxCcYylIHeicacZexfG5A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6VC1D4NCVicfwicEAYsX7wDv3omQiavvibbN2yA5cYfyldFoiaRVNo4vjQMA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6Ec7V2mdpARcXNrxUyhHMk8te0kpDQiaZXvyo6A31AhbuXl7n4ibc9cCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9XP1icfbxx4tSm3LXJWMmF6JibDHMf1cBZRic6MoEicRWSc8EICPuAGKMFwq388JKMxyGarX66EdPd5Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
  
