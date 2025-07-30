#  记一次实战日穿整个系统getshell-共九个漏洞  
猎洞时刻  实战安全研究   2025-06-13 02:00  
  
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
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st3ic4ziaF9eexIaLwV9ic1DBYH6ItsLsXyupLKCYSK68XicxFo0ztvZ329g/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
点击虚拟仿真实验  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stmp77Se00BZTNFT0oUDSc7FYLHKxKjmy3UoYNkWPG3pHobZeQXaTHJg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
验证码存在复用，不影响爆破，进行抓包burp跑出弱口令账密为  
  
test  
  
000000  
  
像这种测试账号，在实战中也是很常见，而且经常拥有admin的高级权限。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7std38elUJwatb3GT0mGibOcZBKtMrBMznicqL0FteibX4MtK2YVibAFt9vtg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
成功登入系统。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stic4Zp3VGMy2FfuMTkjTxCFxOWzNRWMdicWHr2XrhxQNRI4UBhQ9KzMbA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
### 2: sql注入  
### 进入系统后进行抓包测试，发现某个数据包存在order关键词，这种我建议写在自己的hae匹配规则，发现SQL注入关键词自动高亮。数据包中出现order、orderby等关键词要着重注意测试排序注入，排序注入无法直接被预编译防护，因此出现漏洞概率很高。  
  
漏洞url:  
  
https://xxxxScheme/Ajax/GetTrainingList?paper=1&type=1&rows=10  
  
数据包:  
  
POST /xxxxScheme/Ajax/GetTrainingList?paper=1&type=1&rows=10 HTTP/2  
  
HOST: XXXXX  
  
name=1&start=2025-03-31&end=2025-04-15&order=&ordertype=1&time=undefined&schemetype=t0  
  
  
丢入sqlmap发现order处存在注入。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stjk0RxahIRJPHxRkOiazUoppQb69vtBh1IjNo8ETT7BXuNyeYNMB9t3Q/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
### 3.存储型XSS  
  
点击个人信息  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stgMIuEwdmA7WZ8p755brIOEMrkYBR2TgQ705wFE6RibsiaKN5aQdNjUQg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
点击编辑  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stZEJTnmxwgbUOfcPGQKhicEZsgD7AwIxJuxgEZfSryaiaCabCLkOuzSGg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
姓名处写入如下payload:  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td data-colwidth="553" width="553" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0pt 5.4pt;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1pt solid windowtext;max-width: 100%;box-sizing: border-box !important;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px 0px 0pt;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><font face="宋体" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;img src=x onerror=&#34;\u0061\u006c\u0065\u0072\u0074(1)&#34;&gt;</span></font></span><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></span></p></td></tr></tbody></table>  
成功弹框，打出XSS漏洞。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stooiaMYPE5cPRpOwaCt6annmHGDalvU8GRQLa4pRHYxWtKvWYyXfRy3g/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
## 站点二: 财务管理系统  
### 4.存储型xss  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stkNf3fic0oCfibhSorYiaGlqMDwROUpXaQKBOTS5XZv7mI80icaSb7iaw1rQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
点击账号设置  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stzzheJDesgPZnO7XeiaTJOvicW6rgNEWwVORW81hVAwXRRVlDOWdicREXA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
修改昵称,输入在课程中用到的小小payload:  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td data-colwidth="553" width="553" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0pt 5.4pt;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1pt solid windowtext;max-width: 100%;box-sizing: border-box !important;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px 0px 0pt;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><font face="宋体" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;object data=&#34;data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=&#34;&gt;&lt;/object&gt;</span></font></span><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></span></p></td></tr></tbody></table>  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stDCj5zQnfWsL1MFra4fia56eTdPUErE4b1KZmLO9GVVqXiafhONWuD4Tg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
重新点击账号设置  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st8QaXBRA49H03bicxR4WAq62EcDwBOkOoYjkV4cibryosPtbeOw0Ful5Q/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
成功弹框，打出XSS漏洞。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7strficdvF1Wibs8NlSicQOicx4OaoEkyTNR12sia8mNkzz00l3YvzmYAYGZ2Q/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
## 漏洞5: shrio反序列化RCE  
  
漏洞url:  
  
点击如下功能  
  
直接浏览器访问会跳转403,不用管,直接burp拦包获取到cookie即可,为后续工具利用提供方便，毕竟这是一个VPN内部系统，外面工具没法直接访问。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stM8stia0VShuyJeQQ7rFibdfgAEuWvygINCJLCqnrjsVEqUKShqtr0S0A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st1seMvebQe7N2ia87G8duCPB0w3gpL9ZAz2gUicSCLnIkbyaxOvlh6WHw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
经过插件+人工查看发现存在shrio特征rememberMe=deleteMe。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7styGJsd8I2LeQVp7rkN5hRq8PkSsVpmZmWkrSKpGniaDkvCvFd4z9l1kA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
点击响应复制cookie及其以下header放入放入一把嗦工具中  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7sttfVKmfuKRTxwkT7aHAhbtmx1abvbnovrq4D2FOUWZv6FNwJfQMEEmA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
工具网址:  
  
https://github.com/SummerSec/ShiroAttack2  
  
爆破出shrio秘钥为:  
  
kPH+bIxk5D2deZiIxcaaaA==  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stiafQ5f1dYwvQ2sLKBKztxTPLS1KFfZGzrlp4JrbPD6KkBTLVJHzDSqw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stbfUgvrmrsUicJSSDod1cUbGUlRWEbQQ9pnhk6cDXNeBiaEuuu5LQm5yQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
成功执行命令  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stpoD19bGbj6SG6DTXNdrAI03ibD4FaASQlRp2w091gzlL53NEayLAHsg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
内网主机能出网,不打了,点到为止。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stzVcSX8E2ibPC9VlqIDYt8F1mUV6Wbb4D1LFYlUUoCwad72ejYicldia1A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
##   
## 站点三:互联网+在线实验平台  
### 6.弱口令  
  
统一身份认证后点击互联网+在线实验  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st6WlrrPhiaxg4JpVxyWXaiblKr4Tl97NR2EmOwRVVkGibkTcicrp0zrSEXg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
弱口令账密如下(斜杠为分隔符)，该系统不仅仅admin弱口令，仍然存在测试账号弱口令，扣鸡腿！  
  
admin/admin  
  
test/test  
  
admin登入为管理员权限  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stCoewia4Wqj2SlPUwYJpict3fgoMlLgez22rVeibKZUBg74gcLRgYSMkTQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
test用户只有少量权限，但是也可以正常使用。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stx9GPC0rpHKexQ0ceHKRMPmeTxaAFpS6x92djFQ5MtTrE5QnLZgb2Fw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
登录系统后，进行后续的测试操作。  
### 7.存储型xss  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stybZQA1vEgE1jGDtc4ibJwprsic6ID6djUaaGE7WibrzsyV35QF7Kk7uXA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stfFMpwgDpPJ7rFwNoS7WzZLxAcz0LIRSQ6trJEMt5MxgZFuia4lKmSgA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
备注处填入小小的payload:  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td data-colwidth="553" width="553" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0pt 5.4pt;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1pt solid windowtext;max-width: 100%;box-sizing: border-box !important;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px 0px 0pt;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><font face="宋体" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;img src=x onerror=&#34;\u0061\u006c\u0065\u0072\u0074(1)&#34;&gt;</span></font></span><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></span></p></td></tr></tbody></table>  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stbOEtJnQ4mwkWMVcpVnQ1C0CoSmI0rWcUwFRtVXmtSRg6HnVyaj8tKg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
成功弹框，打出XSS漏洞。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stc2ZXbC9aRMxY2JLicbS6hlXqB7co7Rv2c1oakuJU7raMYicuqpcZm48Q/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
### 8.存储型xss  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7st1ptXUdHbYco30yag3JXfVzSjvDlUHRdwzC92Pf9eZXiaQ3iaMqWkibGrQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
新建一个组织进行测试  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stXZ1Gk4DwOmWoEbaGGwUjaBSPrzUWibwau28eOdAXATnFYprBib3QaUCg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
经过测试这两个地方都可以弹,payload为:  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td data-colwidth="553" width="553" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0pt 5.4pt;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1pt solid windowtext;max-width: 100%;box-sizing: border-box !important;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px 0px 0pt;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><font face="宋体" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;img src=x onerror=&#34;\u0061\u006c\u0065\u0072\u0074(1)&#34;&gt;</span></font></span></p></td></tr></tbody></table>  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stYScD6nnpZib94UpaicVlVlYGXY0BUy1tU619uPBpvlQp4ykkiaRwqj41w/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
成功弹框，打出XSS漏洞。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stQESCTCpo1oeghlaa9NMwrUGHusA9Q3QJ1yiavVibkYjg1EU3yXp0iar2A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
### 9.存储型xss  
  
添加课程进行测试  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stBPPIibscU8QeQygojWNbiclyToBcOkfRXIEOPiaavcTVXd81L8rria60EA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
payload:  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td data-colwidth="553" width="553" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0pt 5.4pt;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1pt solid windowtext;max-width: 100%;box-sizing: border-box !important;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px 0px 0pt;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><font face="宋体" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">&lt;img src=x onerror=&#34;\u0061\u006c\u0065\u0072\u0074(1)&#34;&gt;</span></font></span><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;font-size: 11pt;"><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></span></p></td></tr></tbody></table>  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stOwntEwhwN2qk6OrExlfqiaicm4YGxfKkCoHa9EfuE4sW7HAicJA2nk3gA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
成功弹框，打出XSS漏洞。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8VWQOPbxZDB3kouUjgT7stDicRGHKcnGAG6eHeSAzKX5icn9IEfYwkbJn7SXSficbjL3DQlV44QbLNg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
## 总结：  
## 像这种内部VPN系统总是有着各种各样的漏洞，尤其是弱口令有很多，不要总盯着admin账号，像test这种测试账号也经常出现。进入系统后，各种sql注入、rce、xss、越权、未授权等漏洞就多了很多。 以上漏洞均已提交漏洞平台进行修复。  
  
  
