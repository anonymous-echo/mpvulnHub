#  Yakit 近期漏洞复盘   
Z3r0ne  Yak Project   2023-08-31 17:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZc5BYI1O7qwYC876L6gkbkACCZMJOIAPQmNqT0uZojjJZcfPsNJk6EjcbicXiaaSZ6j4APvocaxlI1w/640?wx_fmt=gif "")  
  
  
本文作者Z3r0ne，预计阅读时间为5分钟  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdIrxhBOjaKqpTh2Wlg1RPfvxv4Y3FdJ3HEXeuGF2EWdLxVhe4icr4OgnTicNh3xFJiaSBa9zj6APQUw/640?wx_fmt=png "")  
  
  
最近师傅们提了几个Yakit安全风险的issues，牛牛在这里给大家做一个总结复盘。  
  
Yso-Java Hack  
  
01  
  
  
由l3yx师傅提出的Yso-Java Hack功能存在 `命令注入` 风险。由于Yso-Java Hack功能是由yaklang实现的，后端通过前端传入数据生成yak代码，再通过执行yak代码生成payload。在构造yak代码时，由于是直接将数据拼接，未做转义处理，导致可以注入任意代码，如图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeTK2NoqiaEqunkPt21TvW3MV7riaJlfQibgqJjBqURICgFUU0aQwjrKicoaoAAX5K7ibtukppAFJFbznA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeTK2NoqiaEqunkPt21TvW3MqRficCsiacPYk0V2pQ0vTAWJYJHQVT2nlzehRHic8UwHIQvMPN8oibKwSQ/640?wx_fmt=png "")  
  
问题的原因在于前端传入的数据在未预期情况下作为了控制语句处理，所以需要保证用户前端传入的数据在yak的语义中还是`数据`。  
## 解决方案：  
## 1、解决方案1是转义用户输入的数据，确保用户数据在yaklang代码中的语义是string literal。使用Golang的strconv.Quote函数可以将传入的字符串转为Go string literal近似作为yaklang的string literal使用，但由于yaklang的string literal相较于Golang的还有变量渲染、fuzztag渲染等功能等，后续更新版本可能存在基于二者string literal差异的绕过利用风险，所以还有方案2。  
  
  
2、为了确保传入的数据在yaklang虚拟机执行时还是数据，需要这段数据存在于string类型变量中，让数据以string literal  
的形式定义在yaklang代码中是一种方法。除此外还可以在代码执行前将变量导入虚拟机，直接将golang string 转为 yaklang string变量，如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeTK2NoqiaEqunkPt21TvW3MmEz0QdsRWeI7AmvYJloeWqk9pjFX1R41kII4La3xHCKehoy4xpLRZQ/640?wx_fmt=png "")  
  
  
网络检测  
  
02  
  
  
由Git-Again师傅提出**。**为了方便检测本地Yakit和目标连通性，前端基于ping命令实现了网络检测功能，用于前端是直接通过模板字符串生成ping命令，导致可能存在命令注入。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeTK2NoqiaEqunkPt21TvW3M0LFLglgSTRzmjlye8moVycS5Sm2YepV5uPHspUfCaZ0Xbu2zvCmgNw/640?wx_fmt=png "")  
## 解决方案：  
  
最新版Yakit已经更新为网络诊断功能，支持可配置代理的连通性诊断和dns诊断。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeTK2NoqiaEqunkPt21TvW3MSibkcPAErHwv55YU3tQ2sEIW5ibib7OiaWWqtSE7CtUicZS7T8shcJSFs6Q/640?wx_fmt=png "")  
  
使用远程模式的小伙伴注意下，网络诊断功能是yak引擎实现的，所使用的网络环境也是yak引擎所在主机。  
  
  
任意文件读取漏洞  
  
03  
  
此漏洞由Medi0cr1ty师傅提出的。已经帮师傅申请了CVE:  
  
h  
ttps://gith  
ub.com/yaklang/yaklang/security/advisories  
/GHSA-xvhg-  
w6qc-m  
3qq  
## 原因分析:  
  
由于发起请求的底层_http  
Pool函数默认会对数据包中的请求进行fuzztag解析，而yak的fuzz库使用了_httpPoo  
l函数，导致默认会对请求包中的fuzztag解析。  
mitm插件的传入参数是镜像的代理流量，很多脚本使用fuzz库对目标进行fuzz，导致了漏洞的产生。  
  
响  
应流量是目标可控的，但响应流量不会被渲染，所以需要在响应包中发起新的可控的请求，payload如下:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeTK2NoqiaEqunkPt21TvW3MJribhyPL6TuUslWapXubG2JnRRA2jC2tnnmdHHaUsquiaP9IvRyPHrkA/640?wx_fmt=png "")  
  
  
当浏览器发出POST请求时会将请求流量镜像给插件， 插件中调用了fuzz库，导致渲染了请求中的fuzztag，将本机文件信息携带出去。  
## 解决方案：  
  
fuzz  
库默  
认关闭_httpPool的fuzztag渲染功能。  
  
  
总结  
  
04  
#   
  
Yso-Java Hack功能和网络检测功能导致的问题都是self exploit，不会造成真正安全风险，但对于这种未预期的行为可能作为潜在的安全隐患，所以也及时做了修复。对于任意文件读取漏洞，从发布到修复不到一小时（by 劳模V神），师傅们及时更新就好了。  
  
**注意**  
：  
师傅们在公网部署引擎时不要偷懒使用空密码，别人连上就能RCE。师傅们也不要随便连未知的引擎，小心被反制（例如在前端调用chrome时从引擎获取到恶意的chrome路径）。  
  
**END**  
  
  
  
**更新日志**  
  
**Yaklang 1.2.5-sp4**  
  
1. 修复 CONNECT 中 Host 未设置引发的 BUG  
  
2. 修复 History 中数据包 URI 是完整 URL 的时候的 BUG  
  
3. 优化 MITM 劫持 Host 处理策略  
  
4. 修复 YakVM 符号表并发问题  
  
5. 增加报告的 CWE 支持  
  
6. 修复重定向对 307 和 302 的不当处理  
  
7. MITM 默认页面增加快捷键提示  
  
  
**YAK官方资源**  
  
YAK 语言官方教程：  
https://yaklang.com/docs/intro/Yakit 视频教程：  
https://space.bilibili.com/437503777Github下载地址：  
https://github.com/yaklang/yakitYakit官网下载地址：  
https://yaklang.com/Yakit安装文档：  
https://yaklang.com/products/download_and_installYakit使用文档：  
https://yaklang.com/products/intro/常见问题速查：  
https://yaklang.com/products/FAQ  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc6nLOagqic2nNou7bAeMlkj1CKwGWMGSiaeBCN9r5JBz87nQDSDFyRsPhWia09n3icgcNQicS7bK3qv8Q/640?wx_fmt=jpeg "")  
  
**长按识别添加工作人员**  
  
开启Yakit进阶之旅  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc5BYI1O7qwYC876L6gkbkApbD3olMibe5ibfpRe8dC7ZcUc67sHfqVs4WNUdCiaxG4b2kL7AFvicpmjA/640?wx_fmt=jpeg "")  
  
  
