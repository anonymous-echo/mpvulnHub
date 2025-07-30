#  内网环境-actuator漏洞排查与利用   
zkaq-般若  掌控安全EDU   2023-12-02 12:01  
  
****  
  
扫码领资料  
  
获网安教程  
  
免费&进群  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco1FVfwFUib59ibtxfT0E9p3LCqbNibakO6q1NfX2eEib89fQmJkDc6V8dc2BcvicgIiaQZp4oSHGXgefpQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
#   
  
****  
本文由掌  
控  
安  
全  
学  
院  
   
-  
 般若  
   
投  
稿  
## 内网环境-Actuator漏洞排查与利用  
1. 需要清扫内网环境特定漏洞  
  
1. 速度小于每秒50左右，大于会被封ip  
  
1. 内网禁止安装任何未授权软件-只能自己写脚本  
  
## Actuator介绍  
  
Actuator’æ ktʃʊˌeɪtə是 Spring Boot 提供的对应用系统的自省和监控的集成功能，可以对应用系统进行配置查看、相关功能统计等。在 Spring Cloud 中主要是完成微服务的监控，完成监控治理。可以查看微服务间的数据处理和调用，当它们之间出现了异常，就可以快速定位到出现问题的地方。Actuator监控项![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWIepuYv6LBFf4nwicITGv3zQZMPnROwia35EMywjhvLT2gwQsTh6UznUg/640?wx_fmt=png&from=appmsg "")  
若未授权，则可通过访问的方式获取信息,造成信息泄露  
## 利用方法  
1. http://127.0.0.1:port/actuator  
  
1. http://127.0.0.1:port/actuator/env  
  
## /heapdump利用方法  
  
后缀:http://127.0.0.1:port/actuator/heapdumphttp://127.0.0.1:port/actuator/actuator/heapdump  
  
注:临时网络上随便搜索了一个存在的漏洞做测试演示:利用内存泄漏分析软件MemoryAnalyzer解析Heap Dump（堆转储文件）,获取隐藏的密码探测后缀名actuator/env 若网页存在,全局搜索password,发现如下图:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWfyffMSoNFK6OZ4dTodjcBP3q7ChRdV5M66VuawmpTsiazIicwKZKmAAw/640?wx_fmt=png&from=appmsg "")  
  
访问Actuator/heapdump 后缀发现可下载内存文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWDrQjnaZicibM6HPQu1ZQICjic5iczhbCVtZ71GcUxm56n4vauGFDRFStTA/640?wx_fmt=png&from=appmsg "")  
  
利用内存分析工具分析上述下载文件:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWDrQjnaZicibM6HPQu1ZQICjic5iczhbCVtZ71GcUxm56n4vauGFDRFStTA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWAicplgIicZY9Hf3spcRib3M0FxYDAhzvdQwHYLMKjicNia91HQkQTzAhaDA/640?wx_fmt=png&from=appmsg "")  
1.选择  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWicSwSZekBu6SQmBxZXiaoZ2dq0kZgltVUR4M6mEyQNI2jyVChh86WwEQ/640?wx_fmt=png&from=appmsg "")  
  
2.File->open Heap Dump -> 选择 All Files－＞然后选择hump文件->利用OQL查找  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSW1aunxsOWLXGFk9bA9bN8dnOj5TzEK1TyTy7FtaHdoicy41OKVvFzPBQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWjvY8Fz0eV8DRwGqoVBYziblzo7b2dhSZKrW75t5511aa5r8m8BVGbJA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWS2vrlXC4GXgibEanetUsGWqdiakquFtyOHfjGAewLEKfrnpEvnltTWrA/640?wx_fmt=png&from=appmsg "")  
  
可利用以下可用的oql代码在堆信息中找到明文密码(代码啥意思自行百度吧,我也百度了好几个小时各种尝试实验才完全弄明白…)select * from java.util.Hashtable$Entry x WHERE (toString(x.key).contains("password"))  
  
select * from java.util.LinkedHashMap$Entry x WHERE (toString(x.key).contains("password"))/  
**hua  
**/select * from java.util.LinkedHashMap$Entry x WHERE (toString(x.key).contains("spring.datasource.password"))  
  
select * from java.util.HashMap$Node x WHERE (toString(x.key).contains("password"))  
  
可看到密码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoQWB3nfvqODNlNSYwajYSWKCic3h8YtlBES8JvcYCdRfUuEsoDlPNiaPkmxAvtVh3JOzJTfnZbaAibw/640?wx_fmt=png&from=appmsg "")  
#### 附带极简测试代码  
  
注：需要请自行根据原始代码就行优化，如：增加参数，遍历，日志，独立运行功能等  
  
申  
明  
：  
本  
公  
众  
号  
所  
分  
享  
内  
容  
仅  
用  
于  
网  
络  
安  
全  
技  
术  
讨  
论  
，  
切  
勿  
用  
于  
违  
法  
途  
径  
，  
  
所  
有  
渗  
透  
都  
需  
获  
取  
授  
权  
，  
违  
者  
后  
果  
自  
行  
承  
担  
，  
与  
本  
号  
及  
作  
者  
无  
关  
，  
请  
谨  
记  
守  
法  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**没看够~？欢迎关注！**  
  
  
  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上  
千**教程+工具+交流群+靶场账号**  
哦  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vco1FVfwFUib59ibtxfT0E9p3LGPhDofes96gFP0UgSX1TibYEBb9MTFRCEQyEbuPFD9LwwnRZA0ibkwZg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
******分享后扫码加我！**  
  
  
**回顾往期内容**  
  
X  
r  
a  
y  
挂  
机  
刷  
漏  
洞  
  
零  
基  
础  
学  
黑  
客  
，  
该  
怎  
么  
学  
？  
  
网  
络  
安  
全  
人  
员  
必  
考  
的  
几  
本  
证  
书  
！  
  
文  
库  
｜  
内  
网  
神  
器  
c  
s  
4  
.  
0  
使  
用  
说  
明  
书  
  
代  
码  
审  
计  
   
|  
   
这  
个  
C  
N  
V  
D  
证  
书  
拿  
的  
有  
点  
轻  
松  
  
【  
精  
选  
】  
S  
R  
C  
快  
速  
入  
门  
+  
上  
分  
小  
秘  
籍  
+  
实  
战  
指  
南  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
点  
赞  
+  
在  
看  
支  
持  
一  
下  
吧  
~  
感  
谢  
看  
官  
老  
爷  
~  
   
  
你  
的  
点  
赞  
是  
我  
更  
新  
的  
动  
力  
  
  
