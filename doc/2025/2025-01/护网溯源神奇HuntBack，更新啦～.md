#  护网溯源神奇HuntBack，更新啦～   
原创 ChinaRan404  知攻善防实验室   2025-01-09 07:02  
  
前言  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v8yrCQN46lGibnfXztFesYNPLQKoYfVFK8VW5TOEhXbAHKkMkLnv7iazSic32VwJqfhUss0jcGeWJY1RlqCS3xCow/640?wx_fmt=png "")  
  
  
  
前几天重写了我一年前的项目，因为我确实用这个工具在24年HVV的时候通过这个工具溯源到了人，想着继续强化一下。  
  
这段时间通过群友的反馈指纹还有各种方式对指纹的数量做了提升  
  
目前已经支持的指纹：  
```
AWVS-Web漏洞扫描器
ARL-灯塔资产收集服务
大保健-边界资产梳理工具
H-资产收集工具
LangSrc-资产监控平台
Manjusaka-牛屎花C2管理平台
medusa-美杜莎红队武器库平台
Neme-自动化信息收集
Nessus-主机服务漏扫
NextScan-黑盒扫描
NPS-内网穿透工具
ChatGPT-ChatGPT（GPTweb）
Viper-C2管理平台
HFS-简易HTTP服务平台
Prism-X-棱镜红队作战平台
Everything-文件搜索服务
ScopeSentry-综合信息收集工具
CyberEdge-信息收集工具【老版本】
cyberedge-信息收集工具【GitHub开源】
SerializedPayloadGenerator-反序列化生成器
长亭洞鉴（X-Ray）安全评估系统
xray-scan-Xray扫描输出结果html
vulfocus-漏洞验证平台
Vulinbox-Agent(Yakit靶场)
Golin-基线核查工具
JavaChains-Java反序列化攻击工具
afrog-漏洞扫描

C2检测(C2检测原理是通过jarm指纹进行检测，目前可以用的pyjarm模块有一定的bug，会报错，不必理会)：
vshell_tcp
Cobalt Strike
Mythic
Metasploit ssl listener
Merlin
CDeimos
MacC2
MacShellSwift
Sliver
EvilGinx2
Shad0w
Get2
GRAT2 C2
Covenant
SILENTRINITY
PoshC2
```  
  
  
C2识别是是通过JARM（基于TLS（Transport Layer Security）协议的服务器指纹识别工具）  
  
结合网上已知的指纹进行的识别。  
  
  
使用方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v8yrCQN46lGibnfXztFesYNPLQKoYfVFK8VW5TOEhXbAHKkMkLnv7iazSic32VwJqfhUss0jcGeWJY1RlqCS3xCow/640?wx_fmt=png "")  
  
  
```
pip install whois
pip install ipwhois
pip install requests
pip install prettytable
pip install tqdm
pip install pyjarm
git clone https://github.com/ChinaRan0/HuntBack
如果你访问不了GitHub，可以使用夸克网盘进行下载
https://pan.quark.cn/s/5f057fad6312然后
cd HuntBack 
python HuntBack.py -h
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7voubfWvOccTTMynohwM7FC2lSNKvO0BDMaybxZXKcDq99zibfTv6Dlh22dicJnHPaSqJOFWunqdN3zw/640?wx_fmt=png&from=appmsg "")  
  
目前主要功能支持三种模式  
  
单ip模式、文件模式、值守循环模式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7voubfWvOccTTMynohwM7FC2duGAeJVf0grv5KT4Fa0SgicB3pKVITfcQ2LVDEbiapfzHkVb3iacicgWfA/640?wx_fmt=png&from=appmsg "")  
  
添加指纹  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v8yrCQN46lGibnfXztFesYNPLQKoYfVFK8VW5TOEhXbAHKkMkLnv7iazSic32VwJqfhUss0jcGeWJY1RlqCS3xCow/640?wx_fmt=png "")  
  
  
  
如果你想添加指纹，代码很简单，  
  
rule为指纹文件夹  
  
通过创建check(ip,port)函数，再从infoTest.py调用并且执行即可，当然也可以从交流群（公众号后台回复“  
交流群”）里添加我的好友，并提供指纹案例，我会第一时间去添加。  
  
也可以在公众号留言区活着GitHub的Issues像我留言功能。  
  
  
  
  
