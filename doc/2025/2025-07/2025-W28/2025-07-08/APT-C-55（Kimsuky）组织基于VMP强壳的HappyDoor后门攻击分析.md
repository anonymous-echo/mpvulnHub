> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyMjk4NzExMA==&mid=2247507111&idx=1&sn=aa2c1910a15aed642f0daf7ef8e38699

#  APT-C-55（Kimsuky）组织基于VMP强壳的HappyDoor后门攻击分析  
原创 高级威胁研究院  360威胁情报中心   2025-07-08 09:39  
  
**APT-C-55**  
  
    
**Kimsuky**  
  
APT-C-55（Kimsuky）是位于朝鲜的APT组织，最早由Kaspersky在2013年披露，该组织长期针对于韩国的智囊团、政府外交、新闻组织、教育学术组织等进行攻击，在过去几年里，他们将攻击目标扩大到包括美国、俄罗斯和欧洲各国在内的国家。主要目的为窃取情报、进行间谍活动等。该组织十分活跃，即使近几年不断被安全厂商披露其攻击活动，也未曾阻止APT-C-55的行动，反而有越演越烈的趋势，并不断开发各类攻击载荷，包括带有漏洞的HWP文件、恶意宏文件、释放载荷的PE文件、LNK文件等。  
  
近期，360高级威胁研究院在日常情报挖掘中发现并捕获到了Kimsuky组织针对韩国地区的最新攻击行动。该组织通过下发伪装成bandizip的安装包实施攻击，该安装包不仅会远程加载混淆的恶意代码执行，还会释放VMP壳的HappyDoor木马用于窃密行动。  
#  一、攻击活动分析   
## 1.攻击流程分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3Xv9fX9bMzWccyF7sat5peBRibycbUN7vuXvJchKVKq7vRCsVw60mbgsQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
Kimsuky通过伪造 Bandizip 安装包发起钓鱼攻击。用户运行安装包后，表面上会释放并安装正常的 Bandizip 程序以降低怀疑，但后台会远程加载脚本，分阶段下载并执行多层恶意脚本，同时还会释放并运行一个经vmp加壳的恶意载荷用于窃取敏感信息。  
## 2.载荷投递分析  
  
本次捕获样本信息如下所示：  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;"><td data-colwidth="132" width="132" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 15px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">MD5</span><o:p></o:p></span></p></td><td data-colwidth="421" width="421" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 15px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">f4cd4449e556b0580c2282fec1ca661f</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="132" width="132" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 15px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件大小</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="421" width="421" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 15px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">17.5 MB </span><span style="mso-spacerun:yes;"><span leaf=""> </span></span><span leaf="">(18021 </span></span><span style=""><span leaf="">字节</span><span lang="EN-US"><span leaf="">)</span><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:2;mso-yfti-lastrow:yes;"><td data-colwidth="132" width="132" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 15px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件名</span><span lang="EN-US"><o:p></o:p></span></span></p></td><td data-colwidth="421" width="421" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height: 20.0pt;mso-line-height-rule: exactly;font-size: 15px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mcstpf3s1vwz"><span lang="EN-US" style=""><span leaf="">bandizip installer.exe</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
该程序伪装成bandizip的安装包进行下发，程序内部使用大量无用代码进行赋值分配及释放以此来迷惑分析者。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XvU4dHDctQibv5xic54oVxFoUdIxDseoheI6G6QPK0WoR3j6mhnMssSrA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
跳过这些垃圾代码，其主要功能有3个。  
  
1）在同目录下释放  
반디집  
.exe，该程序实际为BANDIZIP的安装程序。具体做法是读取固定偏移的数据，大小为11555600字节，再通过异或0xDD解密得到。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XgrT9HLrtoNkDjdvuKr6hAtxIMn6VvZCSzAU9xmbTjLibmmC007SfKkg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
接着打开释放的반디집  
.exe，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XbLicJO9qo8icBcf9zib1xaAyuW6OM1DUibHnibhyjGjJbed6Zic7eKvDDOIg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
2）通过读取自身数据，然后异或0xDD，得到dll文件，并释放在temp临时目录下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XrAOIv56GRyaXnFqAT4ugzgKBsoyryiadwKAVzH9Razcm0LpGwev2qSw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
接着使用regsvr32 /s /n /i:a- 方式注册该dll，从而启动恶意流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XN5kPAkpGcg6ADicibVxqID7tUQwG1t8lTibD1Qe5uPM3hqbb015fr1ZPw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
3）使用mshta远程加载恶意代码执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XuDgqEOZU3pUUunJ5FmJPkIH5or6riaZjwvQtoVDwicOmQ7Axs0IsO7UA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
3.  
  
攻击组件分析  
  
如上所示本次攻击组件有2种，一是通过mshta加载的恶意脚本，二是注册的恶意dll,下面就这两种组件进行分析说明。  
   
### 3.1.脚本组件  
  
Mshta远程加载的html文件中有内嵌VBScript代码，如下所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3Xd9k6EBV5XE3Ds78dLom51ia4cdwKJSnfibquu7EcB0NwZBnIDTgicJ0FA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
解码后发现该恶意脚本存在大量无用代码，并且关键代码隐藏在其中，以此来干扰分析，如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XkrWdbY5jg6CYowy7BHXnvc9exI4yZ4PzpXTGIqdeHNJjrTCJ6Y7Ccw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
去除混淆后，可知该代码的功能是继续远程加载恶意代码执行，远程连接为：http://67.217.62[.]222/microsoft/search?zq=cnNCaG00R3JPNmxaaXIvMUtRaDJ4NjBKNkQ5UDQ5aVZqTDFvL1RBZzIrND0%3D。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XnnLkhjyjjpIe2nr1MqeQlnJsA4bD2vkRmQNRHwwdSx4dt5H3FkYzMg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
远程获取的恶意脚本对其去除无用代码后，如下所示，功能为获取用户信息（如用户名、系统信息、IP地址、网络信息、安装的杀毒软件等），以及"%programfiles%", "%programfiles% (x86)", "%programdata%\Microsoft\Windows\Start Menu\Programs", "%appdata%\Microsoft\Windows\Recent"等目录下的文件发送到  
http://67.217.62[.]222/microsoft/search?ta=NmRuVjJlOUttWUFsR2tYR1VQN1duU3JDc2ZKbXkzMzVEYTdUSlJONW5xM2NsNTV0dHQxZksvZFNmTHhEUkwxSitESnBmMVcwVEF4cDZtcmd6SGdoOFBWWXRVQ0cvYjVmZ0dCQXRHKy9WUms9  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XY7ZRMicpQKmG51xvhKWg4kBia5JIkeibAcSOtM05sNJuTWVia4HC8uyS5w/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
接着在%programdata%\Uso1\目录下创建隐藏文件.Uso1Config.conf，并使用ADS备用数据流写入数据，以此增强隐蔽性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XuSJURRB0TOXTvZ7AXHdoJb8RmWuImjp3Pv1xuJx1MDIXtxTibPzrZTg/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
然后创建计划任务执行该释放文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3Xwia5Ojzvic7w004GKvM5F85GjAQ11iawoQZHZHatqnswic0p2UreCPVm9Q/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
Uso1Config.conf文件去除混淆后如下所示，主要功能是执行post请求返回的数据，类似shell的功能。由于该脚本被用于计划任务加载，实际攻击中可通过这种方式实现多样化攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XOLia8QUA5m2ucM3rjYpicnpnOpwjsZkRgao5kq2MpdAmNyfCu6v1FXZw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
3.2.  
  
PE 组件  
  
通过  
bandizip installer.exe程序释放的  
DLL文件导出模块名为“ut_happy(x64).dll”，编译时间是2025-4-18日，是一个具有完整功能的远控程序，并且通过VMProtect进行加壳保护，混淆严重，需要脱壳分析。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XKNR6MAjTEsJ77OsicD3Im1DVqxoeMX6n3shJyp5Yz2Rt7K00veq2W5Q/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
在本次攻击中，恶意安装程序首先会通过“regsvr32.exe /s /n /i:a-”执行“ut_happy(x64).dll”，运行后该DLL会将自身释放到指定目录并通过regsvr32.exe程序多次执行，但是所传入的参数并不相同。第一次传入“a-”参数，以安装“ut_happy(x64).dll”模块，简称“install”操作。第二次传入“i-”参数，进行初始化，简称“init”操作，第三次传入“r-”参数，以执行最终的恶意代码，简称“run”操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3X1k0tkUrqz7E12rXY8B4B21Z1vMc54DBKZnfRS4Sv68uWpBguQsyJFA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
当执行“install”操作时，首先会将自身复制一份到“%AppData%\Roaming\AppRoot\app.package”，然后创建名为“Storage\Disk0\Partition0”的计划任务，该计划任务的操作是以“i-”作为参数通过“regsvr32.exe”执行“app.package”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3Xjk5Tp4YiaUtUlia0phLmWibUuhZc8YHrKn7kkk2hDUokVxzUkMHKrOmFA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
然后通过执行在临时目录下写入随机命名的bat文件，以自删除原始文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XR8yRYNGfJcDY2WytVqyJBtiaWtmlDPWUREFDKfopDxJMgpOyGNatMicA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
当执行“init”操作时，“ut_happy(x64).dll”会复制自身到“%AppData%\Roaming\AppRoot\app.package.i”，并以“i-”作为参数执行“app.package.i”。其中“app.package.i”，“app.package”和原始文件是同一个文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XbY9TSnpdOVRv8W9zkZ2AL5PT6TAHpJzRcwVnhGmbQSShoeZOicU7Atw/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
“run”操作是执行最终的窃密操作，在执行后门功能之前，首先会将RSA密钥，窃密函数地址，窃密函数名称等信息，写入 “HKEY_CURRENT_USER\SOFTWARE\Microsoft\Notepad\IfChar”中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XlffO0dGFgDhGW6vsU2vtw53RBDSWIoyWLugkEgjYMoek5WCWoq1XUQ/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
将C2地址等信息写入到注册表“HKEY_CURRENT_USER\Software\Microsoft\FTP”中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3Xk8QnBClhQuuV1ukymfptvHDz9P9AjVAqAmfpCYPkLbFAtEmibNaVfIw/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
然后，该后门会收集例如“BuildNumber”，“Architecture”等系统信息，以及获取该后门的配置信息，如用户ID、C2服务器地址等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XG1y3X3p7dI4PCuvgjZ8jgQicuXqsVad5ibIE0zZksuSrTUaOOPd204Ww/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
除此之外，该后门主要功能是执行6种不同的信息窃取操作，具体信息如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3Xat0LO7Dw8h9JGWsWwjHeEic2l0j5Bag5xYD7xslnSw5GiaoxsODZH2bA/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;height:22.7pt;mso-height-rule:
  exactly;"><td data-colwidth="126" width="126" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">screenshot</span><o:p></o:p></span></p></td><td data-colwidth="263" width="227" valign="top" style="border-top: 1pt solid windowtext;border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-image: initial;border-left: none;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">截图</span><span lang="EN-US"><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:1;height:22.7pt;mso-height-rule:exactly;"><td data-colwidth="126" width="126" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">keylogger</span><o:p></o:p></span></p></td><td data-colwidth="263" width="227" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">键盘记录器</span><span lang="EN-US"><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:2;height:22.7pt;mso-height-rule:exactly;"><td data-colwidth="126" width="126" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">filemon</span><o:p></o:p></span></p></td><td data-colwidth="263" width="227" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">文件窃取</span><span lang="EN-US"><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:3;height:22.7pt;mso-height-rule:exactly;"><td data-colwidth="126" width="126" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">alarm</span><o:p></o:p></span></p></td><td data-colwidth="263" width="227" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">收集便携式设备</span><span lang="EN-US"><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:4;height:22.7pt;mso-height-rule:exactly;"><td data-colwidth="126" width="126" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">micrec</span><o:p></o:p></span></p></td><td data-colwidth="263" width="227" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span style=""><span leaf="">录音</span><span lang="EN-US"><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:5;mso-yfti-lastrow:yes;height:22.7pt;mso-height-rule:
  exactly;"><td data-colwidth="126" width="126" valign="top" style="border-right: 1pt solid windowtext;border-bottom: 1pt solid windowtext;border-left: 1pt solid windowtext;border-image: initial;border-top: none;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;"><span lang="EN-US" style=""><span leaf="">mtpmon</span><o:p></o:p></span></p></td><td data-colwidth="263" width="227" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid windowtext;border-right: 1pt solid windowtext;padding: 0cm 5.4pt;height: 22.7pt;"><p style="text-align: left;margin-bottom: 6.0pt;mso-line-height-alt: 0pt;font-size: 16px;font-family: &#34;mp-quote&#34;, -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;" data-mpa-action-id="mcsugyq3d3k"><span style=""><span leaf="">移动设备中收集特定文件</span><span lang="EN-US"><o:p></o:p></span></span></p></td></tr></tbody></table>  
  
其中filemon会搜集指定后缀的文件，包括.hwp、.pdf、.doc、.xls、.ppt、.txt、.bmp、.png、.jpg、jpeg等类型,并按照类型保存在指定目录下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XXVuSlGsBm1n6QkuibiamiaPqAe62Gaj7Od13lZkmZGDaeM22PkKyXEDrA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XAibHciateYm6WXaqcYssyGA4yWuhoNFMACBlzoYlBQCvZQ0RkadJ1ECA/640?wx_fmt=png&from=appmsg "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
除了执行窃密操作以外，该后门还会执行部分远控功能，例如终止自身，使用 regsvr32注册DLL，收集信息等功能。![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
![]( "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Pob0QLpqmBicvooKzhTaibic3XbENpBiciamBxmC2Ez49jffTFyK0mlchrGHNKubt4zxT8hQJaCWmpcvug/640?wx_fmt=png&from=appmsg "")  
  
 二、归属研判   
  
通过对样本整体分析，我们发现本次攻击行动与Kimsuky组织之前使用的攻击手段相符合，主要体现在以下几个方面。  
  
1. 脚本行为与历史攻击手法吻合；  
  
在加载的脚本文件中，攻击者会搜集"%programfiles%", "%programfiles% (x86)", "%programdata%\Microsoft\Windows\Start Menu\Programs", "%appdata%\Microsoft\Windows\Recent"等敏感路径中的文件，该组织此前多次使用类似PowerShell脚本进行目录遍历和信息窃取。   
  
2. 最终载荷与之前该组织使用的后门同源；  
  
样本最终释放的PE文件使用VMProtect强壳进行混淆，脱壳后分析显示其核心功能属于HappyDoor后门家族  
[1]  
。该家族曾被Kimsuky组织使用，只是之前样本可能未采用VMP加固，此次升级可能旨在规避沙箱或逆向分析。此外载荷运行过程中释放的bat脚本内容与之前也类似。  
  
3. C2基础设施与历史域名模式匹配；  
  
样本连接的C2域名为u.appw.p-e.kr，符合Kimsuky组织惯用的域名格式，历史上多次注册包含p-e.kr 字符串的域名。  
  
4. 语言与上传地址。  
  
伪装的安装包恶意程序会释放真正的安装程序，并以韩文命名（  
반디집  
.exe），  
在结合上传地址为kr，这都  
与Kimsuky针对韩国目标的攻击历史相符。  
  
综上，将本轮攻击行动归属到APT-C-55（Kimsuky）组织。  
##   
  
**总结**  
  
  
APT-C-55（Kimsuky）组织长期针对韩国政府部门进行攻击，攻击手法灵活多变，常使用社会工程学、鱼叉邮件、水坑攻击等手段投递恶意文件，并且文件类型也是多种多样。本次攻击中通过伪装的恶意安装程序进行多个不同组件的下发，包括脚本文件和VMP壳的后门，并且通过分阶段加载规避检测，从而提高攻击成功率。  
  
需要说明的是，本文披露的相关恶意代码、C&C只是APT-C-55组织近期部分攻击过程中的所使用的载荷，该组织不会因为一次攻击行动的暴露而停止活动，反而会持续更新其载荷。在这里提醒用户加强安全意识，不要执行未知样本、点击来历不明的链接等，否则容易在毫无防范的情况下被攻陷，进而泄漏机密文件、重要情报。  
#   
  
**附录 IOC**  
  
MD5：  
  
f4cd4449e556b0580c2282fec1ca661f  
  
d1ec20144c83bba921243e72c517da5e  
  
16d30316a6b700c78d021df5758db775  
  
a6598bbdc947286c84f951289d14425c  
  
07fbf46d3a595a6f82e477ed4571294b  
  
URL：  
  
http://u.appw.p-e[.]kr/index.php  
  
http://d.appz.p-e[.]kr/index.php  
  
http://mrasis.n-e[.]kr/comarov/search  
  
http://67.217.62[.]222/microsoft/app/google  
  
http://67.217.62[.]222/microsoft/search  
  
  
**参考**  
  
[1] https://asec.ahnlab.com/en/76800/  
  
  
**团队介绍**  
  
  
TEAM INTRODUCTION  
  
**360****高级威胁研究院**  
  
360高级威胁研究院是360数字安全集团的核心能力支持部门，由360资深安全专家组成，专注于高级威胁的发现、防御、处置和研究，曾在全球范围内率先捕获双杀、双星、噩梦公式等多起业界知名的0day在野攻击，独家披露多个国家级APT组织的高级行动，赢得业内外的广泛认可，为360保障国家网络安全提供有力支撑。  
  
