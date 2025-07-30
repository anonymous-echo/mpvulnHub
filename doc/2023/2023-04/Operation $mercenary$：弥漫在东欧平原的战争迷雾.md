#  Operation $mercenary$：弥漫在东欧平原的战争迷雾   
原创 威胁情报中心  奇安信威胁情报中心   2023-04-10 14:00  
  
概述  
  
奇安信威胁情报中心在去年发布了《Operation(верность) mercenary：陷阵于东欧平原的钢铁洪流》介绍Conti Group在2022年上半年的渗透攻击活动。  
  
  
值得一提的是，我们在有些现场发现了Karakurt Group留下的勒索信，这从侧面印证了Karakurt Group曾经与Conti Group存在合作，国外研究人员认为Karakurt Group作为Conti Group的红队专门用来渗透攻击[1]，基于我们观察到的案例，Conti 相关的勒索事件中所用的手法和C2基础设施确实与Karakurt Group有着很深的关联，由于Conti Group已经解散，无法获得更多有价值的信息。但我们观察到新兴的Quantum勒索软件似乎与Karakurt Group有着比较深的联系。  
  
  
本文作为Operation mercenary的补充，重点介绍Karakurt Group在2022年的其他活动，相关IOC均已不活跃，仅供友商参考。  
  
  
攻击事件  
  
        我们最早观察到的攻击面是相关企业可信邮箱定向投递的钓鱼邮件，恶意附件压缩包带有密码，用于绕过邮件检测。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1LjSNbFkwGM45OddkFr669iaMcxDbiapOySVWIsuibg1rZep04dxPHTZtw/640?wx_fmt=png "")  
  
  
压缩包中为ISO文件，bat和dll文件设置了隐藏属性，诱导受害者点击名为documents的lnk文件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1IU9nsMrraWlsWcAo7uJvS8dneX9xTLKfb562pvU6k2vqGibMuVZdt7w/640?wx_fmt=png "")  
  
  
Lnk文件指向同目录下的bat脚本  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1DRcEbTJj5BkqNWZiaCMk3Ko7TMeiab2NALLibgpH9FRGyfjHwZ2EfLb1g/640?wx_fmt=png "")  
  
  
攻击者早期投递的LNK文件出现了test字样，获取到了攻击者生成LNK文件时的路径，测试时间显示为2022年6月6日。  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="560" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">路径</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;mso-yfti-lastrow:yes;"><td width="555.3333333333334" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US" style="font-size:7.5pt;line-height:150%;">C:\Users\lamar\Desktop\test link\<o:p></o:p></span></p></td></tr></tbody></table>  
攻击者后期投递的Lnk文件如下，删除了相关调试信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1Ft2yxdtCyf3Z3AL7lQ480QB2Zj1VyhJ9CU1CWgCLmVefghrwLdJpvA/640?wx_fmt=png "")  
  
  
Bat文件主要功能调用同目录下sta4m7om.dll的第一个导出函数  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1hZl1PL8q2CQRST1ZMArMtOCsw47ViczwAibT2FZKwqxHiarzkSeQXrVQg/640?wx_fmt=png "")  
  
  
主要功能为混淆器，内存加载shellcode，第二阶段shellcode会判断样本运行环境对抗沙箱，最终内存加载IcedID  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE10gFCH8mXiaj8hSWjccnqHt31A7OeasnXa1HPajiaESfiaHOtMErCeSmNA/640?wx_fmt=png "")  
  
  
IcedID的C2如下：  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="569" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:background1;">CC<o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;"><td width="569" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US">dullthingpur.com<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td width="569" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US">toughflatlying.com<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td width="564.3333333333334" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US">ettermangusta.com<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;"><td width="569" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US">wagringamuk.com<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:4;mso-yfti-lastrow:yes;"><td width="569" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US">ebothlips.com<o:p></o:p></span></p></td></tr></tbody></table>  
IcedID随后下发名为lsass.dll的Loader，内存加载CobaltStrike，  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="562" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:background1;">MD5<o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;mso-yfti-lastrow:yes;"><td width="557.3333333333334" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US">4dffb8cc2823b938bdd35506ec79b6bf<o:p></o:p></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1ib32gJKLxCd6NacBWicmSiciaPKwqyrW40lGSszQAkeJSJT5teEME76DCQ/640?wx_fmt=png "")  
  
  
攻击者在内网中尝试攻击域控，并成功拿到域管的账号密码。之后利用域管账号密码向域控下其他机器执行powershell命令内存加载CS，但被天擎拦截  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE155p5sy3HgWjTMmDDMTVKf0icZozqJzP8cWf6NDRNZ6LiaWKQm61RdlDg/640?wx_fmt=png "")  
  
  
随后攻击者通过RDP登录到目标机器，将木马手动加入杀软白名单并执行，我们在天擎隔离区中发现了mimikatz等渗透工具，攻击者在内网漫游过程中一共使用了三个CobaltStrike的C2  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="562" valign="top" style="border-width: 1pt;border-style: solid;border-color: rgb(147, 197, 113);background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:background1;">CC<o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;"><td width="562" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US">111.90.146.218:8443<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td width="557.3333333333334" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US">101.99.90.111:443<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;mso-yfti-lastrow:yes;"><td width="562" valign="top" style="border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-top: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US">172.93.181.165:443(fazehotafa.com)<o:p></o:p></span></p></td></tr></tbody></table>  
时机成熟后攻击者通过RDP登录到受害者机器退出杀软后在C:\ProgramData下批量下发加密程序。  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="300" valign="top" style="border-top: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:background1;">Md5<o:p></o:p></span></strong></p></td><td width="246.33333333333334" valign="top" style="border-top: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: none;background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:1;"><strong><span style="font-size:7.5pt;line-height:150%;font-family:宋体;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;">文件名</span></strong><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;"><td width="288.3333333333333" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US">2db78a7e5bf1854ba24d29b0141e70f9<o:p></o:p></span></p></td><td width="246.33333333333334" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:64;"><span lang="EN-US">32.exe<strong><o:p></o:p></strong></span></p></td></tr><tr style="mso-yfti-irow:1;mso-yfti-lastrow:yes;"><td width="300" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US">fac17fa9794d40d175becc4321f26c86<o:p></o:p></span></p></td><td width="246.33333333333334" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:128;"><span lang="EN-US">32.dll<strong><o:p></o:p></strong></span></p></td></tr></tbody></table>  
投递Quantum勒索软件。Quantum一直以来被认为是Conti Group Team Two来运营，是Conti勒索的替代品。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1eRniboBTrAenK8U7AK48LzQKc2h5BxXwCOyiaicdZ5grIj9xx9g9zicfGw/640?wx_fmt=png "")  
  
  
攻击者在内网横向移动中使用的一个C2（fazehotafa.com）与境外友商DFIR[2]最近发布的Quantum勒索报告中出现了重叠，值得一提的是在友商的报告中出现了另一个域名guteyutu.com，这两个域名与我们在2022年上半年监控到的Karakurt Group活动同源，鉴于Karakurt Group与老Conti之间的亲密关系，  
我们认为Karakurt Group已经深度参与到了Quantum勒索软件的投递过程中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1Mg8LUrHlWqBUVZ37jLkczIyXfLDAJ918NOFe0MrACCp9Hh7QtjXVhw/640?wx_fmt=png "")  
  
  
在Karakurt Group的其他活动中，我们观察到该团伙除了使用传统的CobaltStrike、msf、Anydesk外还了开源后门Gomet，作为CobaltStrike的备份保持对重点服务器的控制。  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td width="313" valign="top" style="border-top: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:5;"><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:background1;">Md5<o:p></o:p></span></strong></p></td><td width="224.33333333333334" valign="top" style="border-top: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-left: none;background: rgb(112, 173, 71);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:1;"><strong><span lang="EN-US" style="font-size:7.5pt;line-height:150%;color:white;mso-themecolor:background1;">CC<o:p></o:p></span></strong></p></td></tr><tr style="mso-yfti-irow:0;"><td width="307.3333333333333" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:68;"><span lang="EN-US">d037d22495a7f724ab619e736fd67def<o:p></o:p></span></p></td><td width="224.33333333333334" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);background: rgb(219, 235, 208);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:64;"><span lang="EN-US">45.76.211.131:8888<strong><o:p></o:p></strong></span></p></td></tr><tr style="mso-yfti-irow:1;mso-yfti-lastrow:yes;"><td width="307.3333333333333" valign="top" style="border-top: none;border-left: 1pt solid rgb(147, 197, 113);border-bottom: 1pt solid rgb(147, 197, 113);border-right: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:132;"><span lang="EN-US">d6ae42478de3e5d864a5d6358ca1ac48<o:p></o:p></span></p></td><td width="218.33333333333334" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(147, 197, 113);border-right: 1pt solid rgb(147, 197, 113);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:128;"><span lang="EN-US">141.164.50.109:8888<strong><o:p></o:p></strong></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1yQWibOW8cMcedicakmSFSRqd8KgBATH1xxRpVIUyEjmNapm2sGUvUhww/640?wx_fmt=png "")  
  
  
       尽管事件已经过去了大半年但其样本在VT上依然有着较高的免杀效果  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1QvoNOp2CDN9lGDNzlvrpRRuPPxVk2TDxWEoZSdZTicQMmAc27MImvpQ/640?wx_fmt=png "")  
  
  
       基于奇安信大数据平台关联，我们有中等程度以上的信心认为境外友商思科被入侵事件[3]与Karakurt Group有关。  
  
  
总结  
  
目前，基于奇安信威胁情报中心的威胁情报数据的全线产品，包括奇安信威胁情报平台（TIP）、天擎、天眼高级威胁检测系统、奇安信NGSOC、奇安信态势感知等，都已经支持对此类攻击的精确检测。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1unGGpvh9AjH5cGsoibJxiapMFdkaptphLtLuEww1dbMTpd95Rev57S6g/640?wx_fmt=png "")  
  
  
IOC  
  
**MD5：**  
  
15dd0873cb6bef0c8e89a0319a202c3a  
  
93787c6a5ba46605c0916be28ef52bf1  
  
fac17fa9794d40d175becc4321f26c86  
  
2db78a7e5bf1854ba24d29b0141e70f9  
  
4dffb8cc2823b938bdd35506ec79b6bf  
  
d037d22495a7f724ab619e736fd67def  
  
d6ae42478de3e5d864a5d6358ca1ac48  
  
3087bb457048fee050089a82c2671eaf  
  
  
**C2：**  
  
dullthingpur.com  
  
toughflatlying.com  
  
ettermangusta.com  
  
wagringamuk.com  
  
ebothlips.com  
  
fazehotafa.com  
  
111.90.146.218:8443  
  
101.99.90.111:443  
  
172.93.181.165:443  
  
45.76.211.131:8888  
  
141.164.50.109:8888  
  
  
参考链接  
  
[1]  https://www.secureworld.io/industry-news/karakurt-ransomware-conti  
  
[2] https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/  
  
[3]  https://blog.talosintelligence.com/recent-cyber-attack/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehicibGBTlOMCdXlPnzJowPgUE1xZKXu40YiaHM7WyAY1Y9W6vTHPzC5H0ZicM6VSBem2mxMWSicZmuibVFbg/640?wx_fmt=gif "")  
  
点击  
阅读原文  
至**ALPHA 6.0**  
  
即刻助力威胁研判  
  
  
