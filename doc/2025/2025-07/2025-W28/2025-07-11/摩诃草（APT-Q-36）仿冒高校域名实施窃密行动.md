> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2MDc2MDA4OA==&mid=2247515318&idx=1&sn=d819efde9332a98af4c85316f2948b95

#  摩诃草（APT-Q-36）仿冒高校域名实施窃密行动  
原创 红雨滴团队  奇安信威胁情报中心   2025-07-11 02:04  
  
团伙背景  
  
摩诃草，又名 Patchwork、白象、Hangover、Dropping Elephant 等，奇安信内部跟踪编号 APT-Q-36。该组织被普遍认为具有南亚地区背景，其最早攻击活动可追溯到 2009 年 11 月，已持续活跃 10 余年。该组织主要针对亚洲地区的国家进行网络间谍活动，攻击目标包括政府、军事、电力、工业、科研教育、外交和经济等领域的组织机构。  
  
  
事件概述  
  
奇安信威胁情报中心近期发现摩诃草组织 LNK 攻击样本从仿冒国内高校域名的远程服务器下载诱饵文档和后续载荷，后续载荷为 Rust 编写的加载器，借助 shellcode 解密并内存加载 C# 木马。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURF3cM7Dzj4O376g4ONJGk0pA9fFhrzt5qIpAhX9Bibmd00guzsYXS1JA/640?wx_fmt=png&from=appmsg "")  
  
  
诱饵 PDF 内容为电力能源行业的技术访问路线，攻击目标可能是相关领域的研究人员。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSUR4K7HLEHhJ7JTbVFeekNOSkD3UP2upxsharn9wicfngabrYK4DLIBtEA/640?wx_fmt=png&from=appmsg "")  
  
  
详细分析  
  
相关样本信息如下：  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td data-colwidth="245" width="245" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-left: 1pt solid rgb(91, 155, 213);border-image: initial;border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  5;"><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:background1;"><span leaf="">MD5</span><o:p></o:p></span></b></p></td><td data-colwidth="128" width="128" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-left: none;border-bottom: 1pt solid rgb(91, 155, 213);border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  1;"><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">文件名</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></b></p></td><td data-colwidth="179" width="179" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-right: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-image: initial;border-left: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  1;"><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">说明</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></b></p></td></tr><tr style="mso-yfti-irow:0;"><td data-colwidth="245" width="245" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">8930abf86e2e94b1a4b373e25d01f2ff</span><o:p></o:p></span></p></td><td data-colwidth="128" width="128" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">89565254.pdf.lnk</span><o:p></o:p></span></p></td><td data-colwidth="179" width="179" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">伪装为</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">PDF</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">的</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">LNK</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">文件</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="245" width="245" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">e5cfa25f8f3fab90dc1777ac1b96c890</span><o:p></o:p></span></p></td><td data-colwidth="128" width="128" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Winver.exe</span><o:p></o:p></span></p></td><td data-colwidth="179" width="179" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">C#</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">木马</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">Loader</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;mso-yfti-lastrow:yes;"><td data-colwidth="245" width="245" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">29e584797a4c1bb71e8c1c018bd431ad</span><o:p></o:p></span></p></td><td data-colwidth="128" width="128" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Protego.exe</span><o:p></o:p></span></p></td><td data-colwidth="179" width="179" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">C#</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">木马</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr></tbody></table>  
  
****  
**LNK**  
  
恶意 LNK 执行命令如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURiaHfOUM5KAUOh7R1MKnPgBYzgicuHDfAKBD4LPYLic3xuVU7NlJrZkzrQ/640?wx_fmt=png&from=appmsg "")  
  
  
首先从 jlu-edu.org 下载诱饵 PDF 文档然后打开，然后下载后续载荷，重命名为 Winver.exe，并为其设置名为 GoogleErrorReport 的计划任务。用于下载文件的远程服务器域名仿冒国内高校，意图将恶意流量伪装为合法来源。  
  
****  
**加载器**  
  
加载器 Winver.exe 在名称上伪装成系统自带的获取版本信息的程序，由 Rust 语言编写，开发者使用的用户名为 testPD。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSUR2k9uT1s0GGsZ93iaD0jpeag4AP9icIxWee99VH5eoHdXh8ExYBFsIarA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSUR9ItJSopO0uID8VRCYfv0CiaRwz6v1GmHZ9iakt050cIjVSY2clWD7TRA/640?wx_fmt=png&from=appmsg "")  
  
  
核心功能是解密内置的一段 shellcode，然后调用 CreateThread 执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURZDU26AVqS4X51UicDvyqa64Juvg1Z4hPlXzkUxz1Xuc7QEW5CHeAcicw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURrn7hoQ06EaSUWIy2WKw3TndzZO7vL4UBw213YsdqRaVADggbkwhorw/640?wx_fmt=png&from=appmsg "")  
  
  
Shellcode 进一步解密自身数据，其中包含一个 PE 文件，shellcode 内存加载该 PE 文件并运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURgmicrw5NWJ32eDuY741gLSDxoViazDeyPeuiaQqWaOkWl5vQdicUFI3qLw/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**C#木马**  
  
内存提取出该 PE 文件，发现程序由 C# 语言编写，程序名称为Protego。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURqkibWPG9WyBaH0OalzH990iaO9MuACQM8ybpZblzQO2SpW70ibiaSZr6TQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURriaX7HDPEYICa2fQHNNbDvg915076mFqOmbuVhibX2KkbXbjicMJx82XQ/640?wx_fmt=png&from=appmsg "")  
  
  
首先创建名为 "kiuwqyergljkwef" 的互斥量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURZmoqTU7VVFjvxSqgKtaTQn9QfnWApibibnedxrThfTLAmBdO2deq39SQ/640?wx_fmt=png&from=appmsg "")  
  
  
程序中的 Accio 类执行收集信息操作，包括主机名、当前用户名、当前目录、木马进程 id 和进程名、设备 UUID 和操作系统产品名称等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURKH3fMt4yEC5GuBPUMTNsuJcDRuRf87rZVP4ibBJQ7DAWIHztAn8a0Dw/640?wx_fmt=png&from=appmsg "")  
  
  
C2服务器相关URL为hxxps://arpawebdom.org/bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURdVl8aoY0vwl0JF6Bvic2zXJSCKF2c2Sdjrb4z1JNXXsxZ3gncn1xWfQ/640?wx_fmt=png&from=appmsg "")  
  
  
木马与 C2 服务器通过 startStage 方法建立连接。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURQBBnmcNJOYfG7fWRxKNnTDuiauvjZnfwLk8ickmqJDVD4ibwehiaPTUia0g/640?wx_fmt=png&from=appmsg "")  
  
  
建立连接的过程有两个阶段。第一阶段调用 fStage 方法将生成的受害者 id（Cid）与设备 UUID（uniqid）经过加密处理后发送到 C2 服务器，并根据服务器响应内容生成后续解密木马指令的 key，然后进入第二阶段 SStage。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURoDQ7BB2CflXI8IJfia2sia1wK7db3QeRNbCK6bCtgW7W4jusyEYNfMcA/640?wx_fmt=png&from=appmsg "")  
  
  
第二阶段 SStage 获取感染设备出口 IP，然后将所有收集的信息加密后发送给 C2，如果服务器响应内容中不包含 "NOT FOUND"，表示连接建立成功，isCompl 成员被设置为 true。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURT0pEX8YnibcgVXRTBGPlDYGibpsfxwNduF3Dx2vSBJyBS1hwaiaH32hfw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURpattZBUfofcb3wx2Tl5cqkl5pYDmeRVQqYbISicndKav2djeMYJqsmg/640?wx_fmt=png&from=appmsg "")  
  
  
连接建立后，木马从 C2 服务器获取指令然后执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURKppsK8hlFX0f2PggiaHqGDBKZRlveL3qxBaCia04eB4iaHDn0QLbSZN1g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURZIGRb2zFD3DOgdZtPoeFqlaiazlCWedRViaiaY0NfuYt9cEDn2GCFhrgA/640?wx_fmt=png&from=appmsg "")  
  
  
木马指令列表如下。  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td data-colwidth="151" width="151" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-left: 1pt solid rgb(91, 155, 213);border-image: initial;border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  5;"><b><span style="font-size:12.0pt;mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">木马指令</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:background1;"><o:p></o:p></span></b></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-right: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-image: initial;border-left: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  1;"><b><span style="font-size:12.0pt;mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">功能</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:background1;"><o:p></o:p></span></b></p></td></tr><tr style="mso-yfti-irow:0;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">die</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">结束进程</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">ping</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">返回木马心跳信息</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">&#34;pong&#34;</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">pwd</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">获取当前工作目录</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">cd</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">设置当前工作目录</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:4;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">rm</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:
  bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">del</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">删除文件</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:5;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">whoami</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">获取当前用户名</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:6;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">dir</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:
  bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">ls</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">不加额外参数时列出当前工作目录信息，否则列出指定目录信息</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:7;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">ipconfig</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:
  bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">ifconfig</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">获取</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">IP</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">信息</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:8;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">cat</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:
  bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">type</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">获取指定文件内容</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:9;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">waittime, wait, responsetime</span></span><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;mso-bidi-font-weight:bold;"><span leaf="">timer</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">设置木马等待时间</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:10;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">screenshot</span></span><span style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:
  bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">schot</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">截屏</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:11;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">upload</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:
  bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">uploadfile</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">向木马感染设备上传指定文件</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:12;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">ps, process</span></span><span style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:
  bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">processes</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">获取进程列表信息</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:13;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">enablecmd, enable</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;mso-bidi-font-weight:bold;"><span leaf="">cmd</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">进入</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">cmd</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">模式，该模式下木马停止解析远程服务器下发的指令</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:14;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">inmem</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">下载载荷并内存执行</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:15;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">download</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-weight:
  bold;"><span leaf="">或</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:
  115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">get</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">将木马感染设备的指定文件打包为</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">zip</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">压缩包回传到远程服务器</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:16;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">downexe</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">下载可执行文件并执行</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:17;mso-yfti-lastrow:yes;"><td data-colwidth="151" width="151" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">lksfjdgjkxv</span><o:p></o:p></span></p></td><td data-colwidth="402" width="402" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">如果指令中包含字符串</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">&#34;lksfjdgjkxv&#34;</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">，则进入</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">cmd</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">模式，执行</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">&#34;lksfjdgjkxv&#34;</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">后的</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">cmd</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">命令，执行结束关闭</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">cmd</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">模式</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr></tbody></table>  
  
  
溯源关联  
  
在 4 月，一个类似的摩诃草 LNK 样本上传到 VT。  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td data-colwidth="245" width="245" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-left: 1pt solid rgb(91, 155, 213);border-image: initial;border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  5;"><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:background1;"><span leaf="">MD5</span><o:p></o:p></span></b></p></td><td data-colwidth="128" width="128" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-left: none;border-bottom: 1pt solid rgb(91, 155, 213);border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  1;"><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">文件名</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></b></p></td><td data-colwidth="179" width="179" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-right: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-image: initial;border-left: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  1;"><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">说明</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></b></p></td></tr><tr style="mso-yfti-irow:0;mso-yfti-lastrow:yes;"><td data-colwidth="245" width="245" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:
  bold;"><span leaf="">4cc371651f43e31df87b9f08013a14f6</span><o:p></o:p></span></p></td><td data-colwidth="128" width="128" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">8754444113.pdf.lnk</span><o:p></o:p></span></p></td><td data-colwidth="179" width="179" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;word-break:break-all;mso-yfti-cnfc:
  64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">伪装为</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">PDF</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">的</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">LNK</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">文件</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr></tbody></table>  
  
执行命令如下图所示，同样下载诱饵 PDF 文档以及恶意文件 Winver.exe 和 ItDoesAll.cfg，并设置计划任务 GoogleErrorReport。当时已有安全研究人员公开披露了该样本[1]  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURI625oRNnH5P5R7PicWx1z6N5etzBuAZOV6xX6LbZPbln9dhuu00USfg/640?wx_fmt=png&from=appmsg "")  
  
  
上面 LNK 样本的后续载荷已无法获取，而奇安信威胁情报中心发现同名恶意文件 Winver.exe（MD5：13c5617da56d8b821e6acd1d5c8f8780）出现在摩诃草组织针对国内用户的攻击中，该样本读取并加载 C:\Users\Public\ItDoesAll.cfg 文件，与 LNK 文件下载后续组件的保存路径一致。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSUR3crB6RicwRGydxacD0yXWK40EWqmOibjyeznhQDdpGfeYwibLqTOGpvzg/640?wx_fmt=png&from=appmsg "")  
  
  
受害者终端上还被下发了其他多个加载器，均是从本地文件中加载恶意载荷。加载器（MD5：2f1b002352c3a5469f5708de756f3f76）读取并加载 C:\Windows\Tasks\Update.cfg 文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURdP4dUOiaJL8Q7xe8vgTBjgu3sXmEpkxkKTVVgJkbzt0HyIPicG45yKrQ/640?wx_fmt=png&from=appmsg "")  
  
  
加载器（MD5：85ba2585c44c95c9ab40fffa2cdd6e36）读取并加载 C:\Windows\Tasks\OfficeAsyn.IDL 文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURzLChgE4qVkbILiaicfjQ3He6vh6cj8vV6mZw4g1tm15kuygFvRJThKibQ/640?wx_fmt=png&from=appmsg "")  
  
  
攻击活动中使用了同种 C# 木马（MD5：d3e719065e938dfbae05039cc305c904），并且程序名和互斥量名称完全相同。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURFtXpFp9ykmdPDPTs54R6vw1yEdlFibXFzebPPJJn9O6mfbBLJWWWD8w/640?wx_fmt=png&from=appmsg "")  
  
  
C2 服务器相关 URL 为 hxxps://aonepiece.org/bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURyvNSbod0YGzxGmiaRIL123upv5Tq3cjKvrBgFFlVacmzCR9EVU1mJXA/640?wx_fmt=png&from=appmsg "")  
  
  
除了上述 C# 木马，攻击者还下发了多个开源木马模块。  
  
开源的 Quasar RAT（MD5：1a2c0de6fa02dc92acde0821eb0e80b4），C2 为 38.146.28.17:1005。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURUPpFiaDcpu16qLrC19nwNT3jytnX4CwrUL5LZFRDuMJUMJmiacNNOW6w/640?wx_fmt=png&from=appmsg "")  
  
  
开源的 SantaRat（MD5：a8326b5c6ae046f3b3e3bf05a0c2c4e3），C2 为 162.216.240.8:6606|7707|8808。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURYCxwUIcYc8DJ8cTNawgcyvdtehFibk7ulcoqQYmtUt457WXhdQeTajg/640?wx_fmt=png&from=appmsg "")  
  
  
开源的 Quasar RAT（MD5：a5d09c82fc474371e3b83e5237310eff），C2 为 38.146.27.237:1005。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicibRHTcOKYOgltu0YErgKSURc8UaAKf5IiaDVVN1NDjMz1kI1PYzuWibph03dqHY8JJYGjOxz4rXticnA/640?wx_fmt=png&from=appmsg "")  
  
  
总结  
  
摩诃草组织针对我国的攻击经常涉及高校和科研机构，在近期攻击活动中，摩诃草仿冒高校域名，试图将恶意通信流量伪装成合法来源，隐藏攻击行为。此外，攻击者尝试更换加载器的加载方式，由读取额外的文件，转变为用内置的 shellcode 执行加载过程，但仍使用同款带有多种远控功能的 C# 木马。根据我们观察到的攻击行动，摩诃草除了利用这种 C# 木马，还会结合其他开源木马实施情报窃取。  
  
  
防护建议  
  
奇安信威胁情报中心提醒广大用户，谨防钓鱼攻击，切勿打开社交媒体分享的来历不明的链接，不点击执行未知来源的邮件附件，不运行标题夸张的未知文件，不安装非正规途径来源的APP。做到及时备份重要文件，更新安装补丁。  
  
若需运行，安装来历不明的应用，可先通过奇安信威胁情报文件深度分析平台（https://sandbox.ti.qianxin.com/sandbox/page）进行判别。目前已支持包括Windows、安卓平台在内的多种格式文件深度分析。  
  
目前，基于奇安信威胁情报中心的威胁情报数据的全线产品，包括奇安信威胁情报平台（TIP）、天擎、天眼高级威胁检测系统、奇安信NGSOC、奇安信态势感知等，都已经支持对此类攻击的精确检测。  
  
  
IOC  
  
**MD5**  
  
8930abf86e2e94b1a4b373e25d01f2ff  
  
e5cfa25f8f3fab90dc1777ac1b96c890  
  
29e584797a4c1bb71e8c1c018bd431ad  
  
4cc371651f43e31df87b9f08013a14f6  
  
13c5617da56d8b821e6acd1d5c8f8780  
  
2f1b002352c3a5469f5708de756f3f76  
  
85ba2585c44c95c9ab40fffa2cdd6e36  
  
d3e719065e938dfbae05039cc305c904  
  
1a2c0de6fa02dc92acde0821eb0e80b4  
  
a8326b5c6ae046f3b3e3bf05a0c2c4e3  
  
a5d09c82fc474371e3b83e5237310eff  
  
  
**C&C**  
  
jlu-edu.org  
  
arpawebdom.org  
  
breatlee.org  
  
aonepiece.org  
  
38.146.28.17:1005  
  
38.146.27.237:1005  
  
162.216.240.8:6606|7707|8808  
  
  
**URL**  
  
hxxps://arpawebdom.org/bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php  
  
hxxps://aonepiece.org/bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php  
  
  
参考链接  
  
[1].https://x.com/ginkgo_g/status/1915332815308403152  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehicibRHTcOKYOgltu0YErgKSUR33Un3KFaWcYezAXgKVrQqNsiajgou8xDv8cul0gqgaAB1kOwBggMJVw/640?wx_fmt=gif&from=appmsg "")  
  
点击  
阅读原文  
至**ALPHA 8.3**  
  
即刻助力威胁研判  
  
  
