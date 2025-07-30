> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2MDc2MDA4OA==&mid=2247515137&idx=1&sn=98a66e3565c09db9b5a0d0fc4674177b

#  Kimsuky（APT-Q-2）组织近期 Endoor 恶意软件分析  
原创 红雨滴团队  奇安信威胁情报中心   2025-06-18 02:00  
  
团伙背景  
  
Kimsuky，别名 Mystery Baby、Baby Coin、Smoke Screen、Black Banshe 等，奇安信内部跟踪编号为 APT-Q-2。该 APT 组织于 2013 年公开披露，攻击活动最早可追溯至 2012 年。Kimsuky 主要攻击目标为韩国，涉及国防、教育、能源、政府、医疗以及智囊团等领域，以机密信息窃取为主。该组织通常使用社会工程学、鱼叉邮件、水坑攻击等手段投递恶意软件，攻击手法多样，拥有针对 Windows 和 Android 平台的攻击武器。  
  
  
事件概述  
  
近期奇安信威胁情报中心发现一批 Kimsuky 组织使用的 Endoor 样本，该后门软件使用 Go 语言编写，曾在我们于 2024 年初发布的报告《软件安装包伪装下的 Kimsuky（APT-Q-2）窃密行动》[1]  
中提及，韩国安全厂商 Ahnlab 将其命名为 Endoor，名字取自样本中 Go 函数路径带有的 "/En/En/" 字符串[2]  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTKFsjRw5fP8TPKMQD7vWg9mZ9R6DpTpfZJDb8DM62icTOz99KAw6AeHA/640?wx_fmt=png&from=appmsg "")  
  
  
详细分析  
  
相关样本信息如下：  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td data-colwidth="236" width="236" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-left: 1pt solid rgb(91, 155, 213);border-image: initial;border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:5;"><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><span leaf="">MD5</span><o:p></o:p></span></b></p></td><td data-colwidth="170" width="170" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-left: none;border-bottom: 1pt solid rgb(91, 155, 213);border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:1;"><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><span leaf="">VT </span></span></b><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">上传时间</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:background1;"><o:p></o:p></span></b></p></td><td data-colwidth="94" width="94" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-left: none;border-bottom: 1pt solid rgb(91, 155, 213);border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:1;"><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">文件名</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></b></p></td><td data-colwidth="95" width="95" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-right: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-image: initial;border-left: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:1;"><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">文件类型</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></b></p></td></tr><tr style="mso-yfti-irow:0;"><td data-colwidth="236" width="236" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">e5c4f8ad27df5aa60ceb36972e29a5fb</span><o:p></o:p></span></b></p></td><td data-colwidth="170" width="170" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">2025-06-04 00:10:15 UTC</span><o:p></o:p></span></p></td><td data-colwidth="94" width="94" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">ex.pdf_</span><o:p></o:p></span></p></td><td data-colwidth="95" width="95" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">EXE</span><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;mso-yfti-lastrow:yes;"><td data-colwidth="236" width="236" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">b15cadf2a4e6670c075f80d618b26093</span><o:p></o:p></span></b></p></td><td data-colwidth="170" width="170" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">2025-06-06 07:03:07 UTC</span><o:p></o:p></span></p></td><td data-colwidth="94" width="94" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">icon.db</span><o:p></o:p></span></p></td><td data-colwidth="95" width="95" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">DLL</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
DLL 样本本身为 Endoor，而 EXE 样本是从自身数据解密出 Endoor 并在内存加载，不过两者使用的 Endoor 核心代码几乎一致，因此先以 DLL 样本为例进行分析，再介绍 EXE 样本作为加载器额外添加的操作。  
  
****  
**Endoor**  
  
DLL 样本（MD5: b15cadf2a4e6670c075f80d618b26093）的恶意功能通过导出函数 XX 进入，最终调用 Go 编写的函数 main_XX。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTo0poNicCcCM63IoRQdiaOLqH4R4938XwTWUVes9IexeEGvWlCK6vY70g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTsoEozFlicUcI3ibo8ClJPPYob0Lx7cZIdKG5WZWDgbOw9N08LXJXSZ2A/640?wx_fmt=png&from=appmsg "")  
  
  
Endoor 核心代码带有 "local.github.com" 字符串，疑似伪装为开源代码掩盖其恶意行为。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTkPTHsaBz3IibMgu1UtUjsjgTF9cp6ZLsfMXBT8BbEur1Tq0UO8bIqRQ/640?wx_fmt=png&from=appmsg "")  
  
  
**初始化操作**  
  
首先生成标记受害者的 UID。获取 Endoor 感染设备的的主机名和用户名，字符串拼接后计算 MD5 hash，提取 hash 值前 5 字节并转换为十六进制字符串格式，再带上 "XX-" 前缀和表示是否具有管理员权限的后缀（"N" 或 "Y"）。完整的 UID 格式如下：  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;mso-yfti-lastrow:yes;"><td data-colwidth="553" width="553" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">&#34;XX-[MD5 hash </span></span><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">部分值</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">]N&#34;</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">或者</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">&#34;XX-[MD5 hash </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">部分值</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">]Y&#34;</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
切换工作目录，并创建 lock 文件保证恶意程序单例运行，lock 文件以生成的 UID 命名。执行完这些初始化操作后，Endoor 进入 LoopSession 的循环。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTiaXK4UJ38SMplhTIyiaeibq2fOydKIDAWnKaPdaibZYlGeo4lJsrnpJsicA/640?wx_fmt=png&from=appmsg "")  
  
  
**C&C 通信**  
  
Endoor 连接的 C&C 服务器 URL 为 "hxxp://june.drydate.p-e.kr:53/"，通过 POST 请求传递数据，与 C&C 服务器的交互主要有获取下发指令（DownloadCommand）和回传结果（UploadResult）两部分。  
  
**(1) 获取下发指令**  
  
获取指令的请求数据格式如下，参数 1 的值为 "2"，参数 2 的值在 UID 后添加了字符 "1"。  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;mso-yfti-lastrow:yes;"><td data-colwidth="575" width="553" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">a[9 </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">字节随机字符串</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">]=2&amp;b[9 </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">字节随机字符串</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">]=[UID]1&amp;c[9 </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">字节随机字符串</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">]=</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTCia94ZLTPM594EonklwMJjVvCSmUN5wvAbzjMicVHyLTqoFUxRkJI32A/640?wx_fmt=png&from=appmsg "")  
  
  
接收到服务器响应后，Endoor 判断首字母是否为 "S"（表示 Success），如果是则尝试对首字母之外的其他数据进行 base64 解码。解码数据由 4 字节的加密 key 和加密数据组成，然后进一步执行解密操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTT9Ss67rRKMd7gvBiciabOo5XdhNLqemkHr8JAxRr4j6OznQqaJd9e1ew/640?wx_fmt=png&from=appmsg "")  
  
  
**(2) 回传结果**  
  
回传结果的请求数据格式如下，参数 1 的值为 "1"，参数 2 的值在 UID 后加了字符 "2"。  
<table><tbody><tr style="mso-yfti-irow:0;mso-yfti-firstrow:yes;mso-yfti-lastrow:yes;"><td data-colwidth="553" width="553" valign="top" style="border: 1pt solid windowtext;padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">x[9 </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">字节随机字符串</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">]=1&amp;y[9 </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">字节随机字符串</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">]=[UID]2&amp;z[9 </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">字节随机字符串</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">]=[</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">加密数据</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">]</span><o:p></o:p></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTib9GRDqxReGOOORGusYbIOPMW800JVdEInnf2K7icTqndIsMsxrYlEzg/640?wx_fmt=png&from=appmsg "")  
  
  
POST 请求中的加密数据通过随机生成的 4 字节 key 进行加密，然后再用 base64 编码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTGUUkkNibEGUErOedT7gOf04AgExlAwc5FLOiaxf4kd6UB6gmX45XsVxg/640?wx_fmt=png&from=appmsg "")  
  
回传数据后，后门根据服务器响应是否为 "S" 判断是否回传成功。  
  
  
**后门指令**  
  
获取指令后，后门根据响应数据的前两字节进行指令分发，之后的数据作为指令参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTD6JjcSjwSZy8AZm3oZrcfkHMCIKeFROXUygZaDraV980dic7MtqcNGw/640?wx_fmt=png&from=appmsg "")  
  
  
后门支持的指令如下：  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;"><td data-colwidth="112" width="112" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-left: 1pt solid rgb(91, 155, 213);border-image: initial;border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:5;"><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><span leaf="">C&amp;C </span></span></b><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">指令</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:background1;"><o:p></o:p></span></b></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-left: none;border-bottom: 1pt solid rgb(91, 155, 213);border-right: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:1;"><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">函数名</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></b></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: 1pt solid rgb(91, 155, 213);border-right: 1pt solid rgb(91, 155, 213);border-bottom: 1pt solid rgb(91, 155, 213);border-image: initial;border-left: none;background: rgb(91, 155, 213);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:1;"><b><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;color:white;mso-themecolor:background1;"><span leaf="">功能</span></span></b><b><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;color:white;mso-themecolor:
  background1;"><o:p></o:p></span></b></p></td></tr><tr style="mso-yfti-irow:0;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;01&#34;   (0x3130)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Sleep</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">休眠指定时间，结束当前</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf=""> C&amp;C </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">通信会话</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:1;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;02&#34; (0x3230)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Cmd</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">创建</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf=""> shell</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">，执行指定远程命令</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;03&#34;   (0x3330)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Pwd</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">获取当前工作目录</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;04&#34; (0x3430)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Cd</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">切换工作目录</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:4;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;05&#34;   (0x3530)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Conn</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">向指定服务器建立</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf=""> TCP </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">连接</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:5;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;06&#34; (0x3630)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Exit</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">退出后门程序</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:6;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;07&#34;   (0x3730)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Where</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">获取后门程序的文件路径</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:7;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;08&#34; (0x3830)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Dirsize</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">获取指定目录的统计信息（子目录和文件数量，目录中文件总大小）</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:8;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;09&#34;   (0x3930)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_GetInfo</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">获取设备信息，包括主机名、用户名、</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf="">CPU </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">信息、内存信息、网卡信息</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:9;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;10&#34; (0x3031)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_CmdPath</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">设置执行</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span lang="EN-US"><span leaf="">shell </span></span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">命令的文件路径（默认为</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf=""> cmd.exe</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">）</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:10;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;11&#34;   (0x3131)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Codepage</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">设置代码页，默认为</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span lang="EN-US"><span leaf="">euc-kr</span></span></span><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">（韩语）</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:11;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;12&#34; (0x3231)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Hibernate</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">设置下次连接的具体日期时间（解析时区为韩国时区</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span lang="EN-US"><span leaf="">Asia/Seoul</span></span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">），结束当前</span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span lang="EN-US"><span leaf="">C&amp;C </span></span></span><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">通信会话</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:12;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;13&#34;   (0x3331)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Die</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">删除后门程序文件</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:13;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;14&#34; (0x3431)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_SocksAdd</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">添加</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf=""> Socks5 </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">代理，并建立连接</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:14;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;15&#34;   (0x3531)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_SocksList</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">列出</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><span leaf=""> Socks5 </span></span><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:
  &#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">代理</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:15;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:4;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;30&#34; (0x3033)</span><o:p></o:p></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Upload</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);padding: 0cm 5.4pt;"><p style="line-height:115%;"><span style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:&#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:&#34;Times New Roman&#34;;"><span leaf="">向感染设备上传文件</span></span><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:16;mso-yfti-lastrow:yes;"><td data-colwidth="112" width="112" valign="top" style="border-right: 1pt solid rgb(156, 194, 229);border-bottom: 1pt solid rgb(156, 194, 229);border-left: 1pt solid rgb(156, 194, 229);border-image: initial;border-top: none;background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:68;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;mso-bidi-font-weight:bold;"><span leaf="">&#34;31&#34;   (0x3133)</span><b><o:p></o:p></b></span></p></td><td data-colwidth="123" width="123" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span lang="EN-US" style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:
  &#34;Times New Roman&#34;,serif;mso-fareast-font-family:仿宋;"><span leaf="">Process_Download</span><o:p></o:p></span></p></td><td data-colwidth="320" width="320" valign="top" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(156, 194, 229);border-right: 1pt solid rgb(156, 194, 229);background: rgb(222, 234, 246);padding: 0cm 5.4pt;"><p style="line-height:115%;mso-yfti-cnfc:64;"><span style="mso-bidi-font-size:10.5pt;line-height:115%;font-family:仿宋;mso-ascii-font-family:
  &#34;Times New Roman&#34;;mso-hansi-font-family:&#34;Times New Roman&#34;;mso-bidi-font-family:
  &#34;Times New Roman&#34;;"><span leaf="">从感染设备下载文件</span></span><span lang="EN-US" style="mso-bidi-font-size:
  10.5pt;line-height:115%;font-family:&#34;Times New Roman&#34;,serif;mso-fareast-font-family:
  仿宋;"><o:p></o:p></span></p></td></tr></tbody></table>  
  
****  
**加载器**  
  
EXE 样本（MD5: e5c4f8ad27df5aa60ceb36972e29a5fb）通过异或解密的方式从自身数据中恢复出一段 Shellcode，然后执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpT9FmmCd7phFMUbnZqb1al7QnWJAydvPuY5qoLicouFCSZ40wyQD0RLKA/640?wx_fmt=png&from=appmsg "")  
  
  
Shellcode 进一步解密出一段 PE 文件数据，长度为 0x6f7000 字节，并在内存中加载执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpThrRyMCtD77BkVsHHsGf2T3iahAaYmPs6d6KHcasYbRLlHpMbfSsv3Hw/640?wx_fmt=png&from=appmsg "")  
  
  
提取的 PE 中包含基本相同的 Endoor 代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTia3BLiaSnicDtwicUalFchUMX1ibySShNqgtpg8vq8PYZicF1Fd23YKSOtTw/640?wx_fmt=png&from=appmsg "")  
  
  
该 Endoor 样本会检查程序启动时的命令行参数，如果不带指定参数运行，则直接执行自删除操作。支持的参数有 "dkgei" 和 "dkeig" 两种。  
  
参数 "dkgei" 下，样本将自身复制为当前用户目录下的"svchost.exe" 文件（即"C:\\Users\\[用户名]\\svchost.exe"），然后创建名为 "Windows Backup" 的计划任务，以参数 "dkeig" 启动。如果计划任务创建成功，则进行自删除，否则尝试与 C&C 服务器通信。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTxy8dpibEuDVN4ZywXqIO5NaMr1Uq2SXVBmcuwMtiaJOWN5EJqAZgUjeQ/640?wx_fmt=png&from=appmsg "")  
  
  
参数 "dkeig" 运行模式下，则直接进入与 C&C 服务器的通信过程。  
  
  
溯源关联  
  
此次发现的 Endoor 样本和之前披露的 Kimsuky 后门[1]  
特征完全一致，包括网络通信的数据格式、后门指令的代码和对应功能。  
  
不过此次 Endoor 后门有两点和历史样本不一样的地方，首先是记录下一次连接 C&C 服务器的时间不再保存在注册表中，而是直接存储在样本的全局变量里。其次，样本在自删除时，使用的是硬编码路径 "C:\\Programdata\\Cache.db"，而不是样本实际的保存位置，比如上面提到的 Endoor 样本将自身复制为 svchost.exe，这会导致自删除操作无法生效，推测可能是攻击者在调整代码时留下的错误。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTEZnRSkyVgkaWXlDMJibFLibiaictn2X5DIuzpq4KicNyxIjXnj7ffaeT8BQ/640?wx_fmt=png&from=appmsg "")  
  
  
C&C 服务器域名 june.drydate.p-e.kr 绑定 IP 162.216.114.133，该 IP 在近期还绑定了其他类似的域名：summer.cooldate.p-e.kr 和 uni.oxford.p-e.kr，后者可能模仿牛津大学。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTqawUXSOY8VnPeJbyhVMubiaLHUQ7tUD2gHBz40RGV6CzbicvDa9Ljrew/640?wx_fmt=png&from=appmsg "")  
  
  
总结  
  
本次发现的 Endoor 后门在功能上变化不大，但攻击者掩盖攻击的方式别出心裁，一方面是恶意函数的文件路径以 local.github.com 开头，试图伪装为来自 github 的开源代码，避开代码审查，另一方面后门连接 C&C 服务器的 53 端口，而不是常规的 80 或者 443 端口，一定程度上可以绕过对恶意流量的检测，体现了 Kimsuky 组织在实施攻击时不断调整手法的灵活性。  
  
  
防护建议  
  
奇安信威胁情报中心提醒广大用户，谨防钓鱼攻击，切勿打开社交媒体分享的来历不明的链接，不点击执行未知来源的邮件附件，不运行标题夸张的未知文件，不安装非正规途径来源的 APP。做到及时备份重要文件，更新安装补丁。  
  
若需运行，安装来历不明的应用，可先通过奇安信威胁情报文件深度分析平台（https://sandbox.ti.qianxin.com/sandbox/page）进行判别。目前已支持包括 Windows、安卓平台在内的多种格式文件深度分析。  
  
目前，基于奇安信威胁情报中心的威胁情报数据的全线产品，包括奇安信威胁情报平台（TIP）、天擎、天眼高级威胁检测系统、奇安信 NGSOC、奇安信态势感知等，都已经支持对此类攻击的精确检测。  
  
  
IOC  
  
**MD5**  
  
b15cadf2a4e6670c075f80d618b26093  
  
e5c4f8ad27df5aa60ceb36972e29a5fb  
  
d4db59139f2ae0b5c5da192d8c6c5fa0  
  
**C&C**  
  
june.drydate.p-e.kr  
  
summer.cooldate.p-e.kr  
  
uni.oxford.p-e.kr  
  
**URL**  
  
hxxp://june.drydate.p-e.kr:53/  
  
  
参考链接  
  
[1].https://mp.weixin.qq.com/s/kKNkTAlUpLL2skXq3TcBfw  
  
[2].https://asec.ahnlab.com/en/63396/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehic8P6s1icK25llRpBzgTGDFpTeWxUxjAJPxib1qv5ZTyaly4qx5edau2BdqzgfE0aLVu4nsuHNYvzjwg/640?wx_fmt=gif&from=appmsg "")  
  
点击  
阅读原文  
至**ALPHA 8.3**  
  
即刻助力威胁研判  
  
  
