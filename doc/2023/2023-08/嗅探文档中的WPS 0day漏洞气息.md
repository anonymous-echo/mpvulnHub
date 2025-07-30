#  嗅探文档中的WPS 0day漏洞气息   
原创 红雨滴团队  奇安信威胁情报中心   2023-08-23 17:40  
  
概述  
  
0day漏洞利用一直是网络攻防的重头戏，近期红雨滴云沙箱率先捕获到针对WPS文档处理软件的0day漏洞利用样本。样本通过**远程代码执行（RCE）**漏洞下载白加黑组件替换WPS自带的公式编辑器组件，启动后进一步从云服务获取后续载荷。经测试，该文档所利用的漏洞在不久前发布的WPS 12.1.0.15355版本上也能触发，且只需打开文档，**不用任何用户交互**，潜在影响面较大。奇安信第一时间将该漏洞利用信息报告给厂商，目前官方已发布更新，建议用户尽快将WPS升级到最新版。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9g2PchGYYkz7l38bw0d1kbcjk6n8Ic4ibjVdou6O4m3ZKrTicdwGxaZ6lA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9g88ocsJcG6qy0oSGYftJWt0iaP1fwLa0kdpFTicS7NvBekkDqjKb29RMA/640?wx_fmt=png "")  
  
  
相关样本红雨滴云沙箱报告链接  
  
捕获到的相关样本红雨滴云沙箱分析报告列表：  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;height:8.55pt;"><td width="181" style="border-width: 1pt 1pt 1.5pt;border-style: solid;border-color: rgb(142, 170, 219);padding: 0cm 5.4pt;" height="8"><p style="text-align:center;mso-yfti-cnfc:5;"><strong><span style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;">样本名称<span lang="EN-US"><o:p></o:p></span></span></strong></p></td><td width="104" style="border-top: 1pt solid rgb(142, 170, 219);border-left: none;border-bottom: 1.5pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;" height="8"><p style="text-align:center;mso-yfti-cnfc:1;"><strong><span lang="EN-US" style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;">MD5<o:p></o:p></span></strong></p></td><td width="92" style="border-top: 1pt solid rgb(142, 170, 219);border-left: none;border-bottom: 1.5pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;" height="8"><p style="text-align:center;mso-yfti-cnfc:1;"><strong><span style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;">红雨滴云沙箱报告链接<span lang="EN-US"><o:p></o:p></span></span></strong></p></td><td width="196" style="border-top: 1pt solid rgb(142, 170, 219);border-left: none;border-bottom: 1.5pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;" height="8"><p style="text-align:center;mso-yfti-cnfc:1;"><strong><span style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;">备注<span lang="EN-US"><o:p></o:p></span></span></strong></p></td></tr><tr style="mso-yfti-irow:0;height:5.8pt;"><td width="161" style="border-right: 1pt solid rgb(142, 170, 219);border-bottom: 1pt solid rgb(142, 170, 219);border-left: 1pt solid rgb(142, 170, 219);border-top: none;background: rgb(217, 226, 243);padding: 0cm 5.4pt;" height="5"><p style="text-align:left;mso-yfti-cnfc:68;"><span style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;mso-bidi-font-weight:bold;">【共克时艰】<span lang="EN-US">2023</span>年企业薪资调整通知<span lang="EN-US">.docx<o:p></o:p></span></span></p></td><td width="104" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);background: rgb(217, 226, 243);padding: 0cm 5.4pt;" height="5"><p style="text-align:left;mso-yfti-cnfc:64;"><span lang="EN-US" style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;mso-bidi-font-weight:bold;">69*******<o:p></o:p></span></p></td><td width="92" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);background: rgb(217, 226, 243);padding: 0cm 5.4pt;" height="5"><p style="text-align:center;mso-yfti-cnfc:64;"><span style="color:#2F5496;">暂不公开<span lang="EN-US"><o:p></o:p></span></span></p></td><td width="216" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);background: rgb(217, 226, 243);padding: 0cm 5.4pt;" height="5"><p style="text-align:center;mso-yfti-cnfc:64;"><span lang="EN-US" style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;">WPS 0day</span><span style="font-size:10.5pt;mso-ascii-font-family:
  等线;mso-fareast-font-family:等线;mso-hansi-font-family:等线;mso-bidi-font-family:
  &#34;Times New Roman&#34;;color:#2F5496;">漏洞利用文档<span lang="EN-US"><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:1;mso-yfti-lastrow:yes;height:5.8pt;"><td width="181" style="border-right: 1pt solid rgb(142, 170, 219);border-bottom: 1pt solid rgb(142, 170, 219);border-left: 1pt solid rgb(142, 170, 219);border-top: none;padding: 0cm 5.4pt;" height="5"><p style="text-align:left;mso-yfti-cnfc:4;"><span style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;mso-bidi-font-weight:bold;">共克时艰<span lang="EN-US">-2023</span>年企业薪资调整通知<span lang="EN-US">.docx<o:p></o:p></span></span></p></td><td width="104" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;" height="5"><p style="text-align:left;"><span lang="EN-US" style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;mso-bidi-font-weight:bold;">3b*******<o:p></o:p></span></p></td><td width="92" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;" height="5"><p style="text-align:center;"><span style="color:#2F5496;">暂不公开<span lang="EN-US"><o:p></o:p></span></span></p></td><td width="216" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;" height="5"><p style="text-align:center;"><span lang="EN-US" style="font-size:10.5pt;mso-ascii-font-family:等线;mso-fareast-font-family:
  等线;mso-hansi-font-family:等线;mso-bidi-font-family:&#34;Times New Roman&#34;;color:#2F5496;">WPS 0day</span><span style="font-size:10.5pt;mso-ascii-font-family:
  等线;mso-fareast-font-family:等线;mso-hansi-font-family:等线;mso-bidi-font-family:
  &#34;Times New Roman&#34;;color:#2F5496;">漏洞利用文档<span lang="EN-US"><o:p></o:p></span></span></p></td></tr></tbody></table>  
  
案例：WPS漏洞利用文档样本分析  
  
  
**样本基本信息**  
  
<table><tbody><tr style="mso-yfti-irow:-1;mso-yfti-firstrow:yes;mso-yfti-lastfirstrow:yes;height:30.8pt;"><td width="134" style="border-width: 1pt 1pt 1.5pt;border-style: solid;border-color: rgb(142, 170, 219);padding: 0cm 5.4pt;" height="30"><p style="text-align:left;mso-yfti-cnfc:5;"><strong><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;">红雨滴云沙箱报告链接</span></strong><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;"><o:p></o:p></span></p></td><td width="450" style="border-top: 1pt solid rgb(142, 170, 219);border-left: none;border-bottom: 1.5pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;" height="30"><p style="mso-yfti-cnfc:1;"><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:
  191;">暂不公开<span lang="EN-US"><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:0;"><td width="134" style="border-right: 1pt solid rgb(142, 170, 219);border-bottom: 1pt solid rgb(142, 170, 219);border-left: 1pt solid rgb(142, 170, 219);border-top: none;background: rgb(217, 226, 243);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:4;"><strong><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:
  191;">样本文件名</span></strong><strong style="mso-bidi-font-weight:normal;"><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;"><o:p></o:p></span></strong></p></td><td width="470" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);background: rgb(217, 226, 243);padding: 0cm 5.4pt;"><p><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;">【共克时艰】<span lang="EN-US">2023</span>年企业薪资调整通知<span lang="EN-US">.docx<o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:1;"><td width="134" style="border-right: 1pt solid rgb(142, 170, 219);border-bottom: 1pt solid rgb(142, 170, 219);border-left: 1pt solid rgb(142, 170, 219);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:4;"><strong><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:
  191;">样本<span lang="EN-US">MD5</span></span></strong><strong style="mso-bidi-font-weight:
  normal;"><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;"><o:p></o:p></span></strong></p></td><td width="470" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;"><p><span lang="EN-US" style="font-size:10.5pt;mso-ascii-font-family:
  等线;mso-fareast-font-family:等线;mso-hansi-font-family:等线;mso-bidi-font-family:
  &#34;Times New Roman&#34;;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;mso-bidi-font-weight:bold;">69*******</span><span lang="EN-US" style="font-size:
  10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:2;"><td width="134" style="border-right: 1pt solid rgb(142, 170, 219);border-bottom: 1pt solid rgb(142, 170, 219);border-left: 1pt solid rgb(142, 170, 219);border-top: none;background: rgb(217, 226, 243);padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:4;"><strong><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:
  191;">样本类型</span></strong><strong style="mso-bidi-font-weight:normal;"><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;"><o:p></o:p></span></strong></p></td><td width="470" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);background: rgb(217, 226, 243);padding: 0cm 5.4pt;"><p><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:
  11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;">Word
  Microsoft Office Open XML Format Document<o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:3;height:22.5pt;"><td width="134" style="border-right: 1pt solid rgb(142, 170, 219);border-bottom: 1pt solid rgb(142, 170, 219);border-left: 1pt solid rgb(142, 170, 219);border-top: none;padding: 0cm 5.4pt;" height="22"><p style="mso-yfti-cnfc:4;"><strong><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:
  191;">样本大小</span></strong><strong style="mso-bidi-font-weight:normal;"><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;"><o:p></o:p></span></strong></p></td><td width="470" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;" height="22"><p><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:
  11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;">20682</span><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;">字节<span lang="EN-US"><o:p></o:p></span></span></p></td></tr><tr style="mso-yfti-irow:4;height:22.5pt;"><td width="134" style="border-right: 1pt solid rgb(142, 170, 219);border-bottom: 1pt solid rgb(142, 170, 219);border-left: 1pt solid rgb(142, 170, 219);border-top: none;background: rgb(217, 226, 243);padding: 0cm 5.4pt;" height="22"><p style="mso-yfti-cnfc:4;"><strong><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;">RAS</span></strong><strong><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:
  191;">检测结果</span></strong><strong style="mso-bidi-font-weight:normal;"><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;"><o:p></o:p></span></strong></p></td><td width="470" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);background: rgb(217, 226, 243);padding: 0cm 5.4pt;" height="22"><p><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:
  11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;">en-US </span><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:red;">wps_equation</span><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;"> zh-CN</span><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:red;"><o:p></o:p></span></p></td></tr><tr style="mso-yfti-irow:5;mso-yfti-lastrow:yes;"><td width="134" style="border-right: 1pt solid rgb(142, 170, 219);border-bottom: 1pt solid rgb(142, 170, 219);border-left: 1pt solid rgb(142, 170, 219);border-top: none;padding: 0cm 5.4pt;"><p style="mso-yfti-cnfc:4;"><strong><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:
  191;">样本基因特征</span></strong><strong style="mso-bidi-font-weight:normal;"><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;"><o:p></o:p></span></strong></p></td><td width="470" style="border-top: none;border-left: none;border-bottom: 1pt solid rgb(142, 170, 219);border-right: 1pt solid rgb(142, 170, 219);padding: 0cm 5.4pt;"><p><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;">解压执行 持久化 探针 </span><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:red;">HTTP</span><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:red;">通信</span><span style="font-size:10.5pt;mso-bidi-font-size:11.0pt;color:#2F5496;mso-themecolor:
  accent1;mso-themeshade:191;"> 加壳程序 隐藏自身 检测虚拟机 <span lang="EN-US">C&amp;C </span>检测杀毒软件
  可疑命令行 勒索软件 联网行为 检测调试器 检测沙箱</span><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:11.0pt;mso-fareast-font-family:宋体;color:#2F5496;mso-themecolor:accent1;mso-themeshade:191;"><o:p></o:p></span></p></td></tr></tbody></table>  
     
  
**使用红雨滴云沙箱分析样本**  
  
通过访问红雨滴云沙箱入口（**https://sandbox.ti.qianxin.com/**）使用沙箱进行辅助分析。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gbmrHsvqO7t3U00Cbl4G8Kd72FVlLkvf9qzXqKYnWGVsFtdkqHARCibA/640?wx_fmt=png "")  
  
红雨滴云沙箱分析入口  
  
   
  
在上传待分析文件后，可以手动设置沙箱分析参数：分析环境（操作系统）、分析时长等。**由于红雨滴云沙箱针对各类样本已经进行了智能化判定，所以基本上以默认方式提交检测即可**。  
  
  
红雨滴云沙箱**支持对WPS文档样本的检测分析**，对于WPS文档，可以选择如下分析环境。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gmL2XCS6A7fJrgiaMDFicoQhdibia1pff0Sy0DCEzLWyAExk58n4ia2zqVzw/640?wx_fmt=png "")  
  
  
点击“**开始分析**”按钮后，会自动跳转到对应样本的分析检测结果页面。稍等数分钟则可以看到整个样本的详细分析报告。  
  
  
上传分析完成后，通过概要信息可看到该样本的基本信息：包括hash、文件类型、签名等。可见**红雨滴云沙箱基于智能的恶意行为综合判断**已经识别出文件可疑并给出了10分的恶意评分。注意到红雨滴云沙箱内置的RAS检测引擎打上了**wps_equation**的可疑标签，这表明该文档可能涉及到启动WPS的公式编辑器。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9g2PchGYYkz7l38bw0d1kbcjk6n8Ic4ibjVdou6O4m3ZKrTicdwGxaZ6lA/640?wx_fmt=png "")  
  
  
点击右侧导航栏的**深度解析**功能，在**流文件信息**中可以看到文档中包含公式编辑器OLE对象数据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gWqPSNMpSXKXq4JCkSHOJ81EUp0L20HiaoiaUhoP6CGKAvPsIBjeq8q2w/640?wx_fmt=png "")  
  
  
**主机行为**中的**进程**信息表明文档打开后，WPS的公式编辑器程序也被启动。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gHicW5YepyEmGDbRz7IiaslZczmIJDl0VCUotvCb03tib5Qwdb0B74sCew/640?wx_fmt=png "")  
  
  
通过**网络行为**可以看到该文档的可疑网络通信行为，访问云服务域名，下载带有exe扩展名的后续载荷，而该云服务域名的解析IP是被公式编辑器进程访问。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gAonGql5zOXTGKnhPClZJybmN617Izp57vVvh2xetE65vsdXMIckm4w/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9g3auYYKX58K3rOJVD3G6Yic7hrOJIGia7JSdzpvD0KcwBL4Mib56EUJxtQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gCJdtNMTwNMKuBGzjbeAx30Dx27ZjL2qASTvGUZekeTFNbbdibk8iaodA/640?wx_fmt=png "")  
  
  
**样本分析**  
  
以上种种可疑迹象表明该样本很可能使用了漏洞，为了探明究竟，我们对样本采取了进一步的分析。文档中存在一处外部链接，当文档打开后，加载该外部链接页面并执行其中的JS代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gn3rOHxb03AtGxone63sTC1ydNtK17h2ic8jo7mVxaGWficJKVuSVibibKg/640?wx_fmt=png "")  
  
  
JS代码进一步下载两个PE文件，替换WPS安装目录中的原有组件”EqnEdit.exe”和”symsrv.dll”，这两个组件与公式编辑器相关。替换完成后，JS代码触发文档中的公式编辑器OLE对象，进而启动覆盖后的EqnEdit.exe文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gHbFjLtMCDNEofeUbby3kaohZnZJ2Luib7c7lWPSq2V459tJ0XNFdu0Q/640?wx_fmt=png "")  
  
  
下载的两个PE文件使用DLL白利用手法，恶意symsrv.dll载入后从云服务下载后续并执行。  
  
  
对于前所未见的包含可疑标签的样本，奇安信威胁情报中心有7x24的分析团队做进一步的人工分析。经测试，该文档无需用户交互，使用WPS打开即可触发对上面外部链接的访问，并且在WPS 12.1.0.15355版本上可以成功执行，因此能够确认该文档利用了WPS的远程代码执行0day漏洞。奇安信威胁情报中心第一时间通知了厂商，目前WPS已发布针对该漏洞的紧急更新，建议相关用户尽快升级到最新版。  
  
  
本次攻防演练中，奇安信的安全检测产品和服务不辱使命，EDR系统和情报沙箱及时发现了两例利用国产办公软件0day漏洞的攻击线索，结合经验丰富的人工分析确认，遵从负责任的漏洞披露原则尽快同步给厂商，有效缓解了漏洞的危害。  
  
  
部分IOC信息  
  
**域名:**  
  
76z1xwz6mp5fq7qi4telphdn0c0.oss-cn-shenzhen.aliyuncs.com （云服务）  
  
6e8t0xobdnmerpraecktu1bge1kmo1cs.oss-cn-shenzhen.aliyuncs.com （云服务）  
  
   
  
**IP:**  
  
123.57.150.145  
  
39.105.128.11  
  
47.93.247.53  
  
123.56.0.10  
  
39.105.138.249  
  
182.92.111.169  
  
  
关于红雨滴云沙箱  
  
红雨滴云沙箱是威胁情报中心红雨滴团队基于多年的APT高级攻防对抗经验、安全大数据、威胁情报等能力，使用软、硬件虚拟化技术开发实现的真正的“上帝模式”高对抗沙箱，**协助奇安信威胁情报中心及相关安服和客户发现了多个在野0day漏洞攻击、nday漏洞攻击，和无数计的APT攻击线索及样本，是威胁情报数据产出的重要基石**。  
  
威胁情报中心红雨滴云沙箱在两年多以前即被威胁分析厂商  
VirusTotal集成：**https://blog.virustotal.com/2020/02/virustotal-multisandbox-qianxin-reddrip.html**  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9g43bA2Vl8Jz6PzDCKZQsMT1xj40u3Q1qJB00OyDyXH647miax7WFBMhQ/640?wx_fmt=png "")  
  
红雨滴云沙箱已集成VirusTotal  
  
   
  
并且，红雨滴云沙箱也是  
VirusTotal中对恶意样本行为检出率最高的沙箱产品之一，部分高危样本可以通过点击**BEHAVIOR**选项卡查看到VirusTotal-红雨滴云沙箱的分析报告[1]。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gBy4tkacKcWAJ1YVtuDsJPbm4ZfX4Olvoe2YF040xUpVZyMUxNkqrAQ/640?wx_fmt=png "")  
  
VirusTotal样本动态分析结果中集成的红雨滴云沙箱分析结果  
  
  
参考链接  
  
[1].https://www.virustotal.com/gui/file/99578e17b3b03ed841c869a6f8497a8786bb1765ff4a32b134e16a30844887f0/behavior/QiAnXin%20RedDrip  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/2AqAgxkehic8peCGP6NfRUGOicZVKcRA9gichNCt2ibQRunnfM4vTWibhliafMpLH5ZXzfTF5qf2zcNwelLzm4vtRXlg/640?wx_fmt=gif "")  
  
点击  
阅读原文至**ALPHA 6.0**  
  
即刻助力威胁研判  
  
  
  
