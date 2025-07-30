#  Operation DevilTiger：APT-Q-12 使用 0day 漏洞技战术披露   
红雨滴团队  奇安信威胁情报中心   2024-08-26 09:15  
  
概述  
  
APT-Q-12，中文名伪猎者，具有东北亚背景，奇安信威胁情报中心最早于 2021 年发布相关技术报告[1]，主要目标包含中国、朝鲜、日本、韩国等东亚地区的国家和实体。实际上该攻击集合最早由境外友商 blackberry 于 2017 年发布的 baijiu 行动中披露[2]，报告中提到 baijiu 行动与卡巴斯基发布的 Darkhotel 组织存在重叠。  
  
从 2019 之后有关 Darkhotel 组织的行动在开源情报中的占比连年降低，与此同时政企终端中出现了数个具有朝鲜半岛背景并且技战术不同的攻击集合，我们根据特马和目标行业对这些攻击集合进行了分类，分别为 APT-Q-11(虎木槿)、APT-Q-12(伪猎者)、APT-Q-14(旺刺)、APT-Q-15、UTG-Q-005 等，经过五年的持续跟踪发现这些组织之间互有重叠，我们认为这些攻击集合都是当年 Darkhotel 的子集。  
  
对 APT 组织的研究深入与否，取决于对其使用的插件类型掌握的程度。目前主流的 APT 组织都是只是将木马当作加载器或者下载者，大部分的间谍行为都由后续的插件来完成，由于不同组织对于目标数据的需求不同，如何在几百上千个内部文档中快速定位自己想要的数据，是导致各个方向的 APT 组织插件差异化巨大的主要原因，例如在 Operation ShadowTiger[3] 活动中，Durain 插件只是用来获取特定的目录结构和移动特定目录下的文档，上传操作则是由 peach 插件利用管道传递参数的方式将数据上传到 C2 服务器上，而 APT37 和新海莲花组织则是只上传文件路径和目录结构，攻击者在后端对文档进行筛选，南亚方向的 CNC 组织先通过小型木马挑选感兴趣的文件目录，最后将文件目录硬编码在窃密插件中递归上传所有文档。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4SdPSWUFaxZhBIjrgibcVic37OLPtMZdDwg7LEia4JcDz5XW3Znt6UrT3w/640?wx_fmt=png&from=appmsg "")  
  
  
所以想要研究 APT 组织背后的行为逻辑和政治目的，仅靠初始的样本分析是远远不够的，插件的研究和捕获是重中之重。  
  
我们建议政企客户在办公区和服务器区同时部署天擎 EDR 并开启云查功能来抵御未知的威胁。  
  
  
信息收集  
  
****  
**探测邮件平台和品牌**  
  
友商在最近的安全大会和 PR 报告中直截了当的对 0day 漏洞进行了分析，但是从攻击者挖掘漏洞到投递鱼叉邮件这中间存在一个非常复杂的信息收集过程。如何探测受害者使用的是 foxmail？163？coremail？以及平台是 win 客户端？网页端？移动端？为了能够完美触发各平台的 0day 漏洞，APT-Q-12 设计了多套复杂的邮件探针并周期性地向目标投递探针邮件以此来收集受害者的使用习惯和行为逻辑，恶意探针邮件非常难以识别，正文模仿各类广告和订阅号。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4Y1DVRhmdYyTGiaT0pPEQK4wHXlf4YcEhW9wopAIoqRqPTmMicBibURGfg/640?wx_fmt=png&from=appmsg "")  
  
  
在合法探针链接下面插入攻击者自己的 C2 探针链接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4423ibh4IsicnSm0DzwSmw9FmZdkUUwiaFY5JLQZMe30fhUsFN5XAr8KgQ/640?wx_fmt=png&from=appmsg "")  
  
  
尽管有些正文和标题容易被识别成垃圾邮件，但是 APT-Q-12 周期性地更换正文内容总能获取到受害者的 User-agent 信息，从而获取目标当前使用的邮件品牌和邮件平台。  
  
****  
**探测Office产品**  
  
在对目标人员 Office 软件的信息进行收集时，APT-Q-12 对 wps 和 word 进行了区别处理。  
  
  
**探测wps**  
  
针对 wps 的探测时，附件内容中内嵌了 ole 对象的 web 控件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4BtPGZhQRkPP7qvLzosnsLCZkqjBhcbcBAKftCh3TzY6saSp1OEqHwQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4AgXll6IKTN4uHn2licMUt7ibjcEo1xCCCWAOVq4g0uo8GUwPcYMsNJMg/640?wx_fmt=png&from=appmsg "")  
  
  
当使用 wps 打开该 mhtml 格式的文件后会将请求内置的 C2 探针，本地测试触发流程如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicic2NmAxJs5tricEDelmkXJqS9kewUmDicYDsjISGK9ZLLxYwbhbWHvZGdYDNTlf9azYwAewC4zMK8QA/640?wx_fmt=png&from=appmsg "")  
  
  
由于 Microsoft word 在十年前就已经就把 web 控件禁用，所以使用 word 打开上述 mhtml 文件时不会向 C2 探针发起请求。  
  
  
**探测Microsoft word**  
  
针对 Microsoft word 的探测时将 C2 探针链接插入模板注入中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4D6RSYOTQqM3sSXGxtut1aPmibJsWtQldpqdMiaicFjx4B0XZdVDfsTxibw/640?wx_fmt=png&from=appmsg "")  
  
  
为了绕过沙箱检测，打开诱饵 docx 时会有一层交互。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4mbnRzzDeQaxicrg5aib9bdlHEXN0lqxb9fLYia6IasPb4kXE6BwNEvAoA/640?wx_fmt=png&from=appmsg "")  
  
  
点击确认后才会请求 C2 探针链接，当使用 wps 打开该文档时则不会发起网络请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicic2NmAxJs5tricEDelmkXJqSWXfKmx3X7iaHfzvhLGmGKsD2EPvDkRlkOMsAcaQFRFuic669mQafBMGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4e6ic58PrmSy9A0xNXgX9wWYYFMYJj25ibfspCiadNKicbCz8N0PqXCYBVw/640?wx_fmt=png&from=appmsg "")  
  
  
攻击者使用上述差异化的探测方式来判断受害者常用的 office 软件。信息收集后的结果在东北亚地区各个 APT 组织中互相共享，而从为后续的 0day攻 击铺平道路。  
  
  
Win 平台邮件客户端 0day 漏洞  
  
****  
**漏洞原理**  
  
我们曾在 operation Dargon Dance[3] 一文中提到基于 CEF 框架开发的国产软件脆弱性的问题，国内的外包人员和黑产都可以轻易的挖掘 RCE 漏洞进而发起大规模的  0day 攻击活动，漏洞入口一般为 XSS  漏洞，后续 payload 落地要么调用内部接口要么使用 chrome 内核较老的 RCE 漏洞来进行触发，内部接口利用方式的攻击链如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4STmQIZxw1Hib0icsoQPXfs2RmzBmeoNKPfgYu3SlHJ2ibb3wGUSCRaU2Q/640?wx_fmt=png&from=appmsg "")  
  
  
0day 邮件正文如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4icGScV4iaLOmGopn3IUjQr6McibdUYrew6Fs9hic0S9QY9NWlW31lox5Hw/640?wx_fmt=png&from=appmsg "")  
  
  
触发时会闭合标题上的代码，执行标题中剩余 js 代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4t1cvVRn83suGln2zsPNzibR2Bnsv5mricBDBucHqB48jX0jHNVomlkng/640?wx_fmt=png&from=appmsg "")  
  
  
解密后的内容如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU44d4a27s7ibo1OJgqwvNfE5gRx6LYm2DANGcTx3dsUZS6fCSziaLpDbtA/640?wx_fmt=png&from=appmsg "")  
  
  
执行邮件正文中的代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4nZYhn8LcI23JkK28as8ib3TvmkZpLEoY4b5IM6icP4icWXRNMH1DUKu1w/640?wx_fmt=png&from=appmsg "")  
  
  
Name 字段解密后内容如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4AbTxEHXvnCxPlmtZyicfibOI0xDDJ2UXEXy0AsNzRLygqd95uNhNMYDQ/640?wx_fmt=png&from=appmsg "")  
  
  
寻找邮件结构中名为 image.png 的资源，并通过内部接口进行调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU40sUNVOI1sDhJbIArX3Otjkw10pFYlY0CB2bRRZgmvuj4pgbvGdetKg/640?wx_fmt=png&from=appmsg "")  
  
Base64 解密后实际为 lnk 文件，执行的 CMD 命令如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4ftwtbWyawg0ccKnRrYkwEjqgLq5XGmL96TNsEM6H6UsMCyxpeyTJ5A/640?wx_fmt=png&from=appmsg "")  
  
  
将 lnk 拷贝到特定目录下，并且解密 lnk 文件的附加数据并释放到 %temp% 目录下命名为 s.mui，启动 rundll32 去执行 s.mui 的导出函数 f。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4UAvGb04AicnzuDpVeI9TezAxA0JCBCHXKLFVBLk36ictyrT1RQLeS17A/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**木马分析**  
  
<table><colgroup><col width="72" span="2" style="width:54pt;"/></colgroup><tbody><tr height="19" style="height:14.25pt;"><td height="14" width="54" style=""><strong>文件名</strong></td><td width="410" style=""><strong><span lang="EN-US">Md5</span></strong></td></tr><tr height="19" style="height:14.25pt;"><td height="14" style=""><span lang="EN-US">s.mui</span></td><td width="358"><span lang="EN-US">764c7b0cdc8a844dc58644a32773990e</span></td></tr></tbody></table>  
s.mui 的主要功能是判断操作系统版本和位数，在 temp 目录下释放 module.cab，调用 expand 将 cab 文件中的木马释放到   
AppData\Local\Microsoft\Windows\StaticCache 目录下，并设置 com 劫持。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4Exc4jTSzoUsnibkIT4XkIVNvqosw5Mic69XIzBtMp6vKpibIviaK8Y1AXw/640?wx_fmt=png&from=appmsg "")  
  
  
<table><colgroup><col width="72" span="2" style="width:54pt;"/></colgroup><tbody><tr height="19" style="height:14.25pt;"><td height="14" width="148" style="word-break: break-all;"><strong>文件名</strong></td><td width="315" style=""><strong><span lang="EN-US">Md5</span></strong></td></tr><tr height="19" style="height:14.25pt;"><td height="14" style="" width="96"><span lang="EN-US">~StaticCache-System.dat</span></td><td width="335"><span lang="EN-US">59cd91c8ee6b9519c0da27d37a8a1b31</span></td></tr></tbody></table>  
~StaticCache-System.dat 文件是 APT-Q-12 常用的第一阶段下载者。  
解密出的 C2 如下:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4kRCQ9dKaAArUau80VUHgThV31rj19lluwhSwUUS5TgekR827Jibmb7Q/640?wx_fmt=png&from=appmsg "")  
  
  
从云盘获取 bmp 并进行解密：  
  
https://bitbucket.org/noelvisor/burdennetted/downloads/OAQDDI32.bmp  
  
https://bitbucket.org/poppedboy/bovrilchant/downloads/32.bmp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU45wpYN0ge2ialzoWvMx2NDt4ialVIIkJ8rZ4KEibNKWL8brVmGWk6jJiaMg/640?wx_fmt=png&from=appmsg "")  
  
<table><colgroup><col width="72" span="2" style="width:54pt;"/></colgroup><tbody><tr height="19" style="height:14.25pt;"><td height="14" width="341" style="word-break: break-all;"><strong><span lang="EN-US">Md5</span></strong></td><td width="101" style=""><strong>导出函数</strong></td></tr><tr height="19" style="height:14.25pt;"><td height="14" style="" width="289"><span lang="EN-US">fa17ed2eabff8ac5fbbbc87f5446b9ca</span></td><td width="81"><span lang="EN-US">extension</span></td></tr></tbody></table>  
解密后的文件为第二阶段的下载者，调用 extension 导出函数，从 bitbucket.org/penguinwear/avoidlover/downloads/3WIGyjvJ.tmp 下载 tmp  文件到%temp% 目录，并进行 AES 解密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4sts7DjmgCJtqMvNMNUzqybJshawNt6WT7tWQFDZiba54Srib2Fm7picPg/640?wx_fmt=png&from=appmsg "")  
  
  
将解密后的数据保存到以下路径 AppData\Local\Microsoft\Windows\SHCore\MMDevAPI.mui。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4IHFZp9ARqSfypWmQ56gibZQl856PYx84TpKFdwQeICMdLXLNxMw3wqA/640?wx_fmt=png&from=appmsg "")  
  
  
<table><colgroup><col width="72" span="2" style="width:54pt;"/></colgroup><tbody><tr height="19" style="height:14.25pt;"><td height="14" width="124" style="word-break: break-all;"><strong>文件名</strong></td><td width="317" style=""><strong><span lang="EN-US">MD5</span></strong></td></tr><tr height="19" style="height:14.25pt;"><td height="14" style="" width="72"><span lang="EN-US">MMDevAPI.mui</span></td><td width="297"><span lang="EN-US">71094ef9f2cf685e6c7d11fe310e5efb</span></td></tr></tbody></table>  
该木马为 APT-Q-12 常用的远控特马，解密后的字符串如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4x2qbU4emia7bKA1Jllk2xAHa9d0f7jehqHribTH67FHnUZl7iafw3ofXQ/640?wx_fmt=png&from=appmsg "")  
  
  
指令功能与 blackberry 于 2017 年披露的功能一致，同年我们又捕获到了另一个 win 平台邮件客户端的 0day 漏洞，由于 CEF 框架中 Chromium 内核版本过低，攻击者通过 XSS 漏洞执行带有 CVE-2017-5070 利用代码的 JS 脚本，从而实现木马落地。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU43uodVicbpZUgJFeBanLhKKm8xRXZrMh5icFmZ2G11RkuJFmbCr1ibQPmg/640?wx_fmt=png&from=appmsg "")  
  
  
XSS 触发入口如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4QvKJ7jKiaKeic1qMGJ9DmVdcwoJM7Vmqkduql2S1EeicPQHwf0p8wT1DA/640?wx_fmt=png&from=appmsg "")  
  
  
CVE-2017-5070 EXP代码如下：![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4CQC9zXCswh3ZiczVLIEbr2Zuaa8YcLwEnNt0XSUFianODdURynX8Recw/640?wx_fmt=png&from=appmsg "")  
  
  
  
一般情况下 CEF 程序的 Chromium 内核不开启沙盒功能，所以攻击者不需要考虑内核提权的步骤，内存加载下载者 shellcode，从远程服务器下载第一阶段下载者，后续流程与上述一致，不再赘述。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4iamHfBoUX5EmtLXeRw2D1hUBxufufYOAq0mMicG6W2p0lmPXXWQWCicSg/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**插件介绍**  
  
我们通过天擎 EDR 告警数据和现场排查捕获了较为完整的插件类型，APT-Q-12 的攻击目标和攻击逻辑与 APT-Q-11(虎木槿)较为吻合：  
<table><colgroup><col width="72" style="width:54pt;"/></colgroup><tbody><tr height="19" style="height:14.25pt;" class="ue-table-interlace-color-single"><td height="14" width="182" style="word-break: break-all;"><strong>插件类型</strong></td></tr><tr height="19" style="height:14.25pt;" class="ue-table-interlace-color-double"><td height="14" style="" width="130">键盘记录插件</td></tr><tr height="19" style="height:14.25pt;" class="ue-table-interlace-color-single"><td height="14" style="" width="130">浏览器窃密插件</td></tr><tr height="19" style="height:14.25pt;" class="ue-table-interlace-color-double"><td height="14" style="" width="130">隧道工具</td></tr><tr height="19" style="height:14.25pt;" class="ue-table-interlace-color-single"><td height="14" style="" width="130">屏幕截图插件</td></tr><tr height="19" style="height:14.25pt;" class="ue-table-interlace-color-double"><td height="14" style="" width="130"><span lang="EN-US">…</span></td></tr></tbody></table>  
  
攻击者一般会通过 powershell 命令下发键盘记录插件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4EfzPkbATIs2PJ2BFkomn5l70DsksNJN7PpdlV0Ar2ySt4rxHFdibDVQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4ia0aeWianZLfN1jufNtwLqZFzGtaib5ecIpIb2xPhYXZhkoKE8FL9FLLQ/640?wx_fmt=png&from=appmsg "")  
  
  
将记录的数据加密存放在 \appdata\roaming\microsoft\vault\bincheck.db 文件中，加密算法如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4yvibuuXbJUHpMAeKQiaDiawHa9yAtQSiahKTDRoEYyylBiahq3d3fC9IaibA/640?wx_fmt=png&from=appmsg "")  
  
  
将数据解密后可以看到键盘记录插件捕获的详细数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4d7NEc2CWJQAMVdACVnRvdLUEGoIfFhb3OYq2XENacnKRHP9U9KxReQ/640?wx_fmt=png&from=appmsg "")  
  
  
出于对隐私的保护，我们无法透露键盘记录中都包含哪些敏感内容。APT-Q-12 对半导体竞争和政治宣传导向等领域的情报较为关注，符合东北亚国家的利益。  
  
接着下发浏览器窃密插件，获取内网 web 平台的凭证信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4afkmMib4XjJ79wmcyorhmH0xHzdY7SxY6cLHb3MJuUIjNZv6MS6WbTw/640?wx_fmt=png&from=appmsg "")  
  
  
在此过程中还会收集机器上保存密码的 txt 文件，尽可能多的获得账密信息，同步下发屏幕截图插件，观察受害者平时的操作习惯和登录方式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4VyI2ll7JXY6AeuNnfiaYRTkuvia47aEwwo04jF4ZaOE0X80MS8D36d7Q/640?wx_fmt=png&from=appmsg "")  
  
  
经过两三个月的蛰伏后，启动反向隧道工具 revsocket 登录内网平台脱取内部数据，该团伙并没有自动化的文件收集插件，会结合其他情报来源得到的未公开事件和未知时间节点，通过木马在受害机器上搜索是否存在相关内部资料。  
  
  
Android 平台邮件客户端 0day 漏洞  
  
旺刺（APT-Q-14）与 2022 年-2023 年投递针对 Android 平台的 0day 漏洞，触发逻辑与 win 平台类似，通过 app 解析邮件结构中出现的 xss 漏洞调用内部接口从而执行附件中的恶意代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU457tZUQI28pgcml4JXs5Fg3gXB2QibAD1q0oCRJD6SudFUmH4ZvNjU7w/640?wx_fmt=png&from=appmsg "")  
  
  
附件中包含了一个名为 0o0o.apk 的恶意程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4JjxmDtmCIl4w19HwRf8tyeUdKhADpRxW6oGQppYbvIgZj1XxTvoSDQ/640?wx_fmt=png&from=appmsg "")  
  
  
与 C2 服务器建立连接实现对目标手机的长期控制，启动后会执行 Curl 命令下载一段 Payload。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU43wkPXgGQ3PCzNPPsVEaokhUkEicFleCxu2HyzXtyjTTayIY5NWs32Lg/640?wx_fmt=png&from=appmsg "")  
  
  
Payload 内容如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4bpnegCNblnKiaiaD5nmrbib5Rgg9uibffnvna3X9bLBETianq1jNXqvzGpA/640?wx_fmt=png&from=appmsg "")  
  
  
从手机中读取对应 app 中的邮件数据经过 tar 打包后通过 toybox 执行 nc 命令上传到 C2 域名上。攻击者想要刺探与中朝贸易有关的情报。  
  
环顾整个亚洲，朝鲜半岛的攻击者拥有无与伦比的进攻能力，整体水平接近 T1 级别，南北双方都将对方视为主要的战略对象，网络攻击不仅对双方造成了巨大影响，也给亚洲其他国家带来了极大的挑战。邻近的国家在这一持续的对抗中，既可能成为攻击的跳板，也可能被波及到战略目标范围内。  
  
  
总结  
  
目前，基于奇安信威胁情报中心的威胁情报数据的全线产品，包括奇安信威胁情报平台（TIP）、天擎、天眼高级威胁检测系统、奇安信NGSOC、奇安信态势感知等，都已经支持对此类攻击的精确检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicJrXesy6fNRo7DSvDAsgU4F3cxzLze3ylkGA7dmA6JUJa0BElalCPFoqibRhYkYjTnFnvaJxdujXQ/640?wx_fmt=png&from=appmsg "")  
  
  
IOC  
  
**MD5:**  
  
764c7b0cdc8a844dc58644a32773990e  
  
59cd91c8ee6b9519c0da27d37a8a1b31  
  
fa17ed2eabff8ac5fbbbc87f5446b9ca  
  
71094ef9f2cf685e6c7d11fe310e5efb  
  
  
**URL:**  
  
hxxps://bitbucket.org/noelvisor/burdennetted/downloads/OAQDDI32.bmp  
  
hxxps://bitbucket.org/poppedboy/bovrilchant/downloads/32.bmp  
  
hxxps://bitbucket.org/poppedboy/bovrilchant/downloads/32.bmp  
  
hxxps://c.statcounter.com/12830663/0/0ee00a3c/1/  
  
hxxps://bitbucket.org/noelvisor/burdennetted/downloads/  
  
  
**C2:**  
  
（已失效）  
  
82.118.27.129:80  
  
web-oauth.com  
  
  
参考链接  
  
[1] https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/exposing-earth-berberoka-a-multiplatform-apt-campaign-targeting-online-gambling-sites  
  
[2] https://blogs.blackberry.com/en/2017/05/baijiu  
  
[3] https://ti.qianxin.com/blog/articles/operation-dragon-dance-the-sword-of-damocles-hanging-over-the-gaming-industry/  
  
  
