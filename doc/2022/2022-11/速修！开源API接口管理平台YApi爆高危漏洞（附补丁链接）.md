#  速修！开源API接口管理平台YApi爆高危漏洞（附补丁链接）   
原创 ThreatBook  微步在线   2022-11-11 16:52  
  
经“X漏洞奖励计划”，微步获取到一个YApi高危漏洞信息，无需点击（0-click），无任何权限要求，即可利用。YApi在GitHub上获得超过25000颗星，包括阿里、腾讯、百度、美团等中国一大批互联网公司都在用，可谓影响广泛。**目前微步TDP支持对该漏洞的检出。**  
  
  
以下为微步情报局对该漏洞的评估结果：  
<table><tbody><tr><td width="253" valign="top" style="word-break: break-all;"><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">公开程度</span></td><td width="253" valign="top" style="word-break: break-all;"><strong><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:
12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">PoC</span><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:
&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:ZH-CN;mso-bidi-language:AR-SA;">未公开</span></strong></td></tr><tr><td width="253" valign="top" style="word-break: break-all;"><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;"><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">利用条件</span></span></td><td width="253" valign="top" style="word-break: break-all;"><strong><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">无权限要求</span></strong></td></tr><tr><td width="253" valign="top" style="word-break: break-all;"><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">交互要求</span></td><td width="253" valign="top" style="word-break: break-all;"><strong><span lang="EN-US" style="font-size:10.5pt;mso-bidi-font-size:
12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">0-click</span></strong></td></tr><tr><td width="253" valign="top" style="word-break: break-all;"><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">漏洞危害</span></td><td width="253" valign="top" style="word-break: break-all;"><strong><span style="font-size: 10.5pt;font-family: 微软雅黑, sans-serif;color: rgb(189, 0, 0);">高危</span></strong><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">、<strong>权限绕过、命令执行</strong></span></td></tr><tr><td width="253" valign="top" style="word-break: break-all;"><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">影响版本</span></td><td width="253" valign="top" style="word-break: break-all;"><strong><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;">≤1.10.2<span lang="EN-US"></span></span></strong><span style="font-size:10.5pt;mso-bidi-font-size:12.0pt;font-family:&#34;微软雅黑&#34;,sans-serif;mso-bidi-font-family:&#34;Times New Roman&#34;;mso-bidi-theme-font:minor-bidi;mso-ansi-language:EN-US;mso-fareast-language:
ZH-CN;mso-bidi-language:AR-SA;"><span lang="EN-US"></span></span></td></tr></tbody></table>  
  
**漏洞复现**  
  
经微步情报局进行复现，YApi接口管理平台通过注入获取到用户token，结合自动化测试API接口写入待命命令，并利用沙箱逃逸触发命令执行。  
  
  
☞****  
**获取用户token：**  
  
YApi中某**函数存在拼接，导致MongoDB注入可获取所有token**，包括用户**ID、项目ID**等必要参数。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Yv6ic9zgr5hTe4shZZN8LSluJ6YTunrrDwiayuHq187bCR6Ke8Rzy2uyNe5oQ76lFV4CP4Tb4TxibaOgHfGAXibiaWA/640?wx_fmt=jpeg "")  
  
☞**命令执行**  
  
YApi后台的pre-request和pre-response功能存在被利用风险，通过填写脚本，调用自动化测试runAutoTest()时会触发跟进变量被传入了 crossRequest 函数。  
  
然后通过分析sandbox函数可发现vm模块，**利用vm模块构造可逃逸的命令执行数据包达到命令执行效果。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Yv6ic9zgr5hTe4shZZN8LSluJ6YTunrrDOdF6nWGicoibldMXS1QicIKXrFNRiaOKXHHwkv445eVTaFyJ4M1rnGGaOg/640?wx_fmt=jpeg "")  
  
  
经分析，目前**YApi所有版本（包括最新的1.12.0版本）都受此高危漏洞影响，没有例外！**  
  
  
**时间轴**  
  
1  
  
2022.07.  
  
●   
微步“**X漏洞奖励计划**”获取该漏洞相关情报;  
  
2  
  
2022.07.  
  
●   
漏洞研究与分析；  
  
3  
  
2022.07.  
  
● **TDP**  
支持对该漏洞检测；  
  
4  
  
2022.08.  
  
● **OneSIG、OneEDR**  
支持对该漏洞检测；  
  
5  
  
2022.09.  
  
● **X企业版**  
支持对该漏洞检测；  
  
6  
  
2022.10.  
  
●   
报送监管、厂商、漏洞情报订阅客户；  
  
7  
  
2022.11.  
  
●   
补丁发布。  
  
**修复方案**  
  
**目前官方已出修复补丁，以下为下载链接：**  
  
  
https://github.com  
/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c  
  
  
· END ·  
  
  
点击下方名片，关注我们  
  
觉得内容不错，就点下  
“**赞**”和  
“**在看**”  
  
如果不想错过新的内容推送，可以设为**星标**  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTYyCkc91euAiaGULJSbiaHricFHs2dd2sib20WTJKwHYD90Jia9HCKxnmJUwnkicGU7rVP3EYCVh3dMnng/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
哦  
  
  
