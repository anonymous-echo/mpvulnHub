> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611495&idx=2&sn=3d0e35264169c731d967995d18dd84e9

#  7-Zip曝出两个可致内存损坏和拒绝服务的漏洞  
 黑白之道   2025-07-22 02:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR385xfQfOZT3FGrBQUN2aE64NWH4tcpeHp17nYSpuMHxYADqGjVTS7baQIlJJGMpGXHBXfPljwia0dQ/640?wx_fmt=other&from=appmsg&randomid=owlsksxl&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
研究人员在全球使用最广泛的开源文件压缩软件7-Zip中新发现两个漏洞（CVE-2025-53816和CVE-2025-53817）。这两个漏洞影响7-Zip 25.0.0之前的所有版本，虽然不能实现远程代码执行，但可能引发内存损坏和拒绝服务（Denial of Service，DoS）风险。  
  
  
根据CVSSv4评分标准，这两个漏洞被评定为5.5分的中危级别，但仍需引起高度重视——特别是处理不可信压缩文件的用户。  
  
  
**Part01**  
## RAR5解压功能存在内存损坏风险  
##   
  
第一个漏洞（CVE-2025-53816）存在于7-Zip处理RAR5压缩包的过程中。具体而言，该软件在解压文件时，会根据攻击者可控的数值错误计算内存清零的字节数。  
  
  
CVE描述指出："在7-Zip 25.0.0之前版本中，RAR5处理器在堆缓冲区外写入零值可能导致内存损坏和拒绝服务"。这是由于涉及_lzEnd变量的算术错误所致，该变量取决于压缩包中前一项的大小，攻击者可对此施加影响。  
  
  
安全公告解释称："攻击者可控制覆写的字节数...虽然不太可能导致任意代码执行，但由于内存损坏可能引发拒绝服务。"尽管目前尚无证据表明该漏洞可被武器化用于代码执行，但堆空间内存损坏可能导致进程不稳定或崩溃。  
  
  
**Part02**  
## 复合文档格式解析漏洞可致程序崩溃  
  
  
第二个漏洞（CVE-2025-53817）影响7-Zip从复合文档（Compound Document）格式提取文件的功能。攻击者通过构造畸形的复合文档文件，可导致7-Zip应用程序意外崩溃，从而中断工作流程，在自动化文件处理环境中可能造成服务中断。  
  
  
**Part03**  
## 修复建议  
  
  
7-Zip已在最新发布的25.0.0版本中修复这两个漏洞。安全专家强烈建议用户立即升级，确保安全处理压缩文件——特别是来自不可信或未知来源的压缩包。  
  
  
> **文章来源：freebuf**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
