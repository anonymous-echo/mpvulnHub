#  7-Zip零日漏洞在俄乌战争中被利用   
原创 hackerson  黑客联盟l   2025-02-06 11:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWhqjlIpdACpYtdVvKD3OPyBmYA5brJN4sK34dYRQcSL3uKNsGNoib9fEN3CEGeChjIvOx8qClscs5w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/dhzGXdxNSYvIcMG3icZZ8D9HvSOLWuzPNelJuicEbhKyCMtXqpvnHyCysVxCeyYDJHwJNlmH8Pcb7dXfNmNGEyPw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
研究人员称，他们最近在 7-Zip 压缩实用程序中发现了一个零日漏洞，在俄罗斯对乌克兰的持续行动中，该漏洞被多次利用。  
  
  
该漏洞使得一个俄罗斯组织能够绕过一项旨在限制执行从互联网下载文件的 Windows 保护机制。这种保护机制通常被称为 “网络标记”（Mark of the Web，简称 MotW）。它的工作原理是在所有从互联网或网络共享下载的文件上放置一个 “Zone.Identifier” 标签。这个标签属于 NTFS 备用数据流的一种，格式为 ZoneID=3，它会让文件受到 Windows Defender SmartScreen 的额外审查，并对其执行方式和时间加以限制。  
  
7-Zip 的这个漏洞使得一个俄罗斯组织能够绕过这些保护措施。其利用方式是将一个可执行文件嵌入到一个压缩包中，然后再将这个压缩包嵌入到另一个压缩包内。外层压缩包带有网络标记标签，而内层的则没有。这个被追踪为 CVE - 2025 - 0411 的漏洞，在去年 11 月下旬随着 24.09 版本的发布得以修复。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dhzGXdxNSYvIcMG3icZZ8D9HvSOLWuzPNY7Naibx2ibObHx8CT1YojnAbhzHK4XkzqoF7GafiaQsp3tic3V1K6vMfdA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dhzGXdxNSYvIcMG3icZZ8D9HvSOLWuzPN5LmM7OqKw1e13J2XI3uT8FXcBP2ibSbeiaKU1A28iaBtaECLKORVwHQeQ/640?wx_fmt=png&from=appmsg "")  
  
  
发现该漏洞的安全公司趋势科技的研究员彼得・吉尔努斯（Peter Girnus）写道：“CVE - 2025 - 0411 的根本原因在于，在 24.09 版本之前，7-Zip 没有将网络标记保护正确应用到双重封装的压缩包内容上。这使得威胁行为者能够制作出包含恶意脚本或可执行文件的压缩包，这些文件不会受到网络标记保护，从而让 Windows 用户易受攻击。”  
  
  
为了更好地掩盖攻击，可执行文件的扩展名使用了所谓的 “同形异义字符”。这些字符不属于 ASCII 标准，尽管它们看起来与某些 ASCII 字符相同或相似。例如，西里尔字母 “С”，它看起来与 ASCII 字符 “C” 一模一样，但实际上两者毫无关联，因为它们属于完全不同的编码方案。多年来，黑客一直使用同形异义字符来伪造敏感网站的域名。  
  
  
利用 7-Zip 零日漏洞的威胁行为者以类似方式使用同形异义字符，让可执行文件看起来像是文档文件。这些双重压缩的文件被附在从乌克兰政府机构真实受入侵账户发出的电子邮件中。  
  
  
**吉尔努斯称，以下机构成为了攻击目标：**  
  
乌克兰国家执行服务局（SES）—— 司法部扎波罗热汽车制造厂（PrJSC ZAZ）—— 汽车、客车和卡车制造商基辅公共交通公司（Kyivpastrans）—— 基辅公共交通服务机构SEA 公司 —— 家电、电气设备及电子产品制造商韦尔霍维纳区州政府 —— 伊万诺 - 弗兰科夫斯克州行政区政府VUSA—— 保险公司第聂伯市地区药房 —— 地区药房基辅供水公司（Kyivvodokanal）—— 基辅供水公司扎利什奇基市议会 —— 市议会  
  
  
任何使用 7-Zip 的用户，尤其是在 Windows 系统上使用的，都应确保使用的是最新版本，目前为 24.09 版本。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/dhzGXdxNSYu9NHeLQtcv3btw1zjO4LfzWI3eeGE0fkD9CaQEgDh4FHsKYk8iaVOjhRgGKfEbfRwZf64QibNxEmWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
关注【**黑客联盟**】带你走进神秘的黑客世界  
  
  
