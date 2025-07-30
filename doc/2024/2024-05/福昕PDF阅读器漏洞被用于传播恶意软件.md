#  福昕PDF阅读器漏洞被用于传播恶意软件   
 网络安全应急技术国家工程中心   2024-05-20 15:32  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GoUrACT176kY9zCQCnYu7vwm5bbYL6IhmWl61WFQKWfbqrtibia92Ty0ZlC0kFFGRicia8Ey4XFkLxwDGuRZRETfEg/640?wx_fmt=png&from=appmsg "")  
  
近日，Check Point的研究人员警告称，黑客正在利用福昕（Foxit）PDF阅读器的设计缺陷通过PDF文档传播多种恶意软件。  
# 漏洞利用方式  
  
研究人员分析了多起利用恶意PDF文件的攻击活动，这些攻击主要针对Foxit Reader的用户。攻击者使用各种.NET和Python漏洞构建器，其中最流行的是“PDF Exploit Builder”，来创建包含宏的PDF文档，这些宏可以执行下载和执行恶意软件（如Agent Tesla、RemcosRAT、Xworm、NanoCore RAT等）的命令或脚本。  
  
恶意PDF文件会触发福昕阅读器的安全警告窗口，但是由于这些警告窗口默认选择了不安全的选项，为攻击者提供了便利。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvbAGhYzDwGpRUaC0zRibpuo1MhssDvNbunpDcQBMia2BM9zZbo4sibwOPiaQVlA5ibcMubF5856iaOKZxuA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
如上图所示，福昕阅读器在打开这些陷阱PDF文件时会显示弹出警告框，用户需要选择是否信任/打开此文档，而警告窗口的默认选项是不安全的“打开”（上图）。攻击得手的原因是很多用户会忽略警告文本，快速接受默认选项，从而允许Foxit执行恶意命令。  
# 福昕承诺解决问题  
  
福昕PDF阅读器在全球拥有超过7亿用户，其客户包括政府和科技部门。Check Point研究人员指出，多年来包括网络犯罪分子和APT组织一直在利用这个漏洞，因为大多数防病毒软件和沙盒环境主要针对Adobe PDF阅读器。这些漏洞的利用成功率很高且检测率低，某些恶意PDF文件可以通过非传统途径（如Facebook）传播而不被社交媒体的恶意软件检测器检测到。  
  
Check Point已将这一问题报告给福昕公司，后者表示将在2024年的新版本中解决这一问题。研究者表示，虽然最理想的方法是检测并禁用CMD执行类型，但研究者认为福昕采取的措施可能仅仅是将默认选项切换为“不要打开”。  
  
**缓解建议**  
  
在获得软件更新之前，安全专家建议福昕用户对潜在的利用保持警惕，并遵守经典的防御实践。为缓解此类威胁的风险，用户必须：  
  
- 通过及时补丁和其他方式保持操作系统和应用程序更新。  
  
- 警惕带有链接的意外电子邮件，尤其是来自未知发件人的电子邮件。  
  
- 增强员工的网络安全意识。  
  
- 如有任何疑问或不确定性，请咨询安全专家。  
  
**参考链接：**  
  
https://research.checkpoint.com/2024/foxit-pdf-flawed-design-exploitation/  
  
  
  
原文来源  
：GoUpSec  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
