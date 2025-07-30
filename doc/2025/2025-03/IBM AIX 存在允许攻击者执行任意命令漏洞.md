#  IBM AIX 存在允许攻击者执行任意命令漏洞   
 网安百色   2025-03-22 19:35  
  
   
   
![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo7gZvZUVbtic2Er91tLZ7Ab37nhHhgoM2l45c3slYljI4GdwM7MdmdynmGicsUZUriabylZh6vWtdE6A/640?wx_fmt=jpeg&from=appmsg "")  
  
IBM AIX作系统中的关键安全漏洞可能允许未经授权的远程攻击者执行任意命令，从而可能危及整个系统。  
  
IBM 已发布安全补丁，以解决影响多个基于 Unix 的作系统版本的这些高严重性缺陷。  
  
跟踪为 CVE-2024-56346 和 CVE-2024-56347 的漏洞都与 AIX 网络安装管理 （NIM） 服务中的不当进程控制有关。  
  
此漏洞会影响 IBM AIX 中的 nimesis Network Installation Management （NIM） 主服务。它被分配了可能的最高 CVSS Base 分数 10.0，表明严重性。  
  
漏洞允许执行命令  
  
此缺陷可能允许远程攻击者在受影响的系统上执行任意命令，而无需任何身份验证或用户交互。  
  
第二个漏洞 （CVE-2024-56347） 影响 AIX nimsh 服务 SSL/TLS 保护机制，并已分配 CVSS Base 分数 9.6。  
  
此漏洞还使远程攻击者能够执行任意命令，尽管它需要一些用户交互。这两个漏洞都源于这些服务实施中的 CWE-114（进程控制）弱点。  
  
鉴于 AIX 经常用于金融、银行、医疗保健和电信部门的关键应用程序，成功利用可能会产生广泛的后果。  
  
此外，由于这些漏洞的 CVSS 得分很高，因此尤其令人担忧。如果不打补丁，攻击者可能会未经授权访问关键的 AIX 系统，从而导致数据盗窃、服务中断或网络内的横向移动。  
  
漏洞摘要如下：  
  
风险因素	漏洞：CVE-2024-56346	CVE-2024-56347漏洞  
  
受影响的产品	IBM AIX 7.2、7.3（包括 VIOS）	IBM AIX 7.2、7.3（包括 VIOS）  
  
冲击	远程执行任意命令	远程执行任意命令  
  
利用先决条件	无需身份验证或用户交互）	无需身份验证或用户交互）  
  
CVSS 3.1 分数	10.0（严重）	9.6 （严重）  
  
受影响的系统和范围  
  
这些安全漏洞会影响 IBM AIX V7.2 和 7.3，包括在 Virtual I/O Server （VIOS） 环境上运行的系统。受影响的特定文件集包括：  
  
bos.sysmgt.nim.客户端  
  
bos.sysmgt.nim.master  
  
bos.sysmgt.sysbr  
  
组织可以通过使用 AIX 命令检查已安装的文件集来确定其系统是否易受攻击：lslpp -L |grep -i bos.sysmgt.nim.client。  
  
  
IBM 通过发布受影响系统的补丁来解决这些漏洞。该公司已分配特定的 APAR（授权程序分析报告）来跟踪修复：  
  
  
对于 AIX 7.2.5：APAR IJ53757 （SP10）  
  
对于 AIX 7.3.1：APAR IJ53929  
  
对于 AIX 7.3.2：APAR IJ53923 （SP04）  
  
对于 AIX 7.3.3：APAR IJ53792 （SP01）  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
