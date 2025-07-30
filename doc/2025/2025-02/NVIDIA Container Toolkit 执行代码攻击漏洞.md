#  NVIDIA Container Toolkit 执行代码攻击漏洞   
 网安百色   2025-02-16 11:23  
  
 ![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
英伟达（NVIDIA）发布了一项安全更新，以解决其NVIDIA容器工具包和NVIDIA GPU操作符中的一个关键漏洞，该漏洞可能允许攻击者执行任意代码，提升权限，并获得对主机文件系统的访问权限。  
  
该漏洞被跟踪为cve - 2035 -23359，被归类为TOCTOU （Time-of-Check - Time-of-Use）漏洞，CVSS v3.1的基本分数为8.3（高）。  
## NVIDIA容器工具包漏洞  
  
该漏洞存在于NVIDIA Container Toolkit for Linux的默认配置中。  
  
它允许恶意构建的容器映像利用竞争条件，获得对主机文件系统的未经授权访问。成功的漏洞攻击可能导致：  
- 攻击者可以在主机上运行任意命令。  
  
- 未授权的用户可以获得提升的权限。  
  
- 系统运行中断。  
  
- 暴露敏感数据。  
  
- 未经授权的文件修改。  
  
此问题影响所有版本的NVIDIA Container Toolkit（包括版本1.17.3）和NVIDIA GPU Operator（包括版本24.9.1）。  
  
NVIDIA赞扬来自Wiz Research的Andres Riancho、Ronen Shustin、Shir Tamari和Lei Wang发现了这个漏洞。  
## 缓解和更新  
  
NVIDIA强烈建议用户更新到以下补丁版本：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo71ibCkoichzxsaEY8Y5ozUKtWBBYR0NXev1iaWUGAQdAzMqa0RlW86qbrtb6lAbmqbIDibxhAI4fj3pQ/640?wx_fmt=png&from=appmsg "")  
  
这些更新更改了NVIDIA Container Toolkit的默认行为，默认情况下不再从/usr/local/cuda/compat将CUDA兼容库挂载到容器中。  
  
需要此功能的用户可以选择启用/etc vidia-container-runtime/config.toml配置文件中的allow-cuda-compat- libraries -from-container特性标志：  
```
```  
  
但启用此功能会重新引入漏洞风险，不推荐使用。  
  
对于NVIDIA GPU运营商用户，可以在安装Helm期间设置此标志：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo71ibCkoichzxsaEY8Y5ozUKtBxpjpGspicrWbfsZeCWKibU5K80ffZDoPxB9N8Jia5qiaf3lGV2J5MJ3Hw/640?wx_fmt=png&from=appmsg "")  
  
另外，需要CUDA前向兼容性的应用程序可以将LD_LIBRARY_PATH环境变量设置为包括/usr/local/cuda/compat，尽管这可能导致跨驱动程序版本的可移植性问题。  
## 缓解措施  
  
该漏洞突出了与容器化环境相关的风险，特别是对于在云中使用gpu或本地系统的AI工作负载。  
  
Wiz Research的研究人员指出，CVE-2025-23359绕过了较早的CVE-2024-0132漏洞，该漏洞于2024年9月被修复，但仍然存在一些安全漏洞。  
  
攻击者可以利用这个漏洞进行供应链攻击或破坏共享的GPU资源。  
  
建议用户立即更新受影响的软件，使用校验和验证验证容器映像，并避免启用已弃用的功能，除非绝对必要。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
