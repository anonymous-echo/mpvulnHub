#  Microsoft WinDbg RCE 存在允许攻击者远程执行任意代码漏洞   
 网安百色   2025-03-11 19:28  
  
 ![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo4z3hLL6buIGvZbEocbO0KPCb1RUNJQueSZ6ciaQcG5pkMAfogkQWxCXFDc3xIib3pgOs7H3kkjRLPg/640?wx_fmt=jpeg&from=appmsg "")  
  
一个高严重性漏洞 CVE-2025-24043，通过 SOS 调试扩展中不正确的加密签名验证实现远程代码执行 （RCE）。  
  
该漏洞影响关键的 .NET 诊断包，包括 dotnet-sos、dotnet-dump 和 dotnet-debugger-extensions，它们是 .NET Core 应用程序调试工作流不可或缺的一部分。  
  
根据 Juan Hoyos 的说法，该缺陷存在于 SOS 调试扩展未能在调试作期间正确验证加密签名。  
  
这允许具有网络访问权限的经过身份验证的攻击者通过特制的调试会话在易受攻击的系统上执行任意代码。  
  
攻击媒介利用 Visual Studio 和 .NET CLI 环境中的包管理器 NuGet 集成。  
  
理论上，恶意行动者可以入侵 NuGet 包存储库或拦截网络流量，以将合法调试组件替换为带有无效签名的篡改版本。  
  
成功利用此漏洞将为攻击者提供对运行 WinDbg 的未修补 Windows 主机的系统级权限，并发布概念验证。  
## 受影响的软件包和修补版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo4z3hLL6buIGvZbEocbO0KPMcp7KgRHOo6kPjDXwDRamibS9QiaickhNdwnCC2jEIjlJpe8dyLRghY5w/640?wx_fmt=png&from=appmsg "")  
  
由于 WinDbg 嵌入在许多 CI/CD 管道和开发人员工具链中，因此此漏洞会造成级联供应链风险。受损的调试会话可能会导致：  
- 跨公司网络的横向移动  
  
- 加密证书和 API 密钥被盗  
  
- 在已编译的二进制文件中注入持久性后门  
  
- 故障转储分析工作流程中断  
  
值得注意的是，Microsoft 的公告确认，除了立即修补之外，没有可行的解决方法。  
  
受影响的程序包中缺少证书固定会加剧风险，因为攻击者可能会使用被盗或伪造的 Microsoft Authenticode 证书来利用此漏洞。  
## 缓解措施  
  
Microsoft 于 2025 年 3 月 6 日通过 Windows 更新和 NuGet 软件包存储库发布了修补版本。开发人员必须更新本地安装和 CI/CD 环境。  
  
管理员应：  
- 审核 WinDbg 9.0.557512 及更早版本的所有实例  
  
- 重新构建包含易受攻击的软件包的 Docker 镜像  
  
- 轮换存储在使用未修补调试器的系统上的凭据  
  
- 监控异常的 windbg.exe 网络连接  
  
Microsoft 的安全响应中心建议为 NuGet 包实施证书透明度日志，并启用 Windows Defender 应用程序控制策略以限制未签名的调试器扩展  
  
截至撰写本文时，尚未报告任何活跃的漏洞利用，但缺乏缓解措施会导致修补窗口变窄。  
  
正如 Microsoft 在其公告中指出的那样，“开发工具和生产基础设施之间的界限已成为一个关键的攻击面，需要同等的安全审查。  
  
依赖 .NET 诊断的组织必须在攻击者从公共公告中对漏洞进行逆向工程之前确定此更新的优先级。此事件凸显了网络攻击中开发人员工具链的攻击目标越来越多。  
  
****  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
