#  漏洞快报 | ​Spring Framework解析不当漏洞、Node.js 权限提升漏洞......   
 梆梆安全   2024-02-29 18:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/YpfGdibD1mRlEhUENIEoRKT24icXeO3JJwibGtsO8Joic50gqlSvLmCHJreMjPSJ65ya8RqWGTpurGMxXM3xJN7faQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
近日，梆梆安全专家整理发布安全漏洞报告，主要涉及以下产品/组件：  
Internet、GitLab、Spring Framework、Node.js，  
**建议相关**  
**用户及时采取措施做好资产自查与预防工作。**  
  
**Windows Internet 快捷方式**  
  
**文件安全特性绕过漏洞**  
  
  
  
  
  
**组件介绍**  
  
微软（Microsoft）是一家美国跨国科技企业，由比尔·盖茨和保罗·艾伦于 1975 年 4 月 4 日创立。  
公司总部设立在华盛顿州雷德蒙德（Redmond，邻近西雅图），以研发、制造、授权和提供广泛的电脑软件服务业务为主。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YpfGdibD1mRm39SialWoKds54WatrtibnrueWVLg7j6SxHN4YjsHIgCgG88P0Vt2GZCXHxUiaRWNiaRzqATajl5gpfw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
**漏洞描述**  
  
**未经身份认证的远程攻击者通过该漏洞制作恶意文件并发送给受害者，诱导受害者打开后将触发该漏洞，绕过安全检查并执行恶意代码。**  
  
  
该漏洞于 2024 年 1 月被攻击团伙 Water Hydra 作为 0day 进行在野攻击活动，此团伙 2023 年曾使用 winrar 0day CVE-2023-38831 发起过攻击，主要针对全球银行、加密货币平台、外汇和股票交易平台、赌博网站和赌场等目标攻击。  
  
  
  
  
**影响范围**  
  
目前受影响的版本：  
  
Windows Server 2019 (Server Core installation)  
  
Windows 10 Version 21H2 for ARM64-based Systems  
  
Windows 10 Version 21H2 for 32-bit Systems  
  
Windows 10 Version 1809 for ARM64-based Systems  
  
Windows 11 version 21H2 for ARM64-based Systems  
  
Windows 10 Version 1809 for 32-bit Systems  
  
Windows 10 Version 1809 for x64-based Systems  
  
Windows Server 2022, 23H2 Edition (Server Core installation)  
  
Windows 11 Version 23H2 for x64-based Systems  
  
Windows Server 2022  
  
Windows 11 version 21H2 for x64-based Systems  
  
Windows 11 Version 23H2 for ARM64-based Systems  
  
Windows 10 Version 22H2 for 32-bit Systems  
  
Windows 10 Version 22H2 for ARM64-based Systems  
  
Windows Server 2019  
  
Windows 10 Version 22H2 for x64-based Systems  
  
Windows 11 Version 22H2 for x64-based Systems  
  
Windows 11 Version 22H2 for ARM64-based Systems  
  
Windows Server 2022 (Server Core installation)  
  
Windows 10 Version 21H2 for x64-based Systems  
  
  
  
  
**官方修复建议**  
  
Windows自动更新：  
  
Windows系统默认启用 Microsoft Update，当检测到可用更新时，将会自动下载更新并在下一次启动时安装。  
  
  
还可通过以下步骤快速安装更新：  
  
1、点击“开始菜单”或按Windows快捷键，点击进入“设置”  
  
2、选择“更新和安全”，进入“Windows更新”（Windows 8、Windows 8.1、Windows Server 2012以及Windows Server 2012 R2可通过控制面板进入“Windows更新”，步骤为“控制面板”-> “系统和安全”->“Windows更新”）  
  
3、选择“检查更新”，等待系统将自动检查并下载可用更新  
  
4、重启计算机，安装更新  
  
  
系统重新启动后，可通过进入“Windows更新”->“查看更新历史记录”查看是否成功安装了更新。对于没有成功安装的更新，可点击该更新名称进入微软官方更新描述链接，点击最新的SSU名称并在新链接中点击“Microsoft 更新目录”，然后在新链接中选择适用于目标系统的补丁进行下载并安装。  
  
下载链接：  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21412  
  
  
  
**GitLab 16.9 存储型XSS漏洞**  
  
  
  
  
  
**组件介绍**  
  
GitLab 是由 GitLab 公司开发的、基于 Git 的集成软件开发平台。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YpfGdibD1mRmt7cL6Tw1CJ7hrEczyDaVZrBRj35FvOA8lIIoPlk4AEhELMeDkhuhZs69nCLfOXDmnbar6ZFrC7A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**漏洞描述**  
  
GitLab 受影响版本中的用户资料页面存在存储型 XSS 漏洞，**攻击者可将恶意载荷添加到个人资料(Pronunciation字段)中，并诱导其他用户访问攻击者个人资料进而执行恶意js，攻击者可能利用该漏洞窃取用户会话令牌等敏感信息。**  
  
  
  
  
**影响范围**  
  
   
16.9≤GitLab≤16.9.1  
  
  
  
**官方修复建议**  
  
目前官方已发布安全修复补丁，建议受影响用户可以升级到最新版本。  
  
将组件 gitlab 升级至 16.9.1 及以上版本  
  
下载链接：  
  
https://gitlab.com/gitlab-org/gitlab-foss/-/commit/eac095941872f337e573563fe59f5c57f7d7c448  
  
  
  
**Spring Framework 解析不当漏洞**  
  
**CVE-2024-22243**  
  
  
  
  
  
**组件介绍**  
  
Spring Framework 是一个功能强大的 Java 应用程序框架，旨在提供高效且可扩展的开发环境。UriComponentsBuilder 是 Spring Framework 提供的一个实用工具类，用于构建和处理URI。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/YpfGdibD1mRmt7cL6Tw1CJ7hrEczyDaVZLY36slqQQec5lYm3OetF3mdic7nb5j2Pic4RKkH2fCYicLzUglxtZ2CtA/640?wx_fmt=jpeg "")  
  
  
  
**漏洞描述**  
  
2月22日，梆梆安全安服团队监测到 Spring Framework 中修复了一个URL解析不当漏洞（CVE-2024-22243）。  
  
  
Spring Framework 受影响版本中，**由于 UriComponentsBuilder 中在处理URL 时未正确过滤用户信息中的”\[“，可能导致威胁者构造恶意URL绕过验证。**  
当应用程序使用 UriComponentsBuilder 来解析外部提供的 URL（如通过查询参数）并对解析的 URL 的主机执行验证检查时可能容易受到 Open 重定向攻击和 SSRF 攻击，导致网络钓鱼和内部网络探测等。  
  
  
  
  
**影响范围**  
  
Spring Framework 6.1.0 - 6.1.3  
  
Spring Framework 6.0.0 - 6.0.16  
  
Spring Framework 5.3.0 - 5.3.31  
  
以及不受支持的旧版本。  
  
  
  
  
**官方修复建议**  
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
Spring Framework 6.1.x：升级到 6.1.4  
  
Spring Framework 6.0.x：升级到 6.0.17  
  
Spring Framework 5.3.x：升级到 5.3.32  
  
下载链接：  
  
https://spring.io/projects/spring-framework  
  
  
用户也可通过以下操作提高应用安全性：  
- 定期更新系统补丁，减少系统漏洞，提升服务器的安全性。  
  
- 加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
- 使用企业级安全产品，提升企业的网络安全性能。  
  
- 加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
- 启用强密码策略并设置为定期修改。  
  
下载链接：  
  
https://spring.io/security/cve-2024-22243  
  
https://github.com/spring-projects/spring-framework/commit/7ec5c994c147f0e168149498b1c9d4a249d69e87  
  
  
  
**Node.js 权限提升漏洞**  
  
**CVE-2023-34051**  
  
  
  
  
  
**组件介绍**  
  
Node.js是开源、跨平台的JavaScript运行时环境，CAP_NET_BIND_SERVICE是Linux操作系统中的一种特殊能力(capabilities)，它允许非特权进程绑定到系统的特权端口上。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YpfGdibD1mRmt7cL6Tw1CJ7hrEczyDaVZjVnJjrMMUkJ3czoc60n5dDxl0m6ia7OF84Tst58Xp1PInp71M4rgLQQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞描述**  
  
Node.js 受影响版本由于 node::credentials 模块对 CAP_NET_BIND_SERVICE 安全机制处理存在缺陷，**导致系统低权限的攻击者可通过修CAP_NET_BIND_SERVICE 将 Node 应用绑定至特权端口，并将恶意代码注入到 Node 应用中，通过修改 NODE_OPTIONS 环境变量，进而以应用当前的用户权限在主机上执行恶意代码。**  
  
  
  
  
**影响范围**  
  
目前受影响的版本：  
  
20.11.0≤Node.js＜20.11.118.19.0≤Node.js＜18.19.121.6.0≤Node.js＜21.6.2  
  
  
  
  
**官方修复建议**  
  
建议用户将组件 Node.js 升级至安全版本，下载链接：  
  
https://github.com/nodejs/node/commit/10ecf400679e04eddab940721cad3f6c1d603b61  
  
  
推荐阅读  
  
  
Recommended  
  
# >移动 APP 成为数据泄露“重灾区”，梆梆安全应用安全测评平台开具良方！  
# >工信部发布 “提升移动互联网应用服务能力” 26条，梆梆安全助力软件更自由、更安全！  
# >移动应用安全监管的主要难点与应对之道  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YpfGdibD1mRnDY5407c6UFGMlacqbuQrzVRU5sgjicTxqFdSDRLzgbfM5BibmVpNibL7Wlia0630UxgBIGaX18IJzqQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
