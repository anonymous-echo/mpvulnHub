#  常见 Web 应用越权漏洞分析与防范研究   
 关键基础设施安全应急响应中心   2023-11-02 14:53  
  
摘要：Web 应用通常用于对外提供服务，由于具有开放性的特点，逐渐成为网络攻击的重要对象，而漏洞利用是实现 Web 攻击的主要技术途径。越权漏洞作为一种常见的高危安全漏洞，被开 放 Web 应 用 安 全 项 目（Open Web Application Security Project，OWASP） 列 入 10 个 最 关 键Web 应用程序安全漏洞列表。结合近几年披露的与越权相关的 Web 应用通用漏洞披露（Common Vulnerability and Exposures，CVE）漏洞，通过分析 Web 越权漏洞成因和常见攻击方法，提出了针对 Web 越权漏洞攻击的防范方法。  
  
随着 Web 技术的迅猛发展，Web 应用已经普及到企业管理、电子商务等各个领域。由于 Web 应用具有开放性的特点，逐渐成为网络攻击者的重点攻击对象。Web 应用在给人们的工作带来方便的同时，也带来了巨大的安全风险。软件一定存在各种已知或未知的漏洞，Web 应用也不例外 。常见的漏洞有结构化查询语言（Structured Query Language，SQL）注入漏洞、跨站脚本漏洞（Cross Site Script，XSS）、跨站请求伪造漏洞（Cross Site Request Forgery，CSRF）、指令执行漏洞、文件包含漏洞、越权访问漏洞等 。  
  
Web 应用漏洞无法杜绝，目前最有效的防范办法是采用 Web 漏洞扫描技术尽可能发现潜在漏洞并进行处理。对于 SQL 注入、XSS、CSRF 等 Web 漏洞，业界已经有了比较成熟的检测和防范方法 ，基于Fuzzing 技术的漏洞挖掘近年也被广泛应用于 Web应用的漏洞检测中 。  
  
Web 越权漏洞是一种常见的逻辑漏洞，是指未对通过身份验证的用户实施恰当的访问控制，攻击者利用这一漏洞，在未经授权的情况下，泄露、修改或销毁数据，或在权限之外执行业务功能。越 权 漏 洞 在 开 放 Web 应 用 安 全 项 目（Open Web Application Security Project，OWASP）中被称为“访问控制失效（Broken Access Control）”。  
  
OWASP 是一个致力于 Web 应用安全研究的开源、非营利、全球性安全组织，每年总结发布最可能发生、最常见、最危险的前 10 个 Web 漏洞的榜单，是 Web 应用安全领域的权威参考。在 2021 年OWASP 发布的榜单中，越权漏洞从 2017 年的第5 名，跃居至第 1 名，成为 Web 应用安全中最可能发生、最危险的安全漏洞类型。由于越权漏洞属于程序逻辑漏洞，其防护和检测的难度非常大。  
  
本文从漏洞威胁等级、影响面、攻击价值、利用难度等几个方面综合考虑，选择近 3 年的典型越权漏洞进行分析，通过分析 Web 越权漏洞的成因和常见攻击方法，给出防范 Web 越权漏洞的一般方法。  
  
# 1、常见 Web 越权漏洞分析  
  
通用漏洞披露（Common Vulnerability and Exposures，CVE）是一个公开的权威网络安全漏洞和暴露的列表，它通过 CVE 标识符唯一标识每个已发现的软 件 漏 洞， 并 基 于 通 用 漏 洞 评 分 系 统（Common Vulnerability Scoring System，CVSS）评分对漏洞进行优先级排序。本文根据 CVE 漏洞描述和 CVSS 漏洞评分，选择近几年发现的与 Apache Superset、Joomla、Alibaba Nacos、Zabbix、Apache ShenYu 这几个在 Web 开发中广泛应用的 Web 组件相关的高危越权漏洞进行分析。  
  
**1.1　Apache Superset 身份验证绕过漏洞**  
  
Apache Superset 身份验证绕过漏洞于 2023 年4 月由 Apache 官方发布，漏洞编号为 CVE-2023-27524，CVSS 漏洞评分为 8.9，属于高危漏洞。由于用户没有修改默认配置，该漏洞使得攻击者可以通过伪造 Cookie 绕过身份验证，属于典型的错误参数配置造成的越权访问漏洞。  
  
Apache Superset 是一种用于数据探索和数据可 视 化 的 开 源 Web 应 用 程 序。它 基 于 PythonFlask 框架，是适用于企业日常生产环境的商业智 能 可 视 化 工 具。该 Web 应 用 的 用 户 状 态 管 理使 用 SECRET_KEY 加 密 签 名 cookie 进 行 验 证，Superset-2.0.1 之前的版本安装时 SECRET_KEY 默认 为 \x02\x01thisismyscretkey\x01\x02\\e\\y\\y\\h， 如果 用 户 使 用 默 认 SECRET_KEY 值， 则 SECRET_KEY 将暴露，攻击者可以使用 SECRET_KEY 生成伪造 cookie，在未授权情况下访问 Web 应用程序，实现敏感数据窃取或任意代码执行。  
  
使用 Flask-Unsign 工具验证目标网站是否存在CVE-2023-27524 漏洞的界面如图 1 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iclynibMMTgBw15mWg1qGH8YJWgj2H6fygg6R2kFZohia8nA4LUCha4m5bpAAHvmLEs9VFNorQSCnu5lBGW0gtW7Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 1 CVE-2023-27524 漏洞验证  
  
**1.2 　Joomla 未经授权访问漏洞**  
  
Joomla 未 经 授 权 访 问 漏 洞 于 2023 年 2 月 由Joomla 官 方 发 布， 漏 洞 编 号 CVE-2023-23752，漏洞评分 7.5，属于高危漏洞。该漏洞是典型的不 安 全 的 应 用 程 序 接 口（Application Programming Interface，API）访问控制造成的越权访问漏洞。  
  
Joomla 是世界上使用最广泛的开源内容管理系 统（Content Management System，CMS） 之 一，该系统用 PHP 语言与 MySQL 数据库开发，可以在Windows、Linux 等多种平台运行，方便用户构建网站和 Web 应用程序。  
  
Joomla 有 3 个路由入口，分别是根目录 index.php（用户访问入口）、administrator/index.php（管理员入口）和 api/index.php（开发者 RestAPI 接口）。由于 Joomla对 Web 服务端点的访问控制存在缺陷，未经身份认证的攻击者可以通过伪造特定请求访问 RestAPI 接口获取 Joomla 相关配置信息，导致敏感信息泄漏。  
  
4.0.0 至 4.2.7 的 Joomla 未 授 权 访 问 统 一 资 源定 位 器（Uniform Resource Locator，URL） 路 径 为api/index.php/v1/config/application?public=true， 通 过该路径访问能够获取用户名、口令等敏感信息，如图 2 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iclynibMMTgBw15mWg1qGH8YJWgj2H6fyghMQAOFBYqxiasXLJETG0p0S5vhbOyY7cdxia8icfUgTrbibHpmzr7y3JZA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 2　CVE-2023-23752 漏洞验证  
  
**1.3　Alibaba Nacos 访问控制漏洞**  
  
Alibaba Nacos 访问控制漏洞于 2020 年 12 月由Alibaba Nacos 官方在 github 发布的 issue 中披露，漏洞编号 CVE-2021-43116，CVSS 漏洞评分 8.8，属于高危漏洞。该漏洞是由于未正确处理超文本传输（Hypertext Transfer Protocol，HTTP） 协 议 头 的User-Agent 参数导致的未授权访问漏洞，利用该漏洞攻击者可以进行任意操作，包括创建新用户及进行认证登录授权操作。  
  
Nacos 是阿里巴巴推出的用于发现、配置和管理微服务的开源软件，广泛应用于微服务应用场景。其 2.0.0-ALPHA.1 以下版本软件为处理服务端到服务端的请求，将协商好的 User-Agent 参数设置“Nacos-Server”。在认证授权操作时，当发现请求的 User-Agent 为“Nacos-Server”时就不进行任何认证，导致了漏洞的出现，如图 3 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iclynibMMTgBw15mWg1qGH8YJWgj2H6fygMV07f1JGMCReggOstUibqyiamOxuMjiblL1XM31sXUzSKJOETu8gZOkNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 3　 CVE-2021-43116 漏洞验证  
  
**1.4　 Zabbix 身份认证绕过漏洞**  
  
Zabbix 身 份 认 证 绕 过 漏 洞 由 Zabbix 官 方 于2022 年初发布，漏洞编号 CVE-2022-23131，CVSS漏洞评分 9.1，为高危漏洞。该漏洞属于会话信息处理机制的问题，因此攻击者可以伪造数据绕过认证进入控制台，属于典型的不当的会话管理造成的越权访问漏洞。  
  
Zabbix 是一个非常流行的企业级开源监控平台，基于 Web 界面提供分布式系统监视及网络监视功能。Zabbix 将会话信息加密后保存在客户端Cookie 中，在 5.4.0 ～ 5.4.8 的版本中，数据只在验证 SessionID 时才进行加密处理，导致其他 Key 数据不会被加密。在通过 SAML SSO 单点登录进行认证时，将直接读取 SAML 中用户信息进行认证。如图 4 所示，由于 SAML 数据未加密，客户端可以伪造数据绕过认证，以管理员身份进入 Zabbix 控制台，造成远程命令执行或敏感信息泄漏。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iclynibMMTgBw15mWg1qGH8YJWgj2H6fyghicdib5RF7qWlh1FfKDXPQ6ENjgbGtKooALHsP1NSPzwiaYVDX9wu4hyg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 4 　CVE-2023-23752 漏洞验证  
  
**1.5　Apache ShenYu 身份验证绕过漏洞**  
  
Apache ShenYu 身 份 验 证 绕 过 漏 洞 于 2021 年11 月 由 Apache 官 方 发 布， 漏 洞 编 号 CVE-2021-37580，CVSS 漏洞评分 9.8，属于高危漏洞。由于ShenyuAdminBootstrap 中 JWT 的错误使用，攻击者可以利用该漏洞绕过身份验证，直接进入目标系统，属于典型的校验不充分造成的越权访问漏洞。  
  
Apache ShenYu 是一款高性能、跨语言、响应式的开源 API 网关，支持 SpringCloud、Motan 等多种协议，兼容多种主流框架，广泛应用于各种微服务场景中。Apache ShenYu 采用 JWT（JSON Web Token）技术进行身份认证。JWT 是一个开放标准，用于作为 JSON 对象在各方之间传递安全信息。在Apache ShenYu Admin 2.3.0 至 2.4.0 版 本 中， 通 过token 获取 userInfo 对象时，仅对 token 进行解析，但未进行充分校验，攻击者可通过该漏洞绕过管理者身份认证，进而获取管理员账号和口令 ，如图 5 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iclynibMMTgBw15mWg1qGH8YJWgj2H6fyg9W8WbVHqLLEC4QosT6PwwGAzj1mBDIZOALDC9tuicZSI94RIHDC9Acg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 5  CVE-2021-37580 漏洞验证  
  
# ２、Web 越权漏洞成因分析  
  
通过以上对典型的 Web 越权漏洞的分析可以看出，Web 越权漏洞形成的主要原因还是开发人员在设计阶段对用户权限的设计存在疏漏，当访问控制没有正确设计与配置时，允许攻击者在未授权的情况下绕过或提升系统或应用程序所分配的权限。  
进一步细分 Web 越权漏洞的成因，主要有以下几种。  
  
(1）错误的访问控制机制：包括不正确的用户权限管理、违反最小化授权原则、缺少访问控制机制，会导致未授权访问或权限提升。  
  
(2）访问控制配置不当：包括未更改默认访问控制设置、错误配置用户权限、未正确配置文件或目录权限，如 Apache Superset CVE-2023-27524身份验证绕过漏洞。  
  
(3）不安全的对象引用：允许用户操作 Web应用内部对象引用，可能导致未授权访问或敏感信息泄露，例如，允许用户直接引用 Web 应用内部的数据库或文件。  
  
(4）不当的会话管理：包括用户在注销后未使会话令牌（Token）失效，以及存在不安全的或可预测的访问控制令牌，可能允许攻击者劫持有效的用户会话进行未授权访问，如 Zabbix CVE-2022-23131 身份认证绕过漏洞。  
  
(5）不安全的 API 访问控制机制：包括未正确验证 API 请求者身份，未限制访问频率，缺少对POST、PUT 和 DELETE 的访问控制，允许不信任的来源访问，如 Joomla CVE-2023-23752 未经授权的 API 访问控制漏洞。  
  
(6）用户输入校验不充分：不充分的输入验证可能允许攻击者通过注入恶意输入或绕过输入过滤器来绕过访问控制，导致路径遍历、文件包含或命令注入等漏洞。  
  
# ３、Web 越权漏洞攻击方法  
  
**3.1　 Web 越权漏洞攻击模式**  
  
Web 越权漏洞的常见攻击模式包括垂直越权、水平越权、不安全的直接对象应用、强行浏览、参数篡改。  
  
(1）垂直越权。在这种攻击模式中，攻击者利用经过认证的用户身份，通过操纵参数、会话令牌或用户角色绕过访问控制，访问或执行更高权限用户的操作，达到提升系统中权限的意图。  
  
(2）水平越权。在这种攻击模式中，攻击者通过操纵参数或会话令牌，绕过在不同账户之间强制分离的访问控制，并以合法用户相同的权限进入另一个账户。  
  
(3）不安全的直接对象引用（Insecure Direct Object References，IDOR）。在 Web 应用中通过用户输入从数据库或其他来源访问或操作资源，而输入没有经过充分地校验或授权时，攻击者可以未经授权对系统资源进行访问。  
  
(4）强行浏览。在这种攻击模式中，攻击者试图通过手动猜测或系统地列举资源 URL 或路径来访问受限制的资源。通过利用不恰当的或薄弱的访问控制，他们可能会发现并访问敏感信息或应受保护的功能。  
  
(5）参数篡改实现权限升级。在这种攻击模式中，攻击者操纵请求中传递的参数改变应用程序的预期行为，如用户 ID、角色或权限，试图获得更高的权限或访问受限制的资源。  
  
(6）不安全的功能级授权。这种攻击模式针对应用程序进行功能级授权处理时存在的漏洞。攻击者利用特定功能或 API 中薄弱或缺失的访问控制，获得对敏感操作或数据的未授权访问。  
  
**3.2　 Web 越权漏洞攻击流程**  
  
Web 越权漏洞攻击的流程一般包括侦查、用户枚举、识别目标用户、漏洞利用、未授权访问。  
  
(1）侦查：攻击者收集有关目标系统的信息，包括识别潜在的用户和他们在系统中的角色或权限。  
  
(2）用户枚举：攻击者通过用户名枚举、搜索用户名单或利用信息泄漏等技术，探测、枚举系统中的有效账户。  
  
(3）识别目标用户：攻击者选择一个具有较低权限的特定账户，并确定具有较高权限的目标账户。  
  
(4）漏洞利用：攻击者分析、识别与利用系统的访问控制机制或应用逻辑中的绕过认证、操纵授权检查及错误配置等漏洞，实现权限提升。  
  
(5）未授权访问：一旦漏洞被成功利用，攻击者就能以更高的权限进入目标账户，修改用户角色、权限或会话令牌，访问敏感数据，执行特权功能，或破坏系统内的其他资源。  
  
# ４、Web 越权漏洞防范方法  
  
通过分析 Web 越权漏洞成因和常见 Web 越权漏洞攻击方法，为了防范 Web 越权漏洞带来的潜在攻击威胁，本文提出了以下措施：  
  
(1）用户输入充分校验。通过验证用户输入，防范如 URL 操纵或参数篡改等可能绕过访问控制的攻击。  
  
(2）安全会话管理。有状态的会话标识符应在注销后在服务器上失效；无状态的 JWT 令牌必须设定较短有效期，以便使基于令牌的攻击时间窗口降到最小，而对于寿命较长的 JWT 令牌，强烈建议遵循 OAuth 标准来撤销访问。  
  
(3）多层访问控制模型。采取深层安全措施在 Web 应用程序、数据库和操作系统等层面综合实施访问控制机制，如自主访问控制（Discretionary Access Control，DAC）、 访 问 控 制 列 表（Access Control List，ACL）、基于角色的访问控制（Role Based Access Control，RBAC）等建立多层保护，强化对未授权访问威胁的防御，即使攻击者突破一个层面，也会被其他层面的防御机制阻止。  
  
(4）适当的错误处理。实施适当的错误处理机制，以避免在错误信息中透露有关访问控制机制或系统内部的敏感信息。  
  
(5）安全测试和审计。定期对 Web 应用进行安全测试，如渗透测试和漏洞扫描，以发掘和检测系统访问控制中的潜在漏洞。  
  
# ５、结语  
  
越权漏洞作为 Web 应用中的一种常见的安全漏洞，利用简单且危害巨大，一旦被利用成功，可能导致未授权访问、敏感信息泄露、数据篡改、执行恶意代码等危害。  
为了防范越权漏洞攻击，本文提出在 Web 应用设计阶段引入越权漏洞防范机制，在编码阶段实施充分验证用户输入、分配最小化权限、安全管理会话及建立多层访问控制保护，在测试运行阶段对重要的数据资产服务器进行重点防护与安全配置检查，并定期进行安全测试和审计。  
  
  
  
原文来源：信息安全与通信保密杂志社  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
