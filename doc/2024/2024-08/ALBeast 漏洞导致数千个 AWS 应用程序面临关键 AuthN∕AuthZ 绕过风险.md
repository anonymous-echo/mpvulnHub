#  ALBeast 漏洞导致数千个 AWS 应用程序面临关键 AuthN/AuthZ 绕过风险   
 独眼情报   2024-08-24 12:34  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnST3xnbsWTWRunF0ibOiaqbNPiatVibNoIt3ah51TfaW5jL00q4aUkkTHokK14suZQtXcF7icLmps5A8xg/640?wx_fmt=other&from=appmsg "")  
  
ALBeast 攻击演示 | 图片：Miggo  
  
  
  
Miggo Research 发现了一种新的基于配置的漏洞，称为 ALBeast，影响大量依赖 AWS 应用程序负载均衡器 (ALB) 进行身份验证的应用程序。此严重漏洞允许攻击者绕过身份验证和授权机制，可能导致未经授权的访问、数据泄露和数据泄露。  
  
  
ALBeast 是一个基于配置的漏洞，针对使用 AWS ALB 身份验证功能的应用程序。通过利用此漏洞，威胁行为者可以绕过身份验证和授权控制，获得对敏感资源的未经授权的访问。该漏洞对受影响应用程序的机密性、完整性和可用性的影响使其成为使用 AWS ALB 的组织的一个关键问题。  
  
Miggo Research 于 2024 年 4 月 6 日首次向 AWS 报告了 ALBeast。从那时起，双方密切合作以解决该问题。AWS 的回应是更新其身份验证功能文档并实施新代码来验证签署令牌的 AWS ALB 实例，从而确保客户免受潜在攻击。尽管做出了这些努力，但 Miggo Research 估计，全球 371,000 个潜在易受攻击的 ALB 和应用程序中仍有超过 15,000 个处于危险之中。  
  
  
  
ALBeast 漏洞可以通过相对简单的攻击序列来利用：  
1. 创建恶意 ALB 实例  
：攻击者在其 AWS 账户中设置自己的 ALB 实例并启用身份验证。  
  
1. 伪造令牌  
：然后攻击者使用此 ALB 签署他们控制的令牌，并更改 ALB 配置以匹配受害者的预期发行者。  
  
1. 绕过安全性  
：利用伪造的令牌，攻击者可以绕过受害者应用程序的身份验证和授权机制，获得对受保护资源的未经授权的访问。  
  
这次攻击表明错误配置很容易被利用，从而将受信任的身份验证机制变成漏洞。  
  
AWS 表示，ALBeast 不是 ALB 服务本身的漏洞，而是共享责任模型中的错误配置导致的问题。在此模型下，AWS 负责云基础设施的安全，而客户负责保护其应用程序和配置。  
  
  
因此，AWS 用户必须确保其应用程序符合 AWS 提供的更新文档和最佳实践。这包括使用 ALB 身份验证验证每个应用程序中的令牌签名者，并限制目标系统仅接受来自其应用程序负载均衡器的流量。  
  
为了防范 ALBeast，Miggo Research 建议采取以下措施：  
1. 令牌签名者验证  
：确保每个使用 AWS ALB 进行身份验证的应用程序都检查令牌签名者，如更新的 AWS 文档中所述。  
  
1. 流量限制  
：配置安全组以将流量限制为仅来自应用程序负载均衡器的目标，进一步降低未经授权访问的风险。  
  
AWS 已  
更新  
其文档以反映这些安全措施，并敦促客户及时采取行动来保护他们的应用程序。  
  
有关 ALBeast 漏洞的详细技术分析及其发现方式，请访问 Miggo Research 的完整报告：寻找 ALBeast：技术演练  
。  
  
https://www.miggo.io/resources/uncovering-auth-vulnerability-in-aws-alb-albeast  
  
