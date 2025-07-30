#  【漏洞通告】Spring Security 访问控制错误漏洞   
安迈应急响应中心  安迈信科应急响应中心   2024-02-29 15:13  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tdibEPWdubQUgErMslSgzVibGKdSFkWPTbTgu83UTXdNYm7eOxRSmuNmOjUIxdicy73wTLufCMnbs6CAsc3uicJUcg/640?wx_fmt=png "")  
### 01 漏洞概况       Spring Security是一个功能强大且高度可定制的身份验证和访问控制框架。      Spring Security版本 6.1.x - 6.1.7之前、6.2.x - 6.2.2 之前，当应用程序直接使用AuthenticationTrustResolver.isFullyAuthenticated（Authentication）方法时，可向其传递一个null身份验证参数，导致错误的true返回值，可利用该漏洞破坏访问控制，可能导致身份验证和授权绕过、未授权访问、信息泄露等。02 漏洞处置综合处置优先级：高漏洞信息漏洞名称Spring Security访问控制错误漏洞漏洞编号CVE编号CVE-2024-22234漏洞评估披露时间2024-02-18漏洞类型访问控制破损危害评级高危公开程度PoC未公开威胁类型远程利用情报在野利用未发现影响产品产品名称Spring Security受影响版本Spring Security 6.1.x - 6.1.7之前、6.2.x - 6.2.2 之前影响范围广有无修复补丁有  
### 03 漏洞排查      用户尽快排查应用Spring Security版本是否受该漏洞影响。04 修复方案当前官方已发布最新版本，建议受影响的用户及时更新升级到以下版本。下载链接：https://spring.io/projects/spring-securitySpring Security 6.1.x：升级到6.1.7Spring Security 6.2.x：升级到6.2.2注意，满足以下任一条件的应用程序不易受到攻击：l  应用程序不直接使用 AuthenticationTrustResolver.isFullyAuthenticated(Authentication)。l  应用程序未将null传递给AuthenticationTrustResolver.isFullyAuthenticated。l  应用程序仅通过Method Security或 HTTP Request Security使用 isFullyAuthenticated。05 时间线      2024.02.18 厂商发布安全补丁      2024.02.29 安迈信科安全运营团队发布通告   关于安迈信科西安安迈信科科技有限公司以“数字化可管理”为核心理念，坚持DevOps自主研发，创新打造“能力聚合、流程闭环、持续赋能”的综合性网络数据安全平台与运营服务。公司从古城西安出发，已在全国范围内为政府、运营商、电力、能源等行业客户提供了高质量的安全保障，并将继续为我国数字化转型和发展贡献力量。知 行 . 至 简 . 致 诚  
  
  
