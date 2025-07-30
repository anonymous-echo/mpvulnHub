#  【漏洞通告】PostgreSQL SQL注入漏洞   
 安迈信科应急响应中心   2025-02-26 07:43  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tdibEPWdubQUgErMslSgzVibGKdSFkWPTbTgu83UTXdNYm7eOxRSmuNmOjUIxdicy73wTLufCMnbs6CAsc3uicJUcg/640?wx_fmt=png "")  
### 01 漏洞概况        PostgreSQL是一个开源、强大的关系型数据库管理系统，支持SQL标准及扩展，广泛应用于企业级应用。它具备高可靠性、可扩展性、数据完整性和并发控制功能，支持多种编程语言和扩展机制。  PostgreSQL的libpq函数（如PQescapeLiteral()、PQescapeIdentifier()、PQescapeString()和PQescapeStringConn()）在某些使用模式下未能正确处理引号语法，可能导致SQL注入漏洞。攻击者可以通过构造恶意输入，利用这些函数的返回结果在PostgreSQL交互终端psql中执行恶意SQL语句。此外，PostgreSQL命令行工具在特定字符编码环境下（如client_encoding为BIG5、server_encoding为EUC_TW或MULE_INTERNAL时）也可能受到类似SQL注入攻击的威胁。02 漏洞处置综合处置优先级：高漏洞信息漏洞名称PostgreSQL SQL注入漏洞漏洞编号CVE编号CVE-2025-1904‍漏洞评估披露时间2025-02-21漏洞类型SQL注入危害评级高危公开程度PoC已公开威胁类型远程利用情报在野利用未发现影响产品产品名称PostgreSQL受影响版本17<=PostgreSQL<17.316<=PostgreSQL<16.715<=PostgreSQL<15.1114<=PostgreSQL<14.1613<=PostgreSQL<13.19影响范围广有无修复补丁有  
### 03 漏洞排查      用户尽快排查PostgreSQL应用版本是否在影响范围之内。若存在应用使用，极大可能会受到影响。04 修复方案1、官方修复方案：当前官方已发布最新版本，建议受影响的用户及时更新升级到相应版本。链接如下：https://github.com/postgres/postgres/tags/2、临时修复方案：(1) 严格验证并过滤用户输入，避免恶意字符。(2) 限制数据库用户权限，确保最低必要权限。05 时间线      2025.02.13 厂商发布安全补丁      2025.02.26 安迈信科安全运营团队发布通告   关于安迈信科西安安迈信科科技有限公司以“数字化可管理”为核心理念，坚持DevOps自主研发，创新打造“能力聚合、流程闭环、持续赋能”的综合性网络数据安全平台与运营服务。公司从古城西安出发，已在全国范围内为政府、运营商、电力、能源等行业客户提供了高质量的安全保障，并将继续为我国数字化转型和发展贡献力量。知 行 . 至 简 . 致 诚  
  
  
