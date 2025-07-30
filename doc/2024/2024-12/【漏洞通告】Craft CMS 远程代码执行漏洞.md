#  【漏洞通告】Craft CMS 远程代码执行漏洞   
 安迈信科应急响应中心   2024-12-26 02:09  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tdibEPWdubQUgErMslSgzVibGKdSFkWPTbTgu83UTXdNYm7eOxRSmuNmOjUIxdicy73wTLufCMnbs6CAsc3uicJUcg/640?wx_fmt=png "")  
### 01 漏洞概况      Craft CMS存在一个远程的远程代码执行漏洞，如果受影响版本的Craft CMS用户的 php.ini 配置文件中启用了"register_argc_argv"，未授权攻击者可以利用该漏洞执行任意代码，导致服务器失陷。02 漏洞处置综合处置优先级：高漏洞信息漏洞名称Craft CMS 远程代码执行漏洞漏洞编号CVE编号CVE-2024-56145‍漏洞评估披露时间2024-12-22漏洞类型执行代码危害评级高危公开程度PoC未公开威胁类型远程利用情报在野利用是影响产品产品名称Craft CMS受影响版本5.0.0-RC1 ≤ Craft CMS < 5.5.2,4.0.0-RC1 ≤ Craft CMS < 4.13.2,3.0.0 ≤ Craft CMS < 3.9.14影响范围广有无修复补丁有  
### 03 漏洞排查      用户尽快排查应用系统Craft CMS应用版本是否在3.9.14、4.13.2 或 5.5.2。若存在应用使用，极大可能会受到影响。04 修复方案官方已发布最新版本修复该漏洞，建议受影响用户将Craft Cms更新到安全版本及以上的版本。安全版本：Craft Cms 4.13.2、Craft Cms 5.5.2下载链接：https://github.com/craftcms/cms/releases/tag       商业版下载链接：https://craftcms.com/pricing临时修复建议：在不影响业务的前提下，关闭 php.ini 中的 register_argc_argv 配置。05 时间线      2024.12.22 厂商发布安全补丁      2024.12.26 安迈信科安全运营团队发布通告   关于安迈信科西安安迈信科科技有限公司以“数字化可管理”为核心理念，坚持DevOps自主研发，创新打造“能力聚合、流程闭环、持续赋能”的综合性网络数据安全平台与运营服务。公司从古城西安出发，已在全国范围内为政府、运营商、电力、能源等行业客户提供了高质量的安全保障，并将继续为我国数字化转型和发展贡献力量。知 行 . 至 简 . 致 诚  
  
  
