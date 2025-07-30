#  【漏洞通告】NAKIVO Backup & Replication任意文件读取漏洞   
 安迈信科应急响应中心   2025-02-27 05:59  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tdibEPWdubQUgErMslSgzVibGKdSFkWPTbTgu83UTXdNYm7eOxRSmuNmOjUIxdicy73wTLufCMnbs6CAsc3uicJUcg/640?wx_fmt=png "")  
### 01 漏洞概况      NAKIVO Backup & Replication 是一款专注于虚拟化、云端及混合环境的备份与灾难恢复的解决方案。      攻击者可利用STPreLoadManagement 类中的 getImageByPath方法，绕过路径验证并读取目标服务器上的任意文件。02 漏洞处置综合处置优先级：高漏洞信息漏洞名称NAKIVO Backup & Replication任意文件读取漏洞漏洞编号CVE编号CVE-2024-48248‍漏洞评估披露时间2025-02-26漏洞类型文件读取危害评级高危公开程度PoC已公开威胁类型远程利用情报在野利用未发现影响产品产品名称NAKIVO Backup & Replication受影响版本NAKIVO Backup & Replication < v11.0.0.88174影响范围广有无修复补丁有  
### 03 漏洞排查      用户尽快排查应用系统NAKIVO Backup & Replication应用版本是否小于v11.0.0.88174。若存在应用使用，极大可能会受到影响。04 修复方案1、官方修复方案：当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：https://www.nakivo.com/resources/download/trial-download/download/2、临时修复方案：暂无05 时间线      2025.02.26 厂商发布安全补丁      2022.02.27 安迈信科安全运营团队发布通告   关于安迈信科西安安迈信科科技有限公司以“数字化可管理”为核心理念，坚持DevOps自主研发，创新打造“能力聚合、流程闭环、持续赋能”的综合性网络数据安全平台与运营服务。公司从古城西安出发，已在全国范围内为政府、运营商、电力、能源等行业客户提供了高质量的安全保障，并将继续为我国数字化转型和发展贡献力量。知 行 . 至 简 . 致 诚  
  
  
