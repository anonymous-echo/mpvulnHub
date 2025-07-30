#  【漏洞通告】Jumpserver Ansible Playbook远程代码执行漏洞   
 安迈信科应急响应中心   2024-04-22 17:16  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tdibEPWdubQUgErMslSgzVibGKdSFkWPTbTgu83UTXdNYm7eOxRSmuNmOjUIxdicy73wTLufCMnbs6CAsc3uicJUcg/640?wx_fmt=png "")  
### 01 漏洞概况       Jumpserver Ansible Playbook存在远程代码执行漏洞，攻击者可以绕过JumpServer的Ansible中的输入验证机制，在Celery容器中执行任意代码。由于Celery容器以root权限运行并具有数据库访问权限，攻击者可以从所有主机窃取敏感信息或操纵数据库。02 漏洞处置综合处置优先级：高漏洞信息漏洞名称Jumpserver Ansible Playbook远程代码执行漏洞漏洞编号CVE编号CVE-2024-29201‍漏洞评估披露时间2024-03-28漏洞类型代码注入危害评级高危公开程度PoC已公开威胁类型远程利用情报在野利用是影响产品产品名称Jumpserver Ansible Playbook受影响版本v3.0.0 ≤ JumpServer < v3.10.7影响范围广有无修复补丁有  
### 03 漏洞排查      用户尽快排查应用系统JumpServer应用版本是否在v3.0.0 ≤ JumpServer < v3.10.7。若存在应用使用，极大可能会受到影响。04 修复方案1、官方修复方案：当前官方已发布最新版本，建议受影响的用户及时更新安全版本。链接如下：https://github.com/jumpserver/jumpserver/security/advisories/GHSA-pjpp-cm9x-6rwj05 时间线      2024.03.28 深信服厂商发布安全补丁      2024.04.22 安迈信科安全运营团队发布通告   关于安迈信科西安安迈信科科技有限公司以“数字化可管理”为核心理念，坚持DevOps自主研发，创新打造“能力聚合、流程闭环、持续赋能”的综合性网络数据安全平台与运营服务。公司从古城西安出发，已在全国范围内为政府、运营商、电力、能源等行业客户提供了高质量的安全保障，并将继续为我国数字化转型和发展贡献力量。知 行 . 至 简 . 致 诚  
  
  
