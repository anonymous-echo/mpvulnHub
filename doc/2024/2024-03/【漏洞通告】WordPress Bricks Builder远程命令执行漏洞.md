#  【漏洞通告】WordPress Bricks Builder远程命令执行漏洞   
安迈应急响应中心  安迈信科应急响应中心   2024-02-29 15:13  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tdibEPWdubQUgErMslSgzVibGKdSFkWPTbTgu83UTXdNYm7eOxRSmuNmOjUIxdicy73wTLufCMnbs6CAsc3uicJUcg/640?wx_fmt=png "")  
### 01 漏洞概况      Bricks Builder主题是一个创新的、社区驱动的、可视化的WordPress网站构建器Bricks Builder（高级版）主题目前拥有约25,000个有效安装。      WordPress Brick Builder 1.9.6及之前版本中存在远程代码执行漏洞，该漏洞源于通过prepare_query_vars_from_settings（）中的eval函数执行用户控制的输入，由于权限检查不当，未经身份验证的威胁者可利用该漏洞在受影响的WordPress网站上执行任意PHP代码。02 漏洞处置综合处置优先级：高漏洞信息漏洞名称WordPress Brick Builder远程命令执行漏洞漏洞编号CVE编号CVE-2024-25600漏洞评估披露时间2024-02-12漏洞类型命令执行危害评级高危公开程度PoC已公开威胁类型远程利用情报在野利用未发现影响产品产品名称WordPress Brick Builder受影响版本WordPress Brick Builder <= 1.9.6影响范围广有无修复补丁无  
### 03 漏洞排查      用户尽快排查应用系统WordPress Brick Builder应用版本是否在Google WordPress Brick Builder <= 1.9.6。若存在应用使用，极大可能会受到影响。04 修复方案当前官方已发布最新版本，建议受影响的用户及时更新升级到以下版本：WordPress Brick Builder >=1.9.6.105 时间线      2024.02.12 厂商发布安全补丁      2024.02.29 安迈信科安全运营团队发布通告   关于安迈信科西安安迈信科科技有限公司以“数字化可管理”为核心理念，坚持DevOps自主研发，创新打造“能力聚合、流程闭环、持续赋能”的综合性网络数据安全平台与运营服务。公司从古城西安出发，已在全国范围内为政府、运营商、电力、能源等行业客户提供了高质量的安全保障，并将继续为我国数字化转型和发展贡献力量。知 行 . 至 简 . 致 诚  
  
  
