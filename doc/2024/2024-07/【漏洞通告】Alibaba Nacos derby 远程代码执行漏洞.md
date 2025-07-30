#  【漏洞通告】Alibaba Nacos derby 远程代码执行漏洞   
 安迈信科应急响应中心   2024-07-19 18:22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/tdibEPWdubQUgErMslSgzVibGKdSFkWPTbTgu83UTXdNYm7eOxRSmuNmOjUIxdicy73wTLufCMnbs6CAsc3uicJUcg/640?wx_fmt=png "")  
### 01 漏洞概况     Alibaba Nacos derby 存在远程代码执行漏洞，由于Alibaba Nacos部分版本中derby数据库默认可以未授权访问，恶意攻击者利用此漏洞可以未授权执行SQL语句，从而远程加载恶意构造的jar包，最终导致任意代码执行。02 漏洞处置综合处置优先级：高漏洞信息漏洞名称Alibaba Nacos derby远程代码执行漏洞漏洞编号CVE编号无‍漏洞评估披露时间2024-07-19漏洞类型代码注入危害评级高危公开程度PoC已公开威胁类型远程利用情报在野利用是影响产品产品名称Alibaba Nacos‍‍‍‍‍‍受影响版本Alibaba Nacos< 2.3.3、Alibaba Nacos<2.4.0‍‍‍‍影响范围广有无修复补丁有  
### 03 漏洞排查      用户尽快排查Alibaba Nacos应用版本是否在Alibaba Nacos< 2.3.3、Alibaba Nacos<2.4.0。若存在应用使用，极大可能会受到影响。04 修复方案临时修复方案(1)  升级nacos到最新版本,杜绝nacos未授权访问漏洞 (2)  禁止nacos的匿名访问，开启鉴权。 (3)  设置得复杂的nacos口令05 时间线      2024.07.15厂商发布安全补丁      2024.07.19 安迈信科安全运营团队发布通告   关于安迈信科西安安迈信科科技有限公司以“数字化可管理”为核心理念，坚持DevOps自主研发，创新打造“能力聚合、流程闭环、持续赋能”的综合性网络数据安全平台与运营服务。公司从古城西安出发，已在全国范围内为政府、运营商、电力、能源等行业客户提供了高质量的安全保障，并将继续为我国数字化转型和发展贡献力量。知 行 . 至 简 . 致 诚  
  
  
