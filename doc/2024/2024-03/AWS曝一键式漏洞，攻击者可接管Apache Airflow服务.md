#  AWS曝一键式漏洞，攻击者可接管Apache Airflow服务   
 关键基础设施安全应急响应中心   2024-03-25 15:08  
  
近日AWS修复了一个关键漏洞，通过利用该漏洞，攻击者可直接接管亚马逊Apache Airflow（MWAA）托管工作流。该漏洞危害较大，虽然利用起来比较复杂，但扔建议及时进行修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39HQOygXABvIau4d1VMTbvxNlWELicgUWZzhTbtrqNyXWQTnKrIibDQPfjDaeBwYhyRVHvHEbXo7bAg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
网络安全公司Tenable披露AWS 一个严重的安全漏洞，将之命名为FlowFixation，攻击者可借此完全控制客户在AWS服务上的账户。AWS承认漏洞存在，并表示该漏洞利用较为困难，且已经在几个月前进行修复，建议用户更新补丁。  
  
Tenable在报告中强调，通过研究发现了一个更加严重、广发的安全问题，并且可能在不久的未来造成伤害。  
  
Apache Airflow托管工作流(MWAA)是亚马逊推出的一项全托管的服务，简化了在 AWS 上运行开源版 Apache Airflow，构建工作流来执行 ETL 作业和数据管道的工作。  
  
Apache Airflow 是一个开源工具，每月下载量达到1200万次，用于通过编程的方式开发、调度和监控被称为“工作流”的过程和任务序列。开发人员和数据工程师用 Apache Airflow 管理工作流，通过用户界面(UI)来监控它们，并通过一组强大的插件来扩展它们的功能。但是，要使用 Apache Airflow，需要进行手动安装、维护和扩展，AWS 解决了这个问题，它为开发人员和数据工程师提供了 MWAA，让他们可以在云端构建和管理自己的工作流，无需关心与管理和扩展 Airflow 平台基础设施相关的问题。  
  
由于MWAA网络管理面板中的会话是固定的，以及AWS域名配置错误可引发跨站脚本攻击（XSS），让FlowFixation漏洞可以实现接管MWAA。  
  
Tenable指出，攻击者可利用该漏洞强迫受害者使用并认证其已知的会话，随后利用已经认证的会话接管受害者的网络管理面板。这一步骤完成后，攻击者将可进行更进一步的入侵动作，包括读取连接字符串、添加配置、触发有向无环图等。此时他可以对底层实例执行远程代码攻击或进行其他横向移动。  
  
Tenable研究还揭示一个更广泛的问题，即共享父域和公共后缀列表（PSL）相关的同站点攻击。而由同一供应商提供云服务往往会共享一个父域，例如多个AWS服务共同使用“amazonaws.com”。这种共享导致了一个攻击场景，攻击者可对在“amazonaws.com”共享父域的子域资产发起攻击。  
  
Tenable解释称，在本地环境中，你通常不会允许用户在子域上运行XSS，但在云上允许却是一个非常自然的操作。例如当用户创建一个AWS S3存储桶时，可以通过存储桶中的HTML页面来运行客户端代码；代码可以在S3存储桶子域的上下文中运行，自然也在共享父域“amazonaws.com”的上下文中运行。  
  
也有研究显示，该风险不仅仅存在于AWS，Azure/Google Cloud等共享父服务域被错误配置，即域名没有出现在PSL上，那么客户也将面临相应的攻击风险，包括cookie tossing、同站点cookie保护绕过等。  
  
AWS和微软都已经采取了措施来减轻Tenable报告中的风险。AWS发言人Patrick Neighorn表示，AWS在2023年9月对上述风险进行修复，因此运行当前版本的Amazon托管工作流Apache Airflow（MWAA）的客户不会受到影响。在2023年AWS已经通知并督促用户通过AWS控制台、API或AWS命令行界面进行更新修复。  
  
**参考资料：**  
  
https://www.securityweek.com/vulnerability-allowed-one-click-takeover-of-aws-service-accounts/  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
