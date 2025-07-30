#  Dirty DAG：微软Azure数据工厂的Apache Airflow集成中的新漏洞   
网空闲话  网空闲话plus   2024-12-17 23:34  
  
**Palo Alto Networks的Unit42研究人员在Azure数据工厂与Apache Airflow集成中发现了三个漏洞，包括两个配置错误和一个身份验证漏洞。这些漏洞可能使攻击者获得对Azure云基础设施的镜像管理员权限，从而带来数据泄露、恶意使用软件和未授权访问等风险。具体来说，漏洞包括Airflow集群中Kubernetes角色的访问控制配置错误、Azure内部Geneva服务的秘密处理配置错误，以及Geneva身份验证薄弱。攻击者可通过控制器DAG文件（一种定义工作流结构的文件）获得初始访问权限，再通过Git存储库秘密等方式篡改DAG文件，利用恶意脚本获得反向shell，并逐步升级权限，控制整个集群及相关基础设施。一旦突破防御，攻击者可利用影子管理员权限窃取数据、部署加密挖掘或恶意软件，甚至利用Geneva扩展至其他Azure端点，进一步威胁企业云安全。研究强调，仅关注云资源边界防御不足，企业需采取全面的云安全策略，包括保护环境内的权限和**  
**配置，利用策略和审计检测和预防潜在威胁，并确保云中敏感数据资产交易的安全，以减少服务支撑带来的风险。Unit 42的研究人员已将这些漏洞分享给Azure。此问题凸显了谨慎管理服务权限以防止未经授权的访问的重要性。它还凸显了监控关键第三方服务的操作以防止此类访问的重要性。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVlnhibXxg2uxgkKVXEGEjVdgdzyAHj1O1qP3kibWibb3s6tcrbQaXJnZQyDtjp9EjYGzzZ1ptHoMpow/640?wx_fmt=webp&from=appmsg "")  
  
**概述**  
  
微软基于Azure的数据集成服务利用开源工作流编排平台的方式中发现三个缺陷，可能允许攻击者获得对公司Azure云基础设施的管理控制，使企业面临数据泄露、恶意软件部署和未经授权的数据访问的风险。  
  
PaloAlto Networks的Unit42研究人员发现了Azure Data Factory的Apache Airflow集成中的漏洞，其中两个是配置错误，第三个涉及弱身份验证。Data Factory使用户能够在不同来源之间移动信息时管理数据管道，而Apache Airflow则有助于复杂工作流程的调度和编排。  
  
尽管微软将这些漏洞归类为低严重性漏洞，但Unit42的研究人员在12月17日发布的一篇博客文章中透露，成功利用这些漏洞可以让攻击者以影子管理员的身份获得对整个Airflow Azure Kubernetes Service(AKS)集群的持久访问权限。  
  
具体来说，数据工厂中发现的缺陷包括：Airflow集群中Kubernetes基于角色的访问控制(RBAC)配置错误；负责管理关键日志和指标的Azure内部Geneva服务的秘密处理配置错误；以及Geneva的身份验证薄弱。  
  
**未经授权的Azure云访问已得到缓解**  
  
研究人员解释说，Airflow实例使用默认的、不可更改的配置，再加上集群管理员角色附加到Airflow运行器，这“导致了安全问题”，该问题可以被操纵“以控制Airflow集群和相关基础设施”。  
  
如果攻击者能够攻破集群，他们还可以操纵Geneva，从而允许攻击者“潜在地篡改日志数据或访问其他敏感的Azure资源”，Unit42人工智能和安全研究经理Ofir Balassiano和高级安全研究员DavidOrlovsky在帖子中写道。  
  
总体而言，这些缺陷凸显了管理服务权限和监控云环境中关键第三方服务操作的重要性，以防止未经授权访问集群。  
  
Unit42向 Microsoft Azure通报了这些漏洞，最终由Microsoft安全响应中心解决了这些问题。研究人员没有具体说明修复了哪些漏洞，而Microsoft也没有立即回应置评请求。  
  
**网络攻击者如何获得初始管理访问权限**  
  
最初的漏洞利用场景是攻击者能够获得对Apache Airflow使用的有向无环图(DAG)文件的未经授权的写入权限。DAG文件将工作流结构定义为Python代码；它们指定应执行任务的顺序、任务之间的依赖关系以及调度规则。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVlnhibXxg2uxgkKVXEGEjVdNg7IO04dTvwWQb1uNmBoYdeefsIuHXlhaPHicap8Zrngy3e8da2m6Uw/640?wx_fmt=jpeg&from=appmsg "")  
  
**Azure 数据工厂和气流群集架构概述**  
  
攻击者有两种方式可以访问和篡改DAG文件。他们可以利用具有写入权限的主体帐户获得对包含DAG文件的存储帐户的写入权限；或者他们可以使用共享访问签名(SAS)令牌，该令牌授予对DAG文件的临时和有限访问权限。  
  
在这种情况下，一旦DAG文件被篡改，“它就会处于休眠状态，直到受害者导入DAG文件，”研究人员解释说。  
  
第二种方式是使用泄露的凭证或错误配置的存储库访问Git存储库。一旦发生这种情况，攻击者可以创建恶意DAG文件或修改现有文件，并且包含恶意DAG文件的目录会自动导入。  
  
在他们的攻击流程中，Unit42的研究人员使用了Git存储库泄露凭据的场景来访问DAG文件。他们在帖子中解释道：“在这种情况下，一旦攻击者操纵了被攻陷的DAG文件，Airflow就会执行它，攻击者就会获得反向shell。”  
  
因此，基本的攻击流程是，攻击者首先制作一个DAG文件，该文件会打开远程服务器的反向shell，并在导入时自动运行。然后，恶意DAG文件被上传到与Airflow集群连接的私有GitHub存储库。  
  
研究人员解释道：“Airflow会自动从连接的Git存储库导入并运行DAG文件，从而在Airflow工作器上打开反向shell。此时，我们通过附加到Airflow工作器的Kubernetes服务帐户获得了集群管理员权限。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVlnhibXxg2uxgkKVXEGEjVdbDIRBSW9TbcibTpE1ekliab2E9VricQMmNjOxfKLRPepG9VcoaKibot8OQ/640?wx_fmt=png&from=appmsg "")  
  
**攻击者可以劫持集群并用于恶意用途**  
  
研究人员写道，随后攻击会逐步升级，接管整个集群；使用影子管理员访问权限来创建影子工作负载，以进行加密挖掘或运行其他恶意软件；窃取企业云中的数据；并利用Geneva到达其他Azure端点进行进一步的恶意活动。  
  
**云安全应该超越集群**  
  
基于云的攻击通常始于攻击者利用本地错误配置，而漏洞利用流程再次凸显了整个云环境如何由于单个节点或集群内漏洞被利用而面临风险。  
  
Unit42的结论认为，该场景表明，不仅要确保云集群的边界安全，还要采取更全面的云安全方法，考虑到如果攻击者突破这一边界会发生什么情况。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVlnhibXxg2uxgkKVXEGEjVd1Q3rYpqSogCibqrqdYhn6zmPMxuIceOibjPGrQRHSWNL0OsAgk56TP4w/640?wx_fmt=png&from=appmsg "")  
  
研究人员写道，该策略应包括“保护环境本身内的权限和配置，并使用策略和审计引擎来帮助检测和预防集群和云中未来的事件”。  
  
他们补充说，企业还应保护与云中不同服务交互的敏感数据资产，以了解哪些数据正在由哪些数据服务处理。这将确保在保护云时考虑到服务依赖性。  
  
  
**参考资源**  
  
1、https://www.darkreading.com/cloud-security/azure-data-factory-bugs-expose-cloud-infrastructure  
  
2、https://unit42.paloaltonetworks.com/azure-data-factory-apache-airflow-vulnerabilities/  
  
