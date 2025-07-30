#  【安全圈】Kubernetes 集群安全漏洞遭利用，算力资源面临严重危机   
 安全圈   2025-04-25 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaK50E4nv3xvMMJaGjmwKyzJic9XyvQUS0iba3Yn8Tdyx8DcFUtOL7Zxov8KfZVSibPpRDrA5Nicbxx0Q/640?wx_fmt=png&from=appmsg "")  
  
对于网络安全专业人士而言，出现了一个令人担忧的新情况：威胁行为者正越来越多地将目标对准未受安全保护的 Kubernetes 集群，以便在受害者组织毫不知情的情况下，利用其计算资源来部署加密货币挖矿活动。  
  
这些攻击利用了容器化环境中的漏洞，尤其侧重于利用配置错误和薄弱的身份验证机制，这些漏洞使得攻击者能够未经授权访问 Kubernetes 基础设施。  
  
攻击通常始于通过密码喷洒技术窃取凭据，随后会创建未经授权的资源组和容器部署。  
  
一旦威胁行为者获得了对 Kubernetes 集群的访问权限，他们就可以部署大量专门用于加密货币挖矿活动的容器，从而有效地将一个组织的计算资源转化为攻击者的盈利资产。  
  
在过去的一年里，出现了一个特别值得关注的案例，攻击者对教育领域的云租户发动了复杂的密码喷洒攻击。  
  
这些攻击涉及使用一个名为 AzureChecker.exe 的命令行界面工具，该工具会连接到恶意域名，以下载包含用于密码喷洒操作的目标信息的 AES 加密数据。  
  
Microsoft的研究人员确定，在这些攻击背后有一个被追踪代号为 Storm-1977 的威胁组织。  
  
在分析攻击方法时，Microsoft威胁情报部门观察到，该工具接受一个名为 accounts.txt 的文件作为输入，该文件包含用户名和密码组合，然后这些组合会被用于对目标租户进行验证。  
  
在一个有记录的事件中，研究人员目睹了一起成功的账户被攻破事件，威胁行为者利用一个来宾账户在被攻破的订阅中创建了一个资源组。  
  
在获得初始访问权限后，攻击者接着在该资源组内创建了 200 多个容器，并专门为加密货币挖矿操作对它们进行了配置。  
  
**通过 Kubernetes 审计检测攻击**  
  
检测这些加密货币挖矿操作的一个关键因素是了解 Kubernetes 审计日志中出现的独特模式。  
  
当威胁行为者部署他们的挖矿基础设施时，他们通常需要特权访问权限，这会在集群的审计跟踪记录中留下可识别的痕迹。  
  
安全团队可以实施特定的追踪查询，以识别诸如特权 Pod 部署之类的可疑活动。  
  
例如，以下查询可以检测到特权容器的创建，这是加密货币挖矿操作的一个常见需求：  
```
CloudAuditEvents
where Timestamp > ago(1d)
where DataSource == “Azure Kubernetes Service”
where OperationName == “create”
where RawEventData.ObjectRef.resource == “pods”
where RawEventData.ResponseStatus.code startswith “20”
extend PodName = RawEventData.RequestObject.metadata.name
extend PodNamespace = RawEventData.ObjectRef.namespace
mv-expand Container = RawEventData.RequestObject.spec.containers
extend ContainerName = Container.name
where Container.securityContext.privileged == “true”
```  
  
针对 Kubernetes 环境的攻击路径展示了威胁行为者是如何从初始访问逐步发展到部署加密货币挖矿操作的。  
  
建议各组织实施强大的安全措施，包括适当的身份验证控制、网络流量限制，以及对容器化环境进行持续监控，以便在这些威胁建立起加密货币挖矿操作之前就识别并缓解它们。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】警惕！新型恶意软件通过多层混淆技术劫持Docker镜像](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069259&idx=1&sn=326c3497b6e6e654a9628f4e662d3909&scene=21#wechat_redirect)  
  
  
  
[【安全圈】重大供应链攻击预警：XRP官方NPM包遭劫持植入私钥窃取程序](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069259&idx=2&sn=afe3ad55e70f079c97b674d104dfe7a4&scene=21#wechat_redirect)  
  
  
  
[【安全圈】加州蓝盾医保470万患者数据遭泄露，误配谷歌分析工具酿近年最大医疗隐私事件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069259&idx=3&sn=a34002c3f2e5b52241931f98f5e52646&scene=21#wechat_redirect)  
  
  
  
[【安全圈】新型钓鱼攻击预警：黑客滥用Google表单绕过邮件安检窃取凭证](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069259&idx=4&sn=37779dd9ac19192b61a98b1d6d0e8b44&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
