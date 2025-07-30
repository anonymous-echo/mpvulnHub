#  在阿里云PostgreSQL数据库中发现安全漏洞   
ang010ela  嘶吼专业版   2023-04-24 12:51  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
研究人员在阿里云PostgreSQL数据库中发现2个安全漏洞。  
  
ApsaraDB RDS for PostgreSQL和AnalyticDB for PostgreSQL是阿里的两个云服务。ApsaraDB RDS是管理数据库托管服务，具有自动监控、备份、灾备功能。ApsaraDB RDS是管理数据仓库服务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzB1oQFqwHW9xRjHhG4tTeUv5fw1EMHMttSl1iaPG6rtVMVicic2nibicA1mZF61Y1gVViavSD7OPrcHCg/640?wx_fmt=png "")  
      

    BrokenSesame漏洞概述  
  
Wiz 研究人员在阿里云PostgreSQL数据库中发现2个安全漏洞——#BrokenSesame：一个AnalyticDB中的权限提升漏洞和一个ApsaraDB RDS中的远程代码执行漏洞。攻击者利用这两个漏洞可以实现容器内的root权限提升，绕过租户隔离保护，实现Kubernetes节点逃逸，最终获得API服务器的非授权访问，并访问属于其他用户的敏感数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzB1oQFqwHW9xRjHhG4tTeUv5fw1EMHMttSl1iaPG6rtVMVicic2nibicA1mZF61Y1gVViavSD7OPrcHCg/640?wx_fmt=png "")  
      

    AnalyticDB for PostgreSQL 攻击流  
  
研究人员利用cronjob任务中的权限提升漏洞来在容器内实现root权限提升；  
  
然后利用共享的PID命名空间来实现底层主机（k8s节点）的逃逸；  
  
然后利用kubelet凭证访问敏感资源，包括服务账户、pods等；  
  
研究人员在分析pod列表时发现了属于同一集群的其他租户的pods。这表明阿里云将该集群用于多租户，即可以获得这些pods的跨租户访问；  
  
因为阿里云使用私有的容器镜像库，因此研究人员需要对应的凭证信息才能访问；  
  
在测试容器镜像注册表的凭证时，研究人员发现不仅有读权限还有写权限。即研究人员具有覆写容器镜像的能力，并有可能针对整个服务和其他服务的镜像发起供应链攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzB1oQFqwHW9xRjHhG4tTeUv5fw1EMHMttSl1iaPG6rtVMVicic2nibicA1mZF61Y1gVViavSD7OPrcHCg/640?wx_fmt=png "")  
      

    ApsaraDB RDS for PostgreSQL攻击流  
  
研究人员利用该漏洞来访问pod内邻居管理容器的源码；  
  
在对管理容器源码进行审计时发现了一个远程代码执行漏洞。然后，研究人员发现该容器是具有特权的，即可以实现主机（k8s节点）的逃逸；  
  
然后研究人员再次确认阿里云使用了多租户集群，随后在该节点了发现了属于其他账户的数据库，既可以访问其他数据；  
  
用于该服务的私有容器注册表库与用于AnalyticDB的相同，也就是说可以用AnalyticDB的凭证对ApsaraDB RDS发起供应链攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzB1oQFqwHW9xRjHhG4tTeUv5fw1EMHMttSl1iaPG6rtVMVicic2nibicA1mZF61Y1gVViavSD7OPrcHCg/640?wx_fmt=png "")  
      

    漏洞影响和补丁  
  
Wiz于2022年12月将该漏洞提交给阿里云，阿里云于2023年4月12日完全修复了漏洞。阿里云确认没有用户数据泄露，用户也无需进行任何操作。  
  
参考及来源：https://www.wiz.io/blog/brokensesame-accidental-write-permissions-to-private-registry-allowed-potential-r  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibzB1oQFqwHW9xRjHhG4tTe0tUMurjiaV22oDBflnJicpickfldlL1n1etn4VY1qWdcqsXumoXA6A3IQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
  
