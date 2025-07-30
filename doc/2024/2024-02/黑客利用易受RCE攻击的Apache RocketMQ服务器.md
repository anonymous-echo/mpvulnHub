#  黑客利用易受RCE攻击的Apache RocketMQ服务器   
胡金鱼  嘶吼专业版   2024-02-04 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
研究人员每天会检测到数百个IP地址，这些地址会利用易受CVE-2023-33246、CVE-2023-37582远程命令执行漏洞影响的Apache RocketMQ服务器进行攻击。  
  
最初，该安全问题被跟踪为CVE-2023-33246，该漏洞影响着多个组件，包括NameServer、Broker和Controller。Apache发布了针对NameServer组件的不完整修复报告。  
  
Apache RocketMQ项目管理委员会称：“RocketMQ NameServer组件仍然存在远程命令执行漏洞，因为CVE-2023-33246漏洞在5.1.1版本中尚未完全修复。”  
  
在存在漏洞的系统上，当名称服务器的地址在网上暴露，且未经相关权限检查时，威胁分子可以利用该漏洞，通过使用名称服务器上的更新配置功能执行命令。  
  
该远程命令执行漏洞编号为CVE-2023-37582，有关人员建议RocketMQ 5.x/4.x的NameServer升级至5.1.2/4.9.7或以上版本，以避免该漏洞进行攻击。  
  
威胁跟踪平台ShadowServer基金会已记录数百台主机扫描在线暴露的RocketMQ 系统，其中就有一些主机试图利用这两个漏洞。  
  
从2023年8月起，黑客就开始针对易受攻击的Apache RocketMQ系统，当时观察到新版本的DreamBus僵尸网络利用CVE-2023-33246漏洞，在易受攻击的服务器上投放XMRig Monero矿工。  
  
2023年9月，美国网络安全和基础设施安全局(CISA)敦促联邦机构在月底前修补该漏洞，并对其活跃的利用状态发出了警告。  
  
文章翻译自：https://www.bleepingcomputer.com/news/security/hackers-target-apache-rocketmq-servers-vulnerable-to-rce-attacks/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28xvtorVmWZ4NcSEib1VdBibkJpSHFichDWycjibmxtx7gyeI8IAwq7W8ia7oorm3paWiaQWZPPjWeq3yCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28xvtorVmWZ4NcSEib1VdBibkppRYThj3Mv7Qb25K1edouyyRiaibdW8xYy11ibQ8TnQ5DZ2oIfcMeTnhw/640?wx_fmt=png&from=appmsg "")  
  
  
