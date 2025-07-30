#  新型Mirai僵尸网络通过命令注入漏洞感染TBK DVR设备  
胡金鱼  嘶吼专业版   2025-06-13 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Mirai恶意软件僵尸网络的一个新变种正在利用TBK DVR-4104和DVR-4216数字视频录制设备中的命令注入漏洞来劫持它们。  
  
该漏洞被CVE-2024-3721跟踪，是安全研究人员netsecfish于2024年4月披露的一个命令注入漏洞。研究人员当时发布的概念验证（PoC）以特制的POST请求的形式发送给易受攻击的端点，通过操纵某些参数（mdb和mdc）实现shell命令的执行。  
  
卡巴斯基报告说，利用netsecfish的PoC，他们在Linux蜜罐中发现了一个新的Mirai僵尸网络变体对CVE-2024-3721的积极利用。  
  
攻击者利用该漏洞释放ARM32恶意软件二进制文件，该二进制文件与命令和控制（C2）服务器建立通信，以将设备招募到僵尸网络群。从那里，该设备很可能被用来进行分布式拒绝服务（DDoS）攻击、代理恶意流量和其他行为。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28VEKjaooqvbxPHqW285bh2icNw3keyyFtFY1GlaiaNbVqGqPj1QZ7W99E43xuMfu4FnjWt3ZFE0GUA/640?wx_fmt=png&from=appmsg "")  
  
Mirai的环境检查  
# 攻击影响和修复  
  
尽管  
netsecfish去年报告称，大约有114000台暴露在互联网上的dvr易受CVE-2024-3721的攻击，但卡巴斯基的扫描显示，大约有50000台暴露设备。  
  
netsecfish  
认为，与最新的Mirai变种有关的大多数感染都发生在印度、埃及、乌克兰、俄罗斯、土耳其和巴西。然而，这是基于卡巴斯基的遥测，并且由于其消费者安全产品在许多国家被禁止，这可能无法准确反映僵尸网络的目标重点。  
  
目前，尚不清楚供应商TBK Vision是否已经发布了安全更新来解决CVE-2024-3721漏洞，或者是否仍未修补。值得注意的是，DVR-4104和DVR-4216已经在Novo， CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login， HVR Login和MDVR品牌下进行了广泛的重新命名，因此受影响设备的补丁可用性是一个复杂的问题。  
  
披露TBK Vision漏洞的研究人员去年还发现了其他漏洞，这些漏洞助长了对报废设备的攻击。具体来说，netsecfish在2024年披露了一个后门账户问题和一个命令注入漏洞，影响了数万台EoL D-Link设备。  
  
在PoC披露后的几天内，在这两起案件中都发现了活跃的利用，这也表明了网络犯罪分子将公共漏洞纳入其武器库的速度之快。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/new-mirai-botnet-infect-tbk-dvr-devices-via-command-injection-flaw/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28VEKjaooqvbxPHqW285bh2N6MWR1pZRKPMicnibAiawpwUWiaRtVfWuHMiaHib1bIjvxZVianZejrneiab3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28VEKjaooqvbxPHqW285bh2pwOMPLuf4JCWBce4rKNuiacODNFWCHnlXhbdUqELj39ZZEN5WicyQELg/640?wx_fmt=png&from=appmsg "")  
  
  
