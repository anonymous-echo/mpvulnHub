#  利用Fortinet漏洞LockBit Black勒索病毒样本分析   
 安全分析与研究   2025-03-24 08:31  
  
**安全分析与研究**  
  
  
专注于全球恶意软件的分析与研究  
  
前言概述  
  
最近几年勒索病毒已经席卷全球，全球范围内越来越多的政府、企业，组织机构等受到勒索病毒黑客组织的攻击，几乎每天都有企业被勒索病毒攻击的新闻被曝光，可能还有更多的企业被勒索病毒攻击之后，选择默默交纳赎金，由于勒索病毒太过于暴利，从而导致越来越多的黑客组织开始使用勒索病毒攻击。  
  
  
国外安全厂商近日报道一个名为“Mora_001”的新勒索病毒运营商正在利用两个Fortinet漏洞来获取防火墙设备的未经授权的访问，并部署一种名为SuperBlack的定制勒索病毒，这两个漏洞均为身份验证绕过漏洞，漏洞编号分别为CVE-2024-55591和CVE-2025-24472，Fortinet 分别于一月和二月披露。  
  
  
攻击者利用这两个Fortinet漏洞，通过jsconsole接口使用基于WebSocket的攻击或向暴露的防火墙接口发送直接HTTPS请求来获得“super_admin”权限，接下来他们创建新的管理员帐户(forticloud-tech、fortigate-firewall、adnimistrator)并修改自动化任务以在被删除时重新创建这些帐户，此后攻击者再映射网络并尝试使用窃取的VPN凭据和新添加的VPN帐户、Windows管理规范(WMIC)和SSH以及TACACS+/RADIUS身份验证进行横向移动。  
  
  
Mora_001使用自定义工具窃取数据，然后加密文件进行双重勒索，优先考虑文件和数据库服务器以及域控制器，加密过程结束后，勒索信会被放入受害者的系统，最后部署一个名为“WipeBlack”的自定制擦除器恶意软件来删除勒索软件可执行文件的所有痕迹，以阻止安全人员取证分析。  
  
  
样本相关信息，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oibWJqH5OVmWMMdJG2JspCjHuqLBsibrt150d5VV6Fx59cgg0UWje7phxhRnlz9eEOH3TrvojibqQLgALblZvPkRw/640?wx_fmt=png "")  
  
原文相关链接：  
  
https://www.bleepingcomputer.com/news/security/new-superblack-ransomware-exploits-fortinet-auth-bypass-flaws/  
  
  
样本分析  
  
1.该勒索病毒主程序，与LockBit3.0构建器生成的样本基本一致，分析过LockBit3.0勒索病毒的基本一眼就可以看出来，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oibWJqH5OVmWMMdJG2JspCjHuqLBsibrt1ftQic3UDYQpBJbsWEHBtWL5JVDfIa6sEyiaicIsVxeWEAugbDSBEialnWA/640?wx_fmt=png "")  
  
2.笔者使用此前泄露的LockBit3.0构建器生成了一个LockBit3.0的攻击样本，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oibWJqH5OVmWMMdJG2JspCjHuqLBsibrt1gdoLFSJnOkjZZU5icOwtQwUhCFH473cztk7NIKbeMkicMSowxITPkb6g/640?wx_fmt=png "")  
  
3.对比上面的勒索病毒样本，代码基本一致，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oibWJqH5OVmWMMdJG2JspCjHuqLBsibrt1EceOAPG2Ke8VIWTL6YM9YkeYwAELY8FgUWa9Avsa95ibsFpXbMRUCibQ/640?wx_fmt=png "")  
  
4.加密后的文件，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oibWJqH5OVmWMMdJG2JspCjHuqLBsibrt1xITw0HYpYwQQTrvEu5EqKZFB8w7rYbPjdILxcq27BcpdBCmL1ibKr3A/640?wx_fmt=png "")  
  
5.生成的勒索提示信息主件为随机文件名，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oibWJqH5OVmWMMdJG2JspCjHuqLBsibrt1ibByDSy3YYxVEf0XKvvLFXcxFf2RvWAkD8PJRtke2AnperqDq3DLP4w/640?wx_fmt=png "")  
  
6.勒索提示信息文件内容，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oibWJqH5OVmWMMdJG2JspCjHuqLBsibrt1picXKPJssCkryo3q6QCPzApaG3UwiaUqX42aBb8CJ5Kr0BoL3NUqVVug/640?wx_fmt=png "")  
  
7.修改桌面背景，如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oibWJqH5OVmWMMdJG2JspCjHuqLBsibrt1ibrQtzoov4tjOALsl1U3VkOskMDpWwYpz2RTpOSXSNj3deleu1sd9FA/640?wx_fmt=png "")  
  
加密之后，主机桌面背景被修改为LockBit Black勒索病毒的背景桌面，通过对样本的静态分析和动态分析，可以确定Mora_001黑客组织疑似使用了泄露LockBit3.0构建器，生成的勒索病毒与LockBit3.0构建器生成的样本基本一致，其次SuperBlack勒索病毒勒索提示信息文件中包含与LockBit运营相关的TOX聊天ID，这表明Mora_001黑客组织要么是前LockBit附属公司之一，要么是其负责赎金支付和谈判的核心团队的前成员。  
  
  
最近全球的勒索攻击活动非常频繁，今年真的是勒索之年，LockBit Black勒索病毒利用Fortinet最新漏洞进行勒索传播，速度非常快。  
  
  
关于LockBit勒索病毒，也可以参考笔者之前的一些文章。  
  
[《针对Mac系统的LockBit勒索病毒样本分析》](https://mp.weixin.qq.com/s?__biz=MzA4ODEyODA3MQ==&mid=2247490990&idx=1&sn=8ea6c2343f2960271d8c014de13f54e7&scene=21#wechat_redirect)  
  
  
[《LockBit勒索病毒生成器被泄露》](https://mp.weixin.qq.com/s?__biz=MzA4ODEyODA3MQ==&mid=2247487539&idx=1&sn=97e7cfe2745a10baa01a24265daf7bdc&scene=21#wechat_redirect)  
  
  
[《LockBit3.0勒索病毒利用PowerShell无文件攻击技术》](https://mp.weixin.qq.com/s?__biz=MzA4ODEyODA3MQ==&mid=2247487460&idx=1&sn=9bca4bf4c8e72ac68a2746a56459df21&scene=21#wechat_redirect)  
  
  
  
总结结尾  
  
黑客组织利用各种恶意软件进行的各种攻击活动已经无处不在，防不胜防，很多系统可能已经被感染了各种恶意软件，全球各地每天都在发生各种恶意软件攻击活动，黑客组织一直在持续更新自己的攻击样本以及攻击技术，不断有企业被攻击，这些黑客组织从来没有停止过攻击活动，非常活跃，新的恶意软件层出不穷，旧的恶意软件又不断更新，需要时刻警惕，可能一不小心就被安装了某个恶意软件。  
  
  
笔者一直从事与恶意软件威胁情报等相关安全分析与研究工作，包含挖矿、勒索、远控后门、僵尸网络、加载器、APT攻击样本、CS木马、Rootkit后门木马等，涉及到多种不同的平台(Windows/Linux/Mac/Android/iOS)，笔者做安全研究的兴趣就是喜欢研究一些最新的恶意软件家族样本，跟踪国内外报道的各种安全事件中涉及到的攻击样本等，通过详细分析各种安全攻击事件中涉及的样本、漏洞和攻击技巧等，可以了解全球黑客组织最新的攻击技术以及攻击活动趋势等，同时还可以推判出他们大概准备做什么，发起哪些攻击活动，以及客户可能会受到什么危害等，通过研究全球的黑客组织以及攻击活动，做到知已知彼，各位读者朋友如果有遇到什么新的恶意软件家族样本或最新的家族变种都可以私信发给笔者，感谢给笔者提供样本的朋友们！  
  
  
安全分析与研究，专注于全球恶意软件的分析与研究，深度追踪全球黑客组织攻击活动，欢迎大家关注，获取全球最新的黑客组织攻击事件威胁情报。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oibWJqH5OVmVr7vhbe1hWMCq5WHPatJ3l9JdcwuIib48qia7wIW79PA24fAAvmHjZxeCWCYg0k9ORSEshLXEXDEibA/640?wx_fmt=jpeg "")  
  
王正  
  
  
笔名：熊猫正正  
  
  
恶意软件研究员  
  
  
长期专注于全球恶意软件的分析与研究，深度追踪全球黑客组织的攻击活动，擅长各种恶意软件逆向分析技术，具有丰富的样本分析实战经验，对勒索病毒、挖矿病毒、窃密、远控木马、银行木马、僵尸网络、高端APT样本都有深入的分析与研究  
  
  
