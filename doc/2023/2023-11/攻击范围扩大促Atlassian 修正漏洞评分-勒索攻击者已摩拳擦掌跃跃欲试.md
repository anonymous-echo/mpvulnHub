#  攻击范围扩大促Atlassian 修正漏洞评分-勒索攻击者已摩拳擦掌跃跃欲试   
 关键基础设施安全应急响应中心   2023-11-08 14:53  
  
针对未修补的Atlassian Confluence数据中心和服务器技术的主动勒索软件和其他网络攻击已促使Atlassian将该漏洞CVE-2023-22518的CVSS评分从原来的9.1分提高到10分，这是该等级中最关键的评级。据称，Atlassian Confluence数据中心和服务器的所有版本都会受到影响，但云实例则不会。公告补充说，目前已观察到针对该漏洞的积极利用，包括勒索软件。Rapid7的研究人员还发布了周末（11月5日）开始的滚雪球式攻击的咨询警告。这种不正确的授权漏洞允许未经身份验证的攻击者重置Confluence并创建Confluence实例管理员帐户。使用此帐户，攻击者可以执行Confluence实例管理员可用的所有管理操作，从而导致机密性、完整性和可用性完全丧失。Atlassian Confluence漏洞于10月31日首次披露，并于11月3日被观察到正在被积极利用，11月6日修正漏洞的CVSS评分至10分。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icWYHe4icB4aoBx2ld8DTtbPhFThNqqia77MTYumvFJfNXV7ggjtA7pWdT5LW4IQZYmbEmTKjQic4FIsw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
不断升级的警告  
  
Atlassian首席信息安全官Bala Sathiamurthy上周就该漏洞向公众发出警告，他表示该漏洞“如果被利用，可能会导致重大数据丢失”。本周晚些时候，该公司更新了其公告，称虽然没有证据表明存在主动利用，但它确实观察到“公开发布的有关该漏洞的关键信息增加了利用风险”。  
  
“在发现未利用的漏洞后，我们于2023年10月31日发布了关键安全公告，敦促客户立即采取行动。尽管仍然没有已知的漏洞利用，但我们于2023年11月2日发布了另一波警示，指出在观察到公开发布的有关该漏洞的关键信息后，尚未应用补丁的任何客户的风险都会增加，”Atlassian发言人周二（11月7日）表示。  
  
“2023年11月3日，我们向客户发出了有关主动利用漏洞的警告，并在发现包括勒索软件攻击在内的恶意活动证据后，于2023年11月6日升级了这一漏洞。”  
  
11月5日，Rapid7的网络安全研究人员和事件响应人员表示，他们看到黑客Cerber利用该进行攻击，Cerber是一个被认为早已不复存在的勒索软件品牌。  
  
Huntress和Red Canary等其他公司也支持Rapid7的评估，即黑客利用该漏洞后正在使用Cerber勒索软件。  
  
真正的大规模攻击已开始  
  
Atlassian发言人周二（11月7日）表示，该公司有证据支持网络安全研究人员周末报告的内容：CVE-2023-22518（影响Confluence 数据中心和Confluence服务器产品的漏洞）正被用于网络犯罪。  
  
攻击链涉及大规模利用易受攻击的面向互联网的Atlassian Confluence服务器来获取远程服务器上托管的恶意有效负载，从而导致勒索软件有效负载在受感染的服务器上执行。  
  
GreyNoise收集的数据显示，攻击尝试来自位于法国、香港和俄罗斯的三个不同IP地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icWYHe4icB4aoBx2ld8DTtbPhCClPJMIFMHrDnOxVmFwovh1bc8rMYBza9oVodh8ia3DbMExED1X4OnQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Atlassian警告安全团队注意以下内容：  
  
失去登录或访问权限  
  
网络访问日志中对 /json/setup-restore* 的请求  
  
安装了未知插件，观察到名为“web.shell.Plugin”的插件的报告  
  
加密的文件或损坏的数据  
  
汇合管理员组的意外成员  
  
意外新创建的用户帐户  
  
Cerber勒索的回归  
  
Cerber勒索软件操作在2016年至2019年期间很活跃，但在2021年发现针对容易受到另一个漏洞CVE-2021-26084影响的Confluence 实例。当时，2021年活动背后的黑客瞄准了中国、德国和美国的受害者，要求0.04比特币来换取解密器。  
  
几位勒索软件专家表示，他们已经很多年没有看到Cerber勒索软件被使用了。  
  
Cerber勒索软件说明，2023年Cerber勒索软件说明。图片：Rapid7  
  
当被问及情况时，Rapid7漏洞研究负责人Caitlin Condon称，该团队提取的勒索软件注释标题为“C3RB3R指令”，文件使用扩展名“L0CK3D”进行加密，这是Cerber勒索软件的常见模式。  
  
“然而，值得注意的是，我们正在分析和归因恶意软件，而不是威胁行为者，”她说。  
  
“近年来，勒索软件生态系统发生了显着变化和多样化——源代码被泄露，组件被重复使用，来自知名团体的对手已经改变了忠诚度（并带走了他们所谓的知识产权），附属机构和访问经纪人已经发展了策略和技术等等。”  
  
Condon接着指出，在最近的其他攻击中，该公司发现黑客使用源代码被泄露的勒索软件。该理论认为，独狼攻击者正在利用泄露的代码来“赚快钱”。  
  
Condon说，研究人员正在“分析恶意软件和工件，而不是归因于人类对手”。  
  
Rapid7表示，多个客户正在通过CVE-2023-22518被利用，Red Canary和Huntress表示，他们在攻击中看到了相同的 .LOCK3D文件扩展名。  
  
Huntress研究人员表示，在线Shodan搜索工具上对“confluence”的基本搜索显示超过200,000个可能存在漏洞的端点，更狭义的搜索发现了超过5,600个可能存在漏洞的端点。但该公司指出，这两种搜索都无法证明可利用性或版本号，而只是“证明Confluence通常是可公开访问的”。  
  
**参考资源：**  
  
1.https://www.darkreading.com/vulnerabilities-threats/atlassian-bug-escalated-10-unpatched-instances-vulnerable  
  
2.https://thehackernews.com/2023/11/experts-warn-of-ransomware-hackers.html  
  
3.https://therecord.media/atlassian-confirms-ransomware-using-confluence-bug-cerber  
  
4.https://confluence.atlassian.com/security/cve-2023-22518-improper-authorization-vulnerability-in-confluence-data-center-and-server-1311473907.html  
  
  
  
原文来源：网空闲话plus  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
