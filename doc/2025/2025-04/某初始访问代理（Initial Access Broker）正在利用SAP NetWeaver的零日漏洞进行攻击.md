#  某初始访问代理（Initial Access Broker）正在利用SAP NetWeaver的零日漏洞进行攻击   
鹏鹏同学  黑猫安全   2025-04-26 23:04  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceib7EYdPwBrQzO5Nz4gBUoY06FbOuasIWM1lLuAUJficCosp9sD7iaAqibWgic87PeSfm1icngvNA9DAD1w/640?wx_fmt=png&from=appmsg "")  
  
网络安全研究人员警告，SAP NetWeaver平台中一个被评为10分（CVSS最高分）的零日漏洞（CVE-2025-31324）正遭活跃利用，数千个暴露在互联网的应用系统面临风险。  
  
**漏洞分析**  
  
该漏洞存在于SAP NetWeaver Visual Composer元数据上传组件，由于缺乏授权验证机制，未认证攻击者可借机向系统上传恶意可执行文件。这些文件在宿主系统执行后，可导致SAP环境完全沦陷。SAP已在2025年4月安全补丁日修复该漏洞。  
  
**发现过程**  
  
ReliaQuest安全团队在调查多起攻击事件时发现该漏洞，部分案例中甚至已打补丁的系统仍遭入侵。其报告指出："2025年4月22日，我们发布针对SAP NetWeaver系统攻击活动的调查报告，发现这个最初被误判为远程文件包含（RFI）的漏洞，实为无限制文件上传漏洞。SAP随后发布补丁，强烈建议用户立即安装。"  
  
**攻击手法**  
  
攻击者通过精心构造的POST请求，向/developmentserver/metadatauploader  
端点上传恶意JSP网页后门，存放于j2ee/cluster/apps/sap.com/irj/servletjsp/irj/root/  
目录。随后通过GET请求即可远程执行，完全控制系统。所有后门文件均具有相似功能，并复用了GitHub某公开RCE项目的代码逻辑。  
  
**攻击者画像**  
- 使用"helper.jsp"、"cache.jsp"等伪装名称的网页后门  
  
- 部分攻击链结合Brute Ratel和Heaven's Gate工具提升隐蔽性  
  
- 初始访问与后续攻击存在数天间隔，符合初始访问代理（IAB）特征  
  
- 可能通过暗网论坛出售VPN/RDP访问权限或漏洞利用途径  
  
**行业影响**  
  
由于SAP系统承载政府和企业核心业务数据，该漏洞对关键基础设施构成重大威胁。值得注意的是，尽管受影响系统已安装最新补丁，攻击者仍能利用这个未公开的RFI漏洞突破防线。ReliaQuest建议所有用户立即应用补丁，并检查系统是否存在异常JSP文件。  
  
  
  
