> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1OTA1MzQzNA==&mid=2651248129&idx=1&sn=b8aaeffedeb8b15bdb3ee6ab715b111d

#  MCP服务泄露客户敏感数据，知名企业紧急下线修补| Linux两大漏洞可串联，无需特殊手段即可获取root权限  
e安在线  e安在线   2025-06-20 02:40  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
# MCP服务泄露客户敏感数据，知名企业紧急下线修补  
  
6月19日消息，美国知名工作管理平台Asana警告称，其新推出的模型上下文协议（MCP）功能在实施过程中存在缺陷，可能导致用户实例中的数据被其他用户访问。  
  
此次数据暴露是由于MCP系统内部存在逻辑漏洞所致，并非黑客攻击所引起。但在某些情况下，其所带来的风险仍可能十分严重。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWjzONF3vNs2Jr3v2FGNoQdV5woXkmRUwtN1M517lgsL6MlZuczpKU3vYsZwhQEJDZDSI1j6rD36LQ/640?wx_fmt=jpeg "")  
  
美国上市公司Asana推出的项目与任务管理SaaS平台Asana，广泛用于组织内部的工作规划、任务分配、截止日期设置及协作管理，所有功能均通过统一界面进行。截至去年，该平台已在全球190个国家拥有超过13万家付费客户，以及数百万免费用户。  
  
  
**MCP服务漏洞暴露企业敏感数据超一个月**  
  
  
5月1日，Asana推出了整合大语言模型的MCP服务器功能，提供包括摘要生成、智能回复、自然语言查询等在内的AI能力。  
  
然而，由于MCP服务器中的一个软件漏洞，Asana各实例中的数据可能被其他MCP用户访问。尽管数据访问范围受限于各用户的权限设定，但仍存在一定程度的数据暴露风险。  
  
这意味着，虽然各组织的完整Asana工作区并未完全泄露至公共领域，但拥有MCP访问权限的其他组织用户，可能会看到来自不同域的部分内容，包括由聊天机器人生成的查询结果。  
  
根据整合类型及与聊天机器人的交互情况，可能被暴露的数据包括任务层级信息、项目元数据、团队细节、评论与讨论内容，甚至包括任何已上传的文件。  
  
Asana于6月4日发现此次数据暴露背后的逻辑漏洞，这意味着跨组织的数据泄漏问题已经持续了一个多月。  
  
鉴于Asana在组织内部往往承担重要职能，本次泄露事件可能涉及敏感信息，对受影响实体在隐私保护与合规方面带来复杂挑战。  
  
  
**客户应检查日志和权限控制**  
  
  
因此，建议管理员审查Asana的MCP访问日志，并检查所有AI生成的摘要与回答内容；发现疑似来自其他组织的数据，应立即进行上报。  
  
同时，建议将大模型整合功能设置为受限访问，并暂停自动重连与机器人流程，直到确认无残余风险并重建信任。  
  
Asana已向所有受影响组织发出通知，并提供附带沟通表单的链接，但尚未就该事件发布公开声明。  
  
外媒BleepingComputer就此事联系Asana，一位发言人回应称，本次事件影响了约1000家客户。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWjzONF3vNs2Jr3v2FGNoQdVdNP8XLrPkCBTNK8NOx17EYFIucBTiaRV3kNeQm1LrPQaCdugxxFuNJw/640?wx_fmt=jpeg "")  
  
Asana MCP服务器已于6月5日被临时下线。官方状态页面显示，该服务在6月17日17:00（UTC时间）按计划恢复正常运行。  
#   
# Linux两大漏洞可串联，无需特殊手段即可获取root权限  
#   
  
Qualys研究人员发现两个本地提权漏洞（CVE-2025-6018、CVE-2025-6019），攻击者可通过组合利用这两个漏洞，"轻松"在多数Linux发行版上获取root权限。  
  
  
**Part01**  
### 漏洞详情分析  
###   
  
**CVE-2025-6018**  
影响openSUSE Leap 15和SUSE Linux Enterprise 15的PAM（Pluggable Authentication Modules，可插拔认证模块）配置，允许无权限的本地攻击者（例如通过远程SSH会话登录的攻击者）获取物理在场用户的"allow_active"权限。  
  
  
PAM框架控制Linux系统中的用户认证和会话启动流程，该漏洞本质上是配置错误，导致系统将任何  
本地登录都视为用户在物理控制台前操作。  
  
  
获取"allow_active"权限后，攻击者可利用**CVE-2025-6019**  
—— libblockdev组件中的漏洞，将权限提升至_root_级别。获得root权限后，攻击者能够关闭EDR代理、植入后门、修改配置等，使受控系统成为渗透整个组织的跳板。  
###   
  
**Part02**  
### 影响范围与修复进展  
  
  
Qualys安全研究产品管理高级经理Saeed Abbasi指出，CVE-2025-6019可通过udisks守护进程利用，该组件默认安装在几乎所有Linux发行版中。Qualys威胁研究部门已开发概念验证代码，确认Ubuntu、Debian、Fedora和openSUSE Leap 15等系统存在可利用的漏洞。  
  
  
漏洞技术细节和PoC已公开，补丁已于上周私下提供给各Linux发行版开发商。  
###   
  
**Part03**  
### 漏洞利用机制与缓解建议  
###   
  
Abbasi强调："这类现代'本地到root'漏洞利用技术，彻底消除了普通登录用户与完全控制系统之间的屏障。通过串联udisks循环挂载和PAM/环境特性等合法服务，控制任何活跃GUI或SSH会话的攻击者能在数秒内突破polkit的allow_active信任区，获取root权限。整个过程无需特殊条件——每个环节都预装在主流Linux发行版及其服务器版本中。"  
  
  
安全公告还指出，CVE-2025-6018为攻击者利用其他需要"allow_active"权限的新漏洞创造了条件。目前主要Linux发行版已开始通过调整规则和/或更新libblockdev、udisks软件包修复漏洞。  
  
  
Abbasi解释缓解措施："默认polkit策略对org.freedesktop.udisks2.modify-device操作可能允许任何活跃用户修改设备。应将策略改为要求管理员认证才能执行此操作。鉴于udisks的普遍性和漏洞利用的简易性，各组织必须将此视为关键且普遍的风险，立即部署补丁。"  
###   
  
  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源： 来源：安全内参、FreeBuf、参考资料：bleepingcomputer.com、  
  
参考来源：  
  
Chaining two LPEs to get “root”: Most Linux distros vulnerable (CVE-2025-6018, CVE-2025-6019)https://www.helpnetsecurity.com/2025/06/18/chaining-two-lpes-to-get-root-most-linux-distros-vulnerable-cve-2025-6018-cve-2025-6019/  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
