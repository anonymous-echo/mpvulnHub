#  Windows Server 2025 "BadSuccessor"漏洞可导致域控接管（PoC已公开，暂无补丁）   
 信息安全大事件   2025-05-28 10:01  
  
漏洞概述  
  
Windows Server 2025操作系统中新发现的"BadSuccessor"安全漏洞（CVE编号待分配）允许攻击者完全接管Active Directory（活动目录）域控制器。目前漏洞验证代码（PoC）已在安全社区流传，但微软尚未发布官方补丁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA7np4uoibkLHSbclOCmNLeYiaqM6qIRylZV9Cyv8QOljiaz2yEvAudAemo9mJXibRib6ibjVJXwJcrGypDQ/640?wx_fmt=png&from=appmsg "")  
  
  
技术影响  
  
该漏洞属于权限提升类缺陷，通过篡改域控的dMSA（动态管理系统账户）验证机制实现域环境接管。攻击者利用此漏洞可：  
- 绕过身份认证获取域管理员权限  
  
- 在目标网络内横向移动  
  
- 部署持久化后门  
  
- 窃取或篡改域内所有凭据数据  
  
当前状态  
  
网络安全研究人员证实：  
- 漏洞影响Windows Server 2025所有已发布版本  
  
- 攻击复杂度评级为"低"（无需特殊权限即可利用）  
  
- 微软安全响应中心已确认收到报告，但未提供补丁时间表  
  
