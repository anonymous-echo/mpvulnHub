#  漏洞预警 | 润申企业标准化管理系统SQL注入漏洞   
浅安  浅安安全   2025-05-13 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
润申信息科技企业标准化管理系统通过给客户提供各种灵活的标准法规信息化管理解决方案，帮助他们实现了高效的标准法规管理，完成个性化标准法规库的信息化建设。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWiaPgw9ZWLZIchhoD6H6DJ5L7XFhUicjKInRGYOjmMvXy3ffmSyRLrg5ByCw6sP9miaJtGQJ5h6RBxQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
  
  
**简述：**  
润申企业标准化管理系统的/  
PDCA/ashx/AllTableHandler.ashx  
和/PDCA/ashx/PdcaUserStdListHandler.ashx接口存在SQL注入漏洞，  
未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 润申企业标准化管理系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.rainsome.cn/index.shtml_ywgcancel20210617  
  
  
  
