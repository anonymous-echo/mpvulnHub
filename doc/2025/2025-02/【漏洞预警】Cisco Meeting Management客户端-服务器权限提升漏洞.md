#  【漏洞预警】Cisco Meeting Management客户端-服务器权限提升漏洞   
原创 MasterC  企业安全实践   2025-02-18 12:07  
  
一、漏洞描述  
  
Cisco Meeting Management的REST API中存在一个漏洞，可允许经过身份验证且具有低权限的远程攻击者在受影响的设备上将权限提升为管理员。存在此漏洞的原因是未对 REST API用户实施适当的授权。攻击者可以通过向特定端点发送API请求来利用此漏洞。成功利用此漏洞可让攻击者获得对Cisco Meeting Management管理的边缘节点的管理员级别控制权。  
  
二、漏洞等级  
  
高危  
  
三、受影响版本  
  
Cisco Meeting Management <= 3.8  
  
Cisco Meeting Management = 3.9.0  
  
四、安全版本  
  
升级到3.9.1、3.9.10版本  
  
五、修复建议  
  
目前官方已修  
复该漏洞，建议受影  
响用户尽快前往官网升级至安全版本  
  
六、缓解方案  
  
1，如果无法立即升级，建议限制对REST API端点的访问权限  
  
2，监控异常的API请求行为  
  
七、参考链接  
  
https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cmm-privesc-uy2Vf8pc  
  
  
