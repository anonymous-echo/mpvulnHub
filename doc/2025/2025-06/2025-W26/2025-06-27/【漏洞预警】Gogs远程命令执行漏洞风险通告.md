> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NjU0OTQyMg==&mid=2247484434&idx=1&sn=fdcc1421f4fe465e4fa8104b5e7ccb6f

#  【漏洞预警】Gogs远程命令执行漏洞风险通告  
原创 masterC  企业安全实践   2025-06-26 10:59  
  
## 一、漏洞描述  
  
Gogs(Go Git Service)是一款基于Go语言开发的开源Git托管平台，采用MIT许可证，提供代码托管、Issue跟踪、权限管理和Webhook等功能。  
  
近日，互联网上披露了关于Gogs中存在一个远程命令执行漏洞。在受影响版本中，由于其在修复CVE-2024-39931漏洞的补丁中仅添加了对路径是否为.git目录的检查，但未对后续步骤中的符号链接进行检查。拥有普通用户权限的攻击者可通过创建指向.git目录的符号链接，进而重写.git目录下的任意文件，成功利用可导致远程命令执行、服务器失陷、数据泄露等严重危害。该漏洞对应的CVE编号为CVE-2024-56731，该漏洞影响较高，请受影响的用户做好安全加固措施。  
## 二、漏洞等级  
  
高  
## 三、影响范围  
  
Gogs <= 0.13.2  
## 四、安全版本  
  
Gogs >= 0.13.3  
## 五、修复建议  
  
目前官方已修复该漏洞，建议受影响用户尽快前往官网升级至安全补丁版本。  
## 六、缓解方案  
  
在Gogs配置文件app.ini中关闭用户注册功能，修改后重启Gogs服务。  
## 七、参考链接  
  
https://github.com/gogs/gogs/releases/tag/v0.13.3  
  
https://github.com/gogs/gogs/security/advisories/GHSA-wj44-9vcg-wjq7  
  
  
