#  Apache CloudStack 严重漏洞可用于执行权限操作  
Guru Baran  代码卫士   2025-06-12 09:52  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Apache CloudStack 的热门版本中存在多个严重漏洞，可导致攻击者执行权限操作并攻陷云基础设施系统。**  
  
Apache Cloudstack 在6月10日发布安全公告，修复了5个CVE漏洞，其中两个是严重级别，可导致资源的机密性、完整性和可用性遭完全攻陷。  
  
  
**0****1**  
  
  
**Kubernetes Cluster 漏洞暴露 API 密钥**  
  
  
  
  
最严重的漏洞CVE-2025-26521影响 Apache CloudStack 项目中的 Container Kubernetes Service (CKS) 集群。当用户在项目中创建基于CKS的Kubernetes 集群时，系统会向有权限访问该集群的其它项目成员不当泄露API密钥和 “kubeadmin” 用户的私钥。  
  
该设计缺陷可导致位于同一个项目中的恶意人员提取这些凭据并假冒集群创建者的账号。该漏洞可导致攻击者执行权限操作，导致基础设施遭完全攻陷。  
  
要缓解已有部署，管理员必须通过 “Project Kubernetes Service Role（项目Kubernetes 服务角色”）通过特定的命名如kubeadmin-<FIRST_EIGHT_CHARACTERS_OF_PROJECT_ID>来创建专门的服务账号。可通过kubectl 命令，更新 Kubernetes 集群中的 CloudStack 机密，修复该漏洞。命令如图：  
  
  
  
**0****2**  
  
  
**域管理员提权**  
  
  
  
  
其它两个严重漏洞CVE-2025-47713和CVE-2025-47849可使 ROOT 域中的域管理员用户提权并控制拥有更高权限的管理员账户。  
  
CVE-2025-47713可导致恶意域管理员重置 Admin 角色账号的密码，而CVE-2025-47849可导致攻击者获得对API密钥和在同样域名中管理员用户密钥的访问权限。  
  
这些漏洞影响 Apache CloudStack 4.10.0.0至4.20.0.0所有版本，可导致攻击者假冒管理员账号并访问敏感的API，可导致数据丢失、拒绝服务和基础设施可用性遭攻陷。这些补丁在角色类型层级中执行严格的验证机制，确保调用程序在目标账号上执行操作前获得正确的权限。  
  
  
**0****3**  
  
  
**补丁已发布**  
  
  
  
  
Apache CloudStack 已在4.19.3.0和4.20.1.0中发布完整修复方案，修复了这些漏洞。  
  
其它漏洞还包括 CVE-2025-30675（可导致攻击者枚举属于不同域的模板和ISO镜像）和CVE-2025-22829（影响4.20.0.0版本中 Quota 插件的权限管理）。新的安全措施引入两个新的域级别的设置：role.types.allowed.for.operations.on.accounts.of.same.role.type（默认为 “Admin, DomainAdmin, ResourceAdmin”）和allow.operations.on.users.in.same.account（默认为真值）。这些配置针对跨账户操作和基于角色的访问管理提供了颗粒度控制。  
  
建议4.20.0.0版本以下的用户完全跳过4.20.0.0版本并直接升级至4.20.1.0，避免遭Quota 插件漏洞影响。用户可通过 Apache CloudStack 下载门户和多种Linux 分发仓库使用官方包。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Apache Roller CVSS 满分漏洞可用于获取持久性访问权限](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522748&idx=1&sn=743ec5c32d3881143ee9922bbd2be8ef&scene=21#wechat_redirect)  
  
  
[Apache Parquet Java 中存在CVSS满分漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522648&idx=1&sn=8642efdcfe877619e821e6fa74e779b7&scene=21#wechat_redirect)  
  
  
[Apache Ignite 严重漏洞可导致RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522291&idx=2&sn=d8279f609eb439d7d723557c865748fe&scene=21#wechat_redirect)  
  
  
[Apache MINA 存在严重的满分漏洞，可导致RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521918&idx=1&sn=acf8324d4a36ec4e8d37b16375da9e75&scene=21#wechat_redirect)  
  
  
[Apache Traffic Control存在严重的SQL注入漏洞，可在数据库中执行任意命令](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521906&idx=1&sn=9cb8ea9b9dbfb2a32eec80f9973d8cf1&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://cybersecuritynews.com/apache-cloudstack-vulnerability-2/#google_vignette  
  
  
  
题图：  
Pixabay Licen  
se  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
