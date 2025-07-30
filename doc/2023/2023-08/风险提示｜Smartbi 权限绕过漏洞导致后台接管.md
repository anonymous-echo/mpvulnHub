#  风险提示｜Smartbi 权限绕过漏洞导致后台接管   
长亭安全应急响应  黑伞安全   2023-08-01 16:05  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicQ64nXneNicIKyCFjT0StSmxZFn36uv3xYXic27uluBwYZDwHCxqGOr8knTXLtD7Q3rrydZQTG0Q4zg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Smartbi是一款商业智能应用，提供了数据集成、分析、可视化等功能，帮助用户理解和使用他们的数据进行决策。近期，长亭科技监测到Smartbi发布新补丁，修复了一处权限绕过漏洞。长亭应急团队经过分析后发现该漏洞类型为权限绕过，仍有较多公网系统仍未修复漏洞。于是根据漏洞原理编写了无害化的X-POC远程检测工具和牧云本地检测工具，目前已向公众开放下载使用。  
**漏洞描述**  
  
   
Description   
  
  
  
**0****1**  
  
Smartbi在特定情况下可被获取用户token，未经授权的攻击者可通过这种方式获取管理员权限。  
**检测工具**  
  
   
Detection   
  
  
  
**0****2**  
#   
# X-POC远程检测工具  
检测方法：xpoc -r 405 -t 目标URL  
工具获取方式：  
https://github.com/chaitin/xpochttps://stack.chaitin.com/tool/detail?id=1036  
#   
# 牧云本地检测工具  
检测方法：在本地主机上执行以下命令即可无害化扫描：smartbi_address_authorization_bypass_vuln_scanner_windows_amd64.exe  
工具获取方式：  
https://stack.chaitin.com/tool/detail?id=1209  
**影响范围**  
  
   
Affects  
   
  
  
  
**0****3**  
```
```  
  
**解决方案**  
  
   
Solution   
  
  
  
**0****4**  
临时缓解方案通过网络ACL策略限制访问来源，例如只允许来自特定IP地址或地址段的访问请求。升级修复方案官方已发布升级补丁包，支持在线升级和离线补丁安装，可在参考链接进行下载使用。  
**产品支持**  
  
   
Support   
  
  
  
**0****5**  
云图：默认支持该产品的指纹识别，同时支持该漏洞的PoC原理检测。洞鉴：支持以自定义 PoC 的进行进行漏洞检测。雷池：已发布虚拟补丁，支持该漏洞利用行为的检测。全悉：已发布规则升级包，支持检测该漏洞的利用行为。牧云：使用管理平台 23.05.001 及以上版本的用户可通过升级平台下载应急漏洞情报库升级包（EMERVULN-23.07.031）“漏洞应急”功能支持该漏洞的检测；其它管理平台版本暂不支持该漏洞检测。  
  
**时间线**  
  
   
Timeline   
  
  
  
**0****6**  
7月28日 长亭科技收到漏洞情报7月31日 长亭应急响应实验室漏洞分析与复现8月1日 长亭安全应急响应中心发布漏洞通告  
参考资料：  
  
https://www.smartbi.com.cn/patchinfo  
  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否收到此次漏洞影响  
  
请联系长亭应急团队  
  
7*24小时，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
应急响应热线：4000-327-707  
  
  
收录于合集   
#  
2023漏洞风险提示  
  
 19  
个  
  
上一篇  
风险提示｜泛微OA e-cology 前台文件上传漏洞  
  
  
