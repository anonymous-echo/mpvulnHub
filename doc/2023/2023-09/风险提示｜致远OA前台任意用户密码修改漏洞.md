#  风险提示｜致远OA前台任意用户密码修改漏洞   
长亭应急响应  黑伞安全   2023-09-07 18:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicSyytKrCM6DlCibyjkAHtKOzMDUSYtnJibkKSqUJ7RhyQNHBzzcqC08uwfCgTpfDjtBdTo3AAJsJeww/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
致远OA是一款企业级办公自动化管理软件，用于协助企业实现日常办公任务和流程管理的高效化和数字化。近期，长亭科技监测到致远官方发布新补丁，修复了一处前台任意密码修改漏洞。长亭应急团队经过分析后发现仍有较多公网系统未修复漏洞。应急响应实验室根据漏洞原理编写了无害化的X-POC远程检测工具和牧云本地检测工具，目前已向公众开放下载使用。  
**漏洞描述**  
  
   
Description   
  
  
  
**0****1**  
  
致远OA存在可未授权访问的密码修改接口，攻击者可构造特定的数据包访问接口修改任意用户密码。  
**检测工具**  
  
   
Detection   
  
  
  
**0****2**  
#   
# X-POC远程检测工具  
检测方法：./xpoc -r 406 -t http://xpoc.org  
  
工具获取方式：  
https://github.com/chaitin/xpochttps://stack.chaitin.com/tool/detail?id=1036#   
# 牧云本地检测工具  
检测方法：在本地主机上执行以下命令即可扫描：seeyon_oa_resetpass_ct_868971_scanner_windows_amd64.exe  
工具获取方式：  
https://stack.chaitin.com/tool/detail/1227  
**影响范围**  
  
   
Affects  
   
  
  
  
**0****3**  
```
```  
  
**解决方案**  
  
   
Solution   
  
  
  
**0****4**  
临时缓解方案通过网络ACL策略限制访问来源，例如只允许来自特定IP地址或地址段的访问请求。升级修复方案官方已发布升级补丁包，可在参考链接进行下载使用。  
  
**产品支持**  
  
   
Support   
  
  
  
**0****5**  
云图：默认支持该产品的指纹识别，同时支持该漏洞的POC原理检测。洞鉴：将以自定义POC形式支持。雷池：已发布虚拟补丁，支持该漏洞利用行为的检测。全悉：已发布规则升级包，支持检测该漏洞的利用行为。牧云：使用管理平台 23.05.001 及以上版本的用户可通过升级平台下载应急漏洞情报库升级包（EMERVULN-23.09.007）“漏洞应急”功能支持该漏洞的检测；其它管理平台版本请联系牧云技术支持团队获取该功能。  
**时间线**  
  
   
Timeline   
  
  
**0****6**  
9月6日 致远OA官方发布补丁9月7日 长亭应急响应实验室漏洞分析与复现9月7日 长亭安全应急响应中心发布漏洞通告  
参考资料：  
  
https://service.seeyon.com/patchtools/tp.html#/patchList?type=%E5%AE%89%E5%85%A8%E8%A1%A5%E4%B8%81&id=171  
  
  
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
  
 20  
个  
  
上一篇  
风险提示｜Smartbi 权限绕过漏洞导致后台接管  
  
  
