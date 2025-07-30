#  0day速修｜Smartbi 远程代码执行漏洞   
 长亭安全应急响应中心   2023-07-03 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicRn5PkUcDrvibgpIUsHnyyasJFs9SYhtyQ5tvM90VEeAB9T6ByqYtFnDWLia5klIXowwMCIjuGDtGbQ/640?wx_fmt=png "")  
  
Smartbi是一款商业智能应用，提供了数据集成、分析、可视化等功能，帮助用户理解和使用他们的数据进行决策。近期，长亭科技安全研究员发现并上报了Smartbi的一个远程代码执行漏洞。该漏洞类型为逻辑绕过漏洞，可实现RCE，而目前仍有较多公网系统仍未修复漏洞。根据漏洞原理编写了无害化的X-POC远程检测工具和牧云本地检测工具，目前已向公众开放下载使用。  
**漏洞描述**  
  
   
Description   
  
  
  
**0****1**  
  
Smartbi可在未经过身份认证的情况下，调用后台接口，执行攻击者构造的代码，从而导致服务器失陷。  
  
**检测工具**  
  
   
Detection   
  
  
  
**0****2**  
#   
#   
# X-POC远程检测工具  
检测方法：./xpoc -r 399 -t http://xpoc.org  
工具获取方式：  
https://github.com/chaitin/xpochttps://stack.chaitin.com/tool/detail?id=1036  
#   
# 牧云本地检测工具  
检测方法：在本地主机上执行以下命令即可无害化扫描：smartbi_remote_code_execution_vuln_scanner_windows_amd64.exe  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicRn5PkUcDrvibgpIUsHnyyasIlx3qnuD0fiaulRURnmWHk1J7C7YWu0DUbgjvK5n0RmIGWRjLcVVpyQ/640?wx_fmt=png "")  
  
工具获取方式：  
https://stack.chaitin.com/tool/detail?id=1191  
  
**影响范围**  
  
   
Affects  
   
  
  
  
**0****3**  
  
Smartbi v8 部分版本  
  
Smartbi v9、v10全版本  
```
```  
  
**解决方案**  
  
   
Solution   
  
  
  
**0****4**  
临时缓解方案使用雷池、全悉等安全设备，无需升级默认支持防护，可阻断漏洞利用行为。同时限制访问来源，如非必要，不要将Smartbi服务开放在公网上。升级修复方案官方已发布升级补丁包，支持在线升级和离线补丁安装，可在参考链接[1]进行下载使用。  
  
**产品支持**  
  
   
Support   
  
  
  
**0****5**  
云图：默认支持该产品的指纹识别，同时支持该漏洞的PoC原理检测。洞鉴：以自定义POC的形式支持改漏洞的PoC原理检测。  
**雷池：**  
默认支持该漏洞利用行为的检测  
。  
  
**全悉：**  
默认支持该漏洞利用行为的检测  
。  
  
**牧云：**  
使用管理平台 23.05.001 及以上版本的用户可通过升级平台下载应急漏洞情报库升级包（EMERVULN-23.06.011）“漏洞应急”功能支持该漏洞的检测；其它管理平台版本暂不支持该漏洞检测。  
  
  
**时间线**  
  
   
Timeline   
  
  
  
**0****6**  
  
5月17日  长亭安全研究员发现漏洞  
  
5月19日  漏洞上报监管  
  
7月3日  官方发布漏洞补丁  
[1]  
  
7月3日  长亭发布漏洞通告  
  
  
参考资料：  
  
✦   
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
  
  
