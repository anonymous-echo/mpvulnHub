#  可RCE速修｜Smartbi内置用户登陆绕过漏洞   
 长亭安全应急响应中心   2023-06-19 16:45  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicTNgpt9nRmhiaDF5gqoZYt44hteiaa6cc7RTx03Tk7SWryEe1DOoLTZzrBeciaVkfgrLe1LNzkoYjPHA/640?wx_fmt=png "")  
  
Smartbi是一款商业智能应用，提供了数据集成、分析、可视化等功能，帮助用户理解和使用他们的数据进行决策。近期，长亭科技监测到Smartbi发布新补丁，修复了一处登录绕过漏洞。长亭应急团队经过分析后发现该漏洞类型为登录绕过，仍有较多公网系统仍未修复漏洞。于是根据漏洞原理编写了无害化的X-POC远程检测工具和牧云本地检测工具，目前已向公众开放下载使用。  
**漏洞描述**  
  
   
Description   
  
  
  
**0****1**  
  
Smartbi在安装时会内置几个用户，在使用特定接口时，可绕过用户身份认证机制获取其身份凭证，随后可使用获取的身份凭证调用后台接口，可能导致敏感信息泄露和代码执行。  
**检测工具**  
  
   
Detection   
  
  
  
**0****2**  
#   
# X-POC远程检测工具  
检测方法：xpoc -r 105 -t 目标URL  
工具获取方式：  
https://github.com/chaitin/xpochttps://stack.chaitin.com/tool/detail?id=1036  
#   
# 牧云本地检测工具  
检测方法：在本地主机上执行以下命令即可无害化扫描：smartbi_internal_user_login_bypass_scanner_windows_amd64.exe scan --output result.json  
工具获取方式：  
https://stack.chaitin.com/tool/detail?id=1187  
  
**影响范围**  
  
   
Affects  
   
  
  
  
**0****3**  
```
```  
  
**解决方案**  
  
   
Solution   
  
  
  
**0****4**  
临时缓解方案在确认不影响业务的前提下，删除内置的几个账号（public、service、system）。同时如非必要，不要将Smartbi系统开放在互联网上。升级修复方案官方已发布升级补丁包，支持在线升级和离线补丁安装，可在参考链接进行下载使用。  
  
**产品支持**  
  
   
Support   
  
  
  
**0****5**  
云图：默认支持该产品的指纹识别，同时支持该漏洞的PoC原理检测。雷池：已发布虚拟补丁，支持该漏洞利用行为的检测。洞鉴：支持以自定义PoC的形式进行检测，已发布自定义PoC。牧云：使用管理平台 23.05.001 及以上版本的用户可通过升级平台下载应急漏洞情报库升级包（EMERVULN-23.06.009）“漏洞应急”功能支持该漏洞的检测；其它管理平台版本暂不支持该漏洞检测。全悉：已发布规则升级包，支持检测该漏洞的利用行为。  
  
**时间线**  
  
   
Timeline   
  
  
  
**0****6**  
6月15日 长亭科技收到漏洞情报6月16日 长亭应急响应实验室漏洞分析与复现6月19日 长亭安全应急响应中心发布通告  
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
  
  
