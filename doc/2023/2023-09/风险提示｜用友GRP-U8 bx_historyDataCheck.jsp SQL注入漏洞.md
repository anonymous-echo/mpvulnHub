#  风险提示｜用友GRP-U8 bx_historyDataCheck.jsp SQL注入漏洞   
长亭应急响应  黑伞安全   2023-09-22 11:33  
  
.辽宁省义务教育阶段学生作业管理“十要求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicT6ictQ215kJUg08qFq3DElzicS3CJkF0HbRdcV2UANgmVRdWPa2VhNgwXyGa1RFxwsicq3yhQPbqmlQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
用友GRP-U8是一款企业管理软件，专为大型企业提供财务、采购、库存、生产等业务管理解决方案。近期，用友官方收到一则漏洞情报，及时发布了补丁，成功修复了一个前台SQL注入漏洞。同时用友与长亭科技联合发布了该漏洞风险提示，共同努力确保该漏洞得到及时修复。长亭全线产品现已支持检测或扫描，可及时获取相关升级支持。应急响应实验室根据漏洞原理编写了无害化的X-POC远程检测工具和牧云本地检测工具，目前已向公众开放下载使用。  
**漏洞描述**  
  
   
Description   
  
  
  
**0****1**  
  
该漏洞是由于用友GRP-U8未对用户的输入进行有效的过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞。  
**检测工具**  
  
   
Detection   
  
  
  
**0****2**  
#   
# X-POC远程检测工具  
检测方法：xpoc -r 409 -t https://xpoc.org  
  
工具获取方式：  
https://github.com/chaitin/xpochttps://stack.chaitin.com/tool/detail/1036  
#   
# 牧云本地检测工具  
检测方法：yonyou_grp_u8_sqli_ct_893849_scanner_windows_amd64.exe  
工具获取方式：  
https://stack.chaitin.com/tool/detail/1232  
  
**影响范围**  
  
   
Affects  
   
  
  
  
**0****3**  
```
```  
  
**解决方案**  
  
   
Solution   
  
  
  
**0****4**  
临时缓解方案通过网络ACL策略限制访问来源，例如只允许来自特定IP地址或地址段的访问请求。升级修复方案官方已发布升级补丁包，可在官方公告https://security.yonyou.com/#/noticeInfo?id=379中进行下载使用。  
  
**产品支持**  
  
   
Support   
  
  
  
**0****5**  
云图：默认支持该产品的指纹识别，同时支持该漏洞的POC原理检测。洞鉴：以自定义POC形式支持。雷池：默认支持该漏洞利用行为检测。全悉：默认支持该漏洞利用行为检测。牧云：使用管理平台 23.05.001 及以上版本的用户可通过升级平台下载应急漏洞情报库升级包（EMERVULN-23.09.021_r1）“漏洞应急”功能支持该漏洞的检测；其它管理平台版本请联系牧云技术支持团队获取该功能。时间线 Timeline 069月20日 用友官方发布漏洞补丁、漏洞公告9月21日 长亭应急响应实验室漏洞分析与复现9月22日 用友联合长亭应急响应中心二次发布漏洞公告参考资料：用友官方漏洞公告与补丁信息-https://security.yonyou.com/#/noticeInfo?id=379  
  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否收到此次漏洞影响  
  
请联系长亭应急团队  
  
7*24小时，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
应急响应热线：4000-327-707  
  
  
  
