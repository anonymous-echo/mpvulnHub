> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIwMDk1MjMyMg==&mid=2247492877&idx=1&sn=f6c804a45992dbfc7e82c40884909de9

#  【已复现】契约锁电子签章系统 pdfverifier 远程代码执行漏洞  
 长亭安全应急响应中心   2025-07-11 03:32  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicQOb3OCkynwqpfctBCGH3WxsLsXpcXiciazfZxjQktShM0NnZqrVpictrLNMxKWlEGOmJBe7jCsC47rA/640?wx_fmt=png&from=appmsg "")  
  
  
契约锁，是一个电子签章及印章管控平台，提供的电子文件具有与纸质文件一样的法律效力。  
  
  
2025年7月，契约锁发布安全补丁修复了远程代码执行漏洞。该漏洞允许未授权攻击者通过特定方式在服务器上执行任意代码。由于该漏洞利用难度较低，建议相关用户及时更新安全补丁进行修复。  
  
  
**漏洞描述**  
  
   
Description  
   
  
  
  
**0****1**  
  
**漏洞成因**  
  
该漏洞源于电子签章系统在处理用户提交的特定格式数据时，输入验证和执行逻辑存在缺陷，导致安全防护机制被绕过。攻击者利用这一缺陷，通过精心构造的恶意请求，在服务器上注入并执行任意系统命令。  
  
## 漏洞影响  
  
远程代码执行  
：攻击者可在服务器上执行任意系统命令，可能导致服务器被完全控制、数据泄露或业务系统沦陷。  
  
  
**处置优先级：高**  
  
漏洞类型：远程代码执行  
  
**漏洞危害等级：**  
高  
  
**触发方式：**  
网络远程  
  
**权限认证要求：**  
无需权限  
  
**系统配置要求：**  
默认配置  
  
**用户交互要求：**  
无需用户交互  
  
**利用成熟度：**  
POC/EXP 未公开  
  
**修复复杂度：**  
低，  
官方提供补丁修复方案  
  
  
  
  
  
**影响版本**  
  
   
Affects  
   
  
  
  
**02**  

```


4.3.8 <= 契约锁 <= 5.x.x && 补丁版本 < 2.1.8
4.0.x <= 契约锁 <= 4.3.7 && 补丁版本 < 1.3.8

```

  
**解决方案**  
  
   
Solution  
   
  
  
  
**03**  
  
##   
  
## 临时缓解方案如非必要，避免将该系统直接暴露在互联网  
  
## 升级修复方案  
  
契约锁官方已发布安全补丁，请  
及时更新安全补丁  
：  
  
下载地址：  
https://www.qiyuesuo.com/more/security/servicepack  
  
  
  
**漏洞复现**  
  
Reproduction  
   
  
  
  
**04**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicQOb3OCkynwqpfctBCGH3WxMdAkagltyXI64ZaOzcGoTpSgnXP5xOjFTzFDntjUZ50WuHEZXJAvRA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**产品支持**  
  
Support  
  
  
  
**05**  
  
云图：默认支持该产品的指纹识别，  
同时支持该漏洞的PoC检测  
  
洞鉴：预计 2025.7.11 支持检测  
  
雷池：  
默认支持检测  
  
全悉：  
默认支持检测  
  
  
  
**时间线**  
  
   
Timeline  
   
  
  
  
**06**  
  
2025年7月   契约锁官方发布安全补丁  
  
2025年7月11日  长亭安全应急响应中心发布通告  
  
  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否受到此次漏洞影响  
  
请联系长亭应急服务团队  
  
7*24小时，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
