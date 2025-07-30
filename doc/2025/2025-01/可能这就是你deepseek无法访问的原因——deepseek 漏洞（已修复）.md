#  可能这就是你deepseek无法访问的原因——deepseek 漏洞（已修复）   
原创 前沿快讯  安全光圈   2025-01-30 06:45  
  
   
  
# 这就是deepseek无法访问的原因吗？deepseek 漏洞（已修复）  
## 漏洞原贴  
  
漏洞研究人员的GitHub地址：https://github.com/h4x0r-dz  
  
公开的推文：https://x.com/h4x0r_dz/status/1884566387349225598  
  
Hello   
@deepseek_ai  
, I have sent an email to   
service@deepseek.com  
 regarding a critical vulnerability that could allow attackers to access your database exposing sensitive data including API KEYS. I strongly recommend addressing this issue as soon as possible.  
  
翻译：我已向   
service@deepseek.com  
 发送了一封电子邮件，内容涉及一个可能允许攻击者访问您的数据库并暴露敏感数据（包括 API KEYS）的重要漏洞。我强烈建议您尽快解决这个问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1X9cMsc6D3xggtycNuKIDIE4doM0OiciaSscqqCrgEz0f9ibUibOHYRJiaD8YFzmZRWzwAXiaDfSQ7Z5ORItDThicibAQ/640?wx_fmt=png&from=appmsg "null")  
  
  
泄露的api(不知道是不是因为这个信息导致的deepseek崩溃)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/g1X9cMsc6D3xggtycNuKIDIE4doM0OiciaI1qzHkV8licicDjhMAwvTIJbxpBYYJ8rgJ9EM48I1GcgA1WS1boN2MDQ/640?wx_fmt=png&from=appmsg "null")  
  
## 当前该问题已经被修复  
  
从图中可以得知泄露的信息足以得到数据库信息，可能是因此被恶意攻击者利用攻击，导致deepseek服务器停摆/维护  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/g1X9cMsc6D3xggtycNuKIDIE4doM0OiciarKZPOP1ydicLHLhBeTgzgV6lib4iceE7uhicdEctv6MqatloOuXEtASnaA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
   
  
  
