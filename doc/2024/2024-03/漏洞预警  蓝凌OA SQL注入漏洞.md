#  漏洞预警 | 蓝凌OA SQL注入漏洞   
浅安  浅安安全   2024-03-02 08:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
蓝凌OA是由深圳市蓝凌软件股份有限公司开发，是一款针对中小企业的移动化智能办公产品。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVYWeZhgoC2Sr4x2V8oP9xibxVjwkNw7mOPBhXIggJJUEib8yBIKKRDaBp0spKcrjBfxviaCWibA2zic2w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
蓝凌OA wechatLoginHelper.do接口处存在SQL注入漏洞，攻击者除了可以利用SQL注入漏洞获取数据库中的信息，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
###   
  
**0x04 影响版本**  
- 蓝凌OA  
  
**0x05****POC**  
  
https://blog.csdn.net/qq_41904294/article/details/136328627  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方暂未发布漏洞修复版本，建议用户关注官网动态****：**  
  
https://www.landray.com.cn/  
  
  
  
