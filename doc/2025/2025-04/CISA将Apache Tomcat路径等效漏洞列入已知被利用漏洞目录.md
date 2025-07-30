#  CISA将Apache Tomcat路径等效漏洞列入已知被利用漏洞目录   
 FreeBuf   2025-04-05 18:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
美国网络安全和基础设施安全局（CISA）已将Apache Tomcat路径等效漏洞（编号CVE-2025-24813）列入其已知被利用漏洞（KEV）目录。该漏洞在公开概念验证（PoC）代码发布仅30小时后即遭活跃利用。  
  
  
**技术细节**  
  
  
  
该漏洞属于Apache Tomcat路径等效缺陷，在满足特定条件时可导致远程代码执行或信息泄露。**受影响版本包括：**  
- 11.0.0-M1至11.0.2  
  
- 10.1.0-M1至10.1.34  
  
- 9.0.0.M1至9.0.98  
  
**漏洞利用需同时满足以下条件：**  
- 默认Servlet启用写入功能（默认禁用）  
  
- 启用部分PUT请求支持（默认启用）  
  
- 存在特定文件处理条件  
  
根据安全公告，原始实现中部分PUT请求会基于用户提供的文件名和路径创建临时文件，并将路径分隔符替换为"."。当满足以下全部条件时，攻击者可查看敏感文件或注入恶意内容：  
- 安全敏感文件的上传目标URL是公共上传目标URL的子目录  
  
- 攻击者知晓正在上传的安全敏感文件名  
  
- 安全敏感文件同样通过部分PUT方式上传  
  
若同时满足以下条件，则可实现**远程代码执行：**  
- 应用程序使用Tomcat基于文件的会话持久化功能（默认存储位置）  
  
- 应用程序包含可被反序列化攻击利用的库  
  
**修复与利用情况**  
  
  
  
Tomcat已发布9.0.99、10.1.35和11.0版本修复该漏洞。Wallarm研究人员确认漏洞正遭活跃利用，攻击者仅需发送单个PUT API请求即可劫持Apache Tomcat服务器。  
  
  
攻击过程分为两个阶段：  
1. **上传恶意序列化会话：**  
攻击者发送包含base64编码的ysoserial工具链的PUT请求，将其存储至Tomcat会话目录  
  
1. **通过会话Cookie触发执行：**  
携带恶意JSESSIONID的GET请求会强制Tomcat  
反序列化并执行载荷  
  
**防御挑战**  
  
  
  
该攻击具有以下特征导致防御困难：  
- 无需认证即可执行  
  
- base64编码可绕过传统安全过滤器检测  
  
多数Web应用防火墙（WAF）无法有效识别，因为：  
- PUT请求看似正常且不含明显恶意内容  
  
- 载荷采用base64编码规避基于模式的检测  
  
- 攻击分两步执行，实际攻击发生在反序列化阶段  
  
**应对措施**  
  
  
  
CISA根据第22-01号约束性操作指令（BOD 22-01）要求联邦机构最迟于2025年4月22日前修复该漏洞。  
  
  
**安全专家建议：**  
- 受影响用户应立即升级至修复版本  
  
- 企业应检查基础设施中是否存在该漏洞  
  
- 关注多步骤攻击的日志监控，建立更完善的文件上传检测机制  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif "")  
  
  
