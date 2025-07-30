#  【神兵利器】最新Nacos综合漏洞利用工具   
h0ny  七芒星实验室   2024-12-24 23:04  
  
**项目介绍**  
  
本工具仅用于安全研究，请勿用于生产环境。  
由  
于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任  
  
**检测列表**  
  
目前工具支持对以下漏洞的检测：  
```
| PoC | Exploit | Vulnerability Name                   | Vulnerability Identifier |
| :-: | :-----: | :----------------------------------- | :----------------------- |
| YES |   YES   | Nacos Default Auth Disabled          | /                        |
| YES |   YES   | Nacos Default Password (nacos/nacos) | AVD-2021-896025          |
| YES |   YES   | Nacos Default server.identity        | /                        |
| YES |   YES   | Nacos Default token.secret.key       | AVD-2023-1655789         |
| YES |   YES   | Nacos Default User-Agent             | AVD-2021-29441           |
| YES |   YES   | Nacos Derby SQL Injection            | AVD-2021-897468          |
| NO  |   YES   | Nacos Client Yaml Deserialization    | /                        |
| NO  |   YES   | Nacos Jraft Hessian Deserialization  | AVD-2023-1700159         |
| NO  |   YES   | Nacos Jraft Services File Operations | AVD-2024-1743586         |
```  
  
  
功能展示  
  
漏洞检测：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnhVbBSXJMXPAvFiaEhetnPnSoa6Nmjibu8MsdarNPt0icR0Tqmd5ZibUKJYfJCMf5FN8naR8MvPaRsog/640?wx_fmt=png&from=appmsg "")  
  
认证绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnhVbBSXJMXPAvFiaEhetnPn5EGUc9e58DcCmDXTBTM0ia1sWvtnYCbfK1oCibMrFVeWSt7qOkD2Gk3Q/640?wx_fmt=png&from=appmsg "")  
  
Derby SQL注入：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnhVbBSXJMXPAvFiaEhetnPn1zcDSqSyvLdG68A6ibjiaxgZV1gkljkJCSJIh5EC7gX1eraU6uL5CCsQ/640?wx_fmt=png&from=appmsg "")  
  
Jraft 反序例化漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnhVbBSXJMXPAvFiaEhetnPn08XpSTOfXcH2krTbk67jo7gupe0tGpKXzIN2rUEBKN9VKYE2MCBiaeg/640?wx_fmt=png&from=appmsg "")  
  
**免责说明**  
  
此开源工具仅供个人学习和研究使用，作者不对您使用该工具所产生的任何后果负任何法律责任  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**241225****】获取**  
**下载链接**  
  
**·推 荐 阅 读·**  
  
# 最新后渗透免杀工具  
# 【护网必备】高危漏洞综合利用工具  
# 【护网必备】Shiro反序列化漏洞综合利用工具增强版  
# 【护网必备】外网打点必备-WeblogicTool  
# 【护网必备】最新Struts2全版本漏洞检测工具  
# Nacos漏洞综合利用工具  
# 重点OA系统漏洞利用综合工具箱    
# 【护网必备】海康威视RCE批量检测利用工具  
# 【护网必备】浏览器用户密码|Cookie|书签|下载记录导出工具  
  
  
  
