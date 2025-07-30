> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIwMDk1MjMyMg==&mid=2247492852&idx=1&sn=63aa481b46b0e2ccc42748ad0107467f

#  【已复现】Gogs 远程命令执行漏洞  
 长亭安全应急响应中心   2025-06-25 15:11  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicQkZUcaW7n3FxfcpagJiaF4coqSiaddRMeZJFeLGurrOXUkC0icYb2bIPEvw6jPxlxIGTVjJmqRr17DA/640?wx_fmt=png&from=appmsg "")  
  
  
Gogs (Go Git Service) 是一款基于 Go 语言开发的开源 Git 托管平台，采用 MIT 许可证，提供代码托管、Issue 跟踪、权限管理和 Webhook 等功能。  
  
  
2025年6月，  
Gogs发布  
新版本，修复了一处命令注入漏洞。拥有用户权限的攻击者利用成功后可执行任意系统命令，  
经长亭科技安全研究员初步验证，  
此漏洞仅影响类Linux系统，  
Windows环境下的Gogs不受此漏洞影响，建议受影响的用户尽快修复。  
  
  
  
**漏洞描述**  
  
   
Description  
   
  
  
  
**0****1**  
  
**漏洞成因**  
  
攻击者可通过符号链接绕过  
CVE-2024-39931漏洞的修复  
补丁，删除.git目录下的文件，覆写相关敏感配置，并实现远程命令执行，控制服务器。  
  
## 漏洞影响  
  
攻击者可在服务器上执行任意系统命令，可能导致服务器被完全控制、数据泄露或业务系统沦陷。  
  
  
**处置优先级：高**  
  
漏洞类型：  
命令注入  
  
**漏洞危害等级：**  
高  
  
**触发方式：**  
网络远程  
  
**权限认证要求：**  
需要权限  
  
**系统配置要求：**  
默认配置  
  
**用户交互要求：**  
无需用户交互  
  
**利用成熟度：**  
POC/EXP 未公开  
  
**修复复杂度：**  
低，  
官方提供版本升级修复方案  
  
  
  
  
  
**影响版本**  
  
   
Affects  
   
  
  
  
**02**  

```

Gogs< 0.13.3

```

  
**解决方案**  
  
   
Solution  
   
  
  
  
**03**  
  
##   
  
## 临时缓解方案禁用用户注册功能，在 Gogs 的配置文件 app.ini 中关闭用户注册功能，防止攻击者通过注册恶意账户进行利用：[auth]DISABLE_REGISTRATION = true生效方式：修改后需重启 Gogs 服务。  
  
## 升级修复方案官方已发布安全修复版本，建议升级到 0.13.3 或更高版本，下载地址：https://github.com/gogs/gogs/releases/tag/v0.13.3漏洞复现Reproduction 04参考资料：[1].https://github.com/gogs/gogs/security/advisories/GHSA-wj44-9vcg-wjq7  
  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否受到此次漏洞影响  
  
请联系长亭应急服务团队  
  
7*24小时，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
