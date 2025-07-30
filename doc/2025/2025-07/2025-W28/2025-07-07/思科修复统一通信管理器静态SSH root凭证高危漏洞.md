> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzA3MTUxNzQxMQ==&mid=2453886107&idx=1&sn=64ce6fbcbe83c971d3046d082da081fb

#  思科修复统一通信管理器静态SSH root凭证高危漏洞  
让数据更安全  德斯克安全小课堂   2025-07-07 01:25  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/c5fPvg33s0G6lAoHwJ1ganA9d6MKYv9Vf4a6CjhKgwfqeUJ0sF8bGd9akwx9oAibG6nJ6URZtzRIJYG8RSZVTqA/640?wx_fmt=jpeg&from=appmsg "")  
## 漏洞概况  
  
数字通信技术巨头思科(Cisco)近日修复了其统一通信管理器(Unified Communications Manager，简称Unified CM)中存在的一个静态SSH凭证漏洞。该漏洞编号为CVE-2025-20309（CVSS评分为10分），存在于思科统一通信管理器及其会话管理版(Session Management Edition)中，允许远程攻击者使用开发阶段设置的硬编码root凭证登录系统。思科统一通信管理器(CUCM)是思科开发的企业级语音、视频、消息和移动通信呼叫处理系统。  
## 漏洞危害  
  
这些静态凭证无法被修改或删除。如果攻击者利用此漏洞，他们可以获取完整的root权限访问系统并执行任意命令。由于无需任何认证，这对受影响设备构成了严重威胁。  
  
思科在安全公告中指出："思科统一通信管理器(Unified CM)和思科统一通信管理器会话管理版(Unified CM SME)中存在漏洞，可能允许未经身份验证的远程攻击者使用root账户登录受影响设备，该账户具有无法更改或删除的默认静态凭证。此漏洞源于root账户保留了开发阶段使用的静态用户凭证。攻击者可以利用该账户登录受影响系统来利用此漏洞。成功利用可能允许攻击者以root用户身份登录受影响系统并执行任意命令。"  
## 修复措施  
  
思科已通过从其统一通信管理器(Unified CM)中移除后门账户的方式解决了该问题。  
  
该漏洞影响思科统一通信管理器和统一通信管理器会话管理版工程特别版本15.0.1.13010-1至15.0.1.13017-1，无论配置如何。这些ES版本是仅通过思科技术支持中心(TAC)共享的有限修复版本。  
  
目前没有针对该漏洞的临时解决方案。思科建议管理员升级到适当的修复软件版本：  
<table><thead><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;font-family: 微软雅黑, PingFangSC;"><th style="box-sizing: border-box;text-align: center;margin: 0px;border-top: 1px solid rgb(204, 204, 204);border-right: 1px solid rgb(204, 204, 204);border-bottom: none;border-left: 1px solid rgb(204, 204, 204);border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;background: rgb(245, 245, 245);padding: 5px 10px;font-family: 微软雅黑, PingFangSC;"><strong><span leaf="">思科统一通信管理器和统一通信管理器会话管理版版本</span></strong></th><th style="box-sizing: border-box;text-align: center;margin: 0px;border-top: 1px solid rgb(204, 204, 204);border-right: 1px solid rgb(204, 204, 204);border-bottom: none;border-left: 1px solid rgb(204, 204, 204);border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;background: rgb(245, 245, 245);padding: 5px 10px;font-family: 微软雅黑, PingFangSC;"><strong><span leaf="">首个修复版本</span></strong></th></tr></thead><tbody><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;font-family: 微软雅黑, PingFangSC;"><td style="box-sizing: border-box;margin: 0px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;padding: 5px 10px;font-family: 微软雅黑, PingFangSC;"><section><span leaf="">12.5</span></section></td><td style="box-sizing: border-box;margin: 0px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;padding: 5px 10px;font-family: 微软雅黑, PingFangSC;"><section><span leaf="">不受影响</span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;font-family: 微软雅黑, PingFangSC;"><td style="box-sizing: border-box;margin: 0px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;padding: 5px 10px;font-family: 微软雅黑, PingFangSC;"><section><span leaf="">14</span></section></td><td style="box-sizing: border-box;margin: 0px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;padding: 5px 10px;font-family: 微软雅黑, PingFangSC;"><section><span leaf="">不受影响</span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;font-family: 微软雅黑, PingFangSC;"><td style="box-sizing: border-box;margin: 0px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;padding: 5px 10px;font-family: 微软雅黑, PingFangSC;"><section><span leaf="">15.0.1.13010-1至15.0.1.13017-11</span></section></td><td style="box-sizing: border-box;margin: 0px;border: 1px solid rgb(204, 204, 204);text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;padding: 5px 10px;font-family: 微软雅黑, PingFangSC;"><section><span leaf="">15SU3(2025年7月)或应用补丁文件：ciscocm.CSCwp27755_D0247-1.cop.sha512</span></section></td></tr></tbody></table>  
需要注意的是，仅列出的ES版本系列存在漏洞，任何版本的常规服务更新(SUs)均不受影响。  
## 当前状况  
  
好消息是，思科产品安全事件响应团队(PSIRT)尚未发现任何在野利用此漏洞的攻击活动。  
## 检测方法  
  
思科提供了用于检测可能受此漏洞影响设备的入侵指标(IoCs)。一个关键入侵指标是root用户成功通过SSH登录，这会在系统日志(
```
/var/log/active/syslog/secure
```

  
)中留下记录。  
  
默认情况下已启用此日志记录功能。管理员可使用以下CLI命令进行检查：  

```
file get activelog syslog/secure
```

  
在日志中查找同时显示
```
sshd
```

  
和root登录会话的条目。  
  
  
  
