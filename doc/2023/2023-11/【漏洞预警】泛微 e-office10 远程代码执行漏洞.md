#  【漏洞预警】泛微 e-office10 远程代码执行漏洞   
cexlife  飓风网络安全   2023-11-28 20:27  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu000F1Dsxibu9ZgMrndvnxa2gEsbjfHuCiaS3C9D5kLbuczU7bDwBZfRypnFXW7HHghTBJGyxtsupNiag/640?wx_fmt=png&from=appmsg "")  
  
**漏洞概述:**  
  
泛微e-office系统是面向中小型组织的专业协同OA软件，致力于为企业用户提供专业OA办公系统、移动OA应用等协同OA整体解决方案。泛微e-office10远程代码执行漏洞。由于泛微e-office10前台存在SQL注入漏洞可以获取管理员账号和口令，配合后台文件包含即可导致远程代码执行,经分析，攻击者可利用该漏洞获取服务器敏感信息、执行任意代码，建议尽快修复。**产品名称:**泛微e-office10**受影响版本:**version < 10.0_20231107**修复方案:****1、官方修复方案：**官方已在最新版修复此问题，建议受影响的用户在服务器管理平台升级到10.0_20231107版本**2、临时修复方案：**使用防护类设备对相关资产进行SQL注入、文件包含等攻击的防护；在确认不影响业务的情况下可临时关闭im服务，或使用网络ACL策略限制im服务的公网访问  
  
