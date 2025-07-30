#  【漏洞复现】用友-畅捷通T+-RRATableController-命令执行   
原创 rain  知黑守白   2024-03-26 06:00  
  
**免责声明**  
  
此内容仅供技术交流与学习，请勿用于未经授权的场景。请遵循相关法律与道德规范。任何因使用本文所述技术而引发的法律责任，与本文作者及发布平台无关。如有内容争议或侵权，请及时私信我们！  
## 0x01 产品简介  
  
          
用友畅捷通 T+是一款基于互联网的新型企业管理软件，功能模块包括：财务管理、采购管理、库存管理等。主要针对中小型工贸和商贸企业的财务业务一体化应用，融入了社交化、移动化、物联网、电子商务、互联网信息订阅等元素。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg10j0VPPWcNd6nuO4S7r2qkbNcm3Bh9LBI3tDzK8s2IX0WnjLZ2iaacEgv7nQ1rpMoGEBy2JGSEKibQ/640?wx_fmt=png&from=appmsg "")  
  
**0x02 漏洞概述**  
  
          
用友畅捷通 T+某模块存在远程命令执行漏洞。攻击者可以通过构造恶意的数据包，成功注入并执行恶意命令，可能导致系统敏感信息泄露、篡改、服务器接管或其他严重后果。  
## 0x03 网络测绘  
```
app="畅捷通-TPlus"
```  
## 0x04 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg10j0VPPWcNd6nuO4S7r2qkhJVyo0qsQ9SHxBDQXr3JXjCxafdhibUg8zJu83qAbqmHNibGujyDazEQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg10j0VPPWcNd6nuO4S7r2qk51Pd2lmUV8aOzaR54iaWdbprLhlel11L4ibXwEMicibwYpYxvc00E4Of4A/640?wx_fmt=png&from=appmsg "")  
## 0x05 Nuclei  
  
**检测脚本请移步星球获取，目前已更新200+漏洞信息**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sicaib9ysOXg1bd3oO7U9UNP8qZGN6iaibps3uTN8ibkcfq2jP2WroLlUqicDV0nLgKZKUlk730pxIictF97wGEFUNFHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg10j0VPPWcNd6nuO4S7r2qkEH0Dibic1tMaicCCl32FKTrAdvekZrOQ0FBibXM9CneBW39AAGNOK1vd6A/640?wx_fmt=png&from=appmsg "")  
  
  
**扫码加入交流群**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/sicaib9ysOXg10j0VPPWcNd6nuO4S7r2qk5DHqppfwq8H72s4ic3vZ15KJHJkq1c0VYoYSYkibIGaUbr8dHylzKP3g/640?wx_fmt=jpeg&from=appmsg "")  
```
0x06 修复建议 

```  
  
          
首先，是输入验证和过滤，确保用户输入的数据不包含任何恶意命令或特殊字符，使用白名单过滤来限制用户输入的范围。其次，采用参数化查询或使用安全的API来与外部系统进行交互，避免直接拼接用户输入到命令中，以防止命令注入攻击。第三，严格限制应用程序的权限，确保应用程序运行时只能访问和执行必要的系统资源和命令。第四，定期更新和维护系统和组件，及时应用安全补丁，以修复已知的漏洞。最后，加强安全培训和意识提升，培养开发人员和系统管理员对命令执行漏洞的认识和应对能力，以提高系统的整体安全性。通过综合这些措施，可以有效地修复命令执行漏洞，并提高系统对命令注入攻击的防范能力。  
  
