#  【漏洞复现 | 含POC】通天星CMSV6车载定位监控平台 point_manage SQL注入漏洞   
小明同学  小明信安   2024-06-29 09:00  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
    通天星CMSV6车载定位监控平台/point_manage/merge接口存在SQL注入漏洞，攻击者可以通过漏洞获取服务器内敏感信息导致信息泄露，甚至通过漏洞写入木马病毒获取服务器权限。  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
body="/808gps"
```  
  
- Hunter  
  
  
```
body="/808gps"
```  
  
- Quake  
  
  
```
body="/808gps"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4AsyLkZOh8TEeUvzT8KuA1lftkpFw7bu8egHOQicwXO7474RDNujbMyCEEw/640?wx_fmt=png&from=appmsg "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- SQL注入写入Webshell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asy0fw2o9oJ5DJqQLQgaMyyk9jeyXqE4c02ibeibVZBfGXl03S0qHvSJFSg/640?wx_fmt=png&from=appmsg "")  
- 访问路径/test.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asy6iaXC2EdJYiaVAIxPRF7zAVQ5JI4hHDHH89JibdCmJBv0963Z2weNOUJA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
- Nuclei批量POC已发布知识星球：  
**小明信安POC库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asyp4PwYLpBeI9KPkeEn3BjFyQ1iaic7WaicZWJPKwPRZBwicyOLH020T9GCg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x07 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asyv1AiaL5MrLSodbBtGObiccGu5Vp3E0O5hg6ibaquk6IbfPlwXjJ7A5vBg/640?wx_fmt=png&from=appmsg "")  
  
**欢迎加入星球，券后价仅39元！！！长期每天更新漏洞POC/EXP**  
  
