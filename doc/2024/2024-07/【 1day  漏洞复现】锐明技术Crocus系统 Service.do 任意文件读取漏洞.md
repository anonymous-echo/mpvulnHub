#  【 1day | 漏洞复现】锐明技术Crocus系统 Service.do 任意文件读取漏洞   
小明同学  小明信安   2024-07-06 09:00  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
    锐明技术Crocus系统Service.do接口Path参数存在任意文件读取漏洞，攻击者可以通过漏洞读取服务器上的敏感文件，包括配置文件、保存的账号密码等敏感信息从而导致进一步攻击。  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
body="/ThirdResource/respond/respond.min.js"
```  
  
- Hunter  
  
  
```
body="/ThirdResource/respond/respond.min.js"
```  
  
- Quake  
  
  
```
body="/ThirdResource/respond/respond.min.js"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIazmicIiajgH2KCeaJr5R3EY54lPOo5qaosic2hrCufjslhCJjrmRcljVoOF3VNqvk92sC8tFp0xGRg/640?wx_fmt=png&from=appmsg "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- 读取C:/windows/win.ini文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIazmicIiajgH2KCeaJr5R3EYHxVmLWn6prOYvPrP2qytZFQ3E4JzN0MTkV7Z9IQTTW0GvpmqAYts7Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
- Nuclei批量漏洞检测POC脚本已发布知识星球：  
**小明信安POC库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIazmicIiajgH2KCeaJr5R3EYGQvoKibQdvKgkibS3AkCOZB1HVyfwWU4DZzr2sKlFfsgjA2cFMVpia8XQ/640?wx_fmt=png&from=appmsg "")  
  
  
**0x06 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asyv1AiaL5MrLSodbBtGObiccGu5Vp3E0O5hg6ibaquk6IbfPlwXjJ7A5vBg/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅39元！！！****长期每天更新漏洞POC/EXP**  
  
