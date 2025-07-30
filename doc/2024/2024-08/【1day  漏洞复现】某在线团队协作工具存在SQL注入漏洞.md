#  【1day | 漏洞复现】某在线团队协作工具存在SQL注入漏洞   
小明同学  小明信安   2024-08-17 13:55  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
    某开源轻量级的在线团队协作工具，提供各类文档工具、在线思维导图、在线流程图、项目管理、任务分发，知识库管理等工具。支持团队在线聊天沟通，订阅任务动态实时推送。   
  
    某开源轻量级的在线团队协作工具存在**SQL注入漏洞**，攻击者可以通过漏洞获取服务器内敏感信息导致信息泄露，甚至通过漏洞写入木马病毒获取服务器权限。  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
title="Wookteam"
```  
  
- Hunter：  
  
  
```
title="Wookteam"
```  
  
- Quake：  
  
  
```
title="Wookteam"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIWJBkz2T7o2bUaw68QPOxFoiajY6JBxpKRYn92xUg7uAk11ka1HPHFR77R7hhkukQiaxfyNzq8uC4A/640?wx_fmt=png&from=appmsg "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- SQL注入获取数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIWJBkz2T7o2bUaw68QPOxFDZPQauFZ8vIDVJ1BsrSuLepUhND5AarJn5sSdF8PeNII9f6UaYy8Lw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
- Nuclei批量漏洞检测POC脚本已发布知识星球：  
**小明信安POC库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIWJBkz2T7o2bUaw68QPOxFwRG3wcciaBod4ic9uQjtZqkhpzVNeC6XsJCRhQOUxJOcyjKIm0fia7ybA/640?wx_fmt=png&from=appmsg "")  
  
  
**0x06 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asyv1AiaL5MrLSodbBtGObiccGu5Vp3E0O5hg6ibaquk6IbfPlwXjJ7A5vBg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIwR3HkggWQao81qT2I77SQlpxF6TygZ84QRfxwibJ3mp2fo2f6b17bQyfbZtvsY7aBYrryuAnWWUA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
