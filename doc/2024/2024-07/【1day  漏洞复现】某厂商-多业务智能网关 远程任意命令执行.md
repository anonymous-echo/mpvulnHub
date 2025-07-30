#  【1day | 漏洞复现】某厂商-多业务智能网关 远程任意命令执行   
小明同学  小明信安   2024-07-28 15:28  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
    某厂商多业务智能网关是一款集多种功能于一体的网络设备，专为中小企业及行业分支机构设计，以满足其多业务接入和带宽提速的需求，是新一代网络产品。网关集成了数据、语音、安全、无线等多种功能，能够为用户提供综合、完整的网络接入解决方案。它们广泛应用于政企单位、商务楼宇、校园、工业园区等场景，为用户带来高效、便捷的网络体验。  
  
    某厂商多业务智能网关存在远程任意命令执行漏洞，攻击者可以通过漏洞执行任意命令从而获取服务器权限，可能导致内网进一步被攻击。  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
body="/images/raisecom/back.gif"
```  
  
- Hunter：  
  
  
```
body="/images/raisecom/back.gif"
```  
  
- Quake：  
  
  
```
body="/images/raisecom/back.gif"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIOvHp1Of0C1EKS6Ah8MGvLIFJ9REH6zAQNfBsHGS98fUsYvmzPsq6icBImR8ib7oKKfs10CN5bIlIA/640?wx_fmt=png&from=appmsg "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- 写入phpinfo  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIOvHp1Of0C1EKS6Ah8MGvLZIkCckM5lyDWaCgnuH33usg3pkzVLcKdfkD4Llz6Rwq7QicrbvmQib6g/640?wx_fmt=png&from=appmsg "")  
- 访问文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIOvHp1Of0C1EKS6Ah8MGvLiazPfQCnHk0CM2PR4pLAYoTlViaPV4L5Qto02hlVudxxN8gXQwGc4F0Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
- Nuclei批量漏洞检测POC脚本已发布知识星球：  
**小明信安POC库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSIOvHp1Of0C1EKS6Ah8MGvLwSdPwhakHibF2bZhPibYRBwvZGwGyw9R3X4v3beBbeRdpeojheonE8Ag/640?wx_fmt=png&from=appmsg "")  
  
  
**0x06 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asyv1AiaL5MrLSodbBtGObiccGu5Vp3E0O5hg6ibaquk6IbfPlwXjJ7A5vBg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**欢迎加入星球一起交流，券后价仅39元！！！**  
  
**长期每天更新，更多的0day/1day漏洞POC/EXP**  
  
**2024攻防演练期间，持续更新最新漏洞威胁情报****。**  
  
