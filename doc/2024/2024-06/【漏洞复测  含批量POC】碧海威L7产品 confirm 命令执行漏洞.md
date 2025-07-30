#  【漏洞复测 | 含批量POC】碧海威L7产品 confirm 命令执行漏洞   
小明同学  小明信安   2024-06-28 21:56  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
    碧海威 L7多款产品/notice/confirm.php 接口存在任意命令执行漏洞。攻击者可以通过漏洞执行任意命令从而获取服务器权限，可能导致内网进一步被攻击。  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
body="https://yun.bithighway.com"
```  
  
- Hunter  
  
  
```
body="https://yun.bithighway.com"
```  
  
- Quake  
  
  
```
body="https://yun.bithighway.com"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4AsyeFBpZCoEaibjcIEhdDZicLzr9icW1RfMfcHicAN11k0nPkibDpeVX2vlBGQ/640?wx_fmt=png&from=appmsg "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- sleep 3  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4AsyJE8s8ugpiaVd2rqKqMHbD1wPRFv2KeYiaq6UQib65jENFxkv5MDiapuyPQ/640?wx_fmt=png&from=appmsg "")  
- sleep 1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asy3bFmcUdX5osr00ePzpoq2iao0OEWWwTmn0t42PZDk6EtEPjkgysedCQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4Asyqia1wMQwgkowdian0Vb0EiapYmicVQykAzNjhtUraMcTiafSez9jsKzZSnQ/640?wx_fmt=png&from=appmsg "")  
  
**0x07 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKPg3iaOJwc8bpPHXxAI4AsyzucS9TxJqo5haA4ZuIT40DtXafibdicyYlsmOPRibTdRWCNc3FhV6WRlA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球，券后价仅39元！！！长期  
每天更新  
漏  
洞POC  
/EXP  
  
