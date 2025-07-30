> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI3NzMzNzE5Ng==&mid=2247490246&idx=1&sn=b8357c865b44476bbafa52f344dc85f5

#  【漏洞预警】Grafana访问控制不当漏洞  
cexlife  飓风网络安全   2025-06-16 13:43  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu025kHTkq1XuUheV2fXB0jGuMRWCzTLMIPherpfo90S59XsGQK4KMvSGPs33bARWJ1e03Lelpib7ClQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
Grafana发布安全公告,披露了一个访问控制不当漏洞,该漏洞是由访问控制配置错误导致,使得查看权限的用户能以明文形式访问警报URL,进而可能查看完整的webhook URL、复制其中嵌入的钉钉令牌或API密钥,还可能通过钉钉集成发送欺骗性或恶意警报,官方已经发布新版本修复此漏洞建议受影  
响用户及时升级到安全版本。  
  
影响版本：  
  
12.0.1<=Grafana Lab Grafana<12.0.1+security-01  
  
11.6.2<=Grafana Lab Grafana<11.6.2+security-01  
  
11.5.5<=Grafana Lab Grafana<11.5.5+security-01  
  
11.4.5<=Grafana Lab Grafana<11.4.5+security-01  
  
11.3.7<=Grafana Lab Grafana<11.3.7+security-01  
  
11.2.10<=Grafana Lab Grafana<11.2.10+security-01  
  
10.4.19<=Grafana Lab Grafana<10.4.19+security-01  
  
修复建议:  
  
针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:  
  
Grafana >= 12.0.1+security-01–public  
  
Grafana >= 11.6.2+security-01–public  
  
Grafana >= 11.5.5+security-01–public  
  
Grafana >= 11.4.5+security-01–public  
  
Grafana >= 11.3.7+security-01–public  
  
Grafana >= 11.2.10+security-01–public  
  
Grafana >= 10.4.19+security-01–public  
  
下载链接:  
  
https://grafana.com/grafana/download  
  
安装前,请确保备份所有关键数据,并按照官方指南进行操作。安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
  
  
  
  
