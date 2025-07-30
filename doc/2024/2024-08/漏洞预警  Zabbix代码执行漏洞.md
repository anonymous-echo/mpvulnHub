#  漏洞预警 | Zabbix代码执行漏洞   
浅安  浅安安全   2024-08-16 08:00  
  
**0x00 漏洞编号**  
- CVE-2024-22116  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Zabbix是一款企业级开源监控解决方案，提供了多种方式来收集、转换、分析和可视化数据，监控任何你想要的东西。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXtAPtWzrWO4iaJicvAtMDHxcXkb1ImnoM0T0jOhtZuabWEIZcfuqAXr8DSnrkrNnKNy6DEes8uhNZQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2024-22116**  
  
**漏洞类型：**  
代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
Zabbix在Ping脚本中存在代码注入漏洞，由于没有对输入的脚本参数进行默认转义或验证，具有受限权限的威胁者可构造特制输入，通过Ping脚本执行任意命令或代码。  
###   
  
**0x04 影响版本**  
- 6.4.0 <= Zabbix <= 6.4.15  
  
- 7.0.0alpha1 <= Zabbix <= 7.0.0rc2  
  
**0x05****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://www.zabbix.com/  
  
  
  
