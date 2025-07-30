#  漏洞预警 | 银达汇智智慧综合管理平台SQL注入和XML实体注入漏洞  
浅安  浅安安全   2025-06-13 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
扁鹊飞救智能急救与质控系统是飞救医疗科技有限公司研发的，集生命体征数据实时采集与远程传输、院前急救电子病历、现场监控、远程诊断、定位跟踪、时间同步、数据挖掘分析及实时质控等功能于一体，基于大急救与区域协同救治理念的急救管理系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWV9iaicwXlvFK8lP3GSPVich79Se9ia2XqHibxRrdspHzzflkuUUlXaAPhg5iav1iard8O1eNIrcpSK1sNw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
漏洞类型：  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
扁鹊飞救智能急救与质控系统的/AppService/BQMedical/WebServiceForFirstaidApp.asmx接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
漏洞类型：  
XML实体注入入  
  
**影响：**  
执行任意代码  
  
**简述：**  
扁鹊飞救智能急救与质控系统的/AppService/BQMedical/WebServiceForFirstaidApp.asmx接口存在XML实体注入漏洞，未经身份验证的攻击者可以通过该漏洞远程执行任意代码，从而控制目标服务器  
。  
  
**0x04 影响版本**  
- 扁鹊飞救智能急救与质控系统  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.ivtbq.com/  
  
  
  
