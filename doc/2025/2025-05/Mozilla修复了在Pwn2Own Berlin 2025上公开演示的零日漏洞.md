#  Mozilla修复了在Pwn2Own Berlin 2025上公开演示的零日漏洞   
鹏鹏同学  黑猫安全   2025-05-20 01:54  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceibPwRoxKuUntZ4pLJpcyUGzged4VkfaPR9OrklicsWFfiaCwtYPPpCczypsaTV6YFia70x33wXRMO5gg/640?wx_fmt=png&from=appmsg "")  
  
Mozilla发布安全更新修复Firefox浏览器两处高危漏洞 攻击者可窃取敏感数据或执行任意代码  
  
"在本周举行的Pwn2Own安全黑客大赛上，研究人员演示了两种针对Firefox内容进程的新型攻击手段。虽然这些攻击均未能突破我们的沙箱防护（获取系统控制权的必要前提），但出于谨慎考虑，我们已在第二起漏洞披露当天紧急发布新版Firefox。"Mozilla安全博客发文称，"更新版本包括Firefox 138.0.4、Firefox ESR 128.10.1、Firefox ESR 115.23.1及安卓版Firefox。尽管攻击实际影响有限，仍建议所有用户和管理员立即升级。"  
  
这两处漏洞在近期Pwn2Own Berlin 2025黑客大赛中均作为零日漏洞被公开演示。  
  
漏洞详情如下：  
  
**CVE-2025-4918**  
- 类型：处理Promise对象时的越界访问漏洞  
  
- 描述："攻击者能够对JavaScript Promise对象执行越界读写操作"  
  
- 发现者：Palo Alto Networks公司Edouard Bochin与Tao Yan（通过趋势科技零日计划提交）  
  
**CVE-2025-4919**  
- 类型：优化线性求和时的越界访问漏洞  
  
- 描述："攻击者通过混淆数组索引大小，可对JavaScript对象执行越界读写"  
  
- 发现者：Manfred Paul（通过趋势科技零日计划提交）  
  
受影响版本包括：  
- Firefox 138.0.4之前所有版本（含安卓版）  
  
- Firefox ESR 128.10.1之前所有扩展支持版  
  
- Firefox ESR 115.23.1之前所有版本  
  
