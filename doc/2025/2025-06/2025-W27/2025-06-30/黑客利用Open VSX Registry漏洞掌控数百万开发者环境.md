> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTc0NDcyNQ==&mid=2247494128&idx=1&sn=14ac134a9a5dc55bd6576bea8e8efadf

#  黑客利用Open VSX Registry漏洞掌控数百万开发者环境  
鹏鹏同学  黑猫安全   2025-06-29 23:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceibYCGPMPtiaaftjkVuTguBnchREHRTezhB1Xw6CCHWPkiafXRu4jYPzjNDxknibibFJpMfaicNZCl96wxA/640?wx_fmt=png&from=appmsg "")  
  
网络安全公司Koi Security研究人员发现，开源扩展仓库Open VSX Registry（open-vsx.org）存在高危漏洞，攻击者可能借此掌控Visual Studio Code扩展市场，通过供应链攻击危及数百万开发者。该平台由Eclipse基金会维护，是微软官方VS Code市场的开源替代方案，用户超800万。  
  
（漏洞技术细节）  
  
• 核心问题：自动化发布流程的GitHub Actions工作流会执行不可信扩展代码的"npm install"命令  
  
• 关键凭证：暴露了具备全量扩展发布权限的@open-vsx服务账户令牌（OVSX_PAT）  
  
• 攻击路径：恶意构建脚本可窃取该令牌，进而篡改任意扩展包  
  
• 影响范围：类似SolarWinds事件的重大供应链风险，波及VS Code/VSCodium/Cursor等主流IDE  
  
（时间线全景）  
  
2025年5月4日15:18 漏洞首次披露  
  
5月5日23:34 提出首个修复方案  
  
5月19日13:29 第五次补丁提交  
  
6月25日19:20 最终修复部署完成  
  
（完整披露周期历时53天，共经历六轮修复迭代）  
  
MITRE已在2025年4月将"IDE扩展攻击"纳入ATT&CK框架，凸显该威胁的战略级风险。研究人员警告："每个市场组件都是潜在后门，必须像对待PyPI/npm等仓库那样严格审计。"  
  
  
