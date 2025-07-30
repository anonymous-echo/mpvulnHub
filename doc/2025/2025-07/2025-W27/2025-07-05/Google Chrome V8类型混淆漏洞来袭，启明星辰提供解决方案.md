> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzA3NDQ0MzkzMA==&mid=2651733657&idx=1&sn=19e1e9619992414367d2cc34dba5c3dc

#  Google Chrome V8类型混淆漏洞来袭，启明星辰提供解决方案  
 启明星辰集团   2025-07-05 00:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhaD9LichERibnfcbZ18Jsx95PwtPiaDIVdd2b0I1EMyiaDLbYEQicPaMt2kNwBHbQ7t4libyxbtdaAbauHg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
近日，启明星辰监控到Google Chrome V8类型混淆漏洞情报(CVE-2025-6554)，该漏洞允许远程攻击者通过精心构造的HTML页面执行任意读/写操作。Google已知该漏洞已被恶意利用，漏洞级别为高危。建议用户尽快更新至修复版本，以避免潜在风险。  
  
  
Google Chrome是由谷歌开发的跨平台网页浏览器，以其速度、安全性和简洁的界面而闻名。它基于开源的Chromium项目，支持现代网页标准，具有强大的扩展性。Chrome的沙箱技术可以限制网页中的恶意代码，增强浏览器的安全性。它还提供了同步功能，允许用户在多个设备间同步书签、历史记录等数据。此外，Chrome定期更新，修复已知漏洞并增强功能，是全球使用最广泛的浏览器之一。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZ4fKxvYycpE3lmjKHcWdCnONBW1Hc5cVq0WeviajFzS4ibeGpIv7SiazQibRSyPu1tYcoLJX1pWCkxiaw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**漏洞复现截图**  
  
  
  
由启明星辰积极防御实验室（ADLab）  
进行漏洞复现。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZ4fKxvYycpE3lmjKHcWdCn1tpHLzEzr8ub0mdFFBXy8TXHwTd9kh6kzdugmvbFtH54Xu6ibEPw1QA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**影响版本**  
  
  
  
< 138.0.7204.96/.97 ( Windows)  
  
< 138.0.7204.92/.93 (Mac )  
  
< 138.0.7204.92 ( Linux )  
  
  
  
**解决方案**  
  
  
  
**一、官方修复方案**  
  
  
请受影响的用户尽快升级版本进行防护，下载链接：  
  
https://www.google.cn/chrome/  
  
  
**二、****启明星辰解决方案**  
  
  
**1、启明星辰漏扫产品方案**  
  
  
（  
1）启明星辰漏洞扫描系统V6.0产品已支持对该漏洞进行扫描。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZ4fKxvYycpE3lmjKHcWdCnmmaIB9C2Ad00JIYkIjDYiadXT3wudYntiblPD37vt1yDfdKdSoc95jcg/640?wx_fmt=png&from=appmsg "")  
  
  
（  
2）启明星辰漏洞扫描系统608X系列版本已支持对该漏洞进行扫描。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZ4fKxvYycpE3lmjKHcWdCngs29Cg4R1EhRCutib6c45EvetdsQBlicGEpM4zAISTH7dgetIbCj1bLw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**2、启明星辰资产与脆弱性管理平台产品方案**  
  
  
启明星辰资产与脆弱性管理平台实时采集并更新情报信息，对入库资产Google Chrome V8类型混淆漏洞 (CVE-2025-6554)进行管理。   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZ4fKxvYycpE3lmjKHcWdCnBu2eUHJrWv2rmiaUoMW4c0dPucJ8vfnjT4DEKEO6vKGiayxQqDCuM4vw/640?wx_fmt=png&from=appmsg "")  
  
  
**3、启明星辰安全管理和态势感知平台产品方案**  
  
  
用户可以通过泰合安全管理和态势感知平台，进行关联策略配置，结合实际环境中系统日志和安全设备的告警信息进行持续监控，从而发现“Google Chrome V8类型混淆漏洞 (CVE-2025-6554) ”的漏洞利用攻击行为。  
  
  
  
（  
1）  
在泰合的平台中，通过脆弱性发现功能针对“Google Chrome V8类型混淆漏洞 (CVE-2025-6554) ”漏洞扫描任务，排查管理网络中受此漏洞影响的重要资产；  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZ4fKxvYycpE3lmjKHcWdCnKC5pUC686KhibmrWn6z7zEmLNtqRDic5xGPpBdopLxnl6yIMUPaicHq0w/640?wx_fmt=png&from=appmsg "")  
  
  
（2）平台“关联分析”模块中，添加“L2_Google Chrome V8类型混淆漏洞 (CVE-2025-6554)”，通过启明星辰检测设备、目标主机系统等设备的告警日志，发现外部攻击行为；  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZ4fKxvYycpE3lmjKHcWdCnKpYeIWQuUUw5vic2xALUPzMkAoLEibnF5ibLCiatYBKibiaFibeVHkaUyzfEg/640?wx_fmt=png&from=appmsg "")  
  
  
通过分析规则自动将"L2_Google Chrome V8类型混淆漏洞 (CVE-2025-6554)"漏洞利用的可疑行为源地址添加到观察列表“高风险连接”中，作为内部情报数据使用；  
  
  
（3）添加“L3_Google Chrome V8类型混淆漏洞 (CVE-2025-6554)”，条件日志名称等于或包含“L2_Google Chrome V8类型混淆漏洞 (CVE-2025-6554)”，攻击结果等于或属于“攻击成功”，目的地址引用资产漏洞或源地址匹配威胁情报，从而提升关联规则的置信度。  
  
  
（4）ATT&CK攻击链条分析与SOAR处置建议  
  
  
  
根据对Chrome V8类型混淆漏洞 (CVE-2025-6554) 的攻击利用过程进行分析，攻击链涉及多个ATT&CK战术和技术阶段，覆盖的TTP包括：  
  
  
- TA0001-初始访问： T1190利用面向公众的应用程序  
  
- TA0002-执行: T1059命令和脚本解释器  
  
- TA0004-权限提升: T1548滥用提权控制机制  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhZ4fKxvYycpE3lmjKHcWdCnMkKicuicc2gXjFZhffstXTxKfmusg6Y9CthlicdrPW9fEdA3B0e4KlIGA/640?wx_fmt=png&from=appmsg "")  
  
  
通过泰合安全管理和态势感知平台内置SOAR自动化或半自动化编排联动响应处置能力，针对该漏洞利用的告警事件编排剧本，进行自动化处置。  
  
  
  
  
•  
  
END  
  
•  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhaSnmwf3icRIibF3hTR99DgpjibNTWWcAM9nku4T17gxCXJyIZLy7pEEAbfXEIy8ffpO6mIUcBictkmZw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MzA3NDQ0MzkzMA==&mid=2651688529&idx=1&sn=15ae6574a6aa36aa6b5b871b081a5da6&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhaOXFAap6OpOk7J3jrs8jWroVOQDibibC40UcRxx343kDbCEuib4KsvWfFZPW1WfEe0t4V5f5caJGGqw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
