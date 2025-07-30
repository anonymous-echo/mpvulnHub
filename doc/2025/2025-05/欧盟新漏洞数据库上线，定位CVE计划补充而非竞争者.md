#  欧盟新漏洞数据库上线，定位CVE计划补充而非竞争者   
 FreeBuf   2025-05-14 11:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![欧盟旗帜](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38xyNIp0kYIkmaicicgibRRp3obhIibicXTgsSH9Xjfv96MEEX4weOf3UHQOcBibdgNL5flONWCcXETQWXg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
本周起，全球科技行业新增了一个查询软件安全漏洞的数据库——欧盟漏洞数据库（European Union Vulnerability Database，简称EUVD）。该数据库由欧盟网络安全局（ENISA）运营，旨在落实欧盟《NIS2网络安全指令》，与以美国通用漏洞披露（CVE）计划为首的全球漏洞跟踪平台形成互补。  
  
### Part01  
## 定位为CVE补充机制  
  
  
ENISA明确表示，EUVD及其新标识系统旨在补充而非取代CVE计划。当漏洞由欧洲企业或计算机应急响应小组（CERT）首次报告，且涉及欧盟关键基础设施或企业时，将被分配EUVD追踪编号。不过，EUVD会与现有CVE编号建立交叉引用关系，仅在未分配CVE编号的罕见情况下使用独立标识。例如本周报告的SAP NetWeaver Visual Composer元数据上传器高危漏洞，既可标记为EUVD-2025-14349，也可对应CVE-2025-42999。  
  
  
欧盟技术主权、安全与民主事务执行副主席汉娜·维尔库宁强调："该数据库是强化欧洲安全与韧性的重要举措。通过整合欧盟市场相关漏洞信息，我们将提升网络安全标准，帮助公共和私营部门更高效自主地保护数字空间。"  
  
### Part02  
## CVE计划危机催生替代方案  
  
  
EUVD的推出时机颇具深意。今年4月，由于美国国土安全部（DHS）未能与运营方MITRE公司续约，已有25年历史的CVE计划一度面临停摆危机，最终由网络安全与基础设施安全局（CISA）紧急注资才得以延续。这次濒危事件暴露出CVE体系过度依赖美国政府资助的弊端，也凸显了仅凭通用漏洞评分系统（CVSS）难以指导企业进行漏洞优先级判定的局限性。  
  
### Part03  
## 行业评价褒贬不一  
  
  
安全厂商BeyondTrust首席安全顾问莫雷·哈伯指出："EUVD兼具优势与风险。虽然能弥补CVE覆盖空白并提升响应速度，但削弱MITRE CVE的全球权威性令人担忧。"他警告这可能引发评分冲突、风险优先级混乱及跨国企业修复漏洞时的协调难题。  
  
  
黑鸭（原Synopsys）高级安全工程师鲍里斯·西波特则认为："安全团队需额外监控一个数据库，这增加了企业全面掌握多源信息、理解差异并确保无遗漏的复杂度。"他建议依赖美国国家漏洞数据库（NVD）的企业评估其软件成分分析（SCA）工具对EUVD的兼容性，或建立人工监控流程以满足欧盟合规要求。  
  
  
目前EUVD网站仍处于测试阶段，ENISA未透露测试周期具体时长。  
  
  
**参考来源：**  
  
**New EU vulnerability database will complement CVE program, not compete with it, says ENISA**  
New EU vulnerability database will complement CVE program, not compete with it, says ENISA | CSO Online  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320343&idx=1&sn=4092a85b3c9cd6eea8dc0dcb48620652&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
