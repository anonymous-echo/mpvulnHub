#  高通Adreno GPU零日漏洞遭利用，全球安卓用户面临攻击风险   
 黑白之道   2025-06-03 02:22  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/3xxicXNlTXLibics42svXEKicYoCvTxdfoZtJzEy5dtLLo2qKvCwSHwV3LtvXE3J9ULDRL57q4aKENqK7Z2mywlS4w/640?wx_fmt=jpeg&from=appmsg "")  
  
移动芯片制造商高通（Qualcomm）近日紧急发布安全补丁，修复其Adreno GPU驱动程序中三个正在被积极利用的关键零日漏洞（zero-day vulnerability），这些漏洞已被用于针对全球安卓用户的定向攻击。  
## 漏洞技术细节  
  
被标记为CVE-2025-21479和CVE-2025-21480的两个漏洞属于高危漏洞，CVSS评分为8.6分，属于图形组件中的授权错误缺陷。攻击者可通过特定命令序列在GPU微码中执行未授权命令，导致内存损坏，可能引发权限提升和系统沦陷。  
  
第三个漏洞CVE-2025-27038的CVSS评分为7.5分，是图形组件中的释放后使用（use-after-free）漏洞。该漏洞主要影响Chrome浏览器中的Adreno GPU驱动渲染过程，可被利用来绕过浏览器隔离机制，在目标系统上执行任意代码。  
## 影响范围与响应措施  
  
这些漏洞影响深远，全球数十亿使用高通Adreno GPU技术的安卓设备面临风险，涉及三星、谷歌、小米和一加等多个智能手机品牌。高通已于2025年5月向原始设备制造商（OEM）分发补丁，并强烈建议立即部署。  
  
谷歌威胁分析小组证实，这三个漏洞可能正在遭受"有限的定向利用"。所有漏洞均通过谷歌安卓安全团队向高通进行了负责任的披露，其中两个关键授权漏洞于2025年1月下旬报告，Chrome相关漏洞则在3月通报。  
## 安全建议与行业影响  
  
安全专家指出，此类GPU漏洞对商业间谍软件运营商和高级持续性威胁（APT）组织具有特殊价值。建议用户联系设备制造商获取补丁信息，并确保设备安装最新安全更新。  
  
这一事件凸显了移动GPU驱动程序面临的安全挑战，也展示了安全研究人员、芯片制造商和设备厂商在应对关键移动安全威胁方面改进的协作机制。此前，商业间谍软件供应商和国家支持的黑客组织曾武器化类似的高通漏洞。  
  
  
> **文章来源：freebuf**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
