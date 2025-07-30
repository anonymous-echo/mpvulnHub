#  微软发现针对伊拉克库尔德民兵的间谍活动中存在0day漏洞利用   
会杀毒的单反狗  军哥网络安全读报   2025-05-13 01:00  
  
**导****读**  
  
  
  
微软研究人员周一表示，一个有土耳其背景的网络间谍组织似乎利用了一款通讯应用程序中的  
0  
day  
漏洞来监视伊拉克库尔德人的军事行动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaELH3YEg8S4VL14rFVP9yiavx5q73Q0jYTHibnot3Lm6ia9I2FOh7KTlhMNHuVfMz8fGCicw7KTZ76akg/640?wx_fmt=png&from=appmsg "")  
  
  
据微软威胁情报显示，这些名为 Marbled Dust 的黑客自 2024 年 4 月以来一直在入侵 Output Messenger（一款常用于工作场所和组织聊天的应用程序）的账户。  
  
  
该团队表示，“高度确信此次袭击目标与在伊拉克活动的库尔德民兵有关，这与此前观察到的Marbled Dust 行动的攻击重点一致。”  
  
  
库尔德工人党（PKK）周一宣布，在与土耳其发生数十年冲突后，该组织宣布解散并解除武装。大多数伊拉克库尔德人居住在与土耳其接壤的一个半自治地区。  
  
  
Marbled Dust 的活动与其他公司追踪的Sea Turtle或 UNC1326 行动重叠。微软表示，这些黑客以攻击欧洲和中东的实体而闻名，“特别是可能代表与土耳其政府利益相悖的政府机构和组织，以及电信和信息技术领域的目标”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaELH3YEg8S4VL14rFVP9yiav2WiaiaMQ3SdaVwuqHwVeVAvXfLyZCGH2Am85P5mt9SoMJXBQb54tV9bA/640?wx_fmt=png&from=appmsg "")  
  
Marbled Dust 攻击链  
  
  
此前未记录的 Output Messenger 漏洞CVE-2025-27920可能允许经过身份验证的用户将恶意文件上传到服务器的启动目录。  
  
  
微软表示，目前尚不清楚 Marbled Dust 是如何在每次攻击中获取经过身份验证的用户账户的，但该组织可能使用了 DNS 劫持或域名抢注等技术来拦截网络流量并获取个人凭证。  
  
  
Output Messenger 的开发商、总部位于印度的 Srimax 公司在微软通知该漏洞后发布了软件更新。研究人员表示，他们还发现了第二个漏洞CVE-2025-27921，该漏洞似乎尚未被利用。Srimax 的补丁也修复了该漏洞。  
  
  
微软表示，利用第一个漏洞可能允许攻击者“无差别地访问每个用户的通信，窃取敏感数据并冒充用户，这可能导致运营中断、未经授权访问内部系统以及大范围的凭证泄露”。  
  
  
技术报告：  
  
https://www.microsoft.com/en-us/security/blog/2025/05/12/marbled-dust-leverages-zero-day-in-output-messenger-for-regional-espionage/  
  
  
新闻链接：  
  
https://therecord.media/microsoft-zero-day-spy-campaign  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
