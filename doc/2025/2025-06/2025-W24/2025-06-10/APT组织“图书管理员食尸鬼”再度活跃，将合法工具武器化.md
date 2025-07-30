#  APT组织“图书管理员食尸鬼”再度活跃，将合法工具武器化  
 FreeBuf   2025-06-10 10:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibSePDMs3WlVMNfqA1xuKdeFliaxaiaokdsDWDh5KH0xe3lnHhf1N3iahiaep7VTnQDZNqHXl8g7k5ibrA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
卡巴斯基实验室最新报告披露，一个被称为"图书管理员食尸鬼"（Librarian Ghouls，别称"稀有狼人"和"Rezet"）的高级持续性威胁（APT）组织近期再度活跃，正在俄罗斯和独联体国家开展大规模网络间谍与加密货币劫持活动。该组织自2024年底至2025年5月持续针对上述地区发动攻击。  
  
  
卡巴斯基分析师指出："该威胁的显著特点是，攻击者倾向于使用合法第三方软件，而非自行开发恶意二进制文件。"  
  
### Part01  
### 攻击链分析  
  
  
攻击始于高度定向的钓鱼邮件，攻击者伪装成合法机构发送带有密码保护的ZIP压缩包，诱骗受害者执行看似无害的付款单据文件。启动后，使用Smart Install Maker制作的自解压安装程序会部署多阶段感染链。  
  
  
感染核心是名为"4t Tray Minimizer"的合法工具，该程序通过将恶意进程最小化到系统托盘来隐藏其活动。图书管理员食尸鬼几乎完全使用改造后的合法工具构建攻击武器库，包括：  
- AnyDesk远程访问工具  
  
- Blat邮件客户端（用于基于SMTP协议的数据外泄）  
  
- Defender Control（用于禁用Windows Defender）  
  
- curl.exe文件下载工具  
  
- WinRAR（通过driver.exe实现静默压缩）  
  
- WebBrowserPassView、Mipko Personal Monitor和ngrok（用于监控和凭证窃取）  
  
报告显示："攻击者使用blat.exe通过SMTP协议将受害者数据与AnyDesk配置文件发送至控制服务器。"  
  
  
**Part02**  
### 持久化控制机制  
  
  
该组织通过PowerShell脚本和计划任务维持持久控制。名为wol.ps1的脚本创建每日凌晨1点启动Microsoft Edge的任务，使系统保持4小时活跃状态供攻击者操作，随后在5点触发关机。  
  
  
卡巴斯基认为，这种"唤醒-休眠"循环通过名为ShutdownAt5AM的计划任务实现，目的是"掩盖攻击痕迹，使用户无法察觉设备已被入侵。"  
  
  
**Part03**  
## 数据窃取与加密货币劫持  
  
  
建立控制后，攻击者收集包括加密货币钱包凭证、助记词、Windows注册表配置单元（HKLM\SAM和HKLM\SYSTEM）在内的敏感数据，压缩为RAR格式后通过邮件外传。  
  
  
最终载荷是基于XMRig的隐蔽挖矿程序，通过bmapps[.]org的文件安装。JSON配置文件指定矿池和攻击者ID，bmcontrol.exe组件则管理挖矿活动并规避检测。报告解释："XMRig矿工启动前，工作进程会收集CPU核心数、内存和GPU信息以优化挖矿效率。"  
  
  
**Part04**  
### 基础设施与影响范围  
  
  
攻击基础设施集中于两个C2服务器（downdown[.]ru和dragonfires[.]ru），均解析至185.125.51[.]5。值得注意的是，多个恶意服务器启用了目录列表功能，罕见地暴露了攻击者的操作细节。  
  
  
卡巴斯基还关联了users-mail[.]ru和deauthorization[.]online等钓鱼域名，这些站点托管伪造的Mail.ru登录页面用于窃取凭证。  
  
  
![关联钓鱼页面示例](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibSePDMs3WlVMNfqA1xuKdeiaGTSkwiaDR9dG3LkkiaK53hjTYGROibNFNDxXfnxF2quy2eQa31BK7w0w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part05**  
### 攻击特征与防御建议  
  
  
该活动已影响数百名受害者，主要针对俄罗斯、白俄罗斯和哈萨克斯坦的工业企业和工程机构。由于使用俄语诱饵和文件名，分析认为攻击者主要针对俄语用户。虽然战术显示潜在黑客活动倾向，但其系统性、持久性和经济动机表明这是资金充足的复杂行动。  
  
  
卡巴斯基总结称："所有恶意功能仍依赖于安装程序、命令和PowerShell脚本...攻击者持续优化其战术。"建议组织（特别是独联体地区）加强钓鱼防御、监控异常计划任务，并检查合法工具的滥用模式。  
  
  
**参考来源：**  
  
Librarian Ghouls APT: The Threat Actor Turning Legitimate Tools into a Cybercrime Toolkit  
  
https://securityonline.info/librarian-ghouls-apt-the-threat-actor-turning-legitimate-tools-into-a-cybercrime-toolkit/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651322750&idx=1&sn=a3c131230639a0c28b18a4475b631066&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
