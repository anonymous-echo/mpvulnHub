> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NTg5MDQ0OA==&mid=2247488275&idx=1&sn=7c7debf288cf110429d8a634fb1402b5

#  一键入侵你的爱车！PerfektBlue漏洞威胁数百万辆汽车安全  
原创 道玄安全  道玄网安驿站   2025-07-11 23:00  
  
**“**  
   
蓝牙连接提示突然弹出，一次看似平常的“配对确认”点击，可能正将你的汽车控制权交给数米外的黑客  
。**”**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPA9bic9zzTydWv4XTTHH2NAiamMp8Kxsh4s2lukPuyuwnia3NiaHkiaU8a3JGFhLvNnYvtLvHTFAd91Rw/640?wx_fmt=png&from=appmsg "")  
  
      
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPMwVHx9iaPDKDhBJiajRW2DIdq0Wxe7JcpgKDia3zMfgicaaD6Auwn6Q3GGm2vI0eNh1Qic6OUhHMjE7g/640?wx_fmt=png&from=appmsg "")  
  
  
  
PS：有内网web自动化需求可以私信  
  
  
  
  
01  
  
—  
  
  
  
导语  
  
  
    停车场里，一名研究人员在笔记本电脑上快速输入指令。七米外的一辆崭新大众ID.4汽车信息屏幕突然闪烁，随后完全失控——GPS定位数据在屏幕上滚动显示，车内麦克风被悄然激活，通话记录和联系人名单被完整下载。  
  
    这是PCA网络安全公司展示的  
**PerfektBlue攻击**  
现场演示。通过蓝牙协议栈中的四个漏洞组合，研究人员成功入侵了这辆汽车的信息娱乐系统。  
  
    “攻击者最多只需诱使用户点击一次，即可通过无线方式实施入侵。”PCA研究人员在安全公告中写道。  
**梅赛德斯-奔驰、大众和斯柯达等品牌的数百万辆汽车**  
因此面临风险，车主的位置隐私、通话记录甚至车辆控制安全受到前所未有的威胁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPxEQmtN7os9gtcyQHocTZRdAn1EuFy6n8UJbhvib5Pon7Hej5movBJK4gLFc88eKLmVzr5t4c7y6Q/640?wx_fmt=png&from=appmsg "")  
## 01 蓝牙框架的致命缺陷  
  
    OpenSynergy公司的BlueSDK蓝牙框架已成为汽车行业的隐形标准。该框架支持经典蓝牙和低功耗模式，具有硬件无关特性，被集成到众多汽车品牌的  
**信息娱乐系统中**  
。  
  
    作为一款  
**高度可定制的框架**  
，BlueSDK允许各汽车制造商根据自身需求调整实现方式。这种灵活性带来了安全隐患，不同厂商在安全配置和配对机制上的差异形成了复杂的攻击面。  
  
    漏洞的核心在于  
**BlueSDK协议栈中的四重安全缺陷**  
，它们可被组合利用形成完整的攻击链：  
  
<table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n17" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 259.672px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVE编号</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n18" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 461.125px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">漏洞描述</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n19" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 161.109px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVSS评分</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n20" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 149.094px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">严重等级</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n22" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 259.672px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVE-2024-45434</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n23" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 461.125px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">AVRCP服务中的释放后使用漏洞</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n24" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 161.109px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">8.0</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n25" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 149.094px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">严重</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n27" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 259.672px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVE-2024-45431</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n28" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 461.125px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">L2CAP通道远程CID验证不当</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n29" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 161.109px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">3.5</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n30" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 149.094px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">低危</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n32" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 259.672px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVE-2024-45433</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n33" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 461.125px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">RFCOMM中函数终止不正确</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n34" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 161.109px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">5.7</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n35" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 149.094px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">中危</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n37" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 259.672px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">CVE-2024-45432</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n38" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 461.125px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">RFCOMM中函数调用参数错误</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n39" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 161.109px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">5.7</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n40" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 149.094px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">中危</span></span></span></td></tr></tbody></table>  
    攻击者首先利用低危的L2CAP通道验证缺陷建立初始连接，再通过RFCOMM协议层的两个中等风险漏洞扩大访问权限，最终触发  
**AVRCP服务中的释放后使用漏洞**  
，获得远程代码执行能力。  
## 02 攻击的现实威胁  
  
    要发起PerfektBlue攻击，黑客需位于目标车辆  
**5-7米范围内**  
。攻击者伪装成普通蓝牙设备与车载娱乐系统建立连接，这一过程最多只需要用户一次点击确认。  
  
    成功入侵后，攻击者可以获取车辆的  
**GPS坐标实时追踪位置**  
，激活车内麦克风进行监听，并完整下载已配对手机的通讯录和通话记录。  
  
    理论上，黑客还能以信息娱乐系统为跳点，向转向、雨刷器、门锁等关键控制系统横向移动。“获得此级别访问权限后，攻击者能操控系统、提升权限并向目标产品的其他组件横向移动。”PCA安全公告强调。  
  
    研究人员已成功在  
**三款主流车载系统**  
上实现漏洞利用：梅赛德斯-奔驰NTG6主机、大众MEB ICAS3信息娱乐系统（ID.4车型）以及斯柯达MIB3主机（速派车型）。  
## 03 修补延迟的危机  
  
    OpenSynergy于2024年5月17日收到漏洞报告，7月确认问题存在，  
**同年9月完成补丁开发**  
。由于汽车行业复杂的供应链，安全修复在终端落地严重滞后。  
  
    “尽管OpenSynergy于2024年9月发布了修复程序，但部分制造商直到2025年6月才完成修补。”安全报告指出。今年3月，PCA启动负责任披露程序时，发现至少  
**一家未具名的主要汽车供应商**  
甚至尚未收到漏洞通知。  
  
    大众汽车表示已着手调查影响和解决方案，而梅赛德斯-奔驰尚未立即回应询问。安全研究人员称，他们向受影响汽车制造商提供了充足时间修复问题，但  
**未收到厂商任何回复**  
。  
## 04 车主的防护策略  
  
    面对这一威胁，车主可采取多项措施降低风险。  
**及时更新车载系统固件**  
是最直接的防护手段。用户应定期检查车辆制造商发布的更新信息，并立即安装可用补丁。  
  
    在不使用蓝牙功能时，  
**彻底关闭车载蓝牙系统**  
可完全阻断此类攻击路径。驾驶者还应对突然出现的蓝牙配对请求保持警惕，避免批准未知设备连接请求。  
  
    汽车制造商则需重新审视安全架构设计。  
**强化网络分段隔离**  
，确保信息娱乐系统与关键控制系统之间有严格的安全边界。对蓝牙协议栈实现进行  
**深度安全验证**  
，并建立高效的漏洞响应机制，缩短补丁部署周期。  
  
    梅赛德斯-奔驰、大众和斯柯达车主们正面临艰难选择：要么放弃蓝牙带来的便利性，要么承受被黑客定位追踪甚至控制车辆的风险。一位研究人员通过笔记本电脑成功入侵斯柯达速派的信息系统后，获得了“phone”权限，随后轻松提取了车辆的GPS历史轨迹和通话记录。  
  
**汽车供应链中的安全漏洞比软件漏洞更加危险**  
。尽管OpenSynergy早在2024年9月就发布了修复程序，但直到研究人员公开漏洞前，仍有汽车制造商尚未收到任何官方漏洞通知。当数百万辆汽车在公路上行驶时，它们的蓝牙系统可能正敞开着数字大门，而车主对此  
**一无所知**  
。  
  
免责声明：  
### 本人所有文章均为技术分享，均用于防御为目的的记录，所有操作均在实验环境下进行，请勿用于其他用途，否则后果自负。  
  
第二十七条：任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序和工具；明知他人从事危害网络安全的活动，不得为其提供技术支持、广告推广、支付结算等帮助  
  
第十二条：  国家保护公民、法人和其他组织依法使用网络的权利，促进网络接入普及，提升网络服务水平，为社会提供安全、便利的网络服务，保障网络信息依法有序自由流动。  
  
任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得危害网络安全，不得利用网络从事危害国家安全、荣誉和利益，煽动颠覆国家政权、推翻社会主义制度，煽动分裂国家、破坏国家统一，宣扬恐怖主义、极端主义，宣扬民族仇恨、民族歧视，传播暴力、淫秽色情信息，编造、传播虚假信息扰乱经济秩序和社会秩序，以及侵害他人名誉、隐私、知识产权和其他合法权益等活动。  
  
第十三条：  国家支持研究开发有利于未成年人健康成长的网络产品和服务，依法惩治利用网络从事危害未成年人身心健康的活动，为未成年人提供安全、健康的网络环境。  
  
  
  
  
  
