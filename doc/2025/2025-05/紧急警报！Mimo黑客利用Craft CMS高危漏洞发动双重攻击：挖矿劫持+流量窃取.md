#  紧急警报！Mimo黑客利用Craft CMS高危漏洞发动双重攻击：挖矿劫持+流量窃取   
原创 道玄安全  道玄网安驿站   2025-05-28 23:00  
  
**“**  
 挖矿。**”**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPA9bic9zzTydWv4XTTHH2NAiamMp8Kxsh4s2lukPuyuwnia3NiaHkiaU8a3JGFhLvNnYvtLvHTFAd91Rw/640?wx_fmt=png&from=appmsg "")  
  
      
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPMwVHx9iaPDKDhBJiajRW2DIdq0Wxe7JcpgKDia3zMfgicaaD6Auwn6Q3GGm2vI0eNh1Qic6OUhHMjE7g/640?wx_fmt=png&from=appmsg "")  
  
  
  
PS：有内网web自动化需求可以私信  
  
  
  
  
01  
  
—  
  
  
  
导语  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yNql9beffpvc4kQy3iaaicicfEvoxSyjXib39yCWxBTSmb79247Qy04ZsGcnnemVLm3hYUMwYgTgeXD0A/640?wx_fmt=png&from=appmsg "")  
  
**一场针对全球网站管理员的隐秘攻击正在上演**  
。知名黑客组织"Mimo"近期利用Craft CMS中的高危漏洞（CVE-2025-32432），向数千台服务器同时植入加密货币挖矿程序和流量代理恶意软件（Proxyware），形成"双重吸血"攻击链。  
### ⚡ 漏洞核心：Craft CMS模板注入漏洞  
  
**CVE-2025-32432**  
 存在于Craft CMS 5.8.0之前的所有版本中。该漏洞源于后台模板解析模块未对用户输入进行严格过滤，攻击者通过构造恶意模板代码，可实现  
**远程命令执行（RCE）**  
。  
```
```  
  
**攻击者仅需获得后台基础权限（如弱口令爆破），即可完全接管服务器。**  
### 🕵️‍♂️ Mimo的攻击组合拳  
  
研究人员发现，Mimo组织在入侵后快速部署两类恶意负载：  
1. **加密货币挖矿程序（Cryptominer）**  
  
1. 植入门罗币（XMRig）挖矿软件  
  
1. 伪装为  
systemd-journald  
等系统进程  
  
1. 消耗90%以上CPU资源，导致服务器响应迟缓、电费激增  
  
1. **流量代理恶意软件（Proxyware）**  
  
1. 安装  
Peer2Profit  
或  
Honeygain  
等商用代理软件  
  
1. 将受害服务器变为  
**代理节点**  
，出售其带宽  
  
1. 造成网络拥堵，并可能引发IP被封禁风险  
  
> 📊 双重攻击数据危害（单台服务器/月）  
> <table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n39" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 288.266px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">攻击类型</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n40" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 288.266px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">直接经济损失</span></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;text-align: left;"><span cid="n41" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 447.469px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">隐性风险</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n43" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 288.266px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">加密货币挖矿</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n44" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 288.266px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">$150+ 电费</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n45" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 447.469px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">硬件损耗、服务瘫痪</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n47" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 288.266px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">流量代理</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n48" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 288.266px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">带宽成本未知</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;text-align: left;"><span cid="n49" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 447.469px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">IP信誉下降、法律风险</span></span></span></td></tr></tbody></table>  
  
### 🛡️ 紧急防护指南  
  
如果你的网站使用Craft CMS，请立即执行以下操作：  
1. **升级！升级！升级！**  
  
1. 立即升级到   
**Craft CMS 5.8.0 或更高版本**  
  
composer update craftcms/cms --with-dependencies  
  
1. **漏洞缓解（临时）**  
  
1. 在  
config/general.php  
中设置：  
  
'allowAdminChanges' => false  
  
（禁用后台配置更改，阻断攻击入口）  
  
1. **服务器入侵排查**  
  
1. 检查异常进程：  
top  
，  
htop  
，  
nvidia-smi  
（GPU服务器）  
  
1. 排查可疑网络连接：  
netstat -antp | grep ESTA  
  
1. 使用ClamAV扫描：  
clamscan -r /var/www/  
  
1. **加固建议**  
  
1. **强制后台双因素认证（2FA）**  
  
1. 限制  
/admin  
目录访问IP（通过.htaccess或防火墙）  
  
1. 部署WAF规则拦截模板注入攻击特征  
  
免责声明：  
### 本人所有文章均为技术分享，均用于防御为目的的记录，所有操作均在实验环境下进行，请勿用于其他用途，否则后果自负。  
  
第二十七条：任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序和工具；明知他人从事危害网络安全的活动，不得为其提供技术支持、广告推广、支付结算等帮助  
  
第十二条：  国家保护公民、法人和其他组织依法使用网络的权利，促进网络接入普及，提升网络服务水平，为社会提供安全、便利的网络服务，保障网络信息依法有序自由流动。  
  
任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得危害网络安全，不得利用网络从事危害国家安全、荣誉和利益，煽动颠覆国家政权、推翻社会主义制度，煽动分裂国家、破坏国家统一，宣扬恐怖主义、极端主义，宣扬民族仇恨、民族歧视，传播暴力、淫秽色情信息，编造、传播虚假信息扰乱经济秩序和社会秩序，以及侵害他人名誉、隐私、知识产权和其他合法权益等活动。  
  
第十三条：  国家支持研究开发有利于未成年人健康成长的网络产品和服务，依法惩治利用网络从事危害未成年人身心健康的活动，为未成年人提供安全、健康的网络环境。  
  
  
  
  
  
  
