#  供应链高危漏洞披露 | Winmail邮件系统曝出存储型XSS漏洞   
原创 悬镜安全情报中心  悬镜安全   2024-03-08 11:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/KOWJ2ib68IGgALRzA4dxvk3TIxjvYl6iaZYTLlFC0WhuKC0ogplsM3dbjcqyicYMDyQWMsI3RiawC0PfeERBeMiaIzg/640?wx_fmt=gif "")  
  
**01**  
   
**漏洞概况**  
  
  
Winmail 是一款功能丰富的邮件服务器软件，支持 Windows 和 Linux 平台，可适配国产化信创平台，具备SMTP、POP3、IMAP、Webmail、邮件归档、Web管理、邮件网关、防毒杀毒、短信提醒、网络硬盘等功能。  
  
  
2023年10月，  
悬镜供应链安全情报中心在Winmail邮件系统中发现一个高危安全漏洞。  
恶意攻击者可利用该漏洞实现未授权窃取受害者邮箱所有邮件，甚至篡改邮箱账户密码接管邮箱权限。  
  
  
悬镜供应链安全情报中心在第一时间向国家信息安全漏洞库CNNVD通告该漏洞细节，也得到Winmail厂商积极确认及修复，近期Winmail已正式发布产品补丁修复该安全漏洞。  
  
  
经分析研判，该漏洞成因是Winmail邮件系统未对邮件内容进行严格安全过滤，导致攻击者可在邮件内容中嵌入恶意代码。  
攻击者可在未授权的情况下，向受害者邮箱发送嵌入漏洞利用代码的恶意邮件，受害者只要浏览该恶意邮件，即可触发漏洞并执行利用代码。  
  
  
**02**  
   
**漏洞影响范围**  
  
  
  
<table><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:8.classicTable1:0" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:0.td@@0" style="border-color: rgb(169, 40, 141);padding: 0px;" width="33.0000%"><section style="margin: 5px 0%;" powered-by="xiumi.us"><section style="padding-right: 5px;padding-left: 5px;"><p style="text-align: center;text-wrap: wrap;"><strong><span style="color: rgb(0, 0, 0);">产品名称</span></strong><br/></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:0.td@@1" style="border-color: rgb(169, 40, 141);padding: 0px;" width="67.0000%"><section style="margin: 5px 0%;" powered-by="xiumi.us"><section style="font-size: 15px;text-align: center;padding-right: 5px;padding-left: 5px;"><p style="text-align: center;">Winmail邮件系统</p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:8.classicTable1:1" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:1.td@@0" style="border-color: rgb(169, 40, 141);padding: 0px;" width="33.0000%"><section style="margin: 5px 0%;" powered-by="xiumi.us"><section style="text-align: center;padding-right: 5px;padding-left: 5px;color: rgb(0, 0, 0);"><p style="text-align: center;"><strong>受影响版本</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:1.td@@1" style="border-color: rgb(169, 40, 141);padding: 0px;" width="67.0000%"><section style="margin: 5px 0%;" powered-by="xiumi.us"><section style="font-size: 15px;text-align: center;padding-right: 5px;padding-left: 5px;"><p style="text-align: center;">Winmail v7.1 for Windows及以下版本</p><p style="text-align: center;">Winmail Pro v5.1 for Linux及以下版本</p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:8.classicTable1:2" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:2.td@@0" style="border-color: rgb(169, 40, 141);padding: 0px;" width="33.0000%"><section style="margin: 5px 0%;" powered-by="xiumi.us"><section style="padding-right: 5px;padding-left: 5px;color: rgb(0, 0, 0);"><p style="text-align: center;text-wrap: wrap;"><strong>影响范围</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:2.td@@1" style="border-color: rgb(169, 40, 141);padding: 0px;" width="67.0000%"><section style="margin: 5px 0%;" powered-by="xiumi.us"><section style="font-size: 15px;text-align: center;padding-right: 5px;padding-left: 5px;"><p style="text-align: center;">万级</p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:8.classicTable1:3" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:3.td@@0" style="border-color: rgb(169, 40, 141);padding: 0px;" width="33.0000%"><section style="margin: 5px 0%;" powered-by="xiumi.us"><section style="text-align: center;padding-right: 5px;padding-left: 5px;color: rgb(0, 0, 0);"><p style="text-align: center;"><strong>有无修复补丁</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:8.classicTable1:3.td@@1" style="border-color: rgb(169, 40, 141);padding: 0px;" width="67.0000%"><section style="margin: 5px 0%;" powered-by="xiumi.us"><section style="font-size: 15px;text-align: center;padding-right: 5px;padding-left: 5px;"><p style="text-align: center;">有</p></section></section></td></tr></tbody></table>  
  
  
Winmail邮件系统在国内公网资产量约1w+，覆盖众多关基行业客户（机关事业单位、税务、电力、电信、物流、医疗、证券、电视媒体、进出口等）。  
  
  
**03**  
   
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KOWJ2ib68IGhPzibLZjicWZNj6oo3XrzLljpSiap2bUdw4mGIcMvibhe0PktoqpwcnBibV4fVwFKEdwFqicEFtOOjksRg/640?wx_fmt=png&from=appmsg "")  
  
远程加载执行任意JS  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KOWJ2ib68IGhPzibLZjicWZNj6oo3XrzLljy6cI38RAMUtmmVcw1w2iaTzuu4QCbK7ibzc8KnmbF2OuwXX6sFnrOooA/640?wx_fmt=png&from=appmsg "")  
  
窃取受害者邮箱邮件  
  
  
**04**  
   
**修复方案**  
  
  
  
**官方修复方案**  
  
  
官方已发布漏洞补丁：  
  
https://www.winmail.cn/download_old.php  
  
  
**临时缓解措施**  
  
  
用户使用Winmail邮件系统时，不要随意浏览未知来源的邮件。  
  
  
**悬镜产品侧支持情况**  
  
  
悬镜安全全线产品已支持该漏洞的检测，详情请联系技术支持团队。  
  
  
**05**  
   
**时间线**  
  
  
**2023-10-16**  
  
悬镜供应链安全情报中心捕获Winmail邮件系统高危安全漏洞。  
  
  
**2023-10-19**  
  
悬镜供应链安全情报中心向CNNVD报送该漏洞。  
  
  
**2023-12-24**  
  
CNNVD确认该漏洞，漏洞编号为  
CNNVD-2023-16889206 。  
  
  
**2024-02-05**  
  
Winmail厂商积极确认并修复该漏洞。  
  
  
**2024-03-04**  
  
悬镜供应链安全情报中心披露漏洞。  
  
悬镜供应链安全情报中心是国内的数字供应链安全情报研究中心，依托悬镜安全团队强大的供应链SBOM管理与监测能力和AI安全大数据云端分析能力，对全球数字供应链安全漏洞、投毒事件、组件风险等进行实时动态监测与溯源分析，为用户智能精准预警“与我有关”的数字供应链安全情报。  
  
  
＋  
  
**推荐阅读**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/KOWJ2ib68IGh2JOqz3xwvLXK8FP3n9h4XibZhmwNKj4ucgibM2ibJHwFGZMOybebJsl9bFawDAr9MIQZs74WmwoMYQ/640?wx_fmt=gif&from=appmsg "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA3NzE2ODk1Mg==&mid=2647789976&idx=1&sn=8b71a2ada186842c1728357912eed43d&chksm=877099cfb00710d9fc1a449fb39e10a8adbd669b29090c4fdaec06722e7c59d93c4593f6c12a&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzA3NzE2ODk1Mg==&mid=2647789976&idx=2&sn=297ddd20ef880c57ad702f7318088979&chksm=877099cfb00710d9796dc14b7f696182eab4d663e5be35d51ef544864d36cba0e7341b200bf5&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzA3NzE2ODk1Mg==&mid=2647789199&idx=1&sn=d16f0b797942e38b8e3f439efc77b3b6&scene=21#wechat_redirect)  
  
[]()  
  
**关于“悬镜安全”**  
  
****  
  
悬镜安全，起源于北京大学网络安全技术研究团队”XMIRROR”，创始人子芽。作为数字供应链安全和DevSecOps敏捷安全开拓者，始终专注于以“代码疫苗”技术为内核，凭借原创专利级”全流程数字供应链安全赋能平台+敏捷安全工具链+供应链安全情报服务”的第三代DevSecOps数字供应链安全管理体系，创新赋能金融、车联网、通信、能源、政企、智能制造和泛互联网等行业用户，构筑起适应自身业务弹性发展、面向敏捷业务交付并引领未来架构演进的共生积极防御体系，持续守护中国数字供应链安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KOWJ2ib68IGgbc11SUokwoUiacpXOWwicJCC2iaPL17Bia4raDLC9kyMgGPBcaicxnw4QbhZ8nyrstrsIbPTicmo0BRwQ/640?wx_fmt=png&from=appmsg "")  
  
  
