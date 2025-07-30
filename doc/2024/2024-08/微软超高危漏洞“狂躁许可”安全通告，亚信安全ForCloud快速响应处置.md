#  微软超高危漏洞“狂躁许可”安全通告，亚信安全ForCloud快速响应处置   
你信任的  亚信安全   2024-08-09 18:26  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbGRhmOWDznDXTFQyyBiaDt59LzIBluXiasCnoccGrM2iaHDc9PyfoJpTQnK7MWNlMPKyNC39vZV0fe0g/640?wx_fmt=jpeg "")  
  
  
今日，亚信安全CERT监控到安全社区研究人员发布安全通告，披露了微软“狂躁许可”漏洞(CVE-2024-38077)。该漏洞由于windows系统的远程桌面授权服务存在边界错误而导致。攻击者可以发送其精心制作的数据传递给应用程序，这可能引发基于堆的缓冲区溢出，从而在目标系统上执行未授权的代码。如果这种漏洞被成功利用，攻击者可能会完全控制受影响的系统。  
  
  
目前厂商官方已发布修复版本。亚信安全CERT建议客户将受影响的Windows Server安装最新补丁。  
  
  
**漏洞编号、类型、等级**  
  
  
  
- CVE-2024-38077  
  
- 远程代码执行漏洞  
  
- 高危  
  
  
  
  
**漏洞状态**  
  
  
  
<table><tbody style="box-sizing: border-box;"><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:9.classicTable1:0" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:0.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">细节</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:0.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">PoC</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:0.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">EXP</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:0.td@@3" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">在野利用</strong></p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:0.td@@4" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(145, 145, 145);box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(255, 255, 255);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;">复现情况</strong></p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:9.classicTable1:1" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:1.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已公开</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:1.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未公开</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:1.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未公开</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:1.td@@3" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">未发现</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:9.classicTable1:1.td@@4" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="padding: 0px 5px;font-size: 14px;color: rgb(62, 62, 62);box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">已复现</p></section></section></td></tr></tbody></table>  
  
  
**受影响版本**  
  
  
  
- Windows Server 2019  
  
- Windows Server 2012 R2（服务器核心安装）  
  
- Windows Server 2012 R2版本  
  
- Windows Server 2012（服务器核心安装）  
  
- Windows Server 2012  
  
- Windows Server 2008 R2 Service Pack 1（用于基于 x64 的系统）（服务器核心安装）  
  
- Windows Server 2008 R2（用于基于x64的系统）Service Pack 1  
  
- Windows Server 2008 Service Pack 2（服务器核心安装）  
  
- Windows Server 2008（用于基于 x64 的系统）Service Pack 2  
  
- Windows Server 2008 for 32-bit Systems Service Pack 2（服务器核心安装）  
  
- Windows Server 2008 Service Pack 2（32位系统）  
  
- Windows Server 2016（服务器核心安装）  
  
- Windows Server 2016  
  
- Windows Server 2022， 23H2 Edition（服务器核心安装）  
  
- Windows Server 2022（服务器核心安装）  
  
- Windows Server 2022  
  
- Windows Server 2019（服务器核心安装）  
  
  
  
  
**修复建议**  
  
  
  
**Windows自动更新**  
  
****  
Windows系统默认启用Microsoft Update，当检测到可用更新时，将会自动下载更新并在下一次启动时安装。  
  
还可通过以下步骤快速安装更新：  
  
  
- 点击“开始菜单”或按Windows快捷键，点击进入“设置”。  
  
- 选择“更新和安全”，进入“Windows更新”（Windows Server 2012以及Windows Server 2012 R2可通过控制面板进入“Windows更新”，步骤为“控制面板”->“系统和安全”->“Windows更新”）。  
  
- 选择“检查更新”，等待系统将自动检查并下载可用更新。  
  
- 重启计算机，等待更新完成。  
  
  
  
**安装补丁**  
  
****  
如果自动更新有困难，请参考Microsoft 官方安全更新程序指南，根据您的 Windows 版本下载并安装相应的补丁。安装补丁后，请重启计算机以确保补丁生效。   
  
  
官方链接：https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077  
  
  
**禁用远程桌面许可服务**  
  
****  
在不影响业务的前提下，请禁用Windows远程桌面许可管理服务（RDL，Remote Desktop Licensing Service）。  
  
  
**亚信安全产品响应建议：**  
  
**使用ForCloud快速响应处置**  
  
  
  
**通过“云主机安全”进行系统漏洞扫描**  
  
****  
信舱ForCloud的云主机安全“系统漏洞”扫描功能支持对Windows漏洞进行扫描，帮助客户收敛攻击面。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbGRhmOWDznDXTFQyyBiaDt59TjKiaAjicibzDjcXDdu9bxVevYFeSUpyzaKnibicYhswQPgCwBzKBlxHPug/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbGRhmOWDznDXTFQyyBiaDt59Bj996lRer3CtcCjAMd5HXmhV63PsGic8SuiawAy4cPSiahWIBqISgWlsg/640?wx_fmt=png "")  
  
  
**通过“云主机补丁管理”进行漏洞扫描与修复**  
  
****  
信舱ForCloud的云主机补丁管理支持对Windows漏洞进行扫描和一键修复。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbGRhmOWDznDXTFQyyBiaDt59plM8ZvibFxjSJCUlH4Dhr6nlghXu5HFicGvricI4mU5fGUI93ovm7ibMiag/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbGRhmOWDznDXTFQyyBiaDt59q2rC8VhvwCW6EdT81iat5Dm13q7FQ1xODXH8ObQXGMSmsT0icUCVQHGQ/640?wx_fmt=png "")  
  
  
**参考链接**  
  
  
  
- https://github.com/CloudCrowSec001/CVE-2024-38077-POC/blob/main/CVE-2024-38077-poc.py  
  
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077  
  
- https://nvd.nist.gov/vuln/detail/CVE-2024-38077  
  
  
  
  
本文发布的补丁下载链接均源自各原厂官方网站。尽管我们努力确保官方资源的安全性，但在互联网环境中，文件下载仍存在潜在风险。为保障您的设备安全与数据隐私，敬请您在点击下载前谨慎核实其安全性和可信度。  
  
  
  
  
了解亚信安全，请点击  
**“阅读原文”**  
  
