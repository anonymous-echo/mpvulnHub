#  神秘组织利用WinRAR最新漏洞，俄方政府再遭网络攻击   
原创 猎影实验室  网络安全研究宅基地   2023-10-23 11:31  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvneJCRkRLHia6qGUXEyDicuryCQgjYhrLqrMPDmOHvIgxAXHrckMnibbju5xRxcGz3hzek4TkSH5W9RnA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
<table><tbody><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:2.classicTable1:0" powered-by="xiumi.us"><td colspan="2" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:0.td@@0" style="border-color: rgb(255, 255, 255);background-color: rgb(179, 9, 16);padding: 6px;" width="99.8100%"><section style="color: rgb(255, 255, 255);text-align: center;font-size: 15px;" powered-by="xiumi.us"><p>骷髅狼（APT-LY-1008）组织利用WinRAR漏洞攻击俄罗斯、白俄罗斯政府及国防部门</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:2.classicTable1:1" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:1.td@@0" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="33.0000%"><section style="text-align: center;font-size: 15px;" powered-by="xiumi.us"><p>内部编号</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:1.td@@1" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="66.8100%"><section style="text-align: center;font-size: 15px;" powered-by="xiumi.us"><p>DBAPP-LY-23101601</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:2.classicTable1:2" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:2.td@@0" style="border-color: rgb(255, 255, 255);background-color: rgb(245, 245, 245);padding: 6px;" width="33.0000%"><section style="font-size: 15px;color: rgb(62, 62, 62);text-align: center;" powered-by="xiumi.us"><p>关键词</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:2.td@@1" style="border-color: rgb(255, 255, 255);background-color: rgb(245, 245, 245);padding: 6px;" width="66.8100%"><section style="font-size: 15px;color: rgb(62, 62, 62);text-align: center;" powered-by="xiumi.us"><p>APT、俄罗斯、白俄罗斯</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:2.classicTable1:3" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:3.td@@0" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="33.0000%"><section style="text-align: center;font-size: 15px;" powered-by="xiumi.us"><p>发布日期</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:3.td@@1" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="66.8100%"><section style="text-align: center;font-size: 15px;" powered-by="xiumi.us"><p>2023年10月16日</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:2.classicTable1:4" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:4.td@@0" style="border-color: rgb(255, 255, 255);background-color: rgb(245, 245, 245);padding: 6px;" width="33.0000%"><section style="font-size: 15px;color: rgb(62, 62, 62);text-align: center;" powered-by="xiumi.us"><p>更新日期</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:4.td@@1" style="border-color: rgb(255, 255, 255);background-color: rgb(245, 245, 245);padding: 6px;" width="66.8100%"><section style="font-size: 15px;color: rgb(62, 62, 62);text-align: center;" powered-by="xiumi.us"><p>2023年10月19日</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:2.classicTable1:5" powered-by="xiumi.us"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:5.td@@0" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="33.0000%"><section style="text-align: center;font-size: 15px;" powered-by="xiumi.us"><p>分析团队</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:2.classicTable1:5.td@@1" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="66.8100%"><section style="text-align: center;font-size: 15px;" powered-by="xiumi.us"><p>安恒研究院猎影实验室</p></section></td></tr></tbody></table>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkGRWPHPQluYogaL0cmyhy1rpT9OvgJeTvqMfzZCwhaY8picNeBic89dXw/640?wx_fmt=png "")  
  
  
**01**  
  
**事件背景**  
  
  
最近，安恒猎影实验室在日常的网络狩猎中成功捕获了多个针对俄罗斯、白俄罗斯政府及国防部门的攻击样本。通过仔细的样本分析和追溯，我们发现这些攻击事件共享相同的攻击组件和模式，因此我们确定该类攻击背后的幕后黑手为同一组织。鉴于该组织攻击手法的独特性，我们将该组织命名为  
**“骷髅狼”(Skeleton Wolf)**，猎影实验室内部追踪代号为**“APT-LY-1008”**。  
  
  
根据此次捕获的攻击样本我们发现“骷髅狼”组织具有以下特征：  
  
1. 目前已发现的该组织攻击目标包括俄罗斯、白俄罗斯的政府、国防部门。  
  
2. 使用WinRAR最新漏洞(CVE-2023-38831)执行恶意指令，具有很强的隐蔽性。  
  
3. 最终加载基于Mythic平台的Athena后门，该后门支持执行各类恶意指令。  
  
  
**02**  
  
**样本信息**  
  
<table><tbody><tr><th><span style="font-size: 14px;">文件名</span></th><th><span style="font-size: 14px;">MD5</span><br/></th></tr><tr><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">Pismo_ishodjashhee_61301-1_8724_ot_27_09_2023_Rassylka_Ministerstva_promyshlennosti.rar</span></td><td valign="center" colspan="1" rowspan="1"><span style="letter-spacing: 0.578px;text-wrap: wrap;color: rgb(0, 0, 0);font-family: 微软雅黑;text-align: left;background-color: rgb(255, 255, 255);font-size: 14px;">129ccb333ff92269a8f3f0e95a0338ba</span></td></tr><tr><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">297vn.rar</span></td><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">b05960a5e1c1a239b785f0a42178e1df</span></td></tr><tr><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">Pismo_ishodjashhee_61301-1_8724_ot_27_09_2023_Rassylka_Ministerstva_promyshlennosti.rar<span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);display: none;line-height: 0px;">‍‍</span></span></td><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">a5051580a58fe56eeed03e714a8afba2</span></td></tr><tr><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">Resultati_soveschaniya30_08_2023.rar</span></td><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">cb4b08946b8eec16cbcf0f78f65a50f7</span></td></tr><tr><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">resultati_sovehchaniya_11_09_2023.rar</span></td><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">a85b9c7212eee05bc3cde3eeba8c7951</span></td></tr><tr><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">Pismo_izveshcanie_2023_10_16.rar</span></td><td valign="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 0.578px;text-align: left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">cd1f48df9712b984c6eee3056866209a</span></td></tr></tbody></table>  
  
本次共捕获相关样本6个，样本名为  
**“xxx通知”、“会议结果”**等诱使用户打开，根据其中包含的诱饵文件具体内容，我们发现本次攻击活动主要  
**针对俄罗斯及白俄罗斯的政府、国防部门。**  
  
  
**如仿冒“俄罗斯工业和贸易部”下发通知，具体内容与俄罗斯国防部相关**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkGicT4zW1YO1q6OBVmwBCxI0KvIAetb2CAxfkmvPyPQRWed23CXq0LxQ/640?wx_fmt=png "")  
  
  
以“欧亚经济委员会”的名义发送会议通知，欧亚经济委员会成立于2015年，成员国包括俄罗斯、哈萨克斯坦、白俄罗斯、吉尔吉斯斯坦和亚美尼亚，总部位于莫斯科。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkKebxhXY3VGesmunf7oNHqq2fw5rOSiafbansvS5LqL7thpFdPIovP4g/640?wx_fmt=png "")  
  
  
以“白俄罗斯国家军工委员会”的名义发送调查军事财产的通知  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTk4JTP58SjQhYzm37qMGNwGOYZrmYianM3HARDjwJv7oPQaAcqUFW8J5g/640?wx_fmt=png "")  
  
  
**03**  
  
**详细分析**  
  
  
该组织使用的攻击样本具有高度的一致性，下图展示了其主要攻击流程：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkKQuo4L1uN0jiaytSzLiaic7K7AwibNGy8bLRY1AriaUt0OPoia0FuqQ1NYtg/640?wx_fmt=png "")  
  
  
根据压缩包中的诱饵内容我们推测该类攻击起始于钓鱼邮件，恶意的压缩包通过邮件附件的形式投递给攻击目标。  
压缩包利用WinRAR漏洞( CVE-2023-38831)执行位于压缩包中的cmd文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkYb03N5RhTa3bIY3f1B3CPmahPJ82wEGndXFfeP9EAeeibvK6MN1afyw/640?wx_fmt=png "")  
  
  
cmd文件中包含的指令会解码并执行另一段经过base64编码的PowerShell指令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkSI9rSUFNCE8A3s2rPwhMCts4TSORuX0XujZmrJ1RKnLeEFia0kcN0Cw/640?wx_fmt=png "")  
  
  
PowerShell指令首先会从指定地址下载与压缩包中相同的pdf诱饵文件，然后打开该诱饵以迷惑用户。  
然后下载exe文件到指定目录，并通过创建名称为“Microsoft Edge”的计划任务的方式执行exe文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkR2kQRECFdpLJY91E07gzsWr3MxdYsveHtEnKGQ8Xfq4MuiceLjFrDMA/640?wx_fmt=png "")  
  
  
下载的exe文件为使用Mythic平台生成的Athena后门，Mythic 是一个开源的渗透测试框架，可支持多平台多类型后门的生成以及各类C2协议的配置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkGBict4pwQLomhnzlY7jia2QH5vdXjAqFibPdsdMdIfkq7pufoxBQzqpWg/640?wx_fmt=png "")  
  
  
以下是Mythic平台支持的后门列表，本次捕获的攻击活动中攻击者使用了其中的Athena后门。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTksFMHWWziaKf71HXAiceG1icclkWpyiawJlasia5QTgiaTSG7hsicic8xCeib0Dw/640?wx_fmt=png "")  
  
  
Athena是一款基于.NET开发的后门，支持Windows，Linux，MacOS等操作系统，并且还支持HTTP，Websocket，Slack，Discard，SMB等协议进行C2通信。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTksh9ib1mZYialTO6MbR6nzMgmLs9IfQOEyQjejFn7cJMLzaB3H8Q4odaQ/640?wx_fmt=png "")  
  
  
通过Mythic平台我们还可以自由配置Athena支持的命令，该后门支持多种类型的命令，以下是完整的指令列表。  
  
<table><tbody><tr><th style="word-break: break-all;border-color: rgb(214, 214, 214);" align="center" valign="middle">指令</th><th style="word-break: break-all;border-color: rgb(214, 214, 214);" align="center" valign="middle">含义</th></tr><tr><td valign="middle" align="center" colspan="1" rowspan="1"><section style="margin-left: 0px;margin-right: 0px;text-indent: 0em;"><span style="color: rgb(62, 62, 62);letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">arp</span></section></td><td valign="middle" align="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">进行arp扫描</span></td></tr><tr><td valign="middle" align="center" colspan="1" rowspan="1"><section style="margin-left: 0px;margin-right: 0px;text-indent: 0em;"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">caffeinate</span></section></td><td valign="middle" align="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">唤醒或休眠电脑</span></td></tr><tr><td valign="middle" align="center" width="207" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: rgb(214, 214, 214);background: rgb(255, 255, 255);"><section style="line-height: 150%;margin-left: 0px;margin-right: 0px;text-indent: 0em;"><span style="font-size: 14px;"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);">cat</span><span style="font-family: 微软雅黑;line-height: 150%;color: rgb(0, 0, 0);"><o:p></o:p></span></span></section></td><td valign="middle" align="center"><span style="color: rgb(62, 62, 62);letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">读取文件内容</span></td></tr><tr><td valign="middle" align="center" width="207" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: rgb(214, 214, 214);background: rgb(255, 255, 255);"><section style="line-height: 150%;margin-left: 0px;margin-right: 0px;text-indent: 0em;"><span style="font-size: 14px;"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);">cd</span><span style="font-family: 微软雅黑;line-height: 150%;color: rgb(0, 0, 0);"><o:p></o:p></span></span></section></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">修改当前路径</span></td></tr><tr><td valign="middle" align="center" width="207" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: rgb(214, 214, 214);background: rgb(255, 255, 255);"><p style="line-height: 150%;margin-left: 0px;margin-right: 0px;"><span style="font-family: 微软雅黑;line-height: 150%;color: rgb(0, 0, 0);font-size: 14px;">coff<o:p></o:p></span></p></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">执行一个COFF文件</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">cp</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">复制文件</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">crop</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">从服务器下发文件到本地</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">drivers</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">获取驱动器信息</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">ds</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">针对域控制器运行 LDAP 查询</span></td></tr><tr style="font-size: 15px;color: rgb(62, 62, 62);letter-spacing: 1px;line-height: 2;padding-right: 10px;padding-left: 10px;margin-top: 10px;margin-bottom: 10px;"><td valign="middle" align="center" style="font-size: 15px;color: rgb(62, 62, 62);letter-spacing: 1px;line-height: 2;padding-right: 10px;padding-left: 10px;margin-top: 10px;margin-bottom: 10px;"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">ds-connect</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">绑定到 LDAP 控制器</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">ds-query</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">针对域控制器运行 LDAP 查询</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">env</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">输出环境变量</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">farmer</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">在Windows 域中收集 NetNTLM哈希值</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">get-clipboard</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">获取剪切板内容</span></td></tr><tr><td valign="middle" align="center"><span style="font-size: 14px;">get-localgroup</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">获取当前用户组</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">get-sessions</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">获取网络会话</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">get-shares</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">获取网络共享</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">hostname</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">显示主机名</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">ifconfig</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">获取IP信息</span></td></tr><tr><td valign="middle" align="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">inject-assembly</span></td><td valign="middle" align="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">向进程注入.NET程序</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">inject-shellcode</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">向进程注入shellcode</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">keylogger</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">记录键盘输入</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">kill</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">关闭指定进程</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">ls</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">枚举指定目录文件</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">mkdir</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">创建目录</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">mv</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">移动文件</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">nslookup</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">执行nslookup查询</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">patch</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">执行asmi绕过</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">ps</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">获取当前进程列表</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">pwd</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">显示当前工作目录</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">reg</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">修改注册表</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">rm</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">删除文件</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">screenshot</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">截取屏幕</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">sftp</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">使用SFTP与指定主机交互</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">shell</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">执行shell指令</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">shellcode</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">执行shellcode</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">test-port</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">检查指定端口是否开放</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">timestomp</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">将两个文件的时间戳进行匹配</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">uptime</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">输出当前时间</span></td></tr><tr><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">whoami</span></td><td valign="middle" align="center"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">显示当前用户信息</span></td></tr><tr><td valign="middle" align="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">win-enum-resources</span></td><td valign="middle" align="center" colspan="1" rowspan="1"><span style="color: rgb(0, 0, 0);font-family: 微软雅黑;letter-spacing: 1px;text-align: -webkit-left;text-wrap: wrap;background-color: rgb(255, 255, 255);font-size: 14px;">识别本地网络资源</span></td></tr></tbody></table>  
  
  
**04**  
  
**思考总结**  
  
  
东欧地区一直以来都是地缘政治竞争的焦点，俄乌战争更加剧了各个国家间的冲突，网络空间的冲突作为现实冲突的延续，往往更加激烈且难以察觉。“骷髅狼”组织具有高度专业化的技术水平，不仅擅长制作精良的诱饵，并且能够成熟地利用最新漏洞，同时使用专业的渗透测试平台，极有可能代表着国家级或高度组织规模的攻击团队。  
  
  
此外这也是我们第一次发现APT组织攻击者使用基于Mythic平台的后门进行攻击，Mythic平台是一个功能强大的工具，其操作相对简单，具备多款强大的后门工具，这使得攻击者能够轻松进行高度复杂的攻击操作。同时，Mythic平台具有很高的可定制性，不得不怀疑，这个攻击组织在未来的攻击中可能会采用其他不同的后门工具。  
  
  
“  
  
**解决方案**  
  
  
1.  鉴于样本触发WinRAR漏洞(CVE-2023-38831)的影响版本为小于6.23版本，可升级WinRAR版本至大于等于6.23  
  
1. 鉴于恶意程序行为：可以查看Windows计划任务，观察是否有名为“Microsoft Edge”的计划任务，进行取证排查，确认危害后删除；排查是否有“AIMP.exe”或者“MikrosoftEdge.exe” 的可疑文件或进程，排除正常应用，确认危害后删除。  
  
  
  
  
“  
  
**安恒信息产品已集成能力**  
  
  
针对该事件中的最新IoC情报，以下产品的版本可自动完成更新，若无法自动更新则请联系技术人员手动更新：  
  
1. AiLPHA分析平台V5.0.0及以上版本  
  
2. AiNTA设备V1.2.2及以上版本  
  
3. AXDR平台V2.0.3及以上版本  
  
4. APT设备V2.0.67及以上版本  
  
5. EDR产品V2.0.17及以上版本  
  
  
  
  
安恒信息再次提醒广大用户，请谨慎对待互联网中来历不明的文件，如有需要，请上传至安恒云沙箱https://sandbox.dbappsecurity.com.cn，进行后续判断。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkc0iaJur7iat4pdS5j1YsWLFyRZRcNIb4FWZMq3cO4kg4oTjfLeFDLbHg/640?wx_fmt=png "")  
  
**安恒云沙箱反馈与合作请联系：sandbox@dbappsecurity.com.cn**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/AvAjnOiazvnew8XtX5SFYGgEQt8wyKQTkJl1xHpBvf2z1Yq422ibtfsicwUJsAmkpjFXicpCcRzfFJPnADiaSOF8HQA/640?wx_fmt=gif "")  
  
  
  
**往期推荐**  
  
  
  
  
  
  
  
- [Confucius针对巴铁兄弟的攻击，这次真的过分了](http://mp.weixin.qq.com/s?__biz=MzUyMDEyNTkwNA==&mid=2247495700&idx=1&sn=5f39caf4d5fafef490ff1ad18f072a16&chksm=f9ed9cabce9a15bd1a5c94d19de5c927bdd0983b55b6183159a40034129bc78b2355aab38d85&scene=21#wechat_redirect)  
  
  
- [挑衅！这个组织公开放出勒索源码](http://mp.weixin.qq.com/s?__biz=MzUyMDEyNTkwNA==&mid=2247495595&idx=1&sn=cad041b727e0b3f05b56376c9abd420c&chksm=f9ed8314ce9a0a025615f0cec1abd4ab950d93b987ce245bfd4b4c1582bd8c51c6e3754db2fa&scene=21#wechat_redirect)  
  
  
- [神秘组织入侵俄罗斯长达三年，多个行业惨遭痛击！](http://mp.weixin.qq.com/s?__biz=MzUyMDEyNTkwNA==&mid=2247495411&idx=1&sn=e767ba37797b73d9011b4c51576e642c&chksm=f9ed824cce9a0b5ad08d1c9e4ce48043184b6942dedcd7047502532dd65068212ea7a16264aa&scene=21#wechat_redirect)  
  
  
  
  
