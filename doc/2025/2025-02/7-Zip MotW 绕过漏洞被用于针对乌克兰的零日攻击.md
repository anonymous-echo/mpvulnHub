#  7-Zip MotW 绕过漏洞被用于针对乌克兰的零日攻击   
 独眼情报   2025-02-05 02:55  
  
> 简单机翻，之前预警过，有些人觉得影响不大  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnTEGmVr8icLROSqvh7mkrJ01yorKmlkaIvlgRxDOkaOV71VItiauyOPLT84N469rYWGmdIyDCfdjdOQ/640?wx_fmt=jpeg&from=appmsg "")  
  
自 2024 年 9 月以来，俄罗斯黑客利用 7-Zip 漏洞作为零日漏洞，该漏洞允许攻击者绕过 Windows 安全功能 Mark of the Web (MotW)。  
  
据趋势科技研究人员称，该漏洞被用于针对乌克兰政府和该国私人组织的 SmokeLoader 恶意软件活动。  
  
Web 标记是一项 Windows 安全功能，旨在警告用户他们即将执行的文件来自不受信任的来源，并通过附加提示请求确认步骤。绕过 MoTW 可让恶意文件在受害者的计算机上运行而无需发出警告。  
  
从网络下载文档和可执行文件或以电子邮件附件形式接收时，Windows 会   
向文件添加一个称为  
“Web 标记” （MoTW）的特殊“Zone.Id”备用数据流。  
  
当尝试打开下载的文件时，Windows 将检查是否存在 MoTW，如果存在，则向用户显示其他警告，询问他们是否确定要运行该文件。同样，当在 Word 或 Excel 中打开带有 MoTW 标志的文档时，Microsoft Office 将生成其他警告并关闭宏。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnTEGmVr8icLROSqvh7mkrJ01o0PubHibbIyucVqWk17uPUqeeetN2GXVKJezyJ1naLfibDfFiamzrhvzg/640?wx_fmt=jpeg&from=appmsg "")  
  
Windows 中的 MoTW 警告来源：BleepingComputer  
  
  
由于 Web 标记的安全功能可防止危险文件自动运行，威胁行为者  
通常  
会尝试  
找到 MoTW 绕过方法  
，以便他们的文件自动运行和执行。  
  
多年来，网络安全研究人员  
一直要求 7-Zip 添加  
对 Web 标记的支持，但直到 2022 年才  
最终添加对该功能的支持  
。  
## 攻击中利用 MoTW 绕过技术  
  
趋势科技的零日计划 (ZDI) 团队于 2024 年 9 月 25 日首次  
发现该漏洞  
，目前追踪为 CVE-2025-0411，并在俄罗斯威胁行为者发起的攻击中观察到该漏洞。  
  
黑客利用 CVE-2025-0411，使用双重存档文件（存档中的存档）来利用 MoTW 标志缺乏继承，从而导致恶意文件执行而不会触发警告。  
  
这些特制的档案文件通过被入侵的乌克兰政府账户的钓鱼邮件发送给目标，以绕过安全过滤器并显得合法。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnTEGmVr8icLROSqvh7mkrJ014kk0GJ5hvNPyeopBDZNvel5Aw0NRSJicxxWZaiakpqnjTjZicMQK1Nm3w/640?wx_fmt=jpeg&from=appmsg "")  
  
攻击活动中使用的钓鱼电子邮件样本来源：趋势科技  
  
  
攻击者利用同形文字技术，将有效载荷隐藏在 7-Zip 文件中，使其看起来是无害的 Word 或 PDF 文档。  
  
虽然打开父档案确实会传播 MoTW 标志，但 CVE-2025-0411 漏洞导致该标志不会传播到内部档案的内容，从而允许恶意脚本和可执行文件直接启动。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTEGmVr8icLROSqvh7mkrJ01H54mgIH4eG1awUN2NiaSXFxkgsFRHH1kve5UXRUOphUogn7prtiawUzQ/640?wx_fmt=png&from=appmsg "")  
  
被屏蔽文件的真实内容来源：趋势科技  
  
  
最后一步会触发 SmokeLoader 负载，这是一种恶意软件投放器，过去用于安装信息窃取程序、木马、勒索软件或创建后门以实现持续访问。  
  
趋势科技表示这些攻击影响了以下组织：  
- 乌克兰国家行政局 (SES)  
 – 司法部  
  
- 扎波罗热汽车制造厂 (PrJSC ZAZ)  
 – 汽车、公共汽车和卡车制造商  
  
- Kyivpastrans  
 – 基辅公共交通服务  
  
- SEA 公司  
– 家用电器、电气设备和电子产品制造商  
  
- 韦尔霍维纳地区国家管理局  
– 伊万诺-弗兰科夫斯克州管理局  
  
- VUSA——  
保险公司  
  
- 德尼普罗市地区药房  
– 地区药房  
  
- Kyivvodokanal  
 – 基辅供水公司  
  
- 扎利希奇基市议会  
– 市议会  
  
## 更新 7-Zip  
  
尽管该零日漏洞早在 9 月份就被发现，但趋势科技直到 2024 年 10 月 1 日才与 7-Zip 的开发人员分享了可行的概念验证 (PoC) 漏洞。  
  
  
后者通过 2024 年 11 月 30 日发布的24.09 版本中实施的补丁  
解决了风险。  
但是，由于 7-Zip 不包含自动更新功能，因此 7-Zip 用户运行过时版本的情况很常见。  
  
因此，强烈建议用户下载最新版本以确保免受此漏洞的影响。  
  
  
