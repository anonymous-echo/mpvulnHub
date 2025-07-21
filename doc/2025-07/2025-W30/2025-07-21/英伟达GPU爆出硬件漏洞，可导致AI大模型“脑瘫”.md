> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQyODI4Ng==&mid=2247497223&idx=1&sn=b00442fda4e3c5789c63aff319b45698

#  英伟达GPU爆出硬件漏洞，可导致AI大模型“脑瘫”  
 网络安全与人工智能研究中心   2025-07-21 07:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHiby2xibacqr9cSTHFjaSVHFo5NM3nRb2WHvGuRbjjerowfQ2YdDXgUtkbibPicPN0koSwgZEPIbichUFMg/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHiby2xibacqr9cSTHFjaSVHFo5H7lOqp7aXm0tvOTcVK56pnDcqHLv98TsmUUYCFhCHqFqA2qqDtg37g/640?wx_fmt=png&from=appmsg "")  
  
一种新的针对英伟达GPU（搭载GDDR6显存）硬件漏洞的RowHammer攻击变体可将“自动驾驶”和“金融风控”等AI模型的准确率“归零”。  
  
  
近日，显卡制造巨头英伟达发布安全公告，警告用户尽快启用系统级纠错码（ECC），以防御一种名为“GPUHammer”的新型RowHammer攻击方式。（较新的NVIDIA GPU例如H100或RTX5090不受影响，因为它们有片上 ECC）  
  
  
该攻击由多所大学研究人员首次实证验证，可通过诱发GPU显存中的比特翻转（bit flip）现象，实现对AI模型等关键数据的破坏性篡改。  
  
  
该攻击被认为是首次在NVIDIA GPU（如搭载GDDR6显存的A6000）上成功演示的RowHammer攻击变体，标志着这类曾广泛威胁DRAM和CPU的硬件漏洞正在向GPU扩散，对AI基础设施的构成重大风险。  
  
  
**GPU版熔断攻击**  
  
  
GPUHammer是RowHammer攻击家族中的最新变种，是一种在AI模型层以下运作的新型攻击——改变内部权重而非外部数据。  
  
  
其攻击原理是通过反复高速访问DRAM某一行，引发邻近行的电干扰，从而造成数据位翻转。这一物理层面的攻击方式在现代GPU内存架构中极具破坏性，类似于针对CPU的Spectre和Meltdown（熔断）攻击，都是杀伤力巨大的硬件级安全漏洞。  
  
  
而与CPU不同的是，GPU由于历史上缺乏侧信道防御研究、校验机制和访问控制，成为天然“薄弱环节”。尽管许多NVIDIA显卡已启用目标刷新率（TRR）等缓解机制，但GPUHammer仍能绕过这些限制，在显存中实施有效篡改。  
  
  
**攻击影响：AI准确率从80%跌至0.1%**  
  
  
来自多伦多大学的研究人员构建的PoC（概念验证）显示，只需一次比特翻转，就能将ImageNet深度神经网络模型的准确率从80%降至0.1%。也就是说，这一攻击不仅能破坏内存数据，还可“静默”削弱AI推理结果，且难以被即时检测。  
  
  
在共享GPU平台（如云端机器学习平台、VDI虚拟桌面等）中，这种攻击还可能演变为跨租户风险。攻击者无需直接访问他人模型，仅凭显存中可控的干扰就能操控邻近任务的模型权重，诱导其输出错误判断。  
  
  
GPUHammer的影响远不止于数据中心训练节点。边缘计算设备、自主驾驶系统、金融风控引擎等也大量依赖GPU并实时推理。如果这些系统遭到显存层级的“静默破坏”，可能出现无法逆转的误判或合规失误。  
  
  
在监管要求严格的行业中，这种攻击带来的AI错误推理可能违反《E.U.AI法案》、ISO/IEC27001等安全性、可解释性和数据完整性合规框架。  
  
  
**如何防御？启用ECC是关键**  
  
  
为防范GPUHammer攻击，NVIDIA建议用户通过命令nvidia-smi-e1启用ECC功能，并使用nvidia-smi-q|grepECC验证状态。尽管ECC启用后可能导致A6000显卡推理性能下降约10%、显存减少6.25%，但其在AI模型完整性方面的保护能力至关重要。  
  
  
此外，组织还应定期检查GPU错误日志（如/var/log/syslog或dmesg），以便发现潜在的比特翻转尝试，并在高风险工作负载（如模型训练）中优先启用ECC。  
  
  
值得注意的是，NVIDIA较新一代显卡（如H100、RTX5090）已原生配备芯片级ECC机制，可自动检测并修复由电压波动引起的显存错误，暂未受GPUHammer影响。  
  
  
GPUHammer的曝光并非孤例.研究人员指出，2022年已有“SpecHammer”技术将RowHammer与Spectre攻击结合，以实现投机执行漏洞的跨域利用。而近日，来自NTT和CentraleSupelec的研究者发布的“CrowHammer”攻击更进一步，其可通过微小比特翻转成功破解Falcon后量子签名算法的私钥，仅需数亿次签名样本。  
  
  
**总结：GPU安全须纳入AI基础设施治理视野**  
  
  
GPUHammer清晰表明，AI模型的脆弱性不仅存在于输入层（如对抗样本），还可能来自硬件底层的显存干扰。在AI日益普及、云端部署广泛的背景下，企业、云服务商与科研机构亟需将GPU内存完整性纳入安全治理与合规检查范围，更新GPU使用策略与硬件选择标准。  
  
  
参考建议：  
  
**高风险任务建议启用ECC；**  
  
**监控系统日志发现潜在翻转事件；**  
  
**对云平台GPU资源进行租户隔离与访问监控；**  
  
**跟进硬件厂商补丁与防护机制更新。**  
  
在AI“深水区”中，GPUHammer敲响了又一次安全警钟。它不再是“显存小故障”，而是直通AI核心系统的攻击入口，自动驾驶或金融风控等AI关键基础设施一旦遭受攻击导致“脑瘫”，可导致灾难性的后果。  
  
  
参考链接：  
  
https://gpuhammer.com  
  
https://nvidia.custhelp.com/app/answers/detail/a_id/5671  
  
END  
  
  
  
  
来源｜“GoUpSec”微信公众号  
  
编辑｜风东曾  
  
审核｜秦川原  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHiby2xibacqr9cSTHFjaSVHFo5SGElXibhHJBpEF0XWrFI3uheF7aRDtsPa1qRdPv8iblRefTzZWc5D3QA/640?wx_fmt=png&from=appmsg "")  
  
  
