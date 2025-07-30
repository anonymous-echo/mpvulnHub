#  Linux恶意软件sedexp使用udev规则来实现持久性和躲避   
鹏鹏同学  黑猫安全   2024-08-26 18:55  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceibMLRv1X8sQLiauXnpN4F7Sf2SoLPzsdiaMiayOKtj7nhNJbCQKQwPZLffgBYV8pk8DLMt2O9Ce0wV2g/640?wx_fmt=png&from=appmsg "")  
  
安永的网络解决方案发现了一种新的恶意软件家族，称为sedexp，依赖于较少知晓的Linux持久性技术。该恶意软件自2022年起就活跃，但一直保持了几年的隐匿状态。专家们指出，这种持久性方法目前还没有被MITRE ATT&CK文档中记录。这种技术允许恶意软件在感染的系统上保持持久性，并隐藏信用卡-skimmer代码。sedexp使用udev规则来保持持久性。udev是一个Linux系统组件，管理着设备事件，允许它根据设备的属性来识别设备，并配置规则来 triggle动作，当设备插入或拔出时。这使sedexp在持久性机制中具有创新之处。  
  
报告中说：“在最近的一次调查中，Stroz Friedberg发现了使用udev规则来保持持久性的恶意软件。这种技术允许恶意软件每当特定的设备事件发生时执行，使其 Stealthy和难以检测。这个规则确保恶意软件在/boot/dev/random被加载时运行。/dev/random是一个特殊文件，用于提供随机数生成器，用于各种系统进程和应用程序获取熵用于加密操作、安全通信和其他需要 randomness的函数。操作系统在每次重新启动时都会加载这个文件，这意味着这个规则将确保sedexp脚本在系统重新启动时运行。”  
  
sedexp恶意软件具有两个可以注意的特点：反向shell能力：它允许攻击者远程控制被劫持的系统。内存修改以保持隐蔽性：恶意软件修改内存，以隐藏包含字符串“sedexp”的文件，从而隐藏Webshell、修改的Apache配置文件和udev规则本身。研究人员认为，sedexp恶意软件背后的威胁actor是具有财务motivation的。  
  
“sedexp的发现表明了财务motivated威胁actor的演进，超出了ransomware。利用较少知晓的持久性技术like udev规则highlighted了需要进行彻底和先进的法医分析的需求。”报告结论说。“组织应该不断更新检测能力，实施prehensive安全措施以 mitigatesuch threats，并确保有能力的DFIRfirm参与对可能被劫持的服务器的法医调查。”  
  
  
