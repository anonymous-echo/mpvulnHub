> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1OTA1MzQzNA==&mid=2651248195&idx=1&sn=0e8285716274d1f15c4ca606f908a2e9

#  遭受惨烈事故后，这家公司将投入超36亿元加强数据安全建设 | Linux启动漏洞可绕过现代Linux系统的安全启动保护  
e安在线  e安在线   2025-07-09 02:04  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
# 遭受惨烈事故后，这家公司将投入超36亿元加强数据安全建设  
  
7月8日消息，韩国政府日前责令SK电讯加强数据安全措施，并处以罚款。消息公布当天，SK电讯股价收盘下跌5.6%。  
  
此前这家韩国最大的移动运营商遭遇网络攻击，导致2696万名用户卡数据泄露。  
  
  
**政府责令SK电讯进行安全检查，**  
  
****  
**并处以罚款**  
  
  
韩国科学技术信息通信部在一份声明中指出：“SK电讯未能尽到保护USIM数据的应有责任，也未能遵守相关法规。”USIM是指智能手机所使用的通用用户身份模块卡。  
  
该部门表示：“因此，公司在此次事件中被认定存在明显疏忽。”这是官方在公布数据泄露事件调查结果时所做出的正式表态。  
  
科学技术信息通信部表示，将对SK电讯处以最高3000万韩元（约合人民币15.75万元）的罚款，并要求公司至少每季度实施一次安全检查，由首席执行官直接负责数据治理，同时增加数据安全领域的人力投入与资金投资。  
  
科学技术信息通信部长柳尚任表示，此次事件为整个网络基础设施的“信息保护敲响了警钟”。  
  
  
**SK电讯计划5年投入超36亿元，**  
  
****  
**加强数据安全建设**  
  
  
在政府宣布相关处罚措施后，SK电讯也公布了一系列应对方案，旨在补偿受影响用户并强化信息保护。  
  
该公司在声明中表示，未来5年将投资约7000亿韩元（约合人民币36.75亿元）用于数据安全，并将为旗下约2400万名客户提供8月通信月费五折优惠，以示补偿。  
  
SK电讯首席执行官柳英相表示：“所有SK电讯的高管与员工都严肃对待此次由政府与企业联合调查得出的结论，并就本次网络攻击事件向广大客户及社会大众表示诚挚歉意。”  
  
SK电讯在一份提交监管机构的申报文件中称，由于此次数据泄露事件需向受影响客户补偿约5000亿韩元（约合人民币26.2亿元），公司已将2025年的营收预期下调8000亿韩元（约合人民币41.92亿元）。  
  
SK集团董事长崔泰源已于上月就此次数据泄露事件公开致歉。SK电讯方面也表示，将对因此事件造成的任何损失承担全部责任。此次事件引发了其2300万用户对个人及财务信息被盗用的广泛担忧。  
  
该移动运营商表示，在事件发生后，已启动为全国2600多家线下门店的全部2300万用户免费更换USIM卡的计划。  
  
SK电讯表示，截至6月底，已有约939万名用户完成了USIM卡的更换。  
  
  
# Linux启动漏洞可绕过现代Linux系统的安全启动保护  
  
现代Linux发行版存在一个重大漏洞，攻击者通过短暂物理接触即可利用initramfs（初始内存文件系统）操控绕过安全启动（Secure Boot）保护机制。  
  
  
该攻击利用系统启动失败时可访问的调试shell，注入持久性恶意软件，这些恶意软件可在系统重启后继续存活，即使用户输入了加密分区的正确密码仍能维持访问权限。  
  
  
**Part01**  
## 核心要点  
  
  
1. 攻击者通过物理接触可利用initramfs在启动失败时的调试shell绕过安全启动保护  
  
  
2. 多次输入错误密码会触发调试访问，允许向未签名的initramfs组件注入持久性恶意软件  
  
  
3. Ubuntu 25.04、Debian 12、Fedora 42和AlmaLinux 10存在漏洞；OpenSUSE Tumbleweed不受影响  
  
  
4. 添加内核参数可禁用调试shell（Ubuntu系统使用panic=0，Red Hat系使用rd.shell=0 rd.emergency=halt）  
  
  
**Part02**  
## Linux initramfs漏洞分析  
  
  
据Alexander Moch指出，该漏洞的核心在于初始内存文件系统（initramfs）——这是Linux启动过程中用于解密根分区的关键组件。  
  
  
与内核镜像和模块不同，initramfs本身通常未经签名，在安全链中形成了可被利用的缺口。当用户多次输入加密根分区的错误密码后，多数发行版会在超时后自动进入调试shell。  
  
  
攻击者可通过该调试shell挂载包含专用工具和脚本的外部USB驱动器。攻击流程包括：使用unmkinitramfs命令解包initramfs，将恶意钩子注入scripts/local-bottom/目录，然后重新打包修改后的initramfs。  
  
  
Moch研究中展示的关键脚本如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icIpibI5JhZ4XkIZu1PaHMxHq71LJS8yml0DJ78Xr5IM0iaE1yQ8vLaaaC0V59H9JsAmr1s5yaWperg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该恶意钩子会在根分区解密后执行，将文件系统重新挂载为可写状态并建立持久性访问。由于攻击遵循常规启动流程且未修改已签名的内核组件，因此能规避传统防护机制。  
  
  
**Part03**  
## 各发行版受影响情况  
  
  
多发行版测试显示不同程度的易受攻击性：  
  
- Ubuntu 25.04仅需三次错误密码尝试即可获得调试shell访问  
  
- Debian 12可通过长按RETURN键约一分钟触发  
  
- Fedora 42和AlmaLinux 10的默认initramfs缺少usb_storage内核模块，但攻击者可通过Ctrl+Alt+Delete触发重启并选择救援条目绕过限制  
  
值得注意的是，OpenSUSE Tumbleweed因其默认启动分区加密实现方式而对此攻击免疫。安全专家将该漏洞归类为"邪恶女仆"攻击场景，需要短暂物理接触目标系统。  
  
  
**Part04**  
## 缓解措施  
  
  
有效防护方案包括：  
  
  
1. 修改内核命令行参数：  
- Ubuntu系添加panic=0  
  
- Red Hat系添加rd.shell=0 rd.emergency=halt 这些参数强制系统在启动失败时直接停止而非提供调试shell  
  
2. 其他防护措施：  
- 配置引导加载程序密码要求  
  
- 启用SSD原生加密  
  
- 对启动分区实施LUKS加密  
  
3. 高级解决方案：  
- 统一内核镜像（UKI）：将内核与initramfs合并为单一签名二进制文件  
  
- 可信平台模块（TPM）：将initramfs完整性度量值存入平台配置寄存器（PCR）  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源： 安全内参、FreeBuf、路透  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
