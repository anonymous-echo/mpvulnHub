#  利用VPN设备漏洞入侵！新型勒索软件CACTUS攻击手法分析   
网络安全研究院  亚信安全   2024-02-03 18:18  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYMvennDYibtTuugkln1hJna7PxMuMecOo2mK5paQgGW0kyUoY5Tlvgng/640?wx_fmt=jpeg "")  
  
近期，亚信安全应急响应中心截获了利用VPN设备已知漏洞传播的新型勒索软件CACTUS，该勒索于2023年3月首次被发现，一直保持着活跃状态。CACTUS勒索软件通过Fortinet VPN的已知漏洞进行入侵（黑客首先获取到VPN账号，再通过VPN服务器入侵到组织内部），获取初始访问权限。随后，勒索团伙会通过网络扫描，远控软件和RDP暴力破解在内网横向移动，窃取被害者的重要信息，并将窃取的信息传输到云存储中。最后，勒索团伙对被害机器进行勒索投毒。  
  
  
**CACTUS勒索软件介绍**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYMyK4icyNkPYC7G2iaMIq8ZbeFPicPHY1HMCTMHMia5EROxzHr9u4mFrBqA/640?wx_fmt=png "")  
  
【CACTUS攻击流程】  
  
  
在内网横向移动阶段，该勒索团伙使用Netscan、PSnmap的修改版本对域内机器进行网络扫描。通过使用PowerShell命令来枚举端点，在Windows事件查看器中查看成功登录来识别用户帐户，并ping远程主机。除此之外，勒索团伙还使用各种合法工具及远程软件对被害者机器进行控制，例如Splashtop、 AnyDesk、SuperOps RMM、Cobalt Strike和基于Go的代理工具Chisel。另外， 该勒索还通过RDP暴力破解获取内网访问权限。  
  
  
获取到内网机器的访问权限后，勒索团伙首先会窃取被害者的敏感信息，并使用Rclone等常见工具将窃取的信息传输到云存储中，然后再进行手动投毒。在勒索阶段，勒索团伙会威胁用户，如果不缴纳赎金，将会泄露窃取到的数据。在数据加密及数据泄露双重威胁下，用户缴纳赎金的概率将会提高。  
  
  
CACTUS勒索与以往勒索软件相比较，其最大不同之处是利用7-Zip进行防御规避。CACTUS 勒索软件使用批处理脚本提取 7-Zip加密保护的勒索软件二进制文件，然后在执行有效负载之前删除 .7z文件。CACTUS勒索软件在加密前会初始化AES密钥以及OpenSSL库，通过OpenSSL库提供加密服务。其还通过创建计划任务达到持久化加密文件目的。在加密过程中，混合使用了 AES 和 RSA 算法，其中，使用 AES 算法对文件数据进行加密，并将加密后的数据写入文件中，然后使用 RSA 公钥对随机生成的加密密钥进行加密，并在文件夹中留下勒索信息说明文件。为防止受害者通过备份恢复数据，其会删除卷影副本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfY8Pyico7WicsGLORLsGZxhRum3AWMiaKdsdj60TzNqibydiaH6ueVI7icm5Yg/640?wx_fmt=png "")  
  
【  
CACTUS勒索信】  
  
  
  
**病毒详细分析**  
  
  
  
该勒索首先执行bat脚本，将test.7z压缩包解压，并将勒索软件复制到C:\windows\目录下，通过脚本中的命令行参数运行，并执行后续加密操作：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYTYq7sITgMicFic2miaIq38UxZhNpgV8mibOfxv6wjrHGvsUWYhkFxq6G0Q/640?wx_fmt=png "")  
  
  
其会创建一个互斥体，防止多个进程运行：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfY2Ig3KxNvJa8e27Da50sxUEvJhl6FgwKq9ChfkkzRuuTibE0DvlatRdw/640?wx_fmt=png "")  
  
  
使用AES算法并初始化密钥，后续用于进行数据加密：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYrkSjn7JNicBDLB4JX6WcTy4Bib3yaSOAy83j4EnFKLKr26N0gjA27URw/640?wx_fmt=png "")  
  
  
提供RSA公钥，后续用于对AES密钥进行加密：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYaNM645ibcxPFSefqHLzI8zPPaqA2FyyRvic00QVKVIaGYzgbjl2iadN7Q/640?wx_fmt=png "")  
  
  
该勒索将自身复制到C:\ProgramData\{文件名}.exe：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYgn93V8jauTpASqOiaSgCvGqBTzG2dCXg5hEOiczKx8hh0oPHA9cVgYfA/640?wx_fmt=png "")  
  
  
其将垃圾数据混淆的十六进制编码配置文件写入 C:\ProgramData\ntuser.dat，其中包含原始 exe 的路径，这是一个 base64 字符串，包含勒索软件运行的相关配置。通过将每个双字符字节表示的对齐方式推出一个字符来进一步混淆处理十六进制字符串：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYecXL84zE8ZqjJRerqnlaMV5Kd1o2RU0MdZbQHtLKibNsUhK8E0mFZLQ/640?wx_fmt=png "")  
  
  
创建计划任务，指向：C:\ProgramData\{文件名}.exe -r：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYzlTEOhuCYUzPFtU3kZLSwfpoURZQkfHicWM4ZWEYWveIbUt8x6ZG45Q/640?wx_fmt=png "")  
  
  
该勒索使用了 OpenSSL 库提供的加密算法对文件进行加密：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYHjVZN5bDIo6CE8g25ZAv1M9wj9Ef6Ebd3DWZiaMyGMahXBTnagtdr7g/640?wx_fmt=png "")  
  
  
其会删除卷影副本，禁用自动修复功能，以防止用户恢复数据：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYXjicaO0bw4UL9kOsTTR4IANk1cggpGfezT29ib2LZicJiaHdNeQJ1L1BNA/640?wx_fmt=png "")  
  
  
获取本地磁盘以及磁盘类型：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYsSRtbxlWBd920TqtWsADyGPodeVwzmcQpWA2HObvRhyXbicV5jfGz7g/640?wx_fmt=png "")  
  
  
创建勒索信：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYwggjK4FciaFHE95VnzRjC0bHwB02ENNHf4cuB5Lknlo3cywHX2FfTWw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYx6kJ9FLnV75VDsGicxIWymwJK2gyFk3BHmPRUKGHjp9ewvlVN7Bnk0w/640?wx_fmt=png "")  
  
  
遍历文件，并对文件进行加密：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYhf4ibVzPkYpxyht00pRUVQPiaicjPPWCrngSmWU07xuy0Qy80hHMS0YmQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYvhQuEmmXic779V1iannbOcmibjtBGgJHpE55TtkJvsuxMzn03e4ZmibLEA/640?wx_fmt=png "")  
  
  
使用AES，RSA和OpenSSL进行文件加密：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYrqMYxdkQLt4hNBQ3ePTxmgIAJL6NaziboUiadd6bIFibX6Nra1WvNibROA/640?wx_fmt=png "")  
  
  
加密文件后，添加加密后缀：.CTS1，.CTS6，.CTS7等：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYvhQuEmmXic779V1iannbOcmibjtBGgJHpE55TtkJvsuxMzn03e4ZmibLEA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYyGDFHCVumWQE2OFAadEIoUgqvfChgwiaG642CViafrgfO2pDgMV8zEnw/640?wx_fmt=png "")  
  
  
  
**亚信安全产品解决方案**  
  
  
  
●  
  
亚信安全病毒码版本18.939.60，云病毒码版本18.939.71，全球码版本18.939.00已经可以检测该勒索软件中对外公开的样本，请用户及时升级病毒码版本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYXBqcUiaMtDfZ4GoG9LMGzcUIQod1ENf6CxJnrh30JvicstwwZibE6NsnA/640?wx_fmt=png "")  
  
  
●  
  
亚信安全梦蝶防病毒引擎可以检测该勒索软件，可检测的病毒码版本为1.6.0.194  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iczzp36h0nbFTWDr5EicRP0mH2nO0SnjfYUVMtFHmbQ1pmKroARzWpCyBAbFKUWdcD5ApcvggedGxk5clhNliaFGA/640?wx_fmt=png "")  
  
  
  
**安全建议**  
  
  
  
●  
  
修复Fortinet VPN已知漏洞  
  
●  
  
全面部署安全产品，保持相关组件及时更新  
  
●  
  
采用高强度密码，避免使用弱口令或重复口令  
  
●  
  
尽量关闭不必要的默认共享，避免被横向传播  
  
●  
  
请注意备份重要文档。备份的最佳做法是采取3-2-1规则，即至少做三个副本，用两种不同格式保存，并将副本放在异地存储  
  
  
  
  
了解亚信安全，请点击  
**“阅读原文”**  
  
