#  Milkyway【具备效的机器探活，端口探活，协议识别，指纹识别，漏洞扫描等功能的全方位扫描工具】   
原创 白帽学子  白帽学子   2025-05-08 00:11  
  
昨天用Milkyway给某政务云做全端口扫描，这工具的乱序模式直接把效率拉满，咱俩唠唠它怎么在实战里真香。  
  
上周红队演练，甲方要求48小时内摸清某金融城的暴露面。用FOFA语句拉取目标的时候，这货直接支持环境变量自动填充，省了我手动填密钥的麻烦。更绝的是--scan-random参数，扫完192.168.0/16段才用了三个小时，比传统顺序扫描快了不止一倍。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/LYy9xnADcdjVQFemFbibvvLQmBl7DVFV3ycjow2Wiba0RlRqknUpRA4yiblQ6rPNuKDmsgtFDRn40jdcvmAZGydEQ/640?wx_fmt=jpeg "")  
  
知道最骚的是啥不？前天蓝队模拟攻击，我故意用--no-match参数绕过指纹匹配。这相当于直接给目标发全量POC，虽然准确率会掉，但能检测出那些指纹库没收录的0day。不过兄弟，这招得看甲方脸色，有些甲方看到全量扫描直接给你脸色看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/LYy9xnADcdjVQFemFbibvvLQmBl7DVFV3ZU5hW06Su1WicvBC9Q0n1x9smMy8lU3oJnGrVfac3ViaFpzg5NglTF0w/640?wx_fmt=jpeg "")  
  
上个月给某游戏公司做安全演练，他们运维老哥非要用自定义指纹文件。Milkyway的--finger-file参数救了我，直接塞进去他们游戏服的特殊握手协议。扫出三个未授权Redis，里面居然存着游戏金币兑换记录，这波直接让甲方连夜改了权限。  
  
说个冷知识，用代理功能的时候千万别用tizi，上周用socks5扫某跨境电商，结果梯子节点被墙直接暴露了。后来改成公司内网代理，配合--poc-tags筛选CVE漏洞，半小时就挖出个未修复的Struts2漏洞。  
  
想要获取工具的小伙伴可以直接**拉至文章末尾**  
  
我们来提取并讨论上述工具描述中涉及的网络安全关键技术点：  
  
1、  
网络资产测绘与漏洞检测技术  
：  
- 在hvv演练或红蓝对抗中，快速定位暴露面是核心需求。通过端口探活、协议识别（如Redis、SMB等）结合指纹库（如25,000+ Web指纹），可快速绘制全网资产地图。例如Milkyway的乱序扫描模式（--scan-random）能绕过传统防火墙的流量检测规则，大幅提升内网扫描效率。漏洞检测方面，集成Nuclei引擎的8000+POC库支持按标签筛选（如CVE、CNVD），配合自定义POC（--poc-file）可精准打击特定场景的脆弱点，例如检测未修复的Struts2漏洞。  
  
2、  
访问控制与身份认证强化技术  
：  
- 无线网络中的认证机制（如WPA2、802.1X）和端口级访问控制是关键防线。例如在企业内网中，通过MAC地址白名单和动态密钥派生（如TKIP/CCMP协议）可防止未授权设备接入。实战中，Milkyway的爆破模块（SSH、MySQL等）能验证弱密码风险，而--verbose参数可暴露明文传输的协议（如老旧SMB版本），辅助制定访问策略。  
  
3、  
加密与流量防护技术  
：  
- 数据加密算法（如AES、RC4）及代理技术是防窃听的核心。无线网络中，CCMP协议通过CTR加密和CBC-MAC校验保障数据完整性与机密性。在渗透测试中，使用socks5代理（-s参数）可隐藏扫描源IP，但需注意代理节点安全性，避免因节点暴露导致溯源风险。此外，SSL/TLS在Web服务中的应用能有效防御中间人攻击。  
  
4、  
  
安全取证与溯源分析技术  
  
：  
- 网络取证依赖日志分析、流量捕获（如Wireshark）和异常行为检测。例如通过解析无线网络中的会话ID、爬虫记录和重定向日志，可追踪攻击路径。Milkyway的实时日志打印功能（结合--finger-file自定义指纹）能快速定位异常协议交互，如发现未授权的Redis数据泄露事件，为溯源提供关键证据。  
  
5、  
主动防御与入侵响应技术  
：  
- 基于动态策略的入侵防御系统（如WIPS）和自动化响应机制是应对0day攻击的关键。通过部署蜜罐或使用--no-match参数绕过指纹匹配，可诱捕攻击者并收集攻击特征。在护网场景中，结合OSSIM等平台对海量日志进行关联分析，能快速识别DDoS或APT攻击，并通过动态调整防火墙规则实现实时阻断。  
  
  
  
  
**下载链接**  
  
https://github.com/polite-007/Milkyway  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/LYy9xnADcdhic61NkXCWKufScrUrmmsG8tztWD8fDRiatPUaljxxpKc1PpnYNFjPibU5FwJmcuO4mZoQg5aXsAcog/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
声明：该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白名单。  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与本公众号无关。  
  
✦  
  
✦  
  
  
