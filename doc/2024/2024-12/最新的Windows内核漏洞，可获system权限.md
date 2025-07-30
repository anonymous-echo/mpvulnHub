#  最新的Windows内核漏洞，可获system权限   
天唯科技  天唯信息安全   2024-12-18 01:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
网络安全和基础设施安全局（CISA）已将两个新的漏洞添加到其已知被利用漏洞目录中，其中一个是涉及 Windows 内核的漏洞，目前正被用于攻击。  
  
  
该漏洞编号为CVE-2024-35250，具体是在 Windows 的 ks.sys 驱动中存在的“不受信任的指针解引用”。这个漏洞可以通过利用未受信任的指针，来进行任意内存读写，最终实现权限提升。这种问题可能导致系统崩溃或使攻击者能够执行任意代码，对安全专业人员来说是一个重要关注点。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icpa18eT1YlRU4d2KsyaE4yjtmDvS5FImKkegAqZs2NtOgic01mkdQIzia2v0lASz6E6NibicLSzzibfEQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
微软已在最近的12月星期二补丁中修复了该漏洞 ，并表示“成功利用这一漏洞的攻击者可能获得 system权限。”该公司在6月发布的安全公告中仅提供了有限的细节，不过发现该漏洞的 DEVCORE 研究团队通过趋势科技的零日计划（Zero Day Initiative）将其报告给微软，并确定受影响的系统组件为 Microsoft Kernel Streaming Service (MSKSSRV.SYS)。  
  
  
**影响版本：**  
- Windows 10 20H2 Build 19042    
  
- Windows 11 22H2 Build 22621    
  
- VMWare Workstation 17 Pro 环境下也可被利用  
  
**漏洞细节：**  
  
攻击者可以通过发送特制的 IOCTL 请求触发 ks.sys 驱动中的漏洞，利用不可信指针的解引用，最终对系统内存进行任意读写操作。  
  
  
**限制条件：**  
   
- 实测该漏洞无法在 Hyper-V 环境中成功利用；  
  
- 攻击者需要拥有中等权限（Medium Integrity Level，通常为普通用户权限），才能触发漏洞进行提权。      
  
当前大部分 XDR（扩展检测和响应）解决方案能够检测并阻止该漏洞的利用行为。  
  
  
另外一个漏洞编号是CVE-2024-20767：此漏洞影响 Adobe ColdFusion，涉及不当的访问控制。攻击者可以利用此类漏洞来获取敏感信息或系统的未经授权访问，对网络安全构成重大威胁。对此，CISA 的操作指令（BOD）22-01，题为“减少已知被利用漏洞的重大风险”，要求联邦政府行政部门（FCEB）机构在指定的截止日期前修补这些漏洞，并表示“此类漏洞是一种常见的攻击途径，对联邦企业构成重大风险。”  
  
  
虽然 BOD 22-01 明确针对 FCEB 机构，但CISA 依旧强烈建议所有组织采取积极措施，以减少其网络攻击的暴露面。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
天唯科技专注于大型组织信息安全领域及IT基础设施解决方案的规划、建设与持续运维服务。帮助客户提高IT基础设施及信息安全管控水平和安全运营能力，使客户在激烈的市场环境中保持竞争力。  
  
我们一直秉承“精兵强将，专业专注”的发展理念。  
先后在江门、深圳成立分公司，在武汉、长沙成立办事处以及成立广州的服务支撑中心。公司已获得高新技术企业认证、已通过IS09001、IS027001、CCRC信息安全集成服务、CCRC信息安全风险评估、CCRC信息安全应急处理等认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNRytkPMNOKYRW452LxR5Ez5Wee8X6KlbhoUMt9XyhhbRxHafKcCLWJic3ib0umJiaH3fl6sOx8KMBiaQ/640?wx_fmt=png "盾牌单图.png")  
  
**END**  
  
  
  
**往期推荐:**  
  
  
  
  
  
[iOS和macOS系统曝关键漏洞，可破坏TCC框架](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503145&idx=1&sn=d055df27ce64c457cf92890ea9161a7d&scene=21#wechat_redirect)  
  
  
  
[文件传输平台Cleo零日漏洞，Clop团伙声称对数据盗窃攻击负责](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503145&idx=2&sn=cc39acbf2eae9f5bcc28c9401e6615e6&scene=21#wechat_redirect)  
  
  
  
[新型攻击技术曝光：通过二维码实现命令与控制操作](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503123&idx=1&sn=38975a0c60dbc007b55dea3ad456cadc&scene=21#wechat_redirect)  
  
  
  
**征文通道:**  
  
  
  
  
  
[发钱！征文！让真诚的分享更有价值](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247490310&idx=1&sn=db4b524d1d9f5aabb4af2184dd831de3&chksm=c25ed7a6f5295eb053d3f90e2dc8cd22a2d8ce1a62561ffa62966340ee563734cd4fd32045f3&scene=21#wechat_redirect)  
  
  
