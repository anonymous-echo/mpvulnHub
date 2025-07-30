#  【安全圈】GitLab 爆出安全漏洞，允许黑客接管账户   
 安全圈   2024-05-24 19:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
近日，GitLab 又爆出一个安全漏洞（被追踪为 CVE-2024-4835），未经认证的威胁攻击者能够利用该漏洞在跨站脚本 (XSS) 攻击中，轻松接管受害者账户。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljuaFSo6043c6GeS8s1vLmOLd8gG2C7BNILSMjM44OyqnQCJmY7A82S4I1soQDwoBBXo4L1lYaO8w/640?wx_fmt=jpeg&from=appmsg "")  
  
> GitLab ：一个基于网络的 Git 存储库，主要面向需要远程管理代码的开发团队，目前共拥有约 3000 万注册用户和 100 万付费客户。  
  
  
收到 CVE-2024-4835 安全漏洞通知后，GitLab 方面表示，在近期发布的 GitLab 社区版（CE）和企业版（EE）的17.0.1、16.11.3 和 16.10.6 版本中都修复了安全漏洞问题，强烈建议所有 GitLab 用户立即升级到其中一个版本。  
> CVE-2024-4835 安全漏洞是 VS 代码编辑器（Web IDE）中的一个 XSS 缺陷，允许威胁攻击者利用恶意制作的页面窃取部分信息。值得一提的是，虽然威胁攻击者可在未经身份验证的攻击中利用该漏洞，但仍需要与用户交互，这就增加攻击的复杂性。  
  
  
GitLab 公司还修复了其他六个中等严重程度的安全漏洞。其中，主要包括通过 Kubernetes 代理服务器的跨站请求伪造（CSRF）漏洞 CVE-2023-7045 和一个可让威胁攻击者破坏 GitLab 网络资源加载的拒绝服务漏洞 CVE-2024-2874。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljuaFSo6043c6GeS8s1vLmO6KhRMGS3RemCsckUiaokkHtzVM8nJQdC2cGkB0SnRxnmZSm9FOL7eDA/640?wx_fmt=jpeg&from=appmsg "")  
  
## GitLab 安全漏洞频出  
  
众所周知，GitLab 存放着包括 API 密钥、专有代码等各种类型的敏感数据，因此早就成为了很多威胁攻击组织眼中的”香饽饽“。一旦有威胁攻击者成功在 CI/CD（持续集成/持续部署）环境中插入恶意代码，破坏组织的资源库，那么被劫持的 GitLab 账户就会面临着重大的网络安全风险，甚至引发严重供应链攻击。  
  
早些时候，CISA 曾经发出警告，威胁攻击者目前正积极利用 GitLab 在 1 月份修补零点击账户劫持漏洞 CVE-2023-7028，漏洞允许未经认证的威胁攻击者通过密码重置接管 GitLab 账户。当时，Shadowserver 发现超过 5300 个在线暴露的 GitLab 漏洞实例（截止到目前仍旧有 2084  个的实例可以访问）。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljuaFSo6043c6GeS8s1vLmO2wFGezQ0NmNGXtklJI5OD3A5HvgQ7a4gTRwRATRm4XrLdosmqIbBgQ/640?wx_fmt=jpeg&from=appmsg "")  
  
2023 年 5月，GitLab 突然发布了 16.0.1 版紧急安全更新，解决了一个被追踪为 CVE-2023-2825 的严重性路径遍历漏洞，该漏洞 CVSS 评分10.0。  
  
据悉，CVE-2023-2825 漏洞源于路径遍历问题，当一个附件存在于至少五个组内嵌套的公共项目中时，未经认证的威胁攻击者便可以在服务器上读取任意文件。不仅如此，一旦成功利用 CVE-2023-2825 漏洞，还可能会非法访问包括专有软件代码、用户凭证、令牌、文件和其他私人信息在内的敏感数据。  
  
好消息是，CVE-2023-2825 漏洞问题与 GitLab 如何管理或解决嵌套在几级组层次结构中的附件文件的路径有关，因此安全漏洞只能在特定条件下才会触发，即当公共项目中有一个附件嵌套在至少五个组中时，好在这并不是所有 GitHub 项目遵循的结构。  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljuaFSo6043c6GeS8s1vLmONHhdc0aMVpFib9CEBLzTKe6IgprpMN6SzUr1OwCLFHLhy2HCDZIHyHA/640?wx_fmt=jpeg "")  
[【安全圈】ChatGPT 严重宕机，结果被造谣 “遭遇俄罗斯黑客入侵”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060477&idx=1&sn=34c7216f8dead66a1ca96d25900cf4c5&chksm=f36e177dc4199e6b5540c6b7611830c28d1de12d3e61936a41b9454a2ebdfbb38ed548dcb18f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtafx9Y8EsvLPGEWGUOEEPPa7OyIruF1tYNUsO1ryrLOMgvt4dqddtxbjsw90SWwf45IiafpPxtfg/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】隐私末日？微软 Windows 11“回忆功能”引发恐慌](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060477&idx=2&sn=bb3234ba8766049d5a06324b97e11c8c&chksm=f36e177dc4199e6b292bd10f43ff45285906f8b105736d474a5f8ac11a1c98eaba4ba248ada9&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljuaFSo6043c6GeS8s1vLmONxKZYtPFomSap9lEXJuwI4M8ofjZ2JvYmPTrcibM2JeJ42v5RPFX74A/640?wx_fmt=jpeg "")  
[【安全圈】曾遭国际刑警“联合围剿”金融木马 Grandoreiro 死灰复燃，瞄准 1500 多家银行发动攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060477&idx=3&sn=d0d00b8630f623729b430c30cb8cf630&chksm=f36e177dc4199e6b060c114175c3e5a051cac3d596496f927476615ac8065a7e77a1fa4870d7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljtafx9Y8EsvLPGEWGUOEEPj6OFWoibibzfT9xjrvRibZhju3rVpyASGClUNNOZCFOSRyhUicgMeuJaPQ/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】英特尔 AI 模型压缩器现满分漏洞，可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060477&idx=4&sn=9bce7bfcfe76a7430ab4f38562be2fbe&chksm=f36e177dc4199e6ba3ce3ee51b0965ab7b1c8400884943742b3367baa278b344954cba189a66&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
