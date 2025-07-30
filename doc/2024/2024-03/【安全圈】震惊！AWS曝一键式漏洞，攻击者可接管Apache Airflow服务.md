#  【安全圈】震惊！AWS曝一键式漏洞，攻击者可接管Apache Airflow服务   
 安全圈   2024-03-25 19:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
近日AWS修复了一个关键漏洞，通过利用该漏洞，攻击者可直接接管亚马逊Apache Airflow（MWAA）托管工作流。该漏洞危害较大，虽然利用起来比较复杂，但扔建议及时进行修复。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj95OQ1KFK2sSfEbjpR0H4sTjtAO3sWCUHPZDJWzqU3XFEbaXvGRc2C1wobEsUoKeWWq7zrKMRZVg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
网络安全公司Tenable披露AWS 一个严重的安全漏洞，将之命名为FlowFixation，攻击者可借此完全控制客户在AWS服务上的账户。AWS承认漏洞存在，并表示该漏洞利用较为困难，且已经在几个月前进行修复，建议用户更新补丁。  
  
Tenable在报告中强调，通过研究发现了一个更加严重、广发的安全问题，并且可能在不久的未来造成伤害。  
  
Apache Airflow托管工作流(MWAA)是亚马逊推出的一项全托管的服务，简化了在 AWS 上运行开源版 Apache Airflow，构建工作流来执行 ETL 作业和数据管道的工作。  
  
Apache Airflow 是一个开源工具，每月下载量达到1200万次，用于通过编程的方式开发、调度和监控被称为“工作流”的过程和任务序列。开发人员和数据工程师用 Apache Airflow 管理工作流，通过用户界面(UI)来监控它们，并通过一组强大的插件来扩展它们的功能。但是，要使用 Apache Airflow，需要进行手动安装、维护和扩展，AWS 解决了这个问题，它为开发人员和数据工程师提供了 MWAA，让他们可以在云端构建和管理自己的工作流，无需关心与管理和扩展 Airflow 平台基础设施相关的问题。  
  
由于MWAA网络管理面板中的会话是固定的，以及AWS域名配置错误可引发跨站脚本攻击（XSS），让FlowFixation漏洞可以实现接管MWAA。  
  
Tenable指出，攻击者可利用该漏洞强迫受害者使用并认证其已知的会话，随后利用已经认证的会话接管受害者的网络管理面板。这一步骤完成后，攻击者将可进行更进一步的入侵动作，包括读取连接字符串、添加配置、触发有向无环图等。此时他可以对底层实例执行远程代码攻击或进行其他横向移动。  
  
Tenable研究还揭示一个更广泛的问题，即共享父域和公共后缀列表（PSL）相关的同站点攻击。而由同一供应商提供云服务往往会共享一个父域，例如多个AWS服务共同使用“amazonaws.com”。这种共享导致了一个攻击场景，攻击者可对在“amazonaws.com”共享父域的子域资产发起攻击。  
  
Tenable解释称，在本地环境中，你通常不会允许用户在子域上运行XSS，但在云上允许却是一个非常自然的操作。例如当用户创建一个AWS S3存储桶时，可以通过存储桶中的HTML页面来运行客户端代码；代码可以在S3存储桶子域的上下文中运行，自然也在共享父域“amazonaws.com”的上下文中运行。  
  
也有研究显示，该风险不仅仅存在于AWS，Azure/Google Cloud等共享父服务域被错误配置，即域名没有出现在PSL上，那么客户也将面临相应的攻击风险，包括cookie tossing、同站点cookie保护绕过等。  
  
AWS和微软都已经采取了措施来减轻Tenable报告中的风险。AWS发言人Patrick Neighorn表示，AWS在2023年9月对上述风险进行修复，因此运行当前版本的Amazon托管工作流Apache Airflow（MWAA）的客户不会受到影响。在2023年AWS已经通知并督促用户通过AWS控制台、API或AWS命令行界面进行更新修复。  
  
   
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljGr6WSPj3FpmyPAicSZakzLtWu0oWXgrP1vy5KSld02wd0AOsvGLGLCFMyb3VVETIxb2eC2OiaKO2w/640?wx_fmt=png&from=appmsg "")  
[【安全圈】同盾科技及多名高管涉侵犯公民个人信息被提起公诉](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056367&idx=1&sn=7947be1618298ae5303d77efbc12695c&chksm=f36e076fc4198e79e6f42e961cbdfc6308e301770388930f6eeacdad471d5fdfbaa07d675b81&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj95OQ1KFK2sSfEbjpR0H4spmmGuNNxV9dT8BibyYHmk19oib1iajiaoTpJicH770ZPTKm0fJ3NPsBSoOQ/640?wx_fmt=jpeg "")  
[【安全圈】事关个人信息安全，这些App存在隐私不合规行为](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056367&idx=2&sn=d6897f027689abbe3d2cabe8ab5ca96a&chksm=f36e076fc4198e790c8ccd22e215881f3336df4c8201038d641588fcf0b6b67ad416c8ae2ce0&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj95OQ1KFK2sSfEbjpR0H4sh95lic9R4PWcxibQY6DB8jXlhxhvrfpQsds7O9lgTkUfbFFzxgysPDHQ/640?wx_fmt=jpeg "")  
[【安全圈】 3.9 万个 WordPress 网站遭Sign1 恶意软件感染](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056367&idx=3&sn=d416f4cabc38ca8e896eb7425f78af85&chksm=f36e076fc4198e79bd4b70dcf792a01a5a2dd037e98d50f5c7a309eddf6bba243ab405fd85d4&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj95OQ1KFK2sSfEbjpR0H4srVnewo59kOvXaEUrGicXKXuGZ0pq4MUvuz2Ym7HXfdFVuzduPoch62A/640?wx_fmt=jpeg "")  
[【安全圈】苹果 Apple Silicon 芯片被曝安全漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652056367&idx=4&sn=77218186bd8b695558705b716f6cbc23&chksm=f36e076fc4198e794df890fc182268f49776f460285135cf0a362b9bf989554fc5894cff04de&scene=21#wechat_redirect)  
  
  
  
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
  
