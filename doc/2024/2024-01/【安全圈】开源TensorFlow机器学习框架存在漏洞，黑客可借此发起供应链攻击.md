#  【安全圈】开源TensorFlow机器学习框架存在漏洞，黑客可借此发起供应链攻击   
 安全圈   2024-01-20 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
黑客攻击  
  
  
在开源TensorFlow机器学习框架中发现的持续集成与持续交付（CI/CD）配置错误，可能被利用来发起供应链攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00dEdrt4RYOlibtHN2sLxkXIFR2sIn7COBGbtKTPPFeb0319KibJw6rErQ/640?wx_fmt=jpeg&from=appmsg "")  
  
TensorFlow 是谷歌的开发者创造的一款开源的深度学习框架，于 2015 年发布。TensorFlow 现已被公司、企业与创业公司广泛用于自动化工作任务和开发新系统，其在分布式训练支持、可扩展的生产和部署选项、多种设备（比如安卓）支持方面备受好评。  
  
Praetorian的研究员Adnan Khan和John Stawinski在本周发布的一份报告中表示，这些配置错误可能被攻击者利用来“通过恶意拉取请求（pull request），在GitHub和PyPi上对TensorFlow版本实施供应链妥协，从而危及TensorFlow的构建代理”，  
  
通过利用这些漏洞，攻击者可将恶意版本上传到GitHub仓库，并获得自托管GitHub运行器（runner）上的远程代码执行权限，甚至检索tensorflow-jenkins用户的GitHub个人访问令牌（PAT）。  
  
TensorFlow使用GitHub Actions自动化软件构建、测试和部署流程。运行器指的是执行GitHub Actions工作流中任务的机器，可以自托管，也可以由GitHub托管。  
  
GitHub在其文档中写道，“建议用户仅在私有仓库中使用自托管运行器，因为公共仓库的分支可能通过创建执行危险代码的工作流拉取请求，在您的自托管运行器机器上运行潜在危险的代码。”  
  
换言之，这允许任何贡献者通过提交恶意拉取请求，在自托管运行器上执行任意代码。然而，这并不会对GitHub托管的运行器构成任何安全问题，因为每个运行器都是短暂的，并且是一个干净、隔离的虚拟机，在任务执行结束后就会被销毁。  
  
Praetorian表示，它能够识别在自托管运行器上执行的TensorFlow工作流，随后发现以前的贡献者提交的分支拉取请求自动触发了相应的CI/CD工作流，且无需批准。  
  
因此，一个想要对目标仓库进行木马化的攻击者的操作是这样的，他会修正一个拼写错误或进行一个小但合法的代码更改，为此创建一个拉取请求，然后等待拉取请求被合并，以成为一个贡献者。这将使他们能够在创建恶意拉取请求时执行代码，而不会引起任何警告。  
  
进一步检查工作流日志显示，自托管运行器不仅是非短暂性的（从而为持久性打开了大门），而且与工作流相关的GITHUB_TOKEN权限包含了广泛的写权限。  
  
研究人员指出“因为GITHUB_TOKEN拥有contents:write权限，它可以上传版本到  
  
https://github[.]com/tensorflow/tensorflow/releases/，攻击者如果危及这些GITHUB_TOKEN，就可以在发布资产中添加他们自己的文件。”而contents:write权限可以被用来直接向TensorFlow仓库推送代码，通过秘密地将恶意代码注入到一个特性分支，并将其合并到主分支。  
  
不仅如此，一个威胁行为者还可以窃取，在发布工作流中用于认证Python包索引（PyPI）注册表的AWS_PYPI_ACCOUNT_TOKEN，并上传一个恶意的Python .whl文件，以便有效地污染包。  
  
“攻击者还可以利用GITHUB_TOKEN的权限来危及JENKINS_TOKEN仓库密钥，尽管这个密钥并未在自托管运行器上运行的工作流中使用。”  
  
随着越来越多的组织自动化他们的CI/CD流程，类似的CI/CD攻击正在上升。“人工智能/机器学习公司尤其脆弱，因为他们的许多工作流需要大量的计算能力，这在GitHub托管的运行器中是不可用的，因此自托管运行器很普遍。”  
  
这一披露是在两位研究员揭示了包括与Chia网络、微软DeepSpeed和PyTorch相关的多个公共GitHub仓库，都容易受到通过自托管GitHub Actions运行器注入恶意代码的攻击。  
  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya0051r7IJm4aicYgUlwjNszJQDCew2ibqoG8bZ72ovHcPh5sj20X05ART0w/640?wx_fmt=jpeg "")  
[【安全圈】富士康集成技术公司遭遇黑客攻击，威胁其支付百万赎金或被公开数据](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052513&idx=1&sn=991c6143b0bd6ac8ecae44b3525fca2b&chksm=f36e3061c419b9772aec6d65d59144f44893aee0748652a39fe574249c4830882bc58e92210f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00JVwZYKkhH5a6JTDvqNjEOfgkbgcpHPVfFK7gW5S3FdV1Lhe56wgndg/640?wx_fmt=jpeg "")  
[【安全圈】因配置错误和安全漏洞，丰田保险公司客户信息遭泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052513&idx=2&sn=b0a5d07f59d75edef89bc1c7052de1ff&chksm=f36e3061c419b977332edb7a6145811241b15a7e61a9759592a776e74a6e57c50e2e703ef843&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00CRMss99yqL7VV3iadPmiaNxxAeswYDa71cUNbh5kAdjNRyY83mRbwaow/640?wx_fmt=png&from=appmsg "")  
[【安全圈】2.83G ！知名国防企业萨博公司内部数据遭泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052513&idx=3&sn=df055ccfe238b60eae30abbaa55c1a04&chksm=f36e3061c419b97709b68435f2da97ec2a3d6de406d1ad24e25527d0628783fec5ee0b82309a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylh8EibTnpJxMCIp1oZs3Ya00sPMXlXG5KpagsIhfIDSbuNTcUulXdyss5JxmZSic5eNgIBjkRXuQePA/640?wx_fmt=jpeg "")  
[【安全圈】CISA 警告 Ivanti EPMM 漏洞正在被广泛利用](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652052513&idx=4&sn=dd56c5eb73fdfbb54c49b7bb7128aaf8&chksm=f36e3061c419b977e44376f0c27224f874c1e6361b5df34021fe5ac622c0f6bb9031af236432&scene=21#wechat_redirect)  
  
  
  
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
  
  
