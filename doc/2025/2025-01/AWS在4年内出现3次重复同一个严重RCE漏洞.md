#  AWS在4年内出现3次重复同一个严重RCE漏洞   
原创 何威风  祺印说信安   2025-01-07 00:10  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rTibWNx9ARWm6QPQrNAW6Z6aNicTGH77EPdHlJoKlXhXXImTbh01feAMkNdKWfSDmOSnV9VxjMraia178Ob2c5nicg/640?wx_fmt=png&from=appmsg "")  
  
过去四年中，亚马逊网络服务 (AWS) 通过其 Neuron SDK 三次引入相同的远程代码执行 (RCE) 漏洞，凸显其 Python 包安装过程的安全保护存在严重失误。  
  
尽管之前已经发出警告并进行了修复，但同样的依赖混淆漏洞在其软件生态系统中随着新软件包的发布再次出现。  
  
该问题最早是在 2022 年 4 月  
发现的  
，当时 Giraffe Security 标记了 AWS 的 Neuron SDK 中的一个漏洞。Neuron SDK 是一组 Python 库，用于在 AWS 的专用硬件上支持机器学习工作负载。  
  
该问题源于 AWS 的官方安装说明和文档，其中推荐了如下命令：  
```
pip install transformers-neuronx --extra-index-url=https://pip.repos.neuron.amazonaws.com
```  
  
乍一看，该命令似乎很简单，指示 Python 的包管理器  
从 AWS 特定的存储库 ( )pip  
安装包。然而，这种方法在如何  
处理参数方面  
存在隐患。transformers-neuronx  
https://pip.repos.neuron.amazonaws.com  
pip  
## 技术问题  
  
该--extra-index-url  
参数并不专门限制包下载到指定的私有存储库。  
  
相反，它允许pip  
在默认的公共  
PyPi 存储库  
中搜索包，如果在指定的索引中找不到包，则返回该存储库。这会产生一个严重的漏洞：恶意行为者可以将同名的包上传到 PyPi，诱骗用户下载并执行恶意代码。  
  
2022 年，Giraffe Security 通过声明mx-neuron  
PyPi 上未受保护的 AWS 软件包名称并通过 AWS 的漏洞赏金计划报告该漏洞证实了此漏洞。  
  
AWS 迅速解决了这个问题，将受影响软件包的占位符“虚拟”版本上传到 PyPi，防止进一步利用。然而，根本原因——对参数的错误依赖--extra-index-url  
——仍未得到解决。  
### 忽视的模式：2020 年和 2022 年  
  
2022 年的进一步研究表明，这并不是此类漏洞的首次出现。开源软件数据库 libraries.io 的历史数据显示，AWS 的torch-neuron  
软件包在 2020 年也曾遭遇过类似的暴露，这表明同样的依赖项混淆风险在更早之前就存在过。  
  
当时，一位安全研究人员已将该软件包的多个版本上传到 PyPi 以突出显示该缺陷，迫使 AWS 采取纠正措施。  
  
尽管 AWS 至少从 2020 年就已经意识到了这个问题，但 AWS 未能实施持久的解决方案，导致 2022 年漏洞再次暴露。  
## 帽子戏法：2024 年发现  
  
尽管多年来多次警告和修复，但 Giraffe Security 在 2024 年 12 月的最新调查显示，AWS 再次引入了同样的漏洞。  
  
Neuron SDK 的私有软件包索引已大幅扩展，但 AWS 却忽视了在 PyPi 上预先声明新增软件包名称。这使得 Giraffe Security 能够成功地将一些新软件包名称注册到自己的 PyPi 帐户下 — — 这清楚地表明 AWS 未能从过去的错误中汲取教训。  
  
亚马逊屡屡失误，让人怀疑其解决这一问题的方法。一方面，他们对过去报告的快速反应表明他们非常重视这一漏洞。然而，同一漏洞的再次出现表明缺乏系统性流程来防止它。  
  
造成这种疏忽的原因可能有很多种：  
1. **文档错误：**  
 AWS 可能会将此视为客户错误解释其文档而导致的配置问题。虽然经验丰富的 Python 开发人员意识到了相关风险--extra-index-url  
，但 AWS 在官方教程中对此参数的依赖可以说是误导性的。  
  
1. **低优先级问题：**  
 AWS 可能认为该问题并不严重，认为客户有责任确保其安装的安全。然而，这种立场忽略了 AWS 的官方文档直接导致了该问题。  
  
这种情况强调了一个重要的安全教训：即使是像官方 AWS 文档这样的可信来源也难免会出现错误。  
  
开发人员应始终仔细检查并充分了解软件包安装过程，然后再将其应用于生产系统。应考虑  
更安全的替代方案，例如使用--index-url  
参数将下载限制为仅下载到私有存储库或利用  
Poetry等现代软件包管理器。  
  
虽然这个反复出现的问题看起来像是一个小众漏洞，但它对云生态系统的安全具有更广泛的影响。  
  
依赖混淆攻击已经成为一个日益严重的问题，特别是随着越来越多的组织依赖私有包注册表以及 PyPi 或 npm 等公共存储库。  
  
降低这些风险的责任不仅在于最终用户，也在于 AWS 等服务提供商，他们必须确保其  
工具  
和文档遵循安全最佳实践。  
## AWS 的沉默  
  
尽管多次尝试联系亚马逊寻求评论，但 Giraffe Security 尚未收到回复。作为全球最大的云提供商之一，AWS 在本案中缺乏强大而永久的解决方案令人惊讶，尤其是考虑到其以优先考虑安全性而闻名。  
  
AWS 屡屡未能解决其 Neuron SDK 中相同的 RCE 漏洞，凸显了安全流程中令人担忧的漏洞。虽然对个别报告的即时修复非常迅速，但缺乏对潜在问题的永久解决方案仍然令人担忧。  
  
— **欢迎关注 往期回顾**  
 —  
  
[精彩回顾：祺印说信安2024之前](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103882&idx=1&sn=fe68b43898a872f40e66a8cdb720d7d7&chksm=8bbccef3bccb47e5bd52249ff6490fe17df9696568053776e4124ef70d790a5ed06f2d3c6809&scene=21#wechat_redirect)  
  
  
[祺印说信安2024年一年回顾](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652113685&idx=1&sn=d3320d1235049cfe41884d009ec597cc&scene=21#wechat_redirect)  
  
  
**——数据安全**  
  
[《网络数据安全管理条例》解读](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652113680&idx=1&sn=86da41ae8e79d457e121599e64b266f3&scene=21#wechat_redirect)  
  
  
**——错与罚**  
  
江苏涟水农村商业银违反网络安全与数据安全管理规定等被罚114.5万  
  
江苏灌南农商行因违反数据安全管理规定等被罚97.5万  
  
网安企业“内鬼”监守自盗，窃取个人信息2.08亿条  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103528&idx=1&sn=fef657b5a0e1982eff81b5c92f33db57&chksm=8bbcc951bccb4047211ef41c22541966c1c25dbee9f79c45e1e429fb485f675b706babdcf347&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652100366&idx=1&sn=27d04d1abc7a02a6b731322416805a1a&chksm=8bbcfd37bccb7421ab6f679bd83b34e02c930e2beca304844ee59a8843d5b18df1bf52d4e032&scene=21#wechat_redirect)  
  
