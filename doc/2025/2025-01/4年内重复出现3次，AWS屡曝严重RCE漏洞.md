#  4年内重复出现3次，AWS屡曝严重RCE漏洞   
Zicheng  FreeBuf   2025-01-07 10:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
据Cyber Security News消息，因为Python 包安装过程方面的严重失误，Amazon Web Services （AWS） 在过去4年中通过其 Neuron SDK 3次引入了相同的远程代码执行 （RCE） 漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38rmg9xJmNnZ1MqNxribsANKeSfgqhicj0DOVL8L0zUwUDpVpJrdsNibN2jy2ycdOicGW5tyxyaBibP59g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该问题于 2022 年 4 月被发现，当时 Giraffe Security 标记了 AWS 的 Neuron SDK 中的一个漏洞，该开发工具包是一组 Python 库，可在 AWS 的专用硬件上启用机器学习工作负载。  
  
  
该问题源于 AWS 的官方安装说明和文档，其中建议使用如下命令：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38rmg9xJmNnZ1MqNxribsANKjoicJ5QnYwFfevOfqFn0xAjB9e1VrX31yWxDsysxcFqMMCBMBoPmyog/640?wx_fmt=png&from=appmsg "")  
  
  
乍一看，该命令似乎很简单，指示 Python 的软件包管理器从特定于 AWS 的存储库安装软件包。  
但是，这种方法包含根植于如何处理参数的隐藏危险。  
  
  
该参数并不专门将包下载限制为指定的私有存储库，相反，它允许在默认的公共 PyPi 存储库中搜索包，如果在指定索引中找不到包，执行退回操作。这会产生一个严重漏洞：攻击者可以将同名的包上传到 PyPi，诱骗用户下载和执行恶意代码。  
  
  
2022年， Giraffe Security 通过在 PyPi 上声明未受保护的 AWS 软件包名称（如 mx-neuron）确认了这一漏洞，并通过 AWS 的漏洞赏金计划报告了这一漏洞。AWS 迅速解决了这个问题做出反应，防止了进一步的利用。然而，问题的根源——对 --extra-index-url 参数的错误依赖仍未得到解决。  
  
  
2022 年的进一步研究显示，这并非此类漏洞的首次出现。来自开源软件数据库 libraries.io 的历史数据显示，AWS 的 torch-neuron 软件包在 2020 年也曾暴露过类似的漏洞，这表明也曾出现过同样的依赖关系混乱风险。当时，一名安全研究人员将该程序包的多个版本上传到 PyPi 以突出显示该漏洞，迫使 AWS 采取纠正措施。  
  
  
尽管已多次发出警告并进行了修复，但 Giraffe Security 在 2024 年 12 月进行的最新调查显示，AWS 再次引入了相同的漏洞。  
  
  
Amazon 一再的失误引发了人们的质疑。一方面，Amazon 对过去漏洞报告的快速反应表明确实有认真对待漏洞，但同样的漏洞反复出现，说明缺乏系统性的防范流程。这种情况凸显了一个重要的安全教训：即使是像 AWS 官方文档这样的可信来源也不一定安全。  
  
  
虽然这个反复出现的问题看似是一个小众漏洞，但它对云生态系统的安全具有更广泛的影响。依赖关系混乱攻击已成为一个日益令人担忧的问题，尤其是当越来越多的组织依赖于私有软件包注册中心、PyPi 或 npm 等公共软件源的情况下。降低这些风险的责任不仅在于最终用户，也在于 AWS 等服务提供商，他们必须确保其工具和文档遵循安全最佳实践。  
  
  
尽管 Giraffe Security 曾多次尝试联系亚马逊以征求意见，但一直没有得到回应。作为全球最大的云服务提供商之一，AWS 在这一事件中未拿出强有力永久性解决方案的情况颇令人意外。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
