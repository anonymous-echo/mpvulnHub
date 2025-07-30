#  【安全圈】新的 OpenSSH 漏洞可能导致 Linux 系统以 Root 身份进行 RCE   
 安全圈   2024-07-06 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
OpenSSH 维护人员发布了安全更新，以修复一个严重的安全漏洞，该漏洞可能导致基于 glibc 的 Linux 系统中以 root 权限执行未经身份验证的远程代码。  
  
该漏洞代号为 regreSSHion，CVE 标识符为 CVE-2024-6387。它位于OpenSSH 服务器组件（也称为 sshd）中，用于监听来自任何客户端应用程序的连接。  
  
Qualys 威胁研究部门高级主管 Bharat Jogi 在今天发布的一份披露文件中表示：“该漏洞是 OpenSSH 服务器 (sshd) 中的信号处理程序竞争条件，允许在基于 glibc 的 Linux 系统上以 root 身份进行未经身份验证的远程代码执行 (RCE) 。该竞争条件会影响默认配置下的 sshd。”  
  
该网络安全公司表示，已发现至少 1400 万个暴露在互联网上的潜在易受攻击的 OpenSSH 服务器实例，并补充说，这是一个已修补的 18 年前的漏洞（跟踪号为CVE-2006-5051）的回归，该问题于 2020 年 10 月作为 OpenSSH 版本 8.5p1 的一部分重新出现。  
  
OpenSSH 在一份公告中表示：“已证明在具有 [地址空间布局随机化]的 32 位 Linux/glibc 系统上可成功利用该漏洞。在实验室条件下，攻击平均需要 6-8 小时的连续连接，直至达到服务器可接受的最大连接时长。”  
  
该漏洞影响 8.5p1 和 9.7p1 之间的版本。4.4p1 之前的版本也容易受到竞争条件漏洞的影响，除非它们针对 CVE-2006-5051 和CVE-2008-4109进行了修补。值得注意的是，OpenBSD 系统不受影响，因为它们包含阻止该漏洞的安全机制。  
  
该安全漏洞很可能也会影响 macOS 和 Windows，尽管其在这些平台上的可利用性仍未得到证实，需要进一步分析。具体来说，Qualys 发现，如果客户端在 120 秒内未进行身份验证（由 LoginGraceTime 定义的设置），则 sshd 的 SIGALRM 处理程序将以非异步信号安全的方式异步调用。  
  
利用 CVE-2024-6387 的最终结果是完全系统入侵和接管，使威胁行为者能够以最高权限执行任意代码、破坏安全机制、窃取数据，甚至保持持续访问。  
  
“漏洞一旦修复，又会在后续软件版本中再次出现，这通常是由于更改或更新无意中再次引入了该问题，”Jogi 说道。“这起事件凸显了彻底的回归测试在防止已知漏洞再次引入环境中的关键作用。”  
  
虽然该漏洞由于其远程竞争条件性质而存在重大障碍，但建议用户应用最新补丁以防范潜在威胁。还建议通过基于网络的控制来限制 SSH 访问，并实施网络分段以限制未经授权的访问和横向移动。  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhhhIj2uHnLF4jiao0zsoa5iaDic1icQVfJicqe5kcjlk6nkRRFrdibufYOicnsSOOlmfsFuibenIRe8s6LNA/640?wx_fmt=jpeg "")  
[【安全圈】日本动漫游戏巨头Kadokawa遭勒索软件攻击，数据泄露多达 1.5TB](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062621&idx=1&sn=cb8910b6f52242567577dcabd399e145&chksm=f36e6fddc419e6cbf8763a15850c43dc83e702c92e294ce63bc99083cb746febd60f683a0c19&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaZFib8gVe2eDt6IvvzYYsuUdeczkrgmQiaLFsEII5GGZQEibZoNp4ENV00sr5jMm3t7KLLCEUdpKVHQ/640?wx_fmt=jpeg "")  
[【安全圈】国际行动关闭了 593 台恶意 Cobalt Strike 服务器](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062621&idx=2&sn=fda4c58f2be7e09f99eaafd4684fee56&chksm=f36e6fddc419e6cb6f20413597452ca046b8669fcec3cb00e772a8b4ae3b4593b472e188aa2a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaZFib8gVe2eDt6IvvzYYsuUw7BA2Sicew28ibwn9n6tvcQoibUw3ZgNicUlu2WQbgiaoAjfZcddFI0VM3w/640?wx_fmt=jpeg "")  
[【安全圈】黑客滥用 API 端点验证了数百万个Authy MFA 电话号码](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062621&idx=3&sn=9fbb95cd5933a4310d84324e09bace04&chksm=f36e6fddc419e6cb9a6c050e5f758a603ecd9d5163c96621234ef305a69082edfd923f563376&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaZFib8gVe2eDt6IvvzYYsuUIKG8wlFeliaGuOtnnlGTPzaK2dXcO4dw5iaibIMibTic66TxiaLoJgRYx21g/640?wx_fmt=other "")  
[【安全圈】已发布补丁！微软披露 Rockwell PanelView Plus 两大漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652062621&idx=4&sn=a0d960abf9bef0212c3233e0d087d087&chksm=f36e6fddc419e6cbac4da04016c102c6761cbac09c8d6209f0013d3417898c3fd61c22875869&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
