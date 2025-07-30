#  【安全圈】“幽灵漏洞”阴魂不散，v2 衍生版被发现：影响英特尔 CPU + Linux 组合设备   
 安全圈   2024-04-11 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
系统漏洞  
  
  
还记得 2018 年曝出的严重处理器“幽灵”（Spectre）漏洞吗？网络安全专家近日发现了 Spectre v2 衍生版本，利用新的侧信道缺陷，  
主要影响英特尔处理器 + Linux 发行版组合设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgm7BPNz5YicMF3LWPzQfvNGFN1iajly8ElgCWRwXo7Bs390bpaUIl7Bsn85DicIMGDeKPcas6FpW0ibQ/640?wx_fmt=jpeg&from=appmsg "“幽灵漏洞”阴魂不散，v2 衍生版被发现：影响英特尔 CPU + Linux 组合设备")  
  
阿姆斯特丹 VU VUSec 安全团队报告了 Spectre v2 漏洞，此外还发布了检测工具，利用符号执行来识别 Linux 内核中可被利用的代码段，以帮助减轻影响。  
  
现阶段很难有效修复 Spectre v2 漏洞，这和处理器现有的推测执行（Speculative execution）机制有关。  
  
推测执行是一种性能优化技术，现代处理器会猜测下一步将执行哪些指令，并提前执行从而加快响应速度。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgm7BPNz5YicMF3LWPzQfvNGfTDADvnbesVdSSSttSgU1dHQO6KP4Lrk8Y8sTo6UQTMrppdwQ3t9jQ/640?wx_fmt=jpeg&from=appmsg "“幽灵漏洞”阴魂不散，v2 衍生版被发现：影响英特尔 CPU + Linux 组合设备")  
  
处理器可以预测程序可能走过的多条路径，并同时执行这些路径。如果其中一个猜测是正确的，应用性能就会提高。如果猜测错误，CPU 就会丢弃之前的工作。  
  
推测执行机制固然可以提高性能，但会在 CPU 缓存中留下特权数据的痕迹，从而带来安全风险，从而给攻击者留下可乘之机，可能访问这些数据。  
  
这些数据可能包括账户密码、加密密钥、敏感的个人或企业信息、软件代码等。  
  
两种攻击方法是分支目标注入（BTI）和分支历史注入（BHI），前者涉及操纵 CPU 的分支预测来执行未经授权的代码路径，后者则操纵分支历史来导致所选小工具（代码路径）的投机执行，从而导致数据泄露。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgm7BPNz5YicMF3LWPzQfvNGTB7FzAObZPsoYARKZAA22viajicePCTTs9lpnJ4eUXFnPBx81veTfvmg/640?wx_fmt=jpeg&from=appmsg "“幽灵漏洞”阴魂不散，v2 衍生版被发现：影响英特尔 CPU + Linux 组合设备")  
  
针对 BTI 方式的追踪编号为 CVE-2022-0001，针对 BHI 方式的追踪编号为 CVE-2022-0002，而最新针对 Linux 的 Spectre v2 漏洞追踪编号为 CVE-2024-2201，官方表示黑客利用该漏洞，绕过旨在隔离权限级别的现有安全机制，读取任意内存数据。  
  
英特尔更新了针对 Spectre v2 的缓解建议，现在建议禁用非特权扩展伯克利数据包过滤器（eBPF）功能、启用增强型间接分支限制猜测（eIBRS）和启用监控模式执行保护（SMEP）。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgm7BPNz5YicMF3LWPzQfvNGias3pM8ZJ6JHGrcRzOKexukkNNkPIiaL0lfplJzhCmUf8icBVwNJ2vCaQ/640?wx_fmt=jpeg "")  
[【安全圈】北京警方成功侦破一起境内外勾连、利用黑客手段“开盒”曝光个人信息的网络犯罪案件](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057700&idx=1&sn=ccc0c31cd5a952ef0346deaf0b03302c&chksm=f36e1c24c41995327c5cc009d1d1c29c828e1f410a07978f6138d9f28a5577dc4da06f6f850f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgm7BPNz5YicMF3LWPzQfvNGwj66k524p6g3nnj0revFRU1V8ic9p2IBo5lyqx5ZKZwq81HWuQXkIEQ/640?wx_fmt=jpeg "")  
[【安全圈】“崩”上热搜！腾讯云回应](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057700&idx=2&sn=91e7428d8b5d40e9bccb7aff3bd7f657&chksm=f36e1c24c4199532d02592f1db41b21547e65afe0b71ad9ca8b77e61a9fba55c814e45b1325f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgm7BPNz5YicMF3LWPzQfvNGZ252BzdoWkPDiaMgWjGdlRzlbCoBCsg7FN2F7EPAdxvpUGjKxDzMskg/640?wx_fmt=jpeg "")  
  
[【安全圈】笔记本制造商 Targus 的文件服务器遭遇了网络攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057700&idx=3&sn=f0e8bfd0f9e3814f2100a376d4c04d1c&chksm=f36e1c24c4199532fff97ad7c84954a695aafd961d64c91bf5cf2532162e7467fb4bb2217d24&scene=21#wechat_redirect)  
      
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgm7BPNz5YicMF3LWPzQfvNGefWiaHwPudEEeZibxfv8yP7cZRBTsZEhy8g6miaaGICo0DATLLNUiciaTpA/640?wx_fmt=jpeg "")  
[【安全圈】英国莱斯特议会遭到网络攻击：数据泄露，敦促保持警惕](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652057700&idx=4&sn=a4bef4c8a4d69a43066b03aa054b3750&chksm=f36e1c24c4199532bf0203d73f256b1e2c4b04684f7b51f61a0b8fe02b984dc930cf41045d11&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
  
