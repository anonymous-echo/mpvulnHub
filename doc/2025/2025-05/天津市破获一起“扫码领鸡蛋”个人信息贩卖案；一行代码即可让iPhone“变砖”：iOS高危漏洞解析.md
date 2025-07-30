#  天津市破获一起“扫码领鸡蛋”个人信息贩卖案；|一行代码即可让iPhone“变砖”：iOS高危漏洞解析   
 黑白之道   2025-05-05 00:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**天津市破获一起“扫码领鸡蛋”个人信息贩卖案；**  
  
  
据公安部网安局官方公众号，近期天津市侦破一起个人信息诈骗案件，不法分子打着“注册账号，花 1 块钱领 1 斤鸡蛋”，“注册账号，一天 150 元”旗号，以蝇头小利骗取公民个人信息贩卖获利。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgvN8bWrliaHIVwDWFSLgS9spfIuIqdiamDa3AsKGy3sLN1Ov9mwvbDpcgeq5OYDlxG9NNytkicFr53Q/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
IT之家参考相应通报获悉，犯罪团伙成员李某、赵某等人在天津市东丽区多个社区超市、农贸市场、劳务市场等区域，冒充大型互联网公司工作人员，打着 App 推广活动的幌子，**以低价购买鸡蛋、兼职招聘等形式，诱骗老年人、外来务工人员注册并且实名认证各大互联网平台网络账号**  
，骗取公民个人信息向下游犯罪团伙贩卖，获利数十万元。  
  
2024 年 7 月，天津市东丽区公安机关将以李某为首的十余人犯罪团伙抓获归案，查获身份证件信息、实名网络账号等各类公民身份信息一批。2024 年底，**天津市东丽区人民法院依法对李某等犯罪团伙成员以侵犯公民个人信息罪判处有期徒刑一年至三年不等**  
。  
  
警方表示，向他人出售或者提供公民个人信息者，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。街头“扫码领鸡蛋”、“扫码抢红包”暗含各种隐患，民众绝不应当贪图此类蝇头小利，应守住个人信息，避免令自己沦为骗子的“提款机”。  
  
**一行代码即可让iPhone“变砖”：iOS高危漏洞解析**  
  
  
iOS系统存在一个高危漏洞（CVE-2025-24091），恶意应用仅需执行一行代码即可永久禁用iPhone。该漏洞通过操作系统的Darwin通知机制触发无限重启循环，导致设备"变砖"，必须通过完整系统恢复才能修复。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icbm1QXk9w6O9EM8c0VvZicmhia9IcxLTuqWX9ThtlxCgz4rYNZibwxibS9xyMQVOTxMR7RvexgQ5vpiag/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
  
**01**  
  
  
  
**Darwin通知系统漏洞分析**  
  
  
该漏洞利用了  
CoreOS  
层的底层消息机制——Darwin通知。与常见的NSNotificationCenter或NSDistributedNotificationCenter不同，Darwin通知属于苹果操作系统的遗留API（  
应用程序接口  
），工作在系统底层。  
  
  
发现该漏洞的安全研究员Guilherme Rambo解释："Darwin通知更为基础，属于CoreOS层组件，为苹果系统进程间提供简单的底层消息交换机制。"  
  
  
漏洞的关键在于：iOS上的任何应用都无需特殊权限即可发送敏感的系统级Darwin通知。最危险的是，这些通知能触发包括"进入恢复模式"在内的强力系统功能。  
  
  
**02**  
  
  
  
**一行代码的攻击实现**  
  
  
攻击代码异常简单，仅需执行以下单行指令即可触发漏洞：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icbm1QXk9w6O9EM8c0VvZicmXgUCIwjgt36lEtoGqwMgWp0PRgqvr4nZJ8t4pHSbgFicyicfaaKx46YA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
执行后设备将强制进入"恢复中"状态。由于实际未进行恢复操作，该过程必然失败并提示用户重启设备。研究人员创建了名为"VeryEvilNotify"的概念验证攻击，将漏洞利用代码植入小组件扩展。  
  
  
研究员指出："iOS会定期在后台唤醒小组件扩展。由于小组件在系统中使用广泛，当安装并启动包含小组件扩展的新应用时，系统会非常积极地执行其小组件扩展。"  
  
  
通过将漏洞代码植入发送通知后反复崩溃的小组件，研究人员构建了持久性攻击——每次重启后都会触发攻击，形成使设备无法使用的无限循环。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icbm1QXk9w6O9EM8c0VvZicm5zJt6ppn4o8QnTVibPm9cJibP9UInsHRuBHN7ibGhuia3cgJB1jm3uhCPQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
  
**03**  
  
  
  
**修复方案**  
  
  
苹果在iOS 18.3中通过实施新的敏感Darwin通知授权机制修复该漏洞，并向研究员支付了7500美元漏洞赏金。  
具体措施包括：  
- 系统通知现在必须包含"com.apple.private.restrict-post."前缀  
  
- 发送进程需持有"com.apple.private.darwin-notification.restrict-post."格式的受限授权  
  
这并非苹果系统首次出现Darwin相关漏洞。此前  
卡巴斯基实验室  
曾发现"Darwin Nuke"漏洞，攻击者可通过特制网络数据包发起远程  
拒绝服务攻击  
。  
  
  
强烈建议所有iPhone用户立即升级至iOS 18.3或更高版本。早期版本设备仍面临攻击风险，攻击可能通过App Store或其他渠道分发的看似无害的应用或小组件实施。  
  
  
该案例凸显了移动操作系统持续面临的安全挑战——即使简单且被忽视的遗留API，若未妥善保护也可能构成重大风险。  
  
  
  
> **文章来源 ：公安部网安局、freebuf******  
  
  
**精彩推荐**  
  
  
  
  
# 乘风破浪|华盟信安线下网络安全就业班招生中！  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575781&idx=2&sn=ea0334807d87faa0c2b30770b0fa710d&chksm=83bdf641b4ca7f5774129396e8e916645b7aa7e2e2744984d724ca0019e913b491107e1d6e29&scene=21#wechat_redirect)  
  
  
# 【Web精英班·开班】HW加油站，快来充电！  
  
  
‍[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650594891&idx=1&sn=b2c5659bb6bce6703f282e8acce3d7cb&chksm=83bdbbafb4ca32b9044716aec713576156968a5753fd3a3d6913951a8e2a7e968715adea1ddc&scene=21#wechat_redirect)  
  
  
‍  
# 始于猎艳，终于诈骗！带你了解“约炮”APP  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575222&idx=1&sn=ce9ab9d633804f2a0862f1771172c26a&chksm=83bdf492b4ca7d843d508982b4550e289055c3181708d9f02bf3c797821cc1d0d8652a0d5535&scene=21#wechat_redirect)  
  
**‍**  
  
  
