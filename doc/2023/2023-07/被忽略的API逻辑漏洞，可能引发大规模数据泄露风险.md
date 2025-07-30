#  被忽略的API逻辑漏洞，可能引发大规模数据泄露风险   
原创 威胁猎人  威胁猎人Threat Hunter   2023-07-13 12:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4mAgZtBianqEAMZCKOk2hWqCfyHibLZbpsRxZEjfRuFptuU3ZwV5d1VLMglrldNwCwo76cJHqbfq08Vr7Y82zOZg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
事情要从2023年6月的某一天说起，  
  
安全研究员在审计业务风险蜜罐流量时，  
  
发现多条高风险预警，  
预警显示：  
  
多家第三方代理商的API存在大规模攻击行为，  
  
黑产对其业务站点下API发起频繁的恶意攻击，  
  
**敏感数据泄露规模达2500W+**。  
  
  
进一步研究调查发现，  
  
这些第三方代理商的多个API  
  
存在  
**参数可遍历、敏感数据伪脱敏**等缺陷，  
  
导致攻击者利用该缺陷进行自动化攻击爬取，  
  
涉及  
**用**  
**户手机号、身份证号**等敏感信息，  
  
可能会给用户带来电话骚扰甚至恶意欺诈  
风险。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4mAgZtBianqHntPiaftAWsTNfEcR9LpXAibKrf0NsTXZHK5scwc9DEwfwD3Y02VI2XOta1JWVriaiageGHPiaw3g6GGg/640?wx_fmt=jpeg "")  
  
  
安全研究员对攻击行为进行研究发现，  
  
攻击者通过API1接口可以获取到sign，  
  
API1：query/{int}  
  
由于API1存在  
**参数可遍历缺陷**  
，  
  
攻击者利用API1的这一缺陷遍历参数，  
  
拿到了不同的sign  
（加密字符串）。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4mAgZtBianqHhibZXe66C0am2scf6roeW493GfV7eWME6gnbXBFxPKarFZv2SUjIfQven3l8vKDhlsiaWCUSsLo3A/640?wx_fmt=jpeg "")  
  
  
  
  
随后攻击者在API2传入  
sign，  
  
API2：api/user/getUserInfo  
  
原本获取到的用户详细信息应该是脱敏的，  
  
由于API2存在  
**伪脱敏缺陷**，  
  
前端页面进行了脱敏展示，  
  
但API2返回的结果中可获取到明文数据，  
  
最终，攻击者利用API2的伪脱敏缺陷获取到大量用户敏感信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4mAgZtBianqFGSDoicCRH2Ep5tlzoF12TBW1nLHpAOAfGzoN5sibNTnUc0fXehSllboXG4jeVwGlgCw7Z0fCwn4ww/640?wx_fmt=png "")  
  
  
  
也就是说，攻击者利用平台存在的  
**两个API缺陷组合的逻辑漏洞**完成了这次攻击，成功爬取用户敏感信息。通过对攻击路径分析发现，攻击者在进行数据爬取时，会  
**选择使用动态的代理IP进行攻击**，达到隐蔽自身身份，以及绕过企业针对IP的限频限量的风控策略的目的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4mAgZtBianqEudibg7EQI60HDKo1PoRWSvzVsUjoX5FO1STuZwAQiccaP8eY7eTe42kQ7IVZqDogiccF5BaG40zXkg/640?wx_fmt=png "")  
  
  
  
同时，威胁猎人通过对**“暗网、黑产论坛、匿名聊天平台”**等黑产交易渠道的情报监测，发现大量第三方代理商的敏感数据正在被交易，字段包括“用户姓名、身份证、电话号码”等。  
  
  
  
  
**由两个不起眼的API缺陷组合的逻辑漏洞**，引发了大规模数据泄漏，其泄露量级令人触目惊心。  
  
  
早在2021年6月，国内某网购平台由于**两个API组合的逻辑漏洞**，导致  
**11.8亿**的用户订单数据被攻击者非法爬取。  
  
  
大规模数据泄露的背后，是针对用户的频繁营销推广骚扰及电信诈骗带来的钱财损失，是备受影响的企业品牌声誉和经济损失，甚至招致难以估量的监管处罚。  
  
  
**为什么会出现API逻辑漏洞，经分析主要原因有以下几点：**  
  
****  
  
**1、从研发角度**，研发这两个API的可能是不同的人员，开发人员很难有意识地把这两个API关联起来，更难以预料到攻击者会如何组合API的调用逻辑进行攻击；  
  
  
**2、从测试角度**，现有的安全工具通常不支持API组合的安全测试，更多的是单一维度的API安全测试，导致API组合漏洞及其风险更加难以把控；  
  
  
**3、从攻防角度**，API的攻击没有明显的流量特征，传统安全设备难以发现；另一方面，攻击者会利用动态代理IP来进行爬取攻击，绕过了基于IP访问限频的安全策略，使得API风险（尤其是API组合漏洞）的感知难度进一步加大。  
  
  
API承载大量流动数据，其安全建设是非常值得企业重视的。当前，API攻击带来的数据泄露量级大，存在高风险、不可控等问题。  
  
  
**一方面，企业对内需要加强API安全的建设**，通过威胁猎人API安全管控平台，以API资产为中心，全面梳理API资产、发现阻断API攻击，提升风险事件的响应速度，以更完善的API安全管理与建设，  
**实现“数据安全守卫战”的有效反击**。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4mAgZtBianqHntPiaftAWsTNfEcR9LpXAib0f5GKlpOiaC8YC7Nq68P6I6No2kANfHy16IAk9kBib3SQN7X9okOISVQ/640?wx_fmt=png "")  
  
****  
**另一方面，企业对外需要借助“情报”及早感知API风险**，减少风险管理的盲区，加强对API攻击、数据泄露等风险的监测和预警。  
  
  
利用外部的风险情报平台，如威胁猎人Karma风险情报平台，可以从  
**业务风险蜜罐流量**中捕获黑产针对企业API进行数据爬取的行为。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4mAgZtBianqHntPiaftAWsTNfEcR9LpXAibWw7CdDYrRAK24R7YEuGePbGjsucq4icoicGxONARPaNXL4e2Q8sUakCg/640?wx_fmt=png "")  
  
  
同时，威胁猎人风险情报平台还会从**黑产论坛、暗网、交易市场等渠道**监测到黑产传播、交易的全过程。除用户数据泄露监测外，提供**网盘文件、文库文档、代码泄露****等**数据监测，通过全面的情报源帮助企业及时感知数据泄漏风险，实现从被动对抗到主动防御的角色转变。  
  
  
  
  
2023年1月5日，永安在线进行品牌焕新，正式更名为**“威胁猎人”**（详见：  
[成立6周年，威胁猎人焕新回归](http://mp.weixin.qq.com/s?__biz=MzI3NDY3NDUxNg==&mid=2247495229&idx=1&sn=08d55c289fd0fc700a5da2d57c361ce6&chksm=eb12c806dc654110208d965813d11524f5ccad88633401518208d21c52aeaf1822a66ade2f64&scene=21#wechat_redirect)  
  
）。  
  
  
