#  2023 SDC 议题预告 | 深入Android可信应用漏洞挖掘   
原创 2023 SDC  看雪学苑   2023-10-14 17:59  
  
**2023 SDC 议题抢先看**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEVGr1Oct8mbuwOJO3y9gNgHQLl72MDZdLT9ndqvVqaXBddUrsucmfcvA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EAIUAHpN4VOk6wFyibY8dLPibo05grfDR6wlXWl3XMYjYd8NBRicyHfrRibIz4YbeRsyaph44icegTnJw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEV8bDnlBUkzDswNo6PxyYAlYMLle8SUghkbM2IdnGZSYkP5CU8IKNdJg/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEV8bDnlBUkzDswNo6PxyYAlYMLle8SUghkbM2IdnGZSYkP5CU8IKNdJg/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEV8bDnlBUkzDswNo6PxyYAlYMLle8SUghkbM2IdnGZSYkP5CU8IKNdJg/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEV8bDnlBUkzDswNo6PxyYAlYMLle8SUghkbM2IdnGZSYkP5CU8IKNdJg/640?wx_fmt=gif "")  
  
  
  
**01 议题前瞻**  
  
  
  
  
  
**深入Android可信应用漏洞挖掘**  
  
在过去的几年中，可信执行环境（TEE，Trusted Execution Environment）在Android生态系统（智能手机、智能汽车、智能电视等）中实现了普及。TEE 运行独立、隔离的 TrustZone 操作系统，与 Android 并行，保证在Android系统沦陷的情况下用户的核心敏感数据或者手机的核心安全策略仍然安全。  
  
  
与Android系统中预置的系统级App一样，TEE系统中也存在必要的应用（Trusted Application， 即TA）以承担数据加密等安全策略的实现。2022下半年演讲者对部分主流厂商的TA实现做了安全研究，目前已有60处漏洞被确认，包括但不限于指纹图片提取、指纹锁屏绕过、支付密钥提取、提取用户的明文密码等严重漏洞。  
  
  
在本次议题中，演讲者将会介绍主流厂商的TEE环境中的TA实现以及常见的攻击面并分享一些针对TA做安全研究的技巧与方法，比如如何尽可能快速的拥有一台具备Root权限的手机用于研究与测试。在研究过程中，演讲者构建了一套模拟系统对这些TA进行模拟和Fuzzing，在本次议题中演讲者也会介绍到如何实现这个模拟系统以及使用到的Fuzzing技术和部分调优策略。  
  
  
**02 演讲嘉宾**  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEV8ZmzHXejv4vfJpXE1xwLBBSwafYoiavibyHvqcEH28MtoZXhwOqMUkfA/640?wx_fmt=jpeg "罗思礼.jpg")  
  
  
**李中权-启明星辰ADLab移动安全专家**  
  
  
专注于Android、Apple、loT方面的漏洞挖掘与Fuzzing。  
曾多次发现Apple、华为、荣耀、三星、小米、OPPO  
、vivo、联发科等主流厂商的高危漏洞，在天府杯上完成过产品破解。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEVPHHjZzLVcsJ7XATRwHsUZiaXfN0UWuTUhnqX7ZOjiaQ69ucDRF4WhJ7Q/640?wx_fmt=png "")  
  
**听众收获**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEVQ7rzfG1BLGQkbWtprdsVLfC8I9bTPcDCGibr0maO9TEicZAGQy3agHRg/640?wx_fmt=png "")  
  
  
1. 了解可信执行环境（TEE）在Android生态系统中的重要性和作用，以及其与Android系统的关系。  
  
2. 了解主流厂商的TEE环境中的Trusted Application（TA）实现，并了解其在安全方面存在的漏洞。  
  
3. 学习一些针对TA进行安全研究的技巧和方法，包括如何快速获取具备Root权限的手机用于研究和测试。  
  
4. 了解如何构建模拟系统对TA进行模拟和Fuzzing，并学习相关的Fuzzing技术和调优策略。  
  
5. 增强对Android生态系统中的安全问题的认识，提高对个人敏感数据和手机安全的保护意识。  
  
6. 了解可信应用漏洞挖掘的重要性和挑战，为相关安全研究和工作提供参考和启发。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC5GUbQCMws4DwCrakx3FiaDA57CMxiaWcSZKIa65Obg7ePmLUNOn0PHQnicRBmGFJIzxSFu0f9iaicFL0Q/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEVYgtql2ROK5N1FbYR6fWw7IhpkR2uJVXBjy004AJQeO4MxXIRKw1pLw/640?wx_fmt=jpeg "")  
  
**扫码报名参会**  
  
  
**更多议题细节，欢迎来 SDC 现场聆听**  
  
****  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEVaR0KPDlN9IGLRdC82iaBnFPicS4DibcogwNwlH89wd8NaKOLExAkEsIZw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEVaR0KPDlN9IGLRdC82iaBnFPicS4DibcogwNwlH89wd8NaKOLExAkEsIZw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEVaR0KPDlN9IGLRdC82iaBnFPicS4DibcogwNwlH89wd8NaKOLExAkEsIZw/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8HUgFTicjjxpdbkFpLIcSibEVB2zjHNgfrry1OOCNoib6PCmr6icETXPricrch5GY5k8MmTPcMP3tLaa3w/640?wx_fmt=gif "")  
  
点击阅读原文查看更多  
  
