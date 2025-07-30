#  众测项目实战--有趣的xss漏洞   
原创 猎洞时刻  猎洞时刻   2024-06-01 21:10  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9evFcNH31Pjh0f83GEqsibSQsGS8uUrBPLU6VJbjw8CTibOgsYYOhqqKpaQHb9BicrJcCOYhZG0tYOg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn6mG6TyJornrhz9JticBo3Nx4zhzUFXcggEDw1lkfzMI0KuLp7dW4dDCvbfgAKlLSX3yGmYg0gtXcw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
```
本公众号“猎洞时刻”旨在分享网络安全领域的相关知识，仅限于学习和研究之用。本公众号并不鼓励或支持任何非法活动。
本公众号中提供的所有内容都是基于作者的经验和知识，并仅代表作者个人的观点和意见。这些观点和意见仅供参考，不构成任何形式的承诺或保证。
本公众号不对任何人因使用或依赖本公众号提供的信息、工具或技术所造成的任何损失或伤害负责。
本公众号提供的技术和工具仅限于学习和研究之用，不得用于非法活动。任何非法活动均与本公众号的立场和政策相违背，并将依法承担法律责任。
本公众号不对使用本公众号提供的工具和技术所造成的任何直接或间接损失负责。使用者必须自行承担使用风险，同时对自己的行为负全部责任。
本公众号保留随时修改或补充免责声明的权利，而不需事先通知
```  
  
  
      
这是一个挺有意思的xss漏洞，正常情况下，一个邮件存在xss漏洞，就可以发给其他普通用户，危害一般也就只能截止到去攻击普通用户，但是这个案例的邮件就很有意思了。  
  
  
打开网站，发现是一个经典的商城界面，这种网站，需要先去注册，注册之后，才能去测试各种功能和各种漏洞。  
  
注册后，直接进入个人中心，这里功能最多，出洞率也更高。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsmXRft6sNxBUUXoWUyaz2zfQVIeAUcoiblib9MIQLfnsNHAgV67iaxyib0Q/640?wx_fmt=png&from=appmsg "")  
  
有意思的地方来了，在你注册账号之后，会有一个由管理员来发送的邮箱来欢迎注册。并且还有能够回复邮件的功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsHiabyd3lFYZTkFUnuddPcRp888VtXdP6xKwHGiahCvxtQFJVdEBlqPBw/640?wx_fmt=png&from=appmsg "")  
  
挖掘xss，就要遵循着万物皆可插，于是在标题和内容都插入xss payload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsCiaHocuLk6aZ4vXUOn1nMMclWhHLCR0Fc4XFA4aM5AOboTmia29cakaQ/640?wx_fmt=png&from=appmsg "")  
  
这里也是成功回复信件成功了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsIdhQfbzlqeXc7X8v6Uv9sSdycx20004QDoscm8tsbMeBVv6aReQXAA/640?wx_fmt=png&from=appmsg "")  
  
然后去查看邮件发送状态，哎呦，弹框了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsPDZyyKKmGoN7Via6BkAWicPjBlkkYqjFgg2NKyQ8UaSyQpyMPXzY2RFA/640?wx_fmt=png&from=appmsg "")  
  
这下是，谁打开邮件收件箱，就会被xss攻击，都不需要去点卡查看信件内容，并且如果运气好的话，也能攻击到管理员。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsMPibXnEMVTXeQSQp0ldNr2bs8wBIDVuLjymxgl2gLtnKj9H98hrmfoA/640?wx_fmt=png&from=appmsg "")  
  
**公众号后台回复【240601】获取一份XSS-Payload典藏版**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsFM96KoDQhAWS4Xt9KdxlQX2duGTibDRDicQMMWsDEePcXwmbSvBj1feQ/640?wx_fmt=png&from=appmsg "")  
  
注册公司和非网安勿进  
# 欢迎加入猎洞内部圈子  
  
   
   
**如果师傅您感觉自己挖掘漏洞很困难，但是又觉得报课程太贵，不如尝试限时79元永久加入我们圈子，内容包括企业src赏金报告，众测赏金报告，CNVD/Edu 漏洞报告和挖洞思路，助您快速获得赏金！**  
**圈子内容180+ 师傅人数160+ 并且内部圈子会分享项目，一个洞就让你几倍回本！**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9NX8HWskWWBWf6QOqBqf5u9rS35JzJtVg4z5VdMcQyOBibTj9UZnoe9SVZQw7KoPDcEiaFMicgG11icg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic0YK5aN4k18agGViaApiaQJThM7iaW4iaibgYhE6DaSfcuPcobicCtRSjaVzxfuWwXsJKkc29l1ylzaRvw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsxsu3jBwNdgVSdJhnjHsPKbQGRB1dh2aNibIaE8Ndf0RCOsyGT6pZRnA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibhEufjGqPhU3FqpibxFqII6SmKV0FhrpWs4dCcdibhTcrrXpeHicFWHbHrW0PUsbD0AFrywQ1ibSe90Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibhEufjGqPhU3FqpibxFqII6Gr1pNsQkfUNmu3n3ibhIS6EZichj5jPR6yOkywQibQsdAAXTCLWDibWOpA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic0YK5aN4k18agGViaApiaQJT3eRZv9URx0AEq0T9TU2QNUdOZnZaiaNQOHt52Cg9icia9kCmUXGssgdNA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic0YK5aN4k18agGViaApiaQJT9FvnEDzlZjqibgGqL4icoESrM4ib597puZf3wALOicEmuNC79Vod9HNP1A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic0YK5aN4k18agGViaApiaQJTI5NibGb2PtsU1z7dPSKvBLmY8ib1GxNFcYWSAOcHxovetCL7GlicqD2ibw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8via4bsEibTpjEj06T4Lll6LfFg6IgbNDH91KhvgYIBL62UFqmsiaicY82RbGMjIwubH9UyBn1icSsGmg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8via4bsEibTpjEj06T4Lll6L7Cx44iaic9icNNfUH7tnUjKan6YiaZonVccPcibKTnN5eZ0FdsJcAXZ3L1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibs31DRFTnM30ia9iaDW5yuRglTsdPhLkzmtFoyg7MyXb8NnSUXIYLDwJOQ/640?wx_fmt=png&from=appmsg "")  
  
想进入交流群或者咨询内部圈子的师傅，请扫码下方二维码加我微信，备注“加群”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibFyKL0pAnqJhjWnODDg40m2hExuNhPPVySVSdJmrCI0stNz5Yomg4lPWNMcxmBqSg6jUvp849GJA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
