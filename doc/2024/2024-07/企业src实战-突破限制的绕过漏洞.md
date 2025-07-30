#  企业src实战-突破限制的绕过漏洞   
原创 猎洞时刻  猎洞时刻   2024-07-03 22:05  
  
猎洞时刻  
  
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
  
  
  
    在进行一次企业src的挖掘过程中，我四处寻找可以突破限制的点，有一句话说的很好，突破原有的限制就算漏洞，只不过危害有大有小。  
  
  
在找到一个站点之后，我就开始找突破点，结果发现他这里提示我，不能创建作品超过两个以上，于是我就开始着手尝试绕过。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHib8KhpiaXiaV494658JTfUzk43QrkcBQjrPWQK2ibRO7A9iavibcY1d8VnDUhqgxADOXK6uQ0zWbK3306w/640?wx_fmt=png&from=appmsg "")  
  
经过测试发现，他这个每次创建作品之前，都会进行校验一次，检验已创建作品的数量，如果超过两个，就会拒绝创建作品。于是分析出下面的绕过方法：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHib8KhpiaXiaV494658JTfUzk4KYBMgribAc566tcbdWAvj0kNnhjpJPVqd970WpsztibAeJgkySlK9pmg/640?wx_fmt=png&from=appmsg "")  
  
他这个  
鉴权方法，无论是前端的校验还是后端的校验，都能很简单的绕过，除非开发者在发送创建数据的时候进行验证数量，才能防止被绕过。  
  
下面进行创建作品然后进行抓包。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHib8KhpiaXiaV494658JTfUzk4NWjpWOVL8hllm5fdq2eySOttx1dcfY5aG0DcyibvQ0Apc6ib0WKYWsBw/640?wx_fmt=png&from=appmsg "")  
  
然后在数据包中进行修改即可，就能达到绕过限制，修改后直接send发包，从而无限创建作品，绕过限制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHib8KhpiaXiaV494658JTfUzk4lOQUic06yHcmXerMwWMxrsNoJbsKo9pr92ofNQwN7KAeDrNLYYlby8A/640?wx_fmt=png&from=appmsg "")  
  
下面可以看出来，创建了多个作品，成功绕过了原本的限制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHib8KhpiaXiaV494658JTfUzk4vEq6USzLxkgzhWdrmVu9N6lLHkGtia3kkR9bUV9iaCn867VmuMLtk7tg/640?wx_fmt=png&from=appmsg "")  
  
**公众号后台回复【**  
**240630****】获取dirsearch目录扫描超级加强版**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHib8KhpiaXiaV494658JTfUzk42XCXQlYF4H8B7ib5tEqkZVa6qy7nvYbbibkw8OmWXVfJC9rgx9s7d8WQ/640?wx_fmt=png&from=appmsg "")  
  
# 限时永久-猎洞内部圈子  
  
   
   
**如果师傅您感觉自己挖掘漏洞很困难，但是又觉得报课程太贵，不如尝试限时79元永久加入我们圈子，内容包括企业src赏金报告，众测赏金报告，CNVD/Edu 漏洞报告和挖洞思路，助您快速获得赏金！**  
圈子内容200+ 师傅人数200+ 并且内部圈子会分享项目，一个洞就让你几倍回本！目前仅需79！！  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH9NX8HWskWWBWf6QOqBqf5u9rS35JzJtVg4z5VdMcQyOBibTj9UZnoe9SVZQw7KoPDcEiaFMicgG11icg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic0YK5aN4k18agGViaApiaQJThM7iaW4iaibgYhE6DaSfcuPcobicCtRSjaVzxfuWwXsJKkc29l1ylzaRvw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibhEufjGqPhU3FqpibxFqII6SmKV0FhrpWs4dCcdibhTcrrXpeHicFWHbHrW0PUsbD0AFrywQ1ibSe90Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibsxsu3jBwNdgVSdJhnjHsPKbQGRB1dh2aNibIaE8Ndf0RCOsyGT6pZRnA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibhEufjGqPhU3FqpibxFqII6Gr1pNsQkfUNmu3n3ibhIS6EZichj5jPR6yOkywQibQsdAAXTCLWDibWOpA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic0YK5aN4k18agGViaApiaQJT3eRZv9URx0AEq0T9TU2QNUdOZnZaiaNQOHt52Cg9icia9kCmUXGssgdNA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic0YK5aN4k18agGViaApiaQJT9FvnEDzlZjqibgGqL4icoESrM4ib597puZf3wALOicEmuNC79Vod9HNP1A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHic0YK5aN4k18agGViaApiaQJTI5NibGb2PtsU1z7dPSKvBLmY8ib1GxNFcYWSAOcHxovetCL7GlicqD2ibw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8via4bsEibTpjEj06T4Lll6LfFg6IgbNDH91KhvgYIBL62UFqmsiaicY82RbGMjIwubH9UyBn1icSsGmg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH8via4bsEibTpjEj06T4Lll6L7Cx44iaic9icNNfUH7tnUjKan6YiaZonVccPcibKTnN5eZ0FdsJcAXZ3L1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTH80yniaZAYib2YKPMV1ibIPjibs31DRFTnM30ia9iaDW5yuRglTsdPhLkzmtFoyg7MyXb8NnSUXIYLDwJOQ/640?wx_fmt=png&from=appmsg "")  
  
想进入交流群或者咨询内部圈子的师傅，请扫码下方二维码加我微信，备注“加群”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/d6JIQYCSTHibFyKL0pAnqJhjWnODDg40m2hExuNhPPVySVSdJmrCI0stNz5Yomg4lPWNMcxmBqSg6jUvp849GJA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
