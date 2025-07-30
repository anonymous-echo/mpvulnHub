#  【安全圈】全球92万台！RouterOS漏洞曝光：设备面临大规模攻击   
 安全圈   2023-07-28 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
# 漏洞曝光  
  
  
  
  
  
      VulCheck研究人员警告称，MikroTik RouterOS有一个关键漏洞，被追踪为CVE-2023-30799（CVSS得分：9.1），可以针对500000多个RouterOS系统发起大规模攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/QmbJGbR2j6xl6ibgSgTpibxfuBaO78ruccmOQ7yCOyx6hAQ9ERbtH1NqCbwE92n41YsQROEoKhR8Y8hT8X1czRcQ/640?wx_fmt=png&wxfrom=13 "")  
  
  
  
  
  
  
  
  
  
      NIST发布的公告中写道：“ MikroTik RouterOS是一个操作系统，在MikroTik的路由器和其他网络设备上运行，很容易出现权限升级问题。远程且经过身份验证的黑客可以在Winbox或HTTP接口上将权限从管理员升级为超级管理员，从而在路由器上获得根外壳程序，利用此漏洞在系统上执行任意代码。”  
  
      该漏洞本身于2022年6月首次披露，但在Vulneck发布新漏洞后才分配了CVE。现在已经有了补丁，但研究人员表示，全球约有47.2万台RouterOS设备通过其网络管理界面仍然存在漏洞，如果通过Winbox管理客户端进行攻击，这一数字将上升到92万多台。  
  
  
  
  
  
  
  
  
      Mikrotik RouterOS操作系统不支持暴力保护，默认的“admin”用户密码在2021年10月之前是空字符串。随着RouterOS 6.49于2021年10月发布，管理员被提示应更改密码。  
  
      更让人震惊的是，检测CVE-2023-30799的利用“几乎不可能”，因为RouterOS web和Winbox接口实现了自定义加密，而威胁检测系统Snort和Suricata无法解密和检查这些加密。一旦黑客在设备上站稳脚跟，RouterOS UI就无法看到它。研究人员建议密切关注暴力尝试或将恶意ELF二进制文件上传到设备的行为，以此来识别任何正在进行的攻击。以下是专家们提出的建议：  
  
1.从互联网上删除MikroTik管理界面。2.限制管理员可以登录的IP地址。3.禁用Winbox和web界面。仅使用SSH进行管理。4.配置SSH以使用公钥/私钥并禁用密码。  
  
      正如我们所看到的，在硬件上利用CVE-2023-30799非常容易。鉴于RouterOS作为APT目标的悠久历史，再加上FOISted早在一年多前就发布了，应该早有群体发现了这一问题。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgZ82bWqvTicJ5n8qeIYHF7j8WPX3oUsLcZ82vIBCvkeONc2SWPW7dibYmMJmeYHVRiaWpxtZUromtbA/640?wx_fmt=png "")  
[【安全圈】“大头”勒索软件三宗罪：伪装Windows更新、勒索、开后门](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040464&idx=1&sn=df8f582cdf62c617bd507ddc530f7995&chksm=f36fc150c41848469bbac05aeede901848b5bfacb4ab2c36c7de19cd135bd758ef060333c5cc&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgZ82bWqvTicJ5n8qeIYHF7jc6uRHicMDDz2QLyohPWy7pMSTFAiaXzghPDqkhaZlLFvUTzAwfiaua4tw/640?wx_fmt=png "")  
[【安全圈】Ubuntu 曝出两个Linux漏洞，近 40% 用户受到影响](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040464&idx=2&sn=439d05a020a648840737075413ed0e38&chksm=f36fc150c41848464d2a601bc750a28094c84df6c389ae4aba261c7434e4e00489f268506baf&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgZ82bWqvTicJ5n8qeIYHF7jcqcW3gQjkDX3zfW5g28C45qKZTU3n7JZYSvg8urToPLic4bgxfwTM6g/640?wx_fmt=png "")  
[【安全圈】北约又遭黑客组织袭击，大量敏感数据泄漏](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040464&idx=3&sn=e446273e777266f022c989abf6aabd19&chksm=f36fc150c418484683b31154b30fc15d7f6fd15300e0f74efcd6d74df43c215927fb93b58f91&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgZ82bWqvTicJ5n8qeIYHF7jaCDAAzpeSaRMFE0Svt5ic6d7UHahNnBITtBia1ah3hy4ia2AAwPe0rTvA/640?wx_fmt=png "")  
[【安全圈】TikTok未修复漏洞节省了千万美元，结果大选期间遭攻击](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652040464&idx=4&sn=2b549225fcaa4938d23bca7cd57cfa46&chksm=f36fc150c41848461342ac41eeae245ac066f245eaf8da28e03462fb2c505e0f60b7f26a8c4a&scene=21#wechat_redirect)  
  
  
  
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
  
  
  
