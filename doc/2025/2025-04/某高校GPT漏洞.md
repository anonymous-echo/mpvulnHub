#  某高校GPT漏洞   
原创 锐鉴安全  锐鉴安全   2025-04-05 08:44  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
关注公众号，设置为星标，  
不定期有宠粉福利  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4ricRiaXQ6WVVlTAgCW8HUbC2rHkicA2rpDNEPAGyiatRibqB9LN5NyHcqLCmbibM1siaumqF5Yu6UtSsYA/640?wx_fmt=png "")  
  
Part-01  
  
背景  
  
    日常开展src测试，通过信息收集，发现某高校自建的gpt系统，还给注册账号！注册完后，测试发现存在html注入漏洞。分享下过程！  
  
  
Part-02  
  
实战  
  
     
秉承  
见框就插的原则，效果立杆见影，先插入常规的poc,<img src =1 onerror=alert(1)>  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RLTNmn7FBP4QUYZ2lYYNMTgWZ7SO5tGicPAkKIfMVicJGdHAfYFLLBb8PRdbxXyZCyGxKH369GUOUVKibt38ESgYw/640?wx_fmt=jpeg "")  
  
   弹框了……  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RLTNmn7FBP4QUYZ2lYYNMTgWZ7SO5tGicgibS4D9Hhicr6MkwibaMTibTK1fg4dMlSjh1ysiaXtkIWQNu6JnFgvVPgtg/640?wx_fmt=jpeg "")  
  
  
弹个cookie试试，<img src=1 onerror=alert(document.cookie）>。依然成……  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RLTNmn7FBP4QUYZ2lYYNMTgWZ7SO5tGicIuiaPQcCpzdNloTAdmr5QtkPZ2XMg5OAgmHzD16v0icmN2ico7NeuANyw/640?wx_fmt=jpeg "")  
  
再试试嵌入页面，<iframe src=https://www.baidu.com></iframe>，还是行。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RLTNmn7FBP4QUYZ2lYYNMTgWZ7SO5tGicRBc2vfHFGiaVnicrwFAdPVVgCLTctNKHu7SxQBeUrVf69b4j2QY2eErw/640?wx_fmt=jpeg "")  
  
