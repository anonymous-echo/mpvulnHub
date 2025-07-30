#  JWT漏洞初步了解   
原创 Caigensec  菜根网络安全杂谈   2025-02-10 04:08  
  
**点击标题下「蓝色微信名」可快速关注**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ick6R1E3YokGicVeM3swHEZaM8cfEGLUB8QRicTAicIKyLaicmlicUGLv7XQP56vvc8dxVNSjYerVCHON8n1dlajco1w/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Sg02xflJ62rdxefX9thdaL8hxJWicY1vPlEmzNIWcBy2ypXTggHXX9e0kFDEVicficwTDdlLHLNrh6ica1SEvMqKeQ/640?wx_fmt=gif "")  
  
免责声明：本文仅用于合法范围的学习交流，若使用者将本文用于非法目的或违反相关法律法规的行为，一切责任由使用者自行承担。请遵守相关法律法规，勿做违法行为！本公众号尊重知识产权，如有侵权请联系我们删除。  
  
  
01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JklNicn4RoOYselcxR3KCEWzc5XxKBV6dHxicYwheES56YJiczBO0ticvSn4pXR7hibHXW2Rpfr6027LhnCurzjwibXg/640?wx_fmt=png "")  
  
  
  
JWT是什么  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rrbZLC2ibIgtgV382cFCwmibpHFT7jndu1ibEDpFia0dzsjETHdt0HFzYlVRnHIaumpf3QyVos7giadDicqSku9zOEibw/640?wx_fmt=jpeg "金属质感分割线")  
  
  
**JWT（JSON Web Token）**  
，用于在网络应用环境间安全传递声明。通常用于身份验证和信息交换，因其紧凑、自包含且易于传输的特性而被广泛使用。  
  
JWT 由三部分组成，用点号.分隔：**Header（头部）、Payload（负载）、Signature（签名）**  
  
## 1、JWT工作流程  
  
  
**用户登录**  
：客户端发送凭据（如用户名和密码）到服务器。  
  
**生成 JWT**  
：服务器验证凭据后，生成 JWT 并返回给客户端。  
  
**存储 JWT**  
：客户端存储 JWT（通常在 localStorage或 sessionStorage中）。  
  
**发送 JWT**  
：客户端在后续请求的 Authorization头中携带 JWT。  
  
**验证 JWT**  
：服务器验证 JWT 的签名和有效期，确认请求合法性。  
  
## 2、JWT的一些特点  
  
### （1）JWT 的优点  
  
**无状态**  
：服务器无需存储会话信息，所有数据都在 JWT 中。  
  
**跨域支持**  
：适用于分布式系统和跨域认证。  
  
**安全性**  
：通过签名确保数据完整性和真实性。  
### （2）JWT 的缺点  
  
**无法撤销**  
：一旦签发，JWT 在有效期内无法撤销，除非设置较短的有效期或使用黑名单。  
  
**存储问题**  
：JWT 存储在客户端，可能面临 XSS 攻击风险。  
  
**数据暴露**  
：负载中的数据是 Base64 编码，非加密，敏感信息需额外加密。  
  
  
02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JklNicn4RoOYselcxR3KCEWzc5XxKBV6dHxicYwheES56YJiczBO0ticvSn4pXR7hibHXW2Rpfr6027LhnCurzjwibXg/640?wx_fmt=png "")  
  
  
  
JWT靶场练手  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rrbZLC2ibIgtgV382cFCwmibpHFT7jndu1ibEDpFia0dzsjETHdt0HFzYlVRnHIaumpf3QyVos7giadDicqSku9zOEibw/640?wx_fmt=jpeg "金属质感分割线")  
  
靶场地址：  
https://portswigger.net/web-security/all-labs#jwt  
  
Lab: JWT authentication bypass via unverified signature  
  
实验目标：请修改会话令牌以访问/admin的管理面板，然后删除用户carlos。  
  
（1）登录靶场提供的账号/密码wiener:peter  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFgeXI6ddtcORdG6P3aZI9EdwcT4aKdgb1YTTtqzwM5thOMqriaI3LyCNfoA0Lr7EicuH3r7FVKtR3A/640?wx_fmt=png&from=appmsg "")  
  
（2）点击My account，进行抓包，发现cookie是一串ey开头的代码，并用点号.隔开  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFgeXI6ddtcORdG6P3aZI9ERQPWre6QFYx7B5GxwYw7j1fwc6qRakz2XW9m9as9P0T7UAa7QhKqWA/640?wx_fmt=png&from=appmsg "")  
  
（3）jwt解码，观察内容  
  
jwt解码网址：  
https://jwt.io/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFgeXI6ddtcORdG6P3aZI9EC9R5vKQomzOX6P9npvEc3pdmVxJzSvPib7ngngkURLfaWRzEcu1dxvw/640?wx_fmt=png&from=appmsg "")  
  
（4）回到burp，选中jwt的payload部分，在右侧将wiener修改为administrator，点击Apply change  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFgeXI6ddtcORdG6P3aZI9EPwNlz3Pu4nAibNmSDWFtybZib4owxOpyZB3g3zm6Olu5mMxvlxXqicbbA/640?wx_fmt=png&from=appmsg "")  
  
（5）请求部分改为/admin，并观察响应包，发现成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFgeXI6ddtcORdG6P3aZI9Er21o2ldWhKncib98ppfsUoq9ibkBavGZb5YmQA6YNHG1nXSqKib4diacSA/640?wx_fmt=png&from=appmsg "")  
  
（6）再次把请求部分改为/admin/delete?username=carlos，实验解决  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFgeXI6ddtcORdG6P3aZI9Esj6650QKc3LoibnMyyBMIBu4kDylbNrBet85uBT5fwiceuGeqeZbK6lw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFgeXI6ddtcORdG6P3aZI9EebwPCaWEAKsAq06iaOGLkar3Kmhduh0CyZtw6a7DHGIYSicX2nPicicoGg/640?wx_fmt=png&from=appmsg "")  
  
  
  
THE END  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ick6R1E3YokFvoM6PLd2g5R9ZyvTVYQhyosDWxvJP5DSfU2zuS01w7sRwGM8y8FPkADsZgW9OzB1fkoEcrsDxmA/640?&wx_fmt=png "")  
  
亲爱的朋友，若你觉得文章不错，请点击关注。你的关注是笔者创作的最大动力，感谢有你  
！  
  
