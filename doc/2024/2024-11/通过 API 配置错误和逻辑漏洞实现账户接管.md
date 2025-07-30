#  通过 API 配置错误和逻辑漏洞实现账户接管   
原创 白帽子左一  白帽子左一   2024-11-24 04:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
#### 漏洞利用只用了 20 分钟  
  
在一次安全研究中，我偶然发现了一个类似论坛的网站，决定对其进行一些探索。不久后，我发现了一个严重的漏洞。  
### 检查 Cookie  
  
注册账号后，我像往常一样打开了开发者工具以检查 Cookie。令我惊讶的是，发现该网站的 Cookie 数据异常庞大，并且似乎是一个 **JWT（JSON Web Token）**。  
  
出于好奇，我将这个令牌粘贴到   
**jwt.io**[1] 上进行解码。结果发现，JWT 中包含了一个 **API 密钥**，这让我联想到它可能赋予用户超出预期的权限和访问能力。  
  
这个发现促使我进一步调查 JWT 的潜在漏洞以及 API 中可能存在的过度权限问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHkKVNstibXiaMEBw4ics0RrBwktgyAibFAicSMKelG21vNRe1EYyyvc1zkKXSd1huLwfRPQdSicCN1Cia9A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHkKVNstibXiaMEBw4ics0RrBwBEka9qAPUdQrLhtxUMyniafQwbGvbScKfQjvFCBfq061jHoV5ic9FJKg/640?wx_fmt=png&from=appmsg "null")  
  
img  
### 测试准备  
  
在测试中，我的用户 **contact_id** 是 **tSprgLvK93SKImu6SVZc**。为了避免对其他用户造成影响，我额外创建了一个测试用户，其 **contact_id** 为 **pmUIxGvvmbrplnw5NujC**。  
### 开始测试  
  
我注意到请求被发送到一个名为 **service.*.*的端点，使用的是 Token-Id** 来检索所有用户信息。最初，请求采用的是 **GET** 方法。  
  
出于好奇，我测试了 **OPTIONS** 方法，发现它还支持 **PUT** 和 **DELETE** 方法。这一发现让我决定尝试使用 **PUT** 方法进行进一步测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHkKVNstibXiaMEBw4ics0RrBwiaa2dt1hAeqKsaKsFic7iaYPQoYvTTESFfZSibSRcK3Y139DOanTCibY7pw/640?wx_fmt=png&from=appmsg "null")  
  
img  
### 修改请求参数  
  
在进一步测试中，我将请求中的 **contact_id** 参数从 **pmUIxGvvmbrplnw5NujC** 修改为 **tSprgLvK93SKImu6SVZc**。令我惊讶的是，这样竟然成功获取到了另一个用户的密码。  
  
注意到 **PUT** 方法被启用后，我开始思考是否可以修改任意用户的密码。与此同时，我还发现这些密码是通过 **SHA-256** 哈希处理的，但没有使用盐值（salt），这大大削弱了密码的安全性。  
  
随后，我尝试修改密码，并且成功了！现在，我的两个用户账户都设置了相同的密码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHkKVNstibXiaMEBw4ics0RrBwAUUCEqL7icQiasuQ7icUToCgcQszCjrpeYFeZZZrGfdREOFKb32m53cBw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
通过一些侦查，我能够识别出网站上的所有用户，包括管理员。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHkKVNstibXiaMEBw4ics0RrBw1nLdx4gU1y8tegK4IxkbWCD4Rib8wHz2HfYjEWx2jkMMsibCPPeXpymA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHkKVNstibXiaMEBw4ics0RrBw2bcK3aZExuRMic0PP0IBvfMPyH53qcmVvv2q8wEp6aictwGEwFoZJS8w/640?wx_fmt=png&from=appmsg "null")  
img  
### 深入测试  
  
这一发现已经非常关键，但很快我又发现了另一个漏洞。在等待一段时间并重复发送请求后，我收到了一条提示令牌过期的消息。然而，当我尝试从请求中完全删除 **Token-Id** 后，仍然能够收到服务器的响应。  
  
这表明 **Token-Id** 的逻辑处理存在缺陷，使我有可能影响任何使用该端点的网站。这一漏洞的严重性因此大幅升级。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHkKVNstibXiaMEBw4ics0RrBwg2rWlZaH5yDdKwvsHen0gYmukKyqG1jIsQK1La7vcic8dGcdHlXJohw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
您可以在这里找到网站信息，包括 **location_id** 和 **contact_id**:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHkKVNstibXiaMEBw4ics0RrBwoEI8tpK0Ptrl0ev51DVBQuAePI9T4f3p5Ag5rxRSphYsp2ShmtJDVA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我立即将该问题报告给开发团队，他们迅速进行了修复。  
### References  
  
[1] **jwt.io**: https://jwt.io/  
  
以上内容由白帽子左一翻译并整  
理。原文：https://medium.com/@greenhatsmail/account-takeover-via-api-misconfiguration-and-logical-flaws-14a1caa90d44  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
