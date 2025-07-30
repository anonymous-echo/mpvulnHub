#  Azure API 管理服务上的经过身份验证的 SSRF 漏洞   
枇杷五星加强版  黑伞安全   2023-06-06 18:30  
  
我们描述了我们如何发现 Azure API 管理服务上的一个重要的服务器端请求伪造 (SSRF) 漏洞，允许任何经过身份验证的用户请求滥用服务器的任何 URL。  
我们于 11 月 12 日向 Microsoft 报告了此漏洞，并于 2022 年 11 月 16 日修复了该漏洞  
  
关于 Azure API 管理服务  
  
Azure API 管理  
由 API 网关、管理平面和开发人员门户组成。  
默认情况下，这些组件由 Azure 托管并完全托管。  
Azure API 管理支持数字体验，简化应用程序集成，支持新的数字产品，并使数据和服务可重用和普遍访问。  
## 我们如何发现 SSRF 漏洞  
  
我们首先创建一个新的 API 管理服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5vwjTick79Dia4NSh3FI5jMRZgMMjzLCLIw6hEXG7icUicdtmmHYJovUSDg/640?wx_fmt=png "")  
  
创建服务后，我们可以转到主服务页面并查看正在发送的各种请求 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5VLiaeH2ScDEtW5TxcjJ7YiaBicpY6XaoDmGNrWicgkt4rgicgYzbMFaSyug/640?wx_fmt=png "")  
  
我们注意到 POST 请求被发送到以下端点 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5VnUooGjh4hb5dd2hdMvhCP2uSJh1MRGK5j3A15dWu9pDvAKoyDgB0A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5d8rz084HnP06xOkQ06OPhL4U48O7nNfBHhYnIZ2hSoavdVibfSXpjcQ/640?wx_fmt=png "")  
  
然后，我们发送了一个请求，通过从https://www.ifconfig.me  
查找其 IP 地址来验证它实际上是发送请求的服务器  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5lLBgEESDKpXJ65uJLvQGP97xsFaTVrV4aD5QoAhTueia76LOr6hicXLg/640?wx_fmt=png "")  
  
我们能够向我的 Burp Collaborator 发送请求——下面屏幕截图的左下角——并从易受攻击的服务器接收回调，如屏幕截图右侧所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5qt18UXD0vjDTPbceHb2FlH0ice8TD7z9kzcZvwicVmCGLMdfGSwe7hQA/640?wx_fmt=png "")  
  
还发送了以下标头，它们是新创建服务的属性 -  
  
Ocp-Apim-Service-Name  
 : ssrfpoc (新服务名称)   
  
Ocp-Apim-Resource-Group  
：lidor-rg（资源组）   
  
Ocp-Apim-Url  
 : null/internal-status-0123456789abcdef (null=由于新的开发者入口还没有准备好，请求被发送到null，这是会被滥用的Header)。  
Ocp-Apim-方法  
：GET（请求方法）   
  
Ocp-Apim-订阅  
：5cd1****-****-****-****-*********c611（订阅）  
  
附注：Azure 服务正在使用和生成各种未记录的标头，尤其是 API 管理服务。  
这在后台服务器收到的各种 JS 文件中有所体现。  
例如，我可以查看以下 JS 文件 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5sDibibZ9FQ4ia66cj4YTjJgmVujHScvb8BFcBGFic0r1SRIpB7ZqKwsAfA/640?wx_fmt=png "")  
  
为了提供一个简单的 SSRF 概念证明，我们可以发送一个简单的 GET 请求到：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5wbyKwOpVZQ0aBKkJaFNNM8ibh2W4AEx9sZ54OVe4n1ibvR7sKZiaiaxYdg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5ZQgeg3bEHR9l1FupiccqiaD4QliaasR9BQsBNdEz1daoTI79Ceib3uQ4mQ/640?wx_fmt=png "")  
  
由于我们能够检索我们向其发送请求的任何端点，因此我们尝试访问 IMDS（实例元数据服务）和 Azure Wire 端点。  
Azure Wire 终结点是一个内部静态 IP 地址 (168.63.129.16)，Azure 服务使用它通过 WAAgent 进行通信。  
它负责各种网络规则，例如服务的入站和出站规则。  
如果远程攻击者能够查询 Wire 服务器，他们可能能够获得有关已安装的扩展、证书及其相应私钥的信息  
  
IMDS（实例元数据服务）端点 - 169.254.169.254 - 提供有关当前正在运行的虚拟机实例的信息，这对于攻击者来说可能是非常有趣的信息。  
我们在一篇关于我们去年发现的  
Oracle SSRF 漏洞的  
博客文章中写了更多相关内容。  
然而，在这种情况下，我们无法访问 IMDS，因此我们枚举了内部端口（还有几个端口，但下面的屏幕截图显示了枚举过程）——  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5IiakTwpHxsRXgfXfu1wic2jwpDd2HiaDydyn2iaib5icDbiaicZQoywV0xhdoA/640?wx_fmt=jpeg "")  
  
发现开放端口：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5I5jTVgWH7rXtSZvvtkXIzNgpIBcp16uZ5pCMibGtS6cFYicOJ0WicN9mQ/640?wx_fmt=png "")  
  
可以根据来自不同端口的各种响应以及服务器收到的响应之一来验证上述信息 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5sDibibZ9FQ4ia66cj4YTjJgmVujHScvb8BFcBGFic0r1SRIpB7ZqKwsAfA/640?wx_fmt=png "")  
  
我们能够审查每个开放的内部端口，并枚举和发现更多敏感数据，但现在我们将关注端口 30005。  
  
发现30005端口是https://apimanagement-cors-proxy-prd.scm.azure-api.net/  
  
这可以从内部和外部端点进行验证——  
  
外部的 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5icyCswZp5sd7LNv6tqNJStVlYJ6AmUR0hqj3MREG0ibdKgbtdLmPlGcg/640?wx_fmt=png "")  
  
内部的 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5wjT8N47Z5SBf0sDZo9B9kvBiaYImZZhxBngctVObxW1cbwx5I2E7BbA/640?wx_fmt=png "")  
  
不同之处在于，通过使用 SSRF 漏洞从服务器内部发送请求，我们设法发现了内部端点和服务——如果我们试图从外部到达相同的端点，这是不可能的。  
  
例如，由于这是一个Kudu Git  
服务器，我们可以假设它使用 Git 客户端从门户上传和保存各种部署。  
  
https://learn.microsoft.com/en-us/azure/api-management/api-management-configuration-repository-git  
  
因此，我们知道我们可以尝试git-upload-pack  
命令并将其直接发送到服务器，因为我们已经通过身份验证 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5LTRLhR8avnb3fYOSPdDgFq3EDDOjyoYsKncMPeS7UKxBWNPicmO76og/640?wx_fmt=png "")  
  
此外，我们可以查看 git-scm 文档 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5b2VyUgrbZiajSibYtMeFXBzMZwhMbHBmZNE2CaePdjxlrf44FztQDKvg/640?wx_fmt=png "")  
  
通过了解我们可以发送到服务器的各种 git-scm 请求，然后我们尝试向远程存储库发送请求以列出 refs。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5jicPUQeMth84f330I6gxRiaESn9r5JTZ8Pv89uQMvfiaDib5rZhVrC3RJg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5Am1ps4ZuwlicD52h6JjIfqf6oXvtdNC7ibTZ6qficKibO2DCXHM7EI3R5A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm57nZNtmE5Br5CMVr5wR0Jd1uGlymJvQDWictev4EOO6lzflWPl76CRAQ/640?wx_fmt=png "")  
  
****  
总之，我们能够检索到 Git 客户端版本、空引用列表和不同的git-scm  
功能。  
从这里开始，将有几种进一步利用的可能性：  
1. 尝试上传远程仓库。  
（类似于此 - https://infosecwriteups.com/git-lfs-exploit-for-remote-code-execution-cve-2020-27955-e8f4786163c3）  
  
1. 枚举Kudu SCM  
服务器中的各种敏感文件。  
  
笔记：  
- 可以在此处找到更多滥用 SCM 服务和端点的文档：–   
https://github1s.com/projectkudu/kudu/blob/98ad238b860f81a4cb4e3419c8785a58ba68e661/Kudu.Services.Web/App_Start/NinjectServices.cs  
  
- 上面的示例仅关注端口 30005 和 Kudu Git SCM 服务器，这只是被发现打开的众多内部端口之一（例如 5985 等）  
  
**知识星球 ：黑伞安全**  
  
**https://t.zsxq.com/0e5REA0NR**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGrf2kPKIbEvqzOk9bgcSMm5THEgWvia4azFaSDQbO5xuSsdVEI6wceUvibe0rPicEQXicsTF3h2MCtahQ/640?wx_fmt=png "")  
  
  
