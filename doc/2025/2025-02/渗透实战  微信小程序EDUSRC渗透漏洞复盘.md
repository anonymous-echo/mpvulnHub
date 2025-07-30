#  渗透实战 | 微信小程序EDUSRC渗透漏洞复盘   
 不秃头的安全   2025-02-09 23:21  
  
# 微信小程序EDUSRC渗透漏洞复盘  
```
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，
严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。
还在学怎么挖通用漏洞和src吗？知识星球最后一次优惠，续费也有优惠私聊~~考证请加联系vx咨询
```  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWSDHicGU1cUcoEQAOL5l6XAQUl5VaD0XTspksCRj1zibBicdxXyjpICU0m8Zjia4X7SpoS4xnibzYXXLA/640?wx_fmt=png&from=appmsg "")  
  
        
  
#   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
哈喽，师傅们这次又来给师傅们分享下最近的一个漏洞挖掘的一个过程，这次跟着一个师傅学习，然后自己动手去挖，也是学习到了不了东西。这次要给师傅们分享的案例是一个微信小程序的案例，这个小程序站点存在多个漏洞可以打，其中最主要是知识点就是开始的一个数据包构造，通过分析登录页面的数据包，进行队里面的数据包构造找到一个敏感信息接口，进而泄露了七千多个用户的sfz、xm、sjh等敏感信息。  
  
然后利用这个泄露的接口来进一步漏洞挖掘，扩大危害，其中微信小程序文件上传漏洞还是多的，小程序好多都没什么过滤的，像还有逆天的危险小程序直接没有任何的过滤的也是存在的。这里也是直接打了一个getshell。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYvU3qWGXMeEyDR86diaquUy3vJ3Gpel5K8F47HTVajMM6LwiaPm9uscWg/640?wx_fmt=png&from=appmsg "")  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 渗透测试**  
### 一、浅谈  
  
这个EDU的小程序可以直接使用微信一键登录，像我们平常在挖掘微信小程序的时候，经常碰到这样的微信一键登录的功能点，像这样的初衷就是为了方便我们使用，但是越是方便其实对于安全来讲越是不安全的一个过程。  
  
就比如常见的一键微信、手机号登录容易造成泄露SessionKey三要素泄露，下面就分享一个我之前挖的一个小程序的微信一键登录泄露SessionKey三要素的一个漏洞。  
  
可以看到这个数据包直接把SessionKey、iv以及加密字段三个部分全部泄露了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYE6SPq1AGeep5evFehUA0RurykCkVVYS0d6iadgMFPqj9zCj6H5KzIUw/640?wx_fmt=png&from=appmsg "")  
  
然后再使用Wx_SessionKey_crypt这个加解密的工具进行解密，可以看到解密出来开始一键微信登录的手机号  
  
工具下载链接：  
https://github.com/mrknow001/wx_sessionkey_decrypt/releases  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYcfvetx0hsTsa9KJvSG7tHpeqVic74rav5GYECib0PIGc11R0FEVo5Khg/640?wx_fmt=png&from=appmsg "")  
  
那么我们是不是可以逆向修改手机号然后加密，再去替换，然后放包就可以登录别人的账户了呢  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYg7lQSQJjwCYibvntKD1HtkCKcCdtoXIFibvlUZITiab0aibLMwadcYBuuw/640?wx_fmt=png&from=appmsg "")  
###   
### 二、burpsuit数据包分析  
  
首先通过微信搜索小程序，找到目标  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYPtGfalRYoe61dDC9EjTGczst23NdibSN7kJ7DEPDYAkicibBK8xpJbfIA/640?wx_fmt=png&from=appmsg "")  
  
这里就再继续跟大家讲下这个小程序的挖掘过程吧，然后带师傅们一起看看这个数据包  
  
这个数据包相信很多师傅们一眼就可以看出来这个是jeecg框架，这里给师傅们总结下判断jeecg框架特征，最简单的就是看数据包路径关键字，比如/jeecg、/sys、/system等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYw5xvZfSE3pd548dbDeNLt4bicx0h3gtrajRJj1oianLOGElRQ6HAkTDQ/640?wx_fmt=png&from=appmsg "")  
  
这里看到这个数据包，利用id（这里是我自己登录时候的id）可以回显出一些三要敏感的信息，比如身份证、姓名、手机号等信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJY6majqKpj8PYOfVicshFxAOn82U65jhibPPJPI9dN0K84I60e4bW7uia9Q/640?wx_fmt=png&from=appmsg "")  
  
然后我就想，看看开始的历史数据包里面有没有泄露遍历查看id的路径，获取大量的id，然后去遍历，从而获取大量的敏感信息，然后在这个list的接口下面确实查到了很多的id  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYiaEonN2OprO55csJjTdDl7q8iaLoWGaNKY1liaF5lHQhPE3eQXscEvlxQ/640?wx_fmt=png&from=appmsg "")  
  
然后我这里就替换到刚才的查询敏感信息的接口，去替换那个id值，但是发现不行，后面才知道这里对X-Access-Token值做了校验，所以这里我们没有权限去访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYyrmE04EkicMI2EJFLxvmDNUZ767hxH80c4ezz6DALicCZtkmF7VCa92g/640?wx_fmt=png&from=appmsg "")  
  
然后这里我开始想爆破这个JWT编码，看看有没有JWT密钥，然后再去构造JWT，再去使用user_id值，然后去编码，抓包放包去遍历或者尝试登录别人的账户信息。  
  
但是这里我使用无影这个工具没有爆破出来，于是就没有利用成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYdRJK1EMX74TsEgSClIM3PDR0KtpJnFccZkq2SGjRqvkohxceJ1TYXA/640?wx_fmt=png&from=appmsg "")  
  
但是这里我给师傅们推荐一篇文章是写JWT伪造实战小程序漏洞案例的文章，写的蛮不错的  
  
[https://mp.weixin.qq.com/s/ITVFuQpA8OCIRj4wW-peAA](https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247485655&idx=1&sn=0598b4c4ba4ae8f0d3fa999818df5c7e&scene=21#wechat_redirect)  
  
###   
### 三、峰回路转  
  
后来我又是回到了原始的页面那几个数据包中，对这几个数据包中的路径进行了一个分析，发现list参数好像都是进行一个数据汇总查看，那么我们上面的数据包通过修改id不成功，那么我们可不可以尝试使用修改接口参数，修改成list的，来进行一个未授权数据访问呢  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYnb4dSoHibbSOsCrs7XxFVwvW0ywTwJstdfnibXxtLVwdvic2xPv6MJHag/640?wx_fmt=png&from=appmsg "")  
  
开始是把id参数和后面的先删掉，然后发现不行，后面再把后面添加list参数发现还是不行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJY6M8rGonLszddjrIPdu7Z49oJY45fOxPj4ToVub8X5CXePHPDQuQ5Rw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYYJE6Nc6NMib7ZTOPsH2DUYxPd7e49bsgGZVdxqarptGLlGiafhR5R72w/640?wx_fmt=png&from=appmsg "")  
  
后来我就直接把前面的queryById参数删掉，再在后面添加list参数，从而就可以未授权访问敏感信息了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYCHgwGibWibcw9FicvIyhvWV3UGC9WWcUmKuSh3pSE1IFB9u09I4Niae81g/640?wx_fmt=png&from=appmsg "")  
  
且泄露的用户数据总共有7802条  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYtERmr6M2bDUE8ENPFwz1aexDkVGU9TZu4LnT0yu2CxGW2ib6Qm5baibg/640?wx_fmt=png&from=appmsg "")  
  
这里再构造接口list?pageNo=1&pageSize=7802  
，就可以看到所有的敏感用户信息了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYgHB3ico3ZBsrKyrTgtVtULkY5dCzEBjNsnoK35AO6kLGOaUpvGy6YlQ/640?wx_fmt=png&from=appmsg "")  
###   
### 四、再次突破  
  
这里碰到了idPhotoF和idPhotoZ参数，这两个参数我之前也是碰到过，在很多的招聘平台遇到过，就是需要我们认证信息，上次个人身份证正反面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYhEdPhuW6VNTKvqKlQOzJNjV2FrMRibRgwiaUlQ8klgN1nOsUlrFDEHyA/640?wx_fmt=png&from=appmsg "")  
  
我们正常思路就是知道这个照片的路径，就直接拼接数据包的host域名，但是这里并没有成功,spring-boot的报错页面，碰到这个师傅们也可以考虑使用曾哥的spring文件泄露扫描工具扫  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYNALfSDIsiaovvqia2kDZUe8p5MslZ1p1fJmS0pr910WpiacFnoZNAu7icA/640?wx_fmt=png&from=appmsg "")  
  
那么我们就得判断是不是路径的问题，那么我们怎么去找正确的文件存储的位置呢，下面就刚好看到了文件下载的功能点，点击尝试下载，然后看看数据包里面文件路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYqQdN3jI7PNLNYjdGegyCibwFic89WvxPl3b1yHmxR356DrERT2mDkpWw/640?wx_fmt=png&from=appmsg "")  
  
可以看到这个路径确实在数据包中，那么我们就可以把路径拼接在这里尝试下，看看能不能有照片回显  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYygIY4mp0cIEYaKDeERaAzTDicQqLxHTlbP8tujqyCUCwhRdUQrdwuRA/640?wx_fmt=png&from=appmsg "")  
  
这里直接拼接/download路径，直接可以回显图片成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYZYVDllKC5HN21ccqyaDEmhq4jhctRQWeYdS4qhicj4po89IpqX2JDCA/640?wx_fmt=png&from=appmsg "")  
  
直接可以在浏览器拼接host访问得到身份证正面照片  
  
  
我们这里总共有7806张身份证正面照片的url路径，这里我们就可以写个python脚本，把他们从数据包中爬取出来，然后再自动拼接到host域名上，python脚本如下：  
```
import json# 假设你已经获取到了JSON数据，这里我们直接使用你提供的JSON数据json_data = '''数据包内容'''# 解析JSON数据data = json.loads(json_data)# 基础URLbase_url = "https://host/路径"# 遍历每个用户，拼接URL并打印for user in data:    id_photo_f = user.get("idPhotoF")    if id_photo_f:        full_url = base_url + id_photo_f        print(full_url)
```  
###   
### 五、文件上传漏洞  
  
然后这里在测试在线申请功能点的时候，这里需要我们实名认证上传身份证照片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYcUxbXJpzO30hEk84OOQ7bSICpOPIbgE1cvh8rv93ULlbMRdpIoyuFg/640?wx_fmt=png&from=appmsg "")  
  
像碰到这样的文件上传功能点肯定得测试下文件上传，看看有没有什么过滤，试试打文件上传getshell，差点也可以尝试打个存储型XSS漏洞  
  
这里先尝试打个XSS漏洞，看看有没有过滤，发现没有，且可以成功解析弹窗XSS漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJY8BTgRgfv86JdXKXo5uvkNsCydDFcerl9ibeyxSRp2DInZWwxsAfoYicQ/640?wx_fmt=png&from=appmsg "")  
  
那么下面我们就可以尝试上传木马，然后进行打下getshell，传马之前，我们得先看这个站点是什么语言写的，使用插件看到是php语言写的网站  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYmBNSbJmzJGryyQxXUfDIs8sIrJQOVwxPmbO8zrgvJaTWf7ZvABMcTw/640?wx_fmt=png&from=appmsg "")  
  
但是这里过滤了php，但是没有过滤phtml，且可以成功解析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYLOdhhKaa6xDld0CKlrSneGMAia8xAhk9wOTTryqrpDhPbXyRmbEysNg/640?wx_fmt=png&from=appmsg "")  
  
这里我直接打一个phpinfo页面，证明下危害即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYcUHsUUo5YgjwVFT0wYMR0zxZpl90bqHX2OGcxzeUOsPg1A4x94fYKA/640?wx_fmt=png&from=appmsg "")  
###   
### 六、越权  
  
这里我们使用微信一键登录的时候并没有进行实名认证，所以点击下面的功能点的时候都会弹窗，需要我们进行实名认证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYviaS6QEc9AHez80FaXK8jgckfDBYUuV7Bw3INFIvn03WJlKuXHC7FLQ/640?wx_fmt=png&from=appmsg "")  
  
那么这里我就在想，要是登录别人的账户是不是就可以使用这些功能，且可以看到别人的信息了，而且在开始登录的数据包构造路径中，我们拿到了好多用户的登录用户数据信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJY7o1pT3KQCYQ5B2BIBD4KZw6MqOH9WiadJ2MIRIZdtdoqvGHpg1eBC6A/640?wx_fmt=png&from=appmsg "")  
  
下面我们先退回登录界面，然后使用bp抓登录包，然后修改用户登录信息，用我们刚开始收集到的用户信息，进行数据包替换，然后看看能不能成功登录别人的账户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYbPQ2FC74WnZ4Nic11naPffGWWXfTsibicDUISnzeH004T0jEiaibTtQdNDw/640?wx_fmt=png&from=appmsg "")  
  
可以看到我们这里直接就可以替换成功用户数据包，从而越权到别人的账户，从而打了一个水平越权漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYv2jG6RQfZnrrm7FzIpS2OxAW3ASicgapRafrsMfgwibSP2zpLcWrSFzg/640?wx_fmt=png&from=appmsg "")  
  
既然可以水平越权，那么我们是不是可以尝试下找到admin管理员权限的用户user数据，然后进行替换越权登录呢，下面就来找下，发现确实存在admin管理员权限的用户，然后就是按照上面的越权方式就可以成功登录到管理员的用户了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVUP26cFr3Omr5swnwJmJJYsIyousOR3msvlI2PJWwQYS6VEKuqMcvFjuX7EtSicanQK2UIQBquDFg/640?wx_fmt=png&from=appmsg "")  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 思路汇总**  
  
  
这里给师傅们总结下我们在进行漏洞挖掘过程中需要注意的细节，比如我们在看到一个功能点多个数据包的时候，我们需要去挨个分析里面的数据包构造，进而分析数据包的走向，去了解数据包的一个业务逻辑，特别是微信小程序，因为它本来就是程序简单，所以对于防御和一些过滤来讲，并没有特别的难，甚至就比如这个小程序都可以文件上传直接getshell了。  
  
到这里这篇文章就结束了，上面的漏洞案例就是给师傅们分享到这里了，还希望自己写的文章队师傅们有帮助哈！祝愿师傅们多挖洞，多过漏洞！  
  
往期推荐：  
  
[渗透技巧 | 小白都能会的通用漏洞挖掘技巧](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488347&idx=1&sn=6f3326467bd484bcf2a7cd3a32d1c201&scene=21#wechat_redirect)  
  
  
[应急 | 隐藏型暗链的排查与解决](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488331&idx=1&sn=b60eafcc6b3ee72e1ca7a6ad1d4935f9&scene=21#wechat_redirect)  
  
  
[漏洞挖掘 | 开始既结束？快速挖洞](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488326&idx=1&sn=64bed920635cd5aa06b69d18c24050be&scene=21#wechat_redirect)  
  
  
[【看完你也行】从源码泄露到后台rce](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488270&idx=1&sn=90ee55a652a608c39748b4e1ba25976c&scene=21#wechat_redirect)  
  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/5XMBWuTy1YdnTAAczP5ENGmlT9xMEAsJuTqV6jib7IyxImNprOeHxrbPLFkKfEPfh2U829KgfaTYB6NLOmx9Ykg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持，考证请加联系vx咨询。  
  
  
  
**关注福利：**  
  
回复“  
google工具  
" 获取 google语法生成工具  
  
回复“  
小程序渗透工具  
" 获取 小程序渗透工具  
  
回复“  
暴力破解字典  
" 获取 各种常用密码字典打包  
  
回复“  
typora激活  
" 获取 最新typora激活程序  
  
回复“  
蓝队工具箱  
”即可获取一款专业级应急响应的集成多种工具的工具集  
  
  
**知识星球**  
  
星球里有什么？年前最后一次优惠速来咨询  
  
CNVD、EDU及SRC赏金，攻防演练资源分享(免杀，溯源，钓鱼等)，各种新鲜好用工具，最新poc定期更新，  
以及一些好东西  
（  
还在学怎么挖通用漏洞吗快来加入  
），16个专栏会持续更新~  
**提前续费有优惠，好用不贵很实惠**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fXSPl8ibuX2P3oHCH6B7MrRYQSa51rqRWCefvVO8WzoNjhcOO2JHtIR51hrGrdibnCpIjcxTp4Kpcqg/640?wx_fmt=png&from=appmsg "")  
  
  
**交流群-过期后加微信拉**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fUlhS2Fv4ibBzE1a69RNGM2VT4zjicW7ibo5vXAVeibTNAWg7mGNYyEJy3bDiaZOofrpCeUzZDibXibTGRfA/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**安全考证**  
  
需要考以下各类安全证书的可以联系我，  
绝对低价绝对优惠、组团更便宜，报名成功先送星球一年，  
CISP  
、PTE、PTS、DSG、IRE、IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理......  
巨优惠  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicVKjibDEuQ9Kib0ia6TibrVmoFRWyXqReDwUhDas8kOqD29OfTA4XzqZjgw1pn8OYibtFfQxvPJq4kNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
