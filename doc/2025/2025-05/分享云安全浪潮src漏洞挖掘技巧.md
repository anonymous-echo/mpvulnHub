#  分享云安全浪潮src漏洞挖掘技巧   
原创 神农Sec  神农Sec   2025-05-11 01:01  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
- 哈喽，师傅们！这次给师傅们分享的是最近在研究的云安全漏洞挖掘的一些技巧，后面好多都是我实战挖掘出的站点漏洞案例，所以希望师傅们能够有帮助，然后后面希望师傅们给我点赞+关注！  
  
- 本篇文章最先开始是以云安全的发展和未来会面临的问题来进行的一个简介介绍，分别从多个角度给师傅们分享云安全的相关优点和缺点，已经最重要的就是安全问题，云安全最大的特点就是方便，但是安全问题也是不能够忽略的。  
  
- 然后下面给师傅们分享下AccessKey  
相关的知识点了。对于云场景的渗透，现在已经层出不穷，获得AK  
和SK  
，也是云安全渗透中重要的一环。  
  
- 下面接着是介绍AWS S3对象存储攻防的相关知识点，也是同样拿了几个实战的案例进行分享，介绍Bucket接管漏洞问题，OSS存储桶漏洞，以及github工具的使用，最下面就是记录我之前挖的EDUSRC和攻防演练中的OSS存储桶漏洞。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 云安全的发展和面临的问题**  
  
### 1、云安全简介  
  
云安全通过互联网连接从远程服务器提供广泛的安全服务，而不是通过安装在本地的软件和硬件来提供安全服务。借助云解决方案，企业无需在现场安装和管理安全解决方案，而且企业云安全团队可以从任何位置通过基于 Web 的仪表板远程管理云程序。云安全通常包括 Zero Trust Network Access、云访问安全代理、威胁情报、数据安全、数据丢失防范以及身份和访问管理等方面的解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXKbQ53NSnbamRFrnjWZTzHWurcNMojlhxAFOaV3h5GhGU9iaDj1yzSKg/640?wx_fmt=png&from=appmsg "")  
### 2、什么是云计算？  
  
“云”，或更具体地说“云计算”，是指通过互联网在本地硬件限制之外访问资源、软件和数据库的过程。通过将部分或大部分基础设施管理转移给第三方托管服务提供商，该技术为组织扩大运营规模提供了灵活性。  
  
最常见和广泛采用的云计算服务包括：  
- IaaS（基础设施即服务）  
：提供一种混合式方法，可支持企业在内部管理部分数据和应用程序。同时，它依靠云供应商来管理服务器、硬件、网络、虚拟化和存储需求。  
  
- PaaS（平台即服务）  
：为组织提供简化应用程序开发和交付的能力。它通过提供自定义应用程序框架来自动管理云中的操作系统、软件更新、存储和支持基础设施。  
  
- SaaS（软件即服务）  
：提供基于云技术的在线托管软件，通常以订阅方式提供。第三方提供商负责管理所有潜在的技术问题，例如数据、中间件、服务器和存储。此设置有助于最大限度地减少 IT 资源支出，并简化维护和支持职能。  
  
### 3、管理云安全面临哪些挑战？  
  
云安全解决方案旨在克服本地技术所面临的相同挑战。  
- **缺乏对云环境的监测能力**  
。公有云提供商无法在其数据中心提供对云环境的无限制监测能力，这使得网络安全团队难以有效跟踪和管理威胁。  
  
- **附带损害**  
。公有云环境提供计算、存储和网络资源，多个客户可以借助这些资源共享同一台物理服务器提供的服务。当同一台服务器上的另一个企业受到攻击时，这种多租户安排可能会给该企业招致潜在的安全风险。  
  
- **影子 IT**  
。许多用户转向使用商业云服务来共享文件或提高工作效率，而不会征求 IT 部门的批准。如果这些影子 IT 实例不受安全策略控制或不受安全程序保护，则可能会带来重大风险。  
  
- **遵守法规要求**  
。法律法规规定了私人客户数据的存储、使用、保留和保护方式。当数据保存在云存储中时，遵守有关数据主权和驻留的法规可能相当复杂。  
  
### 4、云安全有哪些优势？  
  
较之本地解决方案，云安全服务具有诸多优势。  
- **成本更低**  
。借助云安全服务，企业可以省下本地安全解决方案的硬件、软件和许可成本。IT 团队无需增加员工资源即可更轻松地管理安全。  
  
- **事半功倍**  
。即使部署了诸多云安全解决方案，云服务提供商也只需负责与更新软件和应用补丁相关的任务，以理想的节奏修复漏洞。  
  
- **精简的管理**  
。借助云安全，云提供商将负责安全控制管理方面的许多日常任务，让 IT 团队能够专注于其他优先事项。  
  
- **最新的工具**  
。云安全服务允许 IT 团队使用最新的工具、病毒定义、防病毒软件和其他安全解决方案。  
  
- **卓越的可扩展性**  
。与所有云服务一样，云安全产品可以快速轻松地扩展，以保护更多用户、设备和位置。  
  
- **安全专业知识**  
。由于云安全提供商只专注于安全，他们可以聘用能够为工作带来更多技能、经验和专业知识的专家。  
  
- **加速部署**  
。虽然安装和配置本地解决方案可能需要数周或数月时间，但设置云安全服务通常可以在几分钟或几小时内完成。  
  
- **更快的事件响应速度**  
。云解决方案有助于在安全事件发生时缩短响应时间，更快地修复漏洞和消除威胁。  
  
- **轻松满足合规性要求**  
。IT 团队经常发现，要确保符合 HIPAA、GDPR 和 PCI DSS 等框架是一项艰巨的任务。云安全解决方案使企业能够轻松完成合规性任务，使 IT 团队能够减轻合规性方面的许多责任。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 AWS S3 对象存储攻防**  
  
### 一、AWS S3简介  
  
对象存储（Object-Based Storage），也可以叫做面向对象的存储，现在也有不少厂商直接把它叫做云存储。  
  
说到对象存储就不得不提 Amazon，Amazon S3 (Simple Storage Service) 简单存储服务，是 Amazon 的公开云存储服务，与之对应的协议被称为 S3 协议，目前 S3 协议已经被视为公认的行业标准协议，因此目前国内主流的对象存储厂商基本上都会支持 S3 协议。  
  
在 Amazon S3 标准下中，对象存储中可以有多个桶（Bucket），然后把对象（Object）放在桶里，对象又包含了三个部分：Key、Data 和 Metadata  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXYpFt6MVDlcH5Rqf8MAWFZnxQ510TMsIMw74PmiaOCmA6uZUQVmMtW9A/640?wx_fmt=png&from=appmsg "")  
- Key 是指存储桶中的唯一标识符，例如一个 URL 为：  
https://test.s3.amazonaws.com/test，这里的test是存储桶  
 Bucket 的名称，/test就是 Key  
  
- Data 就很容易理解，就是存储的数据本体  
  
- Metadata 即元数据，可以简单的理解成数据的标签、描述之类的信息，这点不同于传统的文件存储，在传统的文件存储中这类信息是直接封装在文件里的，有了元数据的存在，可以大大的加快对象的排序、分类和查找。  
  
操作使用 Amazon S3 的方式也有很多，主要有以下几种：  
- AWS 控制台操作  
  
- AWS 命令行工具操作  
  
- AWS SDK 操作  
  
- REST API 操作，通过 REST API，可以使用 HTTP 请求创建、提取和删除存储桶和对象。  
  
### 二、创建AWS S3储存桶  
  
首先我们得使用亚马逊的这个官网注册用户：  
  
https://signin.amazonaws.cn/signup?request_type=register  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXYUyaLEmvSgRnNuvGxrZic37yJI6wPs34ias7fvWocOia94VHR7SefDVrw/640?wx_fmt=png&from=appmsg "")  
  
然后登录进去，打开Amazon S3面板  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXzia4AcLPVwC4dKxQSTBk0qT3GJyjunT6FwU8aMBswKavQe5f36BlSMw/640?wx_fmt=png&from=appmsg "")  
  
然后再点击创建储存桶并进行配置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FX64rSQ88V8iabdUCJWro1yxlDdibSRlWhaJNURdTaN6iciajOITnXQTaDsQ/640?wx_fmt=png&from=appmsg "")  
  
配置成功如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FX40KOricdT7Y4z0AlB5OjL5dtY0pUNQy1oWVRd9IgAwBzUJ3NXpCH2NQ/640?wx_fmt=png&from=appmsg "")  
### 三、Bucket 爆破  
  
当不知道 Bucket 名称的时候，可以通过爆破获得 Bucket 名称，这有些类似于目录爆破，只不过目录爆破一般通过状态码判断，而这个通过页面的内容判断。  
  
当 Bucket 不存在有两种返回情况，分别是 InvalidBucketName 和 NoSuchBucket  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXsXf2Hiber73cZ5r3umzM3qLfoyM1ONashbf5y12youTb2Cg4ZEH0vHw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXhRbcZBpiaBmkVObImX7tAQ5qwicTZKl7bARXj9WLasceOP5sGs9V9siaA/640?wx_fmt=png&from=appmsg "")  
  
当 Bucket 存在时也会有两种情况，一种是列出 Object  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXyuzf643mTt11xicLGtySPCm5P4K3nrboAria9kYNs7SB2xn7Mz0ibCf8g/640?wx_fmt=png&from=appmsg "")  
  
另一种是返回 AccessDenied  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXYJbiaq0dmWbNY64kzUp197xGMSqn1zm9d37jjcM1LkYeMdLZN16QFbg/640?wx_fmt=png&from=appmsg "")  
### 四、Bucket 接管  
  
假如在进行渗透时，发现目标的一个子域显示如下内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXwGmPBkCg0jIianSBU6AGicJE9fPLspyOOOse3GcP8tGV6PAxAIGpZXKQ/640?wx_fmt=png&from=appmsg "")  
  
通过页面特征，可以判断出这是一个 Amazon 的 S3，而且页面显示 NoSuchBucket，说明这个 Bucket 可以接管的，同时 Bucket 的名称在页面中也告诉了我们，为   
xxxxxxx.s3.amazonaws.com  
  
那么我们就直接在 AWS 控制台里创建一个名称为 xxxxxxx.s3.amazonaws.com的 Bucket 就可以接管了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXdvWexVeb9TibtXrZ5WUhjDxBmKPtEiaCFAd3g1nCLictLBMYbWjbDaCgQ/640?wx_fmt=png&from=appmsg "")  
  
创建完 Bucket 后，再次访问发现就显示 AccessDenied 了，说明该 Bucket 已经被我们接管了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FX9bp7vqPS7W0BVuFTWB7FLZxv66FMHFwaokmBRreLsXOzDOMnicPc5Dw/640?wx_fmt=png&from=appmsg "")  
  
将该 Bucket 设置为公开，并上传个文件试试  
  
可以看到通过接管 Bucket 成功接管了这个子域名的权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXugBPgM2iat8aLf3LQXpmSQWLHAuhFicu1NBiaqv784uArR4dd8wFULukw/640?wx_fmt=png&from=appmsg "")  
### 五、实战案例  
  
这里我拿到一个站点目标，尝试着去访问这个  
  
发现这个是个登录系统页面，尝试使用弱口令和爆破都没有用，前端和逻辑都试了，但是没有突破口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXcpcLe1r6xdoiatc8rCyT8EmFWrvIRbKltOsA2oAtrm3EDMV1dof3HzQ/640?wx_fmt=png&from=appmsg "")  
  
这个时候使用fofa检索这个域名，看看其子域名有没有什么突破口  
  
这里发现子域名存在OSS关键字，应该是存储桶，看看是否存在OSS存储桶漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXljhKkJhZFSf5ckiaeBYQqr1rYiaRmian99lZwc6FZdnOiaTP9psyPDKJLA/640?wx_fmt=png&from=appmsg "")  
  
访问这个oss子域名，发现存在OSS存储桶漏洞，可以发现遍历出不少文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXjH1Yia0tuxCyayG2pkhqv9AYaD9D7vabCUVWyBpbRfIKicTc5s4FhicYQ/640?wx_fmt=png&from=appmsg "")  
  
简单的文件查看就是手动的去拼接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXeD28dqRop6Q7Hfk0TDbT3wa6HlKGQD90X7NVN6f12hB97kll09aHTQ/640?wx_fmt=png&from=appmsg "")  
  
这里给师傅们介绍一款github上的oss存储桶文件遍历工具——OSSFileBrowse  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXHEPGKO2j36BZMaryTFicwNGWfa4ib0T60XTeicpL9D8H67ozotsEqeAVg/640?wx_fmt=png&from=appmsg "")  
  
下载地址如下：  
https://github.com/jdr2021/OSSFileBrowse/releases/tag/v1.1  
  
工具使用如下，直接把存储桶的url放里面直接就可以遍历出所有的文件了（左边是遍历出的文件内容）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXMkibSy1IpibxZVBBOIQA2OONd51hNREAOAu2XLwISySZx4oiaDXHAH2Fw/640?wx_fmt=png&from=appmsg "")  
  
既然想要漏洞扩大漏洞危害那么还可以尝试 文件存储桶文件覆盖  
  
可以看到这里的1.html文件内容，下面我们会进行使用bp抓包PUT上传文件进行原文件覆盖操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXpLMneXhtWHgicBuUnqO2cO2azHibjJ4agjAjXtmlxe7jK5adm6qr9bdg/640?wx_fmt=png&from=appmsg "")  
  
利用PUT文件上传方式来进行覆盖存储桶原始文件，只要名字对应即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXjybJcZY7GWHL4cdnMXEYdpe0JvtZ3vRMdq3bzrEyZVveHiawiauPH23A/640?wx_fmt=png&from=appmsg "")  
  
如果目标的对象存储支持 html 解析，那就可以利用任意文件上传进行 XSS 钓鱼、挂暗链、挂黑页、供应链投毒等操作，我们这个站点就是能够解析html的，也就是说我们可以打个钓鱼链接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXQIyRRxiaYL9jgawdw9z5WS5Bk3DnJh8v8MniabiaghpONIRVzZ6QpgpVA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 AccessKey泄露接管云**  
  
## 一、浅谈  
  
下面的论述也是看完  
曾哥  
的文章，然后加上自己的理解，下面给师傅们分享下AccessKey  
相关的知识点了。对于云场景的渗透，现在已经层出不穷，获得AK  
和SK  
，也是云安全渗透中重要的一环。  
  
通常，我们会在一些敏感的配置文件或者通过未授权访问、任意文件读取漏洞等方式，来寻找AK和SK。  
  
一般常见的通过正则匹配式  
来寻找AK和SK：  
```
(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]
```  
  
下面我给师傅们介绍下常见的几个厂商的Access Key  
内容特征，然后就能够根据不同厂商 Key 的不同特征，直接能判断出这是哪家厂商的Access Key  
，从而针对性进行渗透测试。其中我们云服务器常见的就是阿里云和腾讯云了，我主要给师傅们介绍下面两种Access Key的特点。  
### 二、阿里云  
  
阿里云 (Alibaba Cloud) 的 Access Key 开头标识一般是 “LTAI  
“。  
1. ^LTAI[A-Za-z0-9]{12,20}$  
- Access Key ID长度为16-24个字符，由大写字母和数字组成。  
  
- Access Key Secret长度为30个字符，由大写字母、小写字母和数字组成。  
  
### 三、腾讯云  
  
腾讯云 (Tencent Cloud) 的 Access Key 开头标识一般是 “AKID  
“。  
1. ^AKID[A-Za-z0-9]{13,20}$  
- SecretId长度为17个字符，由字母和数字组成。  
  
- SecretKey长度为40个字符，由字母和数字组成。  
  
### 四、接管云环境  
  
这里拿到这个网站也是直接利用插件findsomething去看看有什么接口信息泄露包括一些js敏感信息，然后下面看到了OSSaccessKeyId，这个是现在云安全有的一个关键字，相当于唯一的账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXN6U9zUo8vOW8EFYDXwiaMCHf3j7qlkl3K2SVLd7bP9KmGFfiah8Xq9Zw/640?wx_fmt=png&from=appmsg "")  
  
然后这里再直接F12检索源代码，右击搜素OSSaccessKeyId关键字，因为OSSaccessKeyId相当于账号，也就是我们需要找到相关云安全的账号以及密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXX0bGyg4W5rBOvib61kYxW3ap7icMDhS2ZtA64liaCRFNBxGUB6lOKjibEg/640?wx_fmt=png&from=appmsg "")  
  
然后再里面继续翻找，然后找到了下面的信息，也就是我们最关注的ossAccessid和ossAccesskey关键字了，有了这两个关键字我们后面就可以使用一些云接管的相关工具进行打一套漏洞了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXstpibHpssu2QXltvblMbb55btND0R9g01XKB611oD9CI8Ibc8rklnxw/640?wx_fmt=png&from=appmsg "")  
### 五、接管云工具——行云管家  
  
使用行云管家  
这个工具去接管云环境  
  
https://yun.cloudbility.com/  
  
第一步：登录行云管家之后选择云主机厂商并导入资源  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXEtfXWGhrNOG4goyrnNre4hgOetOBIJEzEtezsZYSBrWQicTggISD21A/640?wx_fmt=png&from=appmsg "")  
  
第二步：导入key id跟key secret  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FX1IRUgz2ia9giav0F22lRNwr0pnuZxelzAlrIuXlJqrnqoGhEdhjtF1ibg/640?wx_fmt=png&from=appmsg "")  
  
第三步：AK/SK验证通过后选择绑定的云主机  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXYv44ricPUvhrTH9VYqm9SSBkjVbaDXs08ic5v19l5HoHVzBSMQCicvT0g/640?wx_fmt=png&from=appmsg "")  
  
第四步：就是之后完成导入操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXxMGtHEbV0zdEE6rRfccQSgL6Vvh23uF3rKTl1QoEuzs3KOUCmvI3Nw/640?wx_fmt=png&from=appmsg "")  
  
但是里面进去后没有找到什么云主机的信息，是因为开始绑定云主机的时候就没有扫描到，但是没有关系，这里主要是给师傅们一个渗透测试的思路，在找到Access Key  
相关知识关键字的一个思路，碰到这样的该怎么去打一个漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FX9eMw9WucfgY0G6zUNRUAxG63xgt9NXjbuvxcDpWuQXNfqA7IRKJpyA/640?wx_fmt=png&from=appmsg "")  
### 六、oss-browser  
  
有一些他里面你要是没有找到那个访问的url或者访问不了禁止访问登录连接，那么师傅们可以尝试下下面的这个工具oss-browser，就是专门来连接OSS的。  
  
https://github.com/aliyun/oss-browser  
  
下面我们就使用这个工具进行连接，然后看看有没有什么敏感信息泄露之类的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXdpwkdCVvUhKcDqVoz93ZKjrs7jGciauRwbqyGeyAIC9r2vvrDzXEHBQ/640?wx_fmt=png&from=appmsg "")  
  
直接输入泄露的access-key值，直接使用OSS连接工具就可以直接连接成功了  
  
里面有很多的该云主机泄露的信息，后面的内容就不给师傅们分析了，主要是接管云环境的一个思路的分享。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXBlOd8EGQXGzaLlRPeqcIsT2gSjgFMg7tIgicPaV8icyGpLcEoJ0cDgBw/640?wx_fmt=png&from=appmsg "")  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x5 云安全之OSS存储桶漏洞**  
  
  
一、EDUSRC微信小程序  
下面这个漏洞是之前我在挖掘EDUSRC时候，去挖一个某大学的证书站的时候看那个大学的微信小程序挖到的一个OSS存储桶漏洞，这里我打下码然后分享给师傅们学习学习  
  
这里起初是通过这个学校微信小程序的访客系统，这里的这个访客系统teacherName参数可控，把这个参数置空，然后可以打一个信息泄露，就是泄露改系统的一个访客用户的信息，比如姓名、手机号、地址等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXFkgpebuhaKiallTcA2OE4uFBmBNnAibFiasIHqdu76y77AJm5PgWHtpZw/640?wx_fmt=png&from=appmsg "")  
  
但是这里我需要给师傅们讲的是，通过访客预约进群这个系统后面，可以通过文件上传图片的功能点，然后可以使用bp抓取数据包，发现这个小程序可能存在OSS存储桶漏洞，也就是我们今天重点给师傅们介绍的云安全漏洞之一  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXVHm5EIlqQ5zxjUbsmb7M5sJHibMl7zmXTq2k0svr8TA68l5WxiccjcyQ/640?wx_fmt=png&from=appmsg "")  
  
访问这个url，发现就是开始上传的图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXRH2acSIstlRQyFySkNFT7pRscdklAbGMr4OazBuFgnkbfoAjrsukyw/640?wx_fmt=png&from=appmsg "")  
  
那么后面我们就需要去拿这个url，挨个删除目录，然后看这个页面的一个回显信息，比如像下面的如果出现的是AccessDenied关键字，那么就是打不出OSS存储桶漏洞的，没有权限访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXVhQPFxRN3EVHH5N8eBAVhApXsibxpTbnX6GsPPWjYroAQ19ohSd3szA/640?wx_fmt=png&from=appmsg "")  
  
这个微信小程序把这个url挨个目录删除，后面是回显的NoSuchkey关键字，说明可能存在OSS存储桶漏洞的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXiaKGrAMjRVwJiaCs77OQaXVK7t7aKaYEWOjgHrzx9fbZdOZWnF6bZyeg/640?wx_fmt=png&from=appmsg "")  
  
像要是挨个删除目录，然后出现像下面的页面，那么恭喜你成功挖到一枚云安全的存储桶漏洞了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FX9VKCxW8T5ByJNRhMIsKUQJoA9DWduCb4y1SkGeDmRIdbAghbbL3pcw/640?wx_fmt=png&from=appmsg "")  
  
然后把对应的文件图片目录名称拼接到这个url后面，就可以出一个云安全的文件泄露漏洞了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FX4SqDL9090VlsQoCHGEnxrT3NwBISEc71aUFRIm2No87RU6yibuaAagg/640?wx_fmt=png&from=appmsg "")  
### 二、攻防演练中的一次OSS云安全漏洞  
  
比如常见的OSS存储桶漏洞，还有泄露ak/sk的相关敏感信息泄露的漏洞，然后可以看看是云安全OSS相关的敏感泄露，让后可以尝试下面的工具进行一个OSS劫持  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXN4sMHVguumqV7icKmWgpCzAiamEhR39ZmVBpdrcvNhnrZr6STl6u3A8Q/640?wx_fmt=png&from=appmsg "")  
  
比如在某配置详情里面找到了这个东西，这个也是OSS储存桶相关的漏洞，下面的url可以访问下，然后要是有回显的话，然后尝试使用下面的access-key和secret-key进行密钥登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXYhfBOvBjly7OxZPH6DqdINjDtWUYlM1XTfkicspP3NdFc1slKichF32w/640?wx_fmt=png&from=appmsg "")  
  
可以看到这里我直接就登录成功了，且里面都是云空间里面的存储东西，下面可以看到里面的日志信息等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXFKme3ArDB37SKmfKicwJRMtM1yzjZ6B82qRVwcwn6OMAUxfcdwmsbJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXZSAkzeALC3qN22oIdGnspELhJ1MNr6K06nR1wibeiasMjOPdJxVFj3ug/640?wx_fmt=png&from=appmsg "")  
  
然后还可以使用阿里云的OSS接管工具，如下：  
  
https://github.com/aliyun/oss-browser  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXdpwkdCVvUhKcDqVoz93ZKjrs7jGciauRwbqyGeyAIC9r2vvrDzXEHBQ/640?wx_fmt=png&from=appmsg "")  
  
直接输入泄露的access-key值，直接使用OSS连接工具就可以直接连接成功了  
  
里面有很多的该云主机泄露的信息，后面的内容就不给师傅们分析了，主要是接管云环境的一个思路的分享。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWg6VxSWtLejhY8ba8a1FXBlOd8EGQXGzaLlRPeqcIsT2gSjgFMg7tIgicPaV8icyGpLcEoJ0cDgBw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x6 总结**  
  
这篇文章到这里就结束了，主要是给师傅们分享云安全相关的漏洞案例，作者写的文章主要以知识点和实战漏洞案例来结合进行分享，有相关技术不足的地方，希望师傅们可以加个联系方式一起交流学习哈！  
  
到这里这篇文章就结束了，上面的漏洞案例就是给师傅们分享到这里了，还希望自己写的文章队师傅们有帮助哈！祝愿师傅们多挖洞，多过漏洞！  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x7 内部圈子详情介绍**  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于800人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUQrFWcBesgFeibmAaLTXbl25YKcjTuT0F7X8qBLgI7JaOjU1DxsgxfyicbBDibicKwvIhjia1Jm33NQaA/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满800人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXzIXhsuibSCxH9DL0qbmoy9fgFDcSWC6Yyg3eJsoE70q5jJ1OiaSQYcFsw/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
