> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NjUxOTM3Mg==&mid=2247489617&idx=1&sn=627a09e75a07a946e5a6915effa21222

#  XSS基础类型  
原创 一个努力的学渣  一个努力的学渣   2025-06-29 15:12  
  
免责声明  
  
本文只做学术研究使用，不可对真实未授权网站使用，如若非法他用，与平台和本文作者无关，需自行负责！  
  
序章  
  
**XSS：**  
跨站脚本攻击，攻击者通过在目标网页中注入恶意脚本，当用户访问该页面时，脚本在用户浏览器中执行，从而窃取敏感信息、劫持会话或实施其他恶意行为  
  
  
**攻击本质：**  
- **恶意脚本注入**  
：攻击者利用网站对用户输入的信任，将恶意JavaScript代码插入网页（如评论、URL参数等），当其他用户浏览时，浏览器误认为脚本是合法内容并执行  
- **绕过同源策略**  
：通过注入脚本，攻击者间接突破浏览器同源限制，访问用户在该站点的隐私数据（如Cookie、会话令牌）  
**直接危害：**  
XSS不会直接影响数据丢失，中大型企业存在的几率也很高  
- **数据窃取**  
：盗取Cookie、账号密码、银行卡信息  
- **会话劫持**  
：冒充用户身份操作账户（如转账、发帖）  
- **传播恶意内容**  
：篡改页面植入钓鱼表单或勒索软件下载链接  
**高级利用：**  
- **蠕虫传播**  
：存储型XSS可构造自复制脚本（如新浪微博事件，3小时感染3万用户）  
- **供应链攻击**  
：入侵第三方JS库，在所有引用站点植入后门（2020年SaaS平台漏洞案例）  
在挖洞过程中，部分企业可能不收，视情况而定，如邮箱、私信等影响范围较大收的概率大，如只是简单弹个窗，无漏洞组合利用，可能不会收  
  
常用标签：  
https://www.freebuf.com/articles/web/340080.html  
  
测试流程：看输出想输入在哪里，更改输入代码看执行（标签，过滤决定）  
  
漏洞原理：接受输入数据，输出显示数据后解析执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeUCYshBH2iaxscia000FQZiaPhkkZR0t89E0iacJez1n3Bll2KoTFQUDJRQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeXEoY0eQqJ4IsicPhhtkKwgFeB5huQoEXR981eicR5C6txxlx8K903t6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeQ82yAibicQbLFMKLVttZf0dHQoibbNqHqiaF0lluGQaliawq4MAsrzxic7JA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeVBasTqAHykuHEwdWOrWvDZ25YBoSOzsgAFFgP0UFQPCeodvDUjOAhQ/640?wx_fmt=png&from=appmsg "")  
# XSS可能存在的地方  
- 数据交互的地方  
- get  
、post、headers  
- 反馈与浏览：搜索功能、评论和留言、论坛和博客等  
- 富文本编辑器：内容管理系统(CMS)、在线文档编辑等  
- 各类标签插入和自定义  
- 数据输出的地方  
- 用户资料：个人资料页面、用户头像等  
- 数据输出：搜索结果列表、数据报表和统计等  
- 评论，留言等：产品评论、留言板等  
- 关键词、标签、说明：搜索关键词高亮、标签云、产品说明和描述等  
- 文件上传：图片文件、文档文件等  
## 反射型XSS  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeAGWERzia0zgia6qZeBLVF7Bqv9yicbMkWOAEC7oZbeUvbxTr3ia9EpuibVw/640?wx_fmt=png&from=appmsg "")  
  
**触发机制：非持久性**  
，需用户主动点击恶意链接，攻击仅在单次访问中生效  
  
  
**原理：**  
攻击者通过构造一个恶意链接的形式，诱导用户传播和打开，由于链接内所携带的参数会回显于页面中或作为页面的处理数据源，最终造成  
XSS  
攻击  
  
  
**核心危害：**  
- **Cookie劫持**  
：窃取用户会话凭证，冒充身份登录（如网银、社交平台）  
- **钓鱼攻击升级**  
：伪造登录弹窗或下载链接，诱导用户输入敏感信息  
- **传播恶意内容**  
：篡改页面植入广告或政治敏感信息，破坏企业信誉  
一般来说危害小，条件苛刻(如何发给对方、发给对方之后对方是否会点击)，小中型网站一般不收  
  
部分条件苛刻也可以创造条件，让对方大概率点击触发，需要看我们能否勾起对方的好奇心  
  
  
**常见触发点：**  
发生于不跟数据库打交道的地方  
- 搜索功能：搜索结果页面通常会显示用户输入的关键词，若未对关键词进行转义，攻击者可以在关键词中插入恶意脚本  
- 查询参数显示：某些页面会将用户输入的查询参数直接显示在页面上，如“用户信息未找到”等提示信息  
- 错误消息：错误消息中可能会包含用户输入的内容，若未进行转义，可能成为攻击的入口  
- 表单提交反馈：用户提交表单后，服务器返回的反馈信息中包含用户输入的内容  
- URL重定向  
- 二维码跳转：恶意URL嵌入二维码，扫描后触发XSS  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeUCYshBH2iaxscia000FQZiaPhkkZR0t89E0iacJez1n3Bll2KoTFQUDJRQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeXEoY0eQqJ4IsicPhhtkKwgFeB5huQoEXR981eicR5C6txxlx8K903t6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeQ82yAibicQbLFMKLVttZf0dHQoibbNqHqiaF0lluGQaliawq4MAsrzxic7JA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeVBasTqAHykuHEwdWOrWvDZ25YBoSOzsgAFFgP0UFQPCeodvDUjOAhQ/640?wx_fmt=png&from=appmsg "")  
  
  
案例：比如有些网站是获取UA头信息的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOe5R2ApHcwfxlI7bpPgiaCCRb6MouZUr7F5RDiaCrUGEdWEcVx6I2l0ickQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeEIqfpyze6ppMaoIF0TrkcYaaQp9ibqVxRaa4V2vglFsPLIm71sSapiaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOe0h1gFzajlW4p6T7iavv5Fp3wWYm3uQjJSOK3b6icIFX5Wj9tAeBwia9QQ/640?wx_fmt=png&from=appmsg "")  
  
之后尝试XSS语句  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeuiaaRQQHKTwyOAjL0pqEWyV8zf1Nere3bTn0lyoQqTGOayibuDkIUTGg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeLn3q8thKNRllHwuPkOD18iakiaxG3raQaqXKJg8ModdHahe6uPoibiaIuw/640?wx_fmt=png&from=appmsg "")  
  
重新刷新后恢复原样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOe5R2ApHcwfxlI7bpPgiaCCRb6MouZUr7F5RDiaCrUGEdWEcVx6I2l0ickQ/640?wx_fmt=png&from=appmsg "")  
  
利用起来比较麻烦：让受害者带着XSS代码去访问(触发XSS的前提：UA头必须我们能控制，但不现实)，所以这个XSS无害  
  
  
代码审计：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeUfVJc4rLYrYicp8ic6EWX6JqaekiaewXV03KL4lmib06aKallIBnIBhogg/640?wx_fmt=png&from=appmsg "")  
## 存储型XSS  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOegAEeVW6vpmUxMB34ib4TNQXHFIIhiaKeTmFQjvgaSmmZo4vicXZRtr9cA/640?wx_fmt=png&from=appmsg "")  
  
**触发机制：持久性（长期危害），**  
恶意脚本一旦存储，可长期存在，形成“被动攻击链”  
  
  
核心：数据交互  
  
  
**原理：**  
攻击者向可存储用户内容的区域提交恶意脚本，服务器未过滤直接存储到数据库，当其他用户访问受感染页面时，服务器返回恶意内容，造成  
XSS  
攻击  
  
  
**常见触发点：**  
发生于跟数据库打交道的地方（影响范围较大，收的概率大）  
- **论坛和留言板：用户可以发布内容的区域，如论坛帖子、留言板等**  
- **评论区：在博客、新闻文章等页面的评论区**  
- **社交媒体：用户发布动态、评论等**  
- **用户资料：用户的个人资料页面，如个人简介、签名等**  
- **文件上传：允许用户上传文件（如图片、文档），若未对文件内容进行严格检查，攻击者可以上传包含恶意脚本的文件**  
- **产品评价：产品评价内容**  
- **内容管理系统：**  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeibhibbpCHunkNJzAeyGzbxIGFxCgrCMfCoaK8MPm2SATkmONG8SbM1XQ/640?wx_fmt=png&from=appmsg "")  
- **协助平台功能：**  
- **Wiki页面编辑**  
- **共享文档注释**  
- **工单系统描述**  
- **项目协作留言板**  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeaxib36NSnGsFMVxbWc6fJb1LLKMk3P1MgIibr9bibrtJJgJByUDKHZBQA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeVz5bdUyQpO0BPgIdowiaP6oib0neeHicyKg0CJ8epNZCp8AQ3h63iaB8Fw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeRJoQUUfDZ8J7QibgvpTbFEnZJYh6cgibOgutrfCJuDn4IOHr3aw0vxUw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeWcdO1VFqG2nYyhZh70VeGmK3LuneiadqL7P4icKAVgibBhJicMmRh81DHw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeXDdbeWyVkPSw3V6lgMpA7dLqsuItSCXStqXn9BUUaHOxPrDpkXLQvA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeECaaSLRTic2Q6eicgwo5ACmANEYqaJbt5wbRicNbia29KlO7SoIkTvSQHQ/640?wx_fmt=png&from=appmsg "")  
  
  
案例：小皮面板  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeuCKTaKpxqgVI2fkJ5xyNV5ktZ55CoLZ5uexuGlQuH5Ndga4tRsmBJg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOe55Niaz4QDFTkw128pwYUeCmYSouY5XtrgJrDO89HnKKTbeH03obPhbg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOevdISqniaE0xbCjG5ic8icqHnB2bic9sL9oZLN60WwB9pDEHNDJEKQPMsTw/640?wx_fmt=png&from=appmsg "")  
  
真实环境下，简单弹窗没啥用，最起码获取个Cookie，然后利用Cookie登录网站  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeckOctQXSgT59zMdib5wHQYiam4ZsKYkTKsJe9zicuSiahEmGaFEfz0na2Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeVEVPjMv2OByQ8cUuNVK3IzohkBBRzNImpS2OybibJ7KpS6BBTJtKvmg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeyZ4XEIMMsMRsiaDN6o3iactRuibNlVnrOcicIv7Ac4FfTe9NT7TnDbYBfA/640?wx_fmt=png&from=appmsg "")  
  
数据已经写入数据库，每次点击操作日志都会弹窗，除非在数据库中删除此操作日志  
  
  
黑产中的存储型XSS攻击链：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOenzhynHz1qJHnaUS3okicZeX17r7KiaCMGJzbibmCjwEeNiaAmkdPFEbqyw/640?wx_fmt=png&from=appmsg "")  
  
目前挖洞可借鉴：类似推广产品，点击进去之后要求留言，之后我们输入相关信息(XSS语句)，后台没有进行过滤，客服点击进去之后就会中招  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOey8EkYValE4hKZicjfqSrzgVJWLib8GGymu070sf8xv7PCH74Hk4MMz1w/640?wx_fmt=png&from=appmsg "")  
## DOM型XSS  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeamnRvxudEn3Jv6aqUr1ic9D4AvDvNcnYRCwJEh2Z9Is3z16K97whN1g/640?wx_fmt=png&from=appmsg "")  
  
**触发机制：**  
依赖客户端环境，攻击过程不经过服务器处理，而是通过修改页面的DOM结构触发恶意代码执行  
  
  
**原理：**  
通过修改原始的客户端代码，受害者浏览器的  
DOM  
环境改变，导致有效载荷的执行。页面本身没有变化，但由于  
DOM  
环境被恶意修改，代码被包含进导致执行  
  
  
****  
**常见触发点：**  
- URL 参数：恶意脚本通过 window.location 或其他相关对象读取 URL 参数，并将其写入到 DOM 中  
- 表单输入：恶意脚本读取用户在表单中的输入，并将其写入到 DOM 中  
- 存储的数据：恶意脚本读取存储在 localStorage 或 sessionStorage 中的数据，并将其写入到 DOM 中  
- HTTP Headers：恶意脚本读取 HTTP Headers 中的数据，并将其写入到 DOM 中  
- WEB API  
- 现代框架误用  
****  
**代码审计：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeibnwBM4mOS5QcwFJt3icPymAicOo6e6MntqcGM7iaia2Bthor6b0mgSCt4Q/640?wx_fmt=png&from=appmsg "")  
  
  
**DOM型XSS与反射型XSS对比：**  
<table><tbody><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;background-color: rgb(248, 248, 250);"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">维度</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;background-color: rgb(248, 248, 250);"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">DOM型XSS</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;background-color: rgb(248, 248, 250);"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">反射型XSS</span></span></strong></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">触发位置</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">完全在客户端浏览器执行（不经过服务端）</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">恶意脚本经服务端返回后执行</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">数据交互</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">通过前端JavaScript操作DOM树注入恶意代码（如location.hash）</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">恶意脚本通过URL参数传递，服务端未过滤直接返回到HTML</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">持久性</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">非持久性（依赖用户点击特定URL）</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">非持久性（需诱导用户点击恶意链接）</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">检测重点</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">前端JavaScript代码（如innerHTML、eval()）</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">服务端输出编码逻辑（如未转义的URL参数）</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">典型攻击场景</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">修改location.hash、动态插入&lt;script&gt;</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">搜索框参数回显、错误页面未过滤输入</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><strong><span style="color: rgb(55, 58, 64);"><span leaf="">绕过特点</span></span></strong></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">依赖DOM解析漏洞（如拼接字符串触发onclick事件）</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;text-align: left;"><span style="color: rgb(55, 58, 64);"><span leaf="">利用服务端过滤缺陷（如大小写混淆、双写标签）</span></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeuCYS36kj6W23KSiab12KaSWAC6RfjcfWFV7YMFAzAOGp0j14SBKmEUw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeDscVrbbB89AicxTq480TEP93TknIYmOav2U042NEicLfJqqF6NJwlyyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOe15JU0UudrXjgLLibcD79QPgY6zQDerPJ4kHBVJVfVOK9y4dSsU2oGHA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeDPAjXeAxoSYkdrp0RibVSBxILUcVwkd53y3gtGyqOhfFMcXG7bsPIsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOezWaLKicDxC7YIR8t1huVNjtgibUa5jQYpJ5whFAeHvc7ACo2ic4Ba80aQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeBkPSsYKIgWsWVItkxkxs54WTSHxbkbO9E37fTMhClP0D0ldSjD43ww/640?wx_fmt=png&from=appmsg "")  
  
输入以下内容：<a href="javascript:alert('XSS 攻击 via javascript 伪协议')">点击我</a>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOe1BoDBuhyf3oXfzlwSlKPQYIISYoGymOAyocH0dAiasSWZEwqkQw9pOg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeE7PRhiaZq73qibW3gN1HvuyuSks2Nx61keaoJcuRyPrLt3icIAibPe9Q4Q/640?wx_fmt=png&from=appmsg "")  
  
**总结**  
  
挖到XSS之后如何判定属于哪种类型？  
- 存储型XSS：存储在数据库中(每次访问攻击语句都存在)  
- 反射型：一次性触发XSS  
- DOM型：攻击之后，F12查看页面发现JS代码能改变样式、属性、值  
****  
**危害程度对比：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzKuBNDEE5qyfUpPHxyIrOeyxlTTRlk2jbbTWyTibS50YIte1YicGibViaG6bhL9pYfSqJrvV8zBJkCNg/640?wx_fmt=png&from=appmsg "")  
  
**具体危害：**  
- **大规模会话劫持：窃取所有访问用户的Cookie**  
- **水坑攻击：在合法网站植入恶意软件**  
- **网站篡改：修改页面内容散布虚假信息**  
- **键盘记录：监控用户输入窃取凭证**  
- **挖矿攻击：利用用户CPU资源挖掘加密货币**  
- **内部网络探测：扫描企业内网服务**  
****  
**XSS的本质是利用网站对用户输入的信任，诱导浏览器执行恶意脚本。防御需多层覆盖：**  
- **前端**  
：禁用高危DOM操作 + 启用CSP  
- **服务端**  
：输入校验 + 输出编码  
- **全局**  
：HttpOnly Cookie + 安全框架  
****  
**防御策略：**  
- **输入过滤与输出编码：**  
- **输入校验**  
：过滤用户提交内容中的敏感字符（如< > " ' &）  
- **输出转义**  
：根据上下文对动态内容编码（HTML实体化、JavaScript编码）  
- **安全机制强化：**  
- **CSP策略**  
：通过HTTP头Content-Security-Policy限制脚本来源（如default-src 'self'）  
- **HttpOnly Cookie**  
：阻止JS读取Cookie，降低会话劫持风险  
- **避免危险API**  
：禁用innerHTML、eval()，改用textContent等安全方法  
- **开发框架支持：**  
现代前端框架（如React/Vue）自动转义动态内容，减少手动处理漏洞风险  
