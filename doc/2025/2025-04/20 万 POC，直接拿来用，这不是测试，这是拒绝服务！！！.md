#  20 万 POC，直接拿来用，这不是测试，这是拒绝服务！！！   
 sec0nd安全   2025-04-22 15:06  
  
之前看到很多人分享 github 上的一个项目，自动收录全网 nuclei 模板文件，目前已经 19 万了，如果直接拿来对目标进行漏洞探测，无疑会对目标造成巨大伤害，意味着可能要对目标发起十九万次请求以上，可以说是一次小型的 DDoS 攻击，项目地址：  
> https://github.com/adysec/nuclei_poc  
  
  
如图：  
  
![image-20250422151439175](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxCEBOd9aaKL5sqkyq4JXlWXDek5UWzB3sUYdWAWP0BibYwnaTicMx4Xj9g/640?wx_fmt=png&from=appmsg "")  
  
项目作者说已校验有效性并去重，那么真的有这么多漏洞 POC 吗？带着这个疑问，我们来一起分析分析，看看到底质量如何。  
  
首先我们要做的就是将项目下载到本地，做第一步去重操作，编写脚本可以借助 AI 之力完成，在 deepseek 中输入：  
```
帮我编写一个 python3 脚本，实现以下功能：
1、遍历目录 nuclei_poc 下所有 yaml 后缀的文件，循环遍历，存在子目录
2、读取文件内容，提取 requests: 或者 http: 分割后半部分内容，去掉 # 号开头的注释内容
3、将提取的内容，去除空白符（\r, \n, 空格, tab 符等）后进行 md5 哈希计算
4、根据哈希去掉重复文件，将非重复文件复制到目录 step1 下，只保留 yaml 文件，不保留子目录
```  
  
![image-20250422154031818](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxC1tQq0h0dnctnsekaxxPjr19y3IQCXS5fYZj1k5lOR9Ok8eKycPicc2w/640?wx_fmt=png&from=appmsg "")  
  
复制生成的脚本，运行后，在 step1 目录下保留了所有去重之后的文件，共计 72361 个，如图：  
  
![image-20250422155118117](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxCAXBagqINhUmU5wGbVFSsnibYoOics3x0sLW3NMdic5tFMLgzCVwwvzvxw/640?wx_fmt=png&from=appmsg "")  
  
其实看总数已经从 21 万变成了七万多，接下来我们进一步去重，具体处理步骤如下：  
```
帮我编写 python3 脚本，实现以下功能：
1、遍历 step1 目录下的所有 yaml 文件
2、提取 POC 的安全等级的值，具体格式比如 severity: info，其中 info 为安全等级
3、将所有非 info 等级的 poc 移动到 step2 目录下
```  
  
![image-20250422155957268](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxCXC8Tj16FjMDlhW9IFTebo6icos7BQPIbS3yW9SA8e6RB2nf1dyuHUIw/640?wx_fmt=png&from=appmsg "")  
  
运行后的结果如图：  
  
![image-20250422160018268](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxCIyL1lQCiaPZ6MerPrGNswGxnVcCp4kia3MHdqpcSKVfeibEKEbCfW1RgA/640?wx_fmt=png&from=appmsg "")  
  
经过这一步，剩下 50353 个，在分析 poc 时，发现很多 WordPress 的版本比对的 POC，如图：  
  
![image-20250422160126166](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxCNtcQK8uwibVYp5nwQiawhddNnKBD5ibXVre06rIVv1mDsgbpuhd51tNqg/640?wx_fmt=png&from=appmsg "")  
  
我们看看去掉这部分 poc 会留下多少，具体步骤：  
```
帮我编写 python3 脚本，实现以下功能：
1、遍历 step2 目录下的所有 yaml 文件
2、按行读取 poc 文件，如果某行存在  HTTP、GET、POST、PUT、BaseURL 关键词，则进一步判断是否存在关键词  /readme.txt 或者 /style.css，如果存在则跳过，如果不存在，则将该 POC 移动到 step3 目录下
```  
  
![image-20250422162249320](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxChFz8BRAYC6Zbiau6ypuo0STX5wicBfqRqsUuficeI9tbEEDWia5amfgScQ/640?wx_fmt=png&from=appmsg "")  
  
到这里，需要略微修改下脚本中的判断，最终效果如图：  
  
![image-20250422162343201](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxCcU8EL3WiapuUehnOvWexbXOzw3h583BR4XiciaaH7iaboMLk7ouhGydayw/640?wx_fmt=png&from=appmsg "")  
  
第三步之后，剩下的 POC 有 20223 个，有 30130 个 poc 是跟 WordPress 有关，而且是通过比对版本号判断漏洞存在的。  
  
到这里，deepseek 罢工了：  
  
![image-20250422162454786](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfecaHicGr47KBibEdGIvATCxCm0GiaIzI96mD1JsMTjZm3FDibMagJQtgDkRoaxcny7qfT1DN2QLcFib7w/640?wx_fmt=png&from=appmsg "")  
  
今天内容就到这里了，除此之外我还做了以下工作：  
  
1、提取 poc 中漏洞接口，根据漏洞接口去重，这个效果最好，基本上剩下一万多一些  
  
2、根据 POC 管理系统收录的 POC，提取未收录到 POC 管理系统的 POC 进入下一步  
  
3、将未收录的 POC 进行人工分析，提取系统指纹并更新至 POC 管理系统  
  
目前 POC 管理系统收录的 POC 有五千多个，基本可以覆盖互联网公开的漏洞情报了，同时可以通过三个途径调用：  
  
1、公众号后台回复任意网站链接，需要完整的网站地址，智能体可以帮你自动提交识别指纹和匹配 POC，[我的首个 AI 智能体，一键关联漏洞 POC ！](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247499815&idx=1&sn=dce5a2af1a71a8f7765ee5a87161a141&scene=21#wechat_redirect)  
  
  
2、xazlscan 工具，使用 python3 编写，配置好 POC 系统的邮箱和 token 即可自动识别系统，下载 POC 做漏洞探测，[POC系统配套自动化工具发布](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247499570&idx=1&sn=d9fd3a1d60c4673a5a84e379032bd027&scene=21#wechat_redirect)  
  
  
3、xazlcan 插件，一款 burp 的扩展，可以使用 burp 一键触发指纹识别和探测，[我的第一个 burp 扩展](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247499856&idx=1&sn=bcefd95652f5571cc3038729ab99f04d&scene=21#wechat_redirect)  
  
  
4、直接登录 POC 管理系统，通过网页端，提交网址进行识别，[新品发布，渗透必备，限时开放注册](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247499418&idx=1&sn=3db34b64046c5d70dfc63dacaee0ca65&scene=21#wechat_redirect)  
  
  
最后给大家推荐一个福利：京东云 50 元一年的 VPS ，每天都可以抢，贼划算：  
https://3.cn/2f-dKgmo  
（左下角直达活动页面）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfc1ibbG6mEdqV5Xpw0yu9UxtIoLlhiazxU4NakInEiam1mOnHHYw4pVq3nrrCc8tpnn5ictdhmNLUaHuA/640?wx_fmt=png&from=appmsg "")  
  
