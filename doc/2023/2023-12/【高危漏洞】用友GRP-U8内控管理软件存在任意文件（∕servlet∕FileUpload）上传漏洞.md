#  【高危漏洞】用友GRP-U8内控管理软件存在任意文件（/servlet/FileUpload）上传漏洞   
moon  皓月当空w   2023-12-02 15:23  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h1AzajLJTBu7YOczrAwxaw0KAqv7gHNdsWu0BEtibKibaegocwoGb75HNNUpZ0ukoIu7XxnCpsONILQhseSns4zg/640?wx_fmt=png "")  
  
皓月当空，明镜高悬  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/h1AzajLJTBu7YOczrAwxaw0KAqv7gHNdZfzFIibGpEEEjcB4BuCfTfsf4KgL65xJd1EO5ibicom3eT9QDCHzvMr7w/640?wx_fmt=gif "")  
  
  
  
  
  
文末有图片更好保存  
（包含福利内容）~  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h1AzajLJTBu7YOczrAwxaw0KAqv7gHNdjgbENMv47awmAOrpibcD0W1Cyicz2b2RY2qRfeCSL29wSIMCPQMS3T8w/640?wx_fmt=png "")  
  
漏洞早知道  
  
       
  
**漏洞名称**：用友GRP-U8内控管理软件存在任意文件上传漏洞  
  
**漏洞出现时间**：2023年12月1日  
  
**影响等级**：高危  
  
**影响版本**：  
  
用友GRP-U8R10产品                                  
  
**漏洞说明：**  
  
 用友政务公司获知用友GRP-U8内控管理软件存在任意文件（/servlet/FileUpload）上传漏洞后，第一时间组织团队进行应急响应，分析处理漏洞问题并发布相关解决补丁，并对相关支持人员进行培训。本次漏洞通过http://ip:port/servlet/FileUpload接口上传文件，通过更改文件后缀形式绕过系统文件类型校验，并通过上传文件更改文件上传路径，将文件保存到其他路径下。存在一定的安全隐患。      
  
**修复方式：**  
- 厂商已提供漏洞修补方案，请关注厂商主页及时更新：https://security.yonyou.com/#/noticeInfo?id=447  
  
**相关链接：**  
- https://security.yonyou.com/#/noticeInfo?id=447  
  
  
**最快的威胁情报，最全的漏洞评估**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/tqglEQSfnW8On06lc1t8uB3Sia6qzKss2yxNPbiakf5YSc1UyVFTlwCuymUSPoyw2GujZGrmYOaJROuFgfIJhsQg/640?wx_fmt=jpeg "")  
  
  
  
Tips  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h1AzajLJTBu7YOczrAwxaw0KAqv7gHNdjM6hZmEJpn7tvGpPUaMaWjmktwXWhnoEtcDFjczcwLC3v5tYxJV0JA/640?wx_fmt=png "")  
  
  
用友公司成立于1988年，致力于把基于先进信息技术（包括通信技术）的最佳管理与业务实践普及到客户的管理与业务创新活动中，全面提供具有自主知识产权的企业管理/ERP软件、服务与解决方案。  
  
  
图片版本更好保存哦~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h1AzajLJTBsfUbicVQ7V27FToL9Zy9GwcO4rFvhIyg2X1UrIOStNEvfg7u2uECQkKFnTibPRgHGVwomfeic0jlViaA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h1AzajLJTBsGR5jHw9fpxuTmXiaCdhv2XyzlwsZDUwVYeShmG5PSjqqOpUW3KCwb8q4pVmBso9BrqVTibFm576rQ/640?wx_fmt=png "")  
  
近期文章：  
  
[【8-29 网安面试题】今天的题目很简单，我猜你可能不会](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484843&idx=1&sn=772b303b7bfebde91f5178944bbcd375&chksm=cf6f7b37f818f22196b97caa7967c4f5d3f097608df9207c8860b0fc300e22378d7a211403d8&scene=21#wechat_redirect)  
  
  
[【8-27 网安面试题】这些基础题你还记得吗](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484823&idx=1&sn=33b81fbc4fb970c623e77d7a5ef46525&chksm=cf6f7b0bf818f21d3450c49112319228ee7fb2557f4914af6808ec6fc7fa3f9c5bd38780228c&scene=21#wechat_redirect)  
  
  
[【1day细节】某OA pweb 接口sql注入](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484881&idx=1&sn=4e657c8fcc089c836184cf58c51d2b72&chksm=cf6f7b4df818f25be7848c5b789fb6d17032d4ab6d68b415d5395e2aeb1d394c3d6f9fa03be1&scene=21#wechat_redirect)  
  
  
[【严重漏洞】【poc公开】Cacti<1.2.25 reports_user.php SQL注入漏洞](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484904&idx=1&sn=3a044f81c859df4adea4c00eeb52421a&chksm=cf6f7b74f818f26294b63ffcadbb59a3ce1a79acfea6a463bf409c7440cb8cce4201e237510c&scene=21#wechat_redirect)  
  
  
[【严重漏洞】Apache Superset 任意文件写入漏洞](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484901&idx=1&sn=98ccb9719a41ddc842a4cde01112dd2a&chksm=cf6f7b79f818f26f53e2c2990c906302b1a13247f78f31d0cf69e303fea20869b0ea10807821&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484823&idx=1&sn=33b81fbc4fb970c623e77d7a5ef46525&chksm=cf6f7b0bf818f21d3450c49112319228ee7fb2557f4914af6808ec6fc7fa3f9c5bd38780228c&scene=21#wechat_redirect)  
[【严重漏洞】 Apache FreeRDP 出现多个cve漏洞](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484859&idx=1&sn=eb3e9f6d87304e78741397da0c29936b&chksm=cf6f7b27f818f2313bb5832d63d54d85dc146bf3ebcc06278a2c8dd59605e7b1d442b0a3fa25&scene=21#wechat_redirect)  
  
  
[【高危漏洞】【未修复】EduSoho企培开源版存在未授权访问漏洞](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484863&idx=1&sn=fd7d16aef7c10a2699fb491b0ea02bbe&chksm=cf6f7b23f818f235e455e36c1ff8cf56d2dd964ea7f37a11ce67e7c63d2cb705f212ad02278e&scene=21#wechat_redirect)  
  
  
[【高危漏洞】达梦大数据分析平台存在未授权访问漏洞](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484863&idx=2&sn=f6032b4c7a109a838b9392ef2950abce&chksm=cf6f7b23f818f23587ab5d2095882f8ff6a1bb0e205a67c49016dfe860ed4abe67b47e5467ac&scene=21#wechat_redirect)  
  
  
[【严重漏洞】CVE-2023-34968  Samba信息泄露漏洞](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484853&idx=1&sn=e1e42f0123d773143f6eb8b56669ec70&chksm=cf6f7b29f818f23fe32ad614b7c99821d28a1f20e3b8ca2fc4543b754e6c1de14e878862b4ff&scene=21#wechat_redirect)  
  
  
[【高危漏洞】启明星辰信息安全技术有限公司4A统一安全管控平台存在命令执行漏洞](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484849&idx=1&sn=30d011f2463c4912c42491289a590062&chksm=cf6f7b2df818f23b8376cbb2f6e2da22b223ea184c98106ddbbae747b44a0d2299a3c3202d27&scene=21#wechat_redirect)  
  
  
[【高危漏洞】CVE-2023-40195-Apache Airflow 存在反序列化漏洞](http://mp.weixin.qq.com/s?__biz=Mzg4MDg5NzAxMQ==&mid=2247484843&idx=2&sn=b6bcc3857a123bc3a0f79238617ada50&chksm=cf6f7b37f818f2212881d7cbb330d01874949be7a51e6433fbc79450d7ec968bc3eaaca37b51&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h1AzajLJTBu5rgRA4hWkNlNSLvibXD2H6EhLFWwNkqHggDJRelC8d3ic6Wia6X6PvTOaibQibHOsaiaktfp1SejwLCEw/640?wx_fmt=png "")  
  
  
上图中的截图就是目前新开发的系统，但是很多功能都不完善，当然有内部测试的计划，但是目前账号体系还在建立，有意见，或者是提前想进行测试的伙伴可以在公众号后台私信，目前的想法是做一个比较简洁的漏洞情报系统，能够拿到最快的漏洞情报，并且实现推送功能，后期可能会增加一个poc提交或者是报告提交的功能，当然目前还是以漏洞情报展示和推送为主，有好的建议一定要找我哟。  
  
  
平台目前情况：  
  
皓月当空-BugSearch
                
  
当前收录漏洞数量：12160  
  
推送功能目前还没有实现  
  
  
  
当然除了漏洞情报系统，针对公众号还有什么其他问题也可以找我，包括不限于排版，内容以及公众号运营的问题。  
  
  
最后感谢您的关注，江湖寂寞，愿你我同行  
  
  
  
合作可联系：  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/h1AzajLJTBtZliaydD43NQLeXYIiausiabfTib0JY0CbOawQwJgiaM1aCr2bw6PTDC4yic4pOtIAmmZb7hnXWJO4jPAA/640?wx_fmt=jpeg "")  
  
  
  
