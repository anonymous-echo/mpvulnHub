#  Yak与nuclei的深度融合：打造高效漏扫生态，解锁PoC管理新姿势   
原创 intSheep  Yak Project   2024-07-12 17:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZfCSs0zKcMmDXyJt76PDpGiataSbajd3BpbZnPXBCqFaA3icu2mY1LGqAmJHIiaCq5N9qCBv47ktQEYA/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLCXY6yf6dle55U2K81LqmYZUty7TRJjheSUzfdw3mRl0EPNKrQjnPe1Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLCXpiahvLdYS8g6yEtGjGv5fVqNfZKjNukLH2sHM7bxKEka2BnaicoCkTA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLC4GRybicZ8GTDVxHyrTsLuxN5kgutkjBWlwZYepmxwQjcQjFwDw8lD0Q/640?wx_fmt=png&from=appmsg "")  
  
在Yakit中使用nuclei很简单，只需要几行代码。在**Yak Runner**中，使用下面代码，指定扫描的目标与选项，便能调用nuclei的漏扫能力：  
```
results:=nuclei.Scan(target,opts...)~for result in results {    dump(result)}
```  
  
  
比如以下代码，会对目标192.168.135.128:8080使用tags为thinkphp的PoC进行扫描。  
```
results:=nuclei.Scan("192.168.135.128:8080",nuclei.tags("thinkphp"))~
for result in results {
    dump(result)
}
```  
  
而因为数据库里面并没有PoC，因此很多同学第一次执行的时候会出现以下错误：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLC9AHibJicH6Dg9Ae46F1c1mxB2APHYibXlKHU9XcsrXEOzRzRmAIDlhicpA/640?wx_fmt=png&from=appmsg "")  
  
  
  
报错显示没有templates，原因在于Yakit调用的PoC都从数据库拿的，而并非从本地的nuclei-template。解决方法也很简单，在Yakit右上角有个**导入资源**的按钮，可以从这里导入线上或者本地的nuclei资源。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLC3hdX2mHib7iccMnqkon6BEhCNlvo8ulDF8fMibZrUDficpuXZTVxMTwL6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLCg84cLX1MvTSkZoDGf1XzkrMupnicMavOlLTnm7yKex5CEEmzia2nzv5Q/640?wx_fmt=png&from=appmsg "")  
  
  
由此可以看到，Yakit调用nuclei逻辑和原生的nuclei操作逻辑是不一样的。许多师傅习惯了  
**nuclei -t**指定目录模板的操作，而在使用Yak代码调用nuclei的时候会很疑惑为什么没反应。请记住，Yakit中数据库就是你的弹药库，如果有你一些珍藏的PoC，请将其加入到弹药库中吧！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLClxk5ia1c03wUNRMePmEMkp2JxTSvn08wv8jSRfNsDVTD29nFgkh4C7w/640?wx_fmt=png&from=appmsg "")  
  
我们将nuclei的扫描结果加入到我们的漏洞展示页面，让其展示更为直观。在将Yaml格式的PoC导入后，便能够使用命令行进行扫描了，如果扫描成功，那么在Yakit的**数据库-漏洞**便能够看到告警。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLC0ksfAdyMaVnywJm6AF2nn8QYEcJ3j3GzMxvFdKBObnYCuzvOLKl2dA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLCwmxIibYjz2btxBU3YntXjPhMHGVxK2gicooDPLo4SzIddpL2lUocpVHg/640?wx_fmt=png&from=appmsg "")  
  
  
漏扫结果中，所有信息，包括IP地址、漏洞类型甚至是发送包和返回包都清晰可见。如果需要的话，可以将漏洞报告进行导出，支持导出csv和html格式的报告。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZcxV5w9ibKiaicGsWVrpy6QuLCuzz80X1BBnI126F94lpWL9o68b4V6Ru7xgI9AR10a7W2ziacwDjdz0w/640?wx_fmt=png&from=appmsg "")  
  
在整个nuclei漏扫过程中，PoC的编写尤为重要，一个好的PoC能让渗透测试做到事半功倍，而Yakit能快速生成Yaml格式的PoC。  
  
使用Web Fuzzer，可以将数据包的内容快速转化为Yaml格式。只需在Web Fuzzer标签页中点击生成Yaml模板，即可一键生成PoC。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdP3vS9ZqJXAsRQ6D9eGumsX1JPSwHwbweW4kY0731qAibIG09USEFCQN1QibJSHGicSqkOtIC6e2naA/640?wx_fmt=png&from=appmsg "")  
  
  
关于这方面Rookie师傅在PoC免写攻略做了分享，包括PoC如何验证响应与调试等功能。  
  
> 值得一提的是，随着版本的迭代，原本在"高级配置"里的匹配器，已经变更到"规则"里面来了，不要找错咯。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdP3vS9ZqJXAsRQ6D9eGumsg2Lec0NANNbZsxT7W7RE0WSnXh7MbRWlrzTgpb5LbicSfCD46BlFYNA/640?wx_fmt=png&from=appmsg "")  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdP3vS9ZqJXAsRQ6D9eGumsvibywDPeU7NqBWKl2O8ONIA52r1j6icxnmjIyARbBEZVcxeMPebhzNtw/640?wx_fmt=png&from=appmsg "")  
  
得益于Yakit的插件系统，你可以很方便的管理你所拥有的PoC，你可以将你的PoC按照资产、项目或者时间进行分类成组，以便下次需要的时候可以一把“梭哈”。  
  
管理插件组的入口在插件仓库本地插件的高级筛选中：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdP3vS9ZqJXAsRQ6D9eGumsE2Dk06gHxwWzr1W5XDdJbiakh9l3XTS1VBKzNWsQjwjJxWTvklI8Mrw/640?wx_fmt=png&from=appmsg "")  
  
选择想要成组的PoC，然后点击添加到组，并在搜索栏中写入你想要分组的名称，如果该组不存在，下方将会有一个新增分组的选项。勾选选项，再次点击添加到组，即可将这些PoC分类成组。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdP3vS9ZqJXAsRQ6D9eGumsvZnM64OpbnibQV7N4ib29LNpibNeD4AhpBN9royAfRab4kAf7cN8sRlaA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdP3vS9ZqJXAsRQ6D9eGumsVxmcJkYicPBiadHyqUpbI9y4lRITUUnCsNYj5I06fyECLw8DOMlibNicWA/640?wx_fmt=png&from=appmsg "")  
  
  
  
对成组的PoC进行批量执行，可以点击左上角的“批量执行”：  
  
#   
#   
  
**SUMMARIZE**  
  
  
**总结**  
  
  
#   
  
  
Yak集成nuclei，并非只是将该工具生硬地放了进来，而是在更高层面做了有机的融合，打通了nuclei的生态与Yak的生态的壁垒，体现了Yak安全能力融合的思想。这种融合有许多应用场景，比如渗透测试的复测。在渗透测试过程中，对目标资产测试完成之后，往往需要过段时间再进行第二次测试，也就是复测。可以想到的是，利用Yak的nuclei的操作流程可以帮你更好地进行复测。比方说，在第一次渗透测试出结果的时候，可以使用Web Fuzzer将HTTP数据包转化为Yaml格式的PoC，并通过插件系统，将本次PoC添加成一组，而在下次复测的时候，即可使用批量执行的功能，并在漏洞数据库中查看复测的结果。  
  
  
**END**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzk0MTM4NzIxMQ==&mid=2247520696&idx=1&sn=11d3dc7d59607ff96a9951d0e524c809&chksm=c2d1ed1cf5a6640a2ea4dfbc9f747daa0f4c0299185af6fd5dce8a86793061765df6c1a1380a&scene=21#wechat_redirect)  
  
点击上方图片跳转链接 ⬆️  
  
  
Yakit插件  
活动补  
充信息：  
  
参与插件治理活动的小伙伴们请知悉  
  
1.在提交误报插件时，为方便更好地为大家计数  
  
请以文字方式在插件评论区备注**"修复误报"**并发布  
  
重复提交同一个误报，以提交时间最先的为准  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdP3vS9ZqJXAsRQ6D9eGumsmSufoRlRv7bVt6dic8xmia0WOAOkw2Ivk1ibI81jEfAAqfDBotU4bPWyw/640?wx_fmt=png&from=appmsg "")  
  
  
2.报告重复插件时，请评论备注**“该插件与XX插件重复”**并发布。方法同上  
  
重复插件将保留发布时间最早的版本，被下架插件会在yakit软件内通知作者  
  
  
特此补充说明，以便后续统计和赠礼  
  
再次感谢大家的支持  
  
  
  
  
  
  
 **YAK官方资源**  
  
  
Yak 语言官方教程：  
https://yaklang.com/docs/intro/Yakit 视频教程：  
https://space.bilibili.com/437503777Github下载地址：  
https://github.com/yaklang/yakitYakit官网下载地址：  
https://yaklang.com/Yakit安装文档：  
https://yaklang.com/products/download_and_installYakit使用文档：  
https://yaklang.com/products/intro/常见问题速查：  
https://yaklang.com/products/FAQ  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeX0EdicJxBOjGjQuecg0TvCJp46Gs2kLCdSMrt5NUSvLq0fZvtej1gcR3CQfDxgf29BxBlibLRYIZg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZeX0EdicJxBOjGjQuecg0TvCvRgqibPwyOUp8untXs9Cl5XKux2yQQf27ibgZ0ic0Fm2yicdbYg6c4xUJg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
