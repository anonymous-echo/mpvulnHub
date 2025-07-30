#  YongYouNcTool-一款高效利用用友NC系列漏洞检测利用工具   
原创 track  泷羽Sec-track   2025-01-24 12:43  
  
>   
> 声明！本文章所有的工具分享仅仅只是供大家学习交流为主，切勿用于非法用途，如有任何触犯法律的行为，均与本人及团队无关！！！  
  
  
公众号后台回复**25124**  
即可获取  
  
**往期推荐：**  
  
**2024Goby红队版工具-附2024年poc合集，支持导入自定义poc库**  
  
**一款功能强大的红蓝对抗工具Potato Tool-具备免杀,提权,漏扫,内存马生成,ai分析,溯源等高效的网络安全综合工具**  
  
**红队单兵作战渗透利器-DudeSuite，一款集成漏洞验证,安全工具,信息收集的图形化工具**  
## YongYouNcTool  
  
一款漏洞检测工具：用友NC系列漏洞检测利用工具，支持**一键检测、命令执行回显、文件落地、一键打入内存马、文件读取**  
等功能  
  
源地址：  
```
https://github.com/wgpsec/YongYouNcTool

```  
## 启动及适配环境  
  
双击此插件即可启动  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWia6XSXxcRwEzLtHgRh4ZwB4POfE0X1y5rrJu5CTGibQR6RxN4oN0DFCicA/640?wx_fmt=png&from=appmsg "")  
```
启动环境：jdk8

```  
## 核心功能  
- **BshServlet rce**  
  
- **jsInvoke rce**  
  
- **DeleteServlet cc6 反序列化**  
  
- **DownloadServlet cc6 反序列化**  
  
- **FileReceiveServlet cc6 反序列化**  
  
- **fsDownloadServlet cc6 反序列化**  
  
- **MonitorServlet cc6 反序列化**  
  
- **MxServlet cc6 反序列化**  
  
- **monitorservlet cc6 反序列化**  
  
- **UploadServlet cc6 反序列化**  
  
- **NCMessageServlet cc7 反序列化**  
  
- **NCFindWeb 文件读取/列目录**  
  
## 界面预览  
### 一键检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiacTblh7PAhfroPtIpIqGAcCrREK5dibqq2MrAe8HRl0CulViawUtzVzIA/640?wx_fmt=png&from=appmsg "")  
  
一键检测  
### 命令执行回显  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiao1g06bib8HdQcoxRgbVCd0HzT65m0NQR4nAMNOwDS7kO6GibevM53uNg/640?wx_fmt=png&from=appmsg "")  
  
命令执行回显  
### 文件落地  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiaKNSzicAGp3fCa1D3BIkmZqqHsIR1Ovhqzz6FQsibT6RGlrXYO50SsyRg/640?wx_fmt=png&from=appmsg "")  
  
文件落地  
### 一键打入内存马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiaHHwPjpWIQIhvwXI14Xy1xACKrMcuAwd4ucgLa5ia4FeXuJ17qXWZ6MA/640?wx_fmt=png&from=appmsg "")  
  
一键打入内存马  
### 文件读取/目录浏览  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiakYPUCoXJ2Hia9xXd5Fgfk1u6ibTQlj7hf1CuuZtf0bAmqaBvcvCQ0Tog/640?wx_fmt=png&from=appmsg "")  
  
文件读取/目录浏览  
### http/socks5代理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiawLSjnfYEn7bszufUHnKvXgVl8PUr3deIuo46HiaNJyH31XibfGKJGS7Q/640?wx_fmt=png&from=appmsg "")  
  
http/socks5代理  
## 工具注意事项  
- 不同类型的漏洞能够利用的方式也不同，比如有的能打内存而有的不能(也有的是暂未实现进去)  
  
- 不同的实战环境可能存在差异，请理性看待。  
  
- jsInvoke rce命令执行模块建议打了一次后抓包出来手动执行，目前的方案是执行一次就写入一个文件，很不优雅。另外就是为了兼容windows和linux，工具内置了两种命令格式，但由于目标环境原因命令实际上会被执行两次，所以还是建议抓包出来手动执行后续命令。  
  
# end  
## oscp  
  
有对红队工作感兴趣，或者有意报考oscp的师傅，可以考虑一下我们的培训课程，加我微信咨询，好处如下：  
  
**1.报考后课程随时可看，并且如果对考试没有信心，还可以留群跟第二批课程学习，不限次数时间，报考即是一辈子可看**  
  
**2.200+台靶机及官方课程，lab靶机+域的内容团队泷老师和小羽老师会带大家全部过一遍，并且群内随时答疑，团队老师及群友都会积极解答，全天可答疑**  
  
**3.目前可接受分期付款，无利息，最多分四个月，第一次付完即可观看视频**  
  
**4.加入课程可享受工作推荐机会，优秀者可内推至红队，月薪3w+**  
  
**5.报考即送送官方文档中文版，以及kali命令详解中文版，纯人工翻译，版权为团队所有**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiaSwLr7J8Kqua0ia12o8KclD8I7XEWeDlWnzjpWUqicWibX6CC8Wial30B5A/640?wx_fmt=png&from=appmsg "")  
  
**资料：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiakASKwiarucrZPO8bhNkuicx9nkZAt9ePewQxaUCGEPXsdliaLia2majubA/640?wx_fmt=png&from=appmsg "")  
## 知识星球  
  
**还可以加入我们的知识星球，包含cs二开，甲壳虫，网恋避险工具，红盟工具等，还有很多src挖掘资料包**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWia2pv550JM1DvI3DAtSOOAG0Zq8r6ViaMHDse7yamNLJMCPKpcuJQhm0w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWia5jAvcnlic41sDTJibfUWMfjWtE4tFiaZicxIxic9SmnicZ1cFFoibg6MltXTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWiaC4DvtBH2D92sXVTSu9AkgBxADZ0uXkUZpsW8ibCMSmE5icbgHC6pLUqw/640?wx_fmt=jpeg&from=appmsg "")  
## 学习交流群  
  
在**公众号后台**  
这里选择**学习交流**  
即可，如果图片二维码过期，可以加我微信获取  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YxCBEqEyrw2mJxibQ1u5WgZWibSPVOBGWia34Kb2CR88rNZD5Q0BYwoBut5ghy8LibhajyXLl6bj0JG6zRAKjsIbibA/640?wx_fmt=png&from=appmsg "")  
  
  
  
