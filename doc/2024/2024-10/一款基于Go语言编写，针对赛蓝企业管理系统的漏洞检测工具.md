#  一款基于Go语言编写，针对赛蓝企业管理系统的漏洞检测工具   
Seven1an  夜组安全   2024-10-07 20:00  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2Xvvlzc5lra8XdgLYGCfX5ooaMiaUJy4vKvStTngQp4122jauXltltcCuYib5WBBdaXu5dh91dGvibyQ/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**工具介绍**  
  
  
一款基于Go语言编写，针对  
赛蓝企业管理系统的漏洞检测工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpaFao49fsHtelic1Z4y5tXpvrlbbl9AspiauMHsVghCkhMyJS6HPKiaJCOTpHHRt4ASGiaTa8iaKgJng/640?wx_fmt=png&from=appmsg "")  
  
  
**02**  
  
**检测漏洞**  
  
本项目所有内容仅作为安全研究和授权测试使用, 相关人员对因误用和滥用该项目造成的一切损害概不负责  
  
截止到2024年10月1日，  
支持所有已披露漏洞的检测   
9 个 ，后续会随着公开而增加  
  
包括  
- AuthToken接口任意账号登录漏洞  
  
- DownloadBuilder任意文件读取漏洞  
  
- GetCssFile存在任意文件读取漏洞  
  
- GetExcellTemperatureSQL注入漏洞  
  
- GetImportDetailJsonSQL注入漏洞  
  
- GetJSFile任意文件读取漏洞  
  
- ReadTxtLog任意文件读取漏洞  
  
- EHR_Holidays/SubmitUploadify任意文件上传漏洞  
  
- System_FocusList/SubmitUploadify任意文件上传漏洞  
  
  
  
**03**  
  
**工具使用**  
  
```
CailsoftVulCheck.exe -u http://example.com/ -vul [1-9](default: any)
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpaFao49fsHtelic1Z4y5tXb9g5TP22QvpbNTlibXDOHhMNAgRfgQKOibmWYPyOrN3YB3EgW0q00ibLQ/640?wx_fmt=png&from=appmsg "")  
  
存在的漏洞会亮色输出  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpaFao49fsHtelic1Z4y5tX21eGvMGYRicicoMSSgDZ6z15EHkueUCM5ngXv3kKjpE4IScTvE9cTXAg/640?wx_fmt=png&from=appmsg "")  
  
指定漏洞检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WpaFao49fsHtelic1Z4y5tXQFOj57GUYg5n5SaOSDm6ZV2egQzsUREZiaBNKzIsPmHgX3kORabvicVQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**04**  
  
**工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【241007****】获取**  
**下载链接**  
  
  
**05**  
  
**往期精彩**  
  
[ 这款渗透测试工具库，你还没有用过吧！ ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492318&idx=1&sn=350f958583ae2b8ed550ced4ae2a8a18&chksm=c36ba626f41c2f30bc88092ad31423868e9a4c94f1e61f3c99bb6568ad055cb1ce08b00e9121&scene=21#wechat_redirect)  

						  
  
  
[ 一个轮子，用于渗透测试优化的 DNS/HTTP 日志工具，简洁、轻便、更易于使用。 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492304&idx=1&sn=49d0fd21822ce52bb5234144b64f90af&chksm=c36ba628f41c2f3e173df5e7cc2010eda7ba77e9972b4448abf0d0a7e1386632842a93cc99a6&scene=21#wechat_redirect)  

						  
  
  
[ 好用！备案查询、空间测绘、漏洞测试、编码及加解密.... ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247492295&idx=1&sn=de2d6d7920ea10f2ddda69760245b693&chksm=c36ba63ff41c2f29321131da63867354f83cadc9124a2a9c06e674626cb39bb85f8438c717ab&scene=21#wechat_redirect)  

						  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557 "")  
  
