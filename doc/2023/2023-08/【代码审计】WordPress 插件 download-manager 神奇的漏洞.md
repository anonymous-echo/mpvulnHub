#  【代码审计】WordPress 插件 download-manager 神奇的漏洞   
津  火线Zone   2023-08-11 18:31  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULf6ZEsEEA6oeUpr957yA8ibgtQmIWoVMm9TYJ1PhvLvamdicB5GUjJKE4A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfI3yIwsolviay103p29wM3I3SFMu7EpCLDiaaic2jw1DfHibMIBQWibho3Jg/640?wx_fmt=jpeg "")  
  
  
这个漏洞是历史版本发现的漏洞，在最新版本上已经被修复。  
  
WordPress 下载管理器是一个文件/文档管理插件，旨在管理、跟踪和控制 WordPress 网站的文件下载。您可以使用密码和用户角色来控制对文件的访问、管理下载速度并限制每个用户的下载数量。  
  
  
它还提供验证码锁定或 IP 阻止等功能来阻止机器人、不需要的用户或垃圾邮件发送者。您甚至可能要求用户在下载之前同意您的条款和条件。Wordpress download-manager 插件存在越权漏洞，攻击者在知道某个文件的下载密码后，可以下载网站上的任意加密文件。  
  
  
神奇的越权漏洞  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/SeErbKf71pDiaRoiau20KUnxok09GdtYSxJMTLHqVKib5KlO1cGKMpUAqa0M9hQDHmLajKvypYKBB3gH4N3jjDU8A/640?wx_fmt=gif "")  
  
**漏洞测试**  
  
  
  
插件下载地址  
  
https://downloads.wordpress.org/plugin/download-manager.3.2.70.zip  
  
登录后台后，上传并加载启用插件，我们添加两个不同的文件，并设置不同的密码  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfGtoiasS67m2zvLq07Xt0OCnbNULuQicRNlrI8ezBgtB7Tfwicy3o6m69w/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfn83HH5TvLymeYoEeiafxoGianuTZNpAVBV2O3k00iawLV7EEo56V2R4LQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfx058Bed6wzg4pM6fvHpQ8Q7bRGZ5ArDQ9bQe5GPUl6N2pMIXrNXvaQ/640?wx_fmt=png "")  
  
访问对应的下载页面  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULf0ic37pEoKeibh7BozNwE8oCx0xQvSaBkVFtCjj76GXq3cSENgeeKxSfQ/640?wx_fmt=png "")  
  
点击下载均需要输入密码  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfgmY7jdRp5qSI0eaP3lef7Sf5DHqOzImwG7kciaicC97OibqKJfTiaxIeIA/640?wx_fmt=png "")  
  
  
此时我们仅知道文件1 的下载密码是123456 文件二的密码并不清楚  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULftXa7bnL4Ck3DiaRMB46YueaJlZzo5nfAy7hKwp8oLFoM55q6xSuzbwQ/640?wx_fmt=png "")  
  
  
输入密码显示出了文件的下载地址此时我们访问下载地址  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfpXviapknjmtkuFCvMoPL5UlYmuoSa8Er77Y43TmaCYC73bVbich4U0fQ/640?wx_fmt=png "")  
  
  
下载的文件一的内容，同时修改参数wpdmdl 的值  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfDJGGU6O5sm38xsj8U8dAmH4goYQgRx8FtlfPdmf6PUkjIG0WNs7ib3g/640?wx_fmt=png "")  
  
  
发现将文件二也下载了下来  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/SeErbKf71pDiaRoiau20KUnxok09GdtYSxJMTLHqVKib5KlO1cGKMpUAqa0M9hQDHmLajKvypYKBB3gH4N3jjDU8A/640?wx_fmt=gif "")  
  
**漏洞分析**  
  
  
  
\WPDM__\Apply::triggerDownload 处理下载操作  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfVfBCDmjyYQSf3fPwydglJbVMqB3BAxfddpobZqFODcDI9qjpiaKDq6w/640?wx_fmt=png "")  
  
  
\is_wpdmkey_valid  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfLJrgCvXg7ib954mwd8fkUNDGOXtk9l7huXkib9ia9cfW7aVB8kArUWMZw/640?wx_fmt=png "")  
  
  
\WPDM__\TempStorage::get  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfX4bMoYMfq5NYjQWTtZib3Faib1RBl73NO0K71MROJFEjkdhk5H39NjLQ/640?wx_fmt=png "")  
  
  
我们注意到key 的处理查询跟时间有关，跟 id 无关，所以获取的key 在时间范围内可以下载任意加密文件，无论密钥值。  
  
  
  
  
**往期推荐**  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247498599&idx=1&sn=d3c70a256802e80d58c08e21e751feea&chksm=eaa97347dddefa51d734914a418e96af9a78bb728a091a3a533a40ed4dc49aa78f3b0d0a6715&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247498599&idx=2&sn=f22240741a60db730a06105fc8c4f0d4&chksm=eaa97347dddefa51cfdeafe130071cab15c5b9027574f32fa9a4727b767f6de8cf95ebe2a087&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247498566&idx=1&sn=3b36a36f6c55879d734e5324187b459a&chksm=eaa97366dddefa7017a35e7728d9749b8db19698c13343b49adf394f3e8af564262b8fab759d&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaQLOh0nUvibslzOcviaq7BULfWVq7uOkkxEVj8vDpVonoOY2VWwooAR2QzgPV94PT1779jNs321OXPg/640?wx_fmt=png "")  
  
火线Zone是火线安全平台运营的安全社区，拥有超过20,000名可信白帽安全专家，内容涵盖渗透测试、红蓝对抗、漏洞分析、代码审计、漏洞复现等热门主题，旨在研究讨论实战攻防技术，助力社区安全专家技术成长，2年内已贡献1300+原创攻防内容，提交了100,000+原创安全漏洞。  
  
欢迎具备分享和探索精神的你加入火线Zone社区，一起分享技术干货，共建一个有技术氛围的优质安全社区！  
  
  
  
  
