#  WPS最新0day漏洞？电脑被控仅仅是一个PDF（含视频）   
原创 余老师  白帽子安全笔记   2024-11-29 05:18  
  
   
  
继上篇文章，我们发现使用Adobe  
打开PDF  
可导致电脑被远程控制[《无法被拦截的PDF钓鱼》](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486500&idx=1&sn=2fbc0a619fece7b9e75f88d37333b368&scene=21#wechat_redirect)  
  
，而现在使用WPS  
的用户也面临同样的问题，赶紧一起来看下。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kLDN0giaqxE2X7T1aEqwRqh41bWCU3pb07vt4LkibgzQM0KskMeaEzLA94xJmjRiaNWTP3YMJJOK6jibp8icrhIxNBA/640?wx_fmt=jpeg&from=appmsg "null")  
  
## WPS-PDF注入  
  
此方式由于无需利用漏洞，无需伪装，正常PDF 弹出一个对话框要求重定向到外部网站，引导用户下载所谓的插件，普通用户稍不留心就可能去下载并安装，导致电脑被远程操控，由于是日常工作的PDF文件，通常得以绕过各种安全防护，再加上木马的免杀，容易攻击成功。  
#### 技术采用  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">编号</span></section></td><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">技术</span></section></td><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">详细</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">1</span></section></td><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">PDF注入</span></section></td><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">暂不公开</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">2</span></section></td><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">加载器</span></section></td><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><a href="https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&amp;mid=2247486226&amp;idx=1&amp;sn=f2ec6a817ee2ae9c804ab86638310e47&amp;scene=21#wechat_redirect" title="《间接系统调用APC注入EDR绕过免杀加载器》" style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));color: rgb(87, 107, 149);text-decoration: none;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;"><span leaf="">《间接系统调用APC注入EDR绕过免杀加载器》</span></a></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">3</span></section></td><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">C2</span></section></td><td valign="top" style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><a href="https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&amp;mid=2247486407&amp;idx=1&amp;sn=3d5aac035de86b7ebaa473a414954cea&amp;scene=21#wechat_redirect" title="《完全无法检测的CobaltStrike》" style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));color: rgb(87, 107, 149);text-decoration: none;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;"><span leaf="">《完全无法检测的CobaltStrike》</span></a></td></tr></tbody></table>  
  
视频区域  
  
  
### 注意事项  
  
由此可见，WPS在PDF打开时，默认是允许  
, 且域名缩略显示  
，易被伪造  
。稍不注意就点击允许导致木马下载至本地，风险较大。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kLDN0giaqxE2X7T1aEqwRqh41bWCU3pb0NkHescffos24YUnXQOkDMBL90n4LmKDyuQ2x7XFO5b01Ujtm44LMwA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
最后，还需提高信息安全意识，对来历不明的文件尽量不要去打开，即便是PDF。  
#### 推荐阅读  
- • [无法被拦截的PDF钓鱼](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486500&idx=1&sn=2fbc0a619fece7b9e75f88d37333b368&scene=21#wechat_redirect)  
  
  
- • [高级lnk快捷方式，常规杀毒软件无法拦截](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486482&idx=1&sn=3ae91be8bc850c87797b70895cc26002&scene=21#wechat_redirect)  
  
  
- • [[bug修复]完全无法检测的CobaltStrike](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486425&idx=1&sn=19911e3793263a7e493204e2b666403c&scene=21#wechat_redirect)  
  
  
- • [完全无法检测的CobaltStrike](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486407&idx=1&sn=3d5aac035de86b7ebaa473a414954cea&scene=21#wechat_redirect)  
  
  
- • [堆栈欺骗和内存扫描绕过](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486298&idx=1&sn=843bfa04153607c316b286588f465706&scene=21#wechat_redirect)  
  
  
- • [地狱之门进程注入官方免杀插件](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486285&idx=1&sn=270d87f08f2bc49e53290e0cf88ffe37&scene=21#wechat_redirect)  
  
  
- • [Beacon 命令和 OPSEC 操作绕过查杀](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486270&idx=1&sn=bb5dbb6430c7de3749624cf16b307dd4&scene=21#wechat_redirect)  
  
  
- • [我有关于免杀的2个概念和3个误区要讲](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486240&idx=1&sn=9dcae74cda0f749c4baef1e1a9ff5939&scene=21#wechat_redirect)  
  
  
- • [间接系统调用APC注入EDR绕过免杀加载器](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486226&idx=1&sn=f2ec6a817ee2ae9c804ab86638310e47&scene=21#wechat_redirect)  
  
  
- • [三步免杀卡巴斯基，免杀数字时长达一周以上](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486117&idx=1&sn=cac318d7138c1f44790f45b611511750&scene=21#wechat_redirect)  
  
  
- • [免杀HelloWorld，0/71通过所有杀软](https://mp.weixin.qq.com/s?__biz=Mzg2ODE5OTM5Nw==&mid=2247486097&idx=1&sn=6a0e75ace072e5fe2981444cdd3d1b93&scene=21#wechat_redirect)  
  
  
欢迎点赞分享并留言，同时欢迎关注视频号。  
  
  
  
