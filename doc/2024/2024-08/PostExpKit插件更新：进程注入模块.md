#  PostExpKit插件更新：进程注入模块   
 Hack分享吧   2024-08-29 19:30  
  
今  
天更新下PostExpKit插件的进程注入模块，目前已集成CS内置进程注入命令spawnto  
、spawn  
、inject  
，另外还有PoolPartyBof  
、ThreadlessInject  
和CS-Remote-OPs-BOF下Injection  
（12种注入方式），总计有20+进程注入方式吧，也可将shellcode注入到指定进程中执行...。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOdoeZXibdMUVu4HL85DmrskGjBUkZzS4Hyibo3RsPhjGJ3JWD0U64dfaUQdafljA8Dl2KH3AJIwTMuw/640?wx_fmt=png&from=appmsg "")  
  
  
有关PostExpKit插件的其他功能模块和更新记录可以看之前发的几篇文章：  
- [简单好用的CobaltStrike提权插件](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247509423&idx=1&sn=e477e0292a4a4a7e37b2b98832b55dba&chksm=cfa501bcf8d288aa1a1360e63d54624af98655e4b6e13da06ed08bf4cbe22edce29b8f0a97ca&scene=21#wechat_redirect)  
  
  
- [PostExpKit - 20240423更新](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247510007&idx=1&sn=fc00a0327c290d9a1d65eba9a68d064c&chksm=cfa503e4f8d28af2fedd5e848bd1e3d3fad030637cef63a854636908ec6334a218bfd7abc08f&scene=21#wechat_redirect)  
  
  
- [PostExpKit插件更新：用户操作模块](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247510375&idx=1&sn=b5c342092f312fe74bb2ca278b8d6d4d&chksm=cfa50d74f8d284623d66ce11c79ec58c9b19fcd3fc65a17d74cd9b97fddd1564fbbce8f47542&scene=21#wechat_redirect)  
  
  
**实战应用场景**  
  
我们实战测试中如果使用默认进程注入方式被某些杀软检测拦截，这时可以尝试使用这个进程注入模块中的方法PoolPartyBof  
、ThreadlessInject  
、Injection  
等。  
  
建议注入到一些可信白名单进程......，因为这样不容易被检测拦截，实战中常遇到的以下几个场景（仅供参考）。  
```
目标主机存在某些安全防护软件，检测拦截CS默认注入进程行为、进程链等情况；
目标主机存在Windows Defender，Beacon执行命令会被拦截，导致掉线等情况；
线程土豆提权getuid为system高权限，但whoami为iis低权限，无法执行高权限操作等情况；
[...SNIP...]
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOdoeZXibdMUVu4HL85DmrskG7d4M6I6Wn6dVOiafUzQKibiaSf8aKqiajrPN3OLKAKl5JVTHl4LFUdic4Qw/640?wx_fmt=png&from=appmsg "")  
  
  
**部分功能演示**  
  
**CS-Injections（BOF）：**  
  
集成多种注入方式，可以选择其中1种将本地shellcode文件注入到指定进程中执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/XOPdGZ2MYOdoeZXibdMUVu4HL85DmrskGhbB7Fhw9eUAY3CSuMRBsIib23fCBgtfSegUzickFm7xwRgPyZeNlwVKg/640?wx_fmt=gif&from=appmsg "")  
  
  
**PoolPartyBof（BOF）：**  
  
一个完全无法检测的滥用Windows线程池进程注入技术集合，BOF武器化支持5种技术/变体。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/XOPdGZ2MYOdoeZXibdMUVu4HL85DmrskGTlh6pBdwvYopUEWW1v3Ac2q6JkPVPew4o7dV9eSchPBDXBToP3MLdw/640?wx_fmt=gif&from=appmsg "")  
  
  
**ThreadlessInject（BOF）：**  
  
一种新颖的进程注入技术，涉及从远程进程挂钩导出函数以获得shellcode执行，NtTerminateProcess为进程关闭时执行，NtOpenFile  
为打开文件后执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/XOPdGZ2MYOdoeZXibdMUVu4HL85DmrskGQbfXEt4EMY01tBRMia3yALw1t4jKc26YZuk2x6JPedY3cWSCo3wjiaXg/640?wx_fmt=gif&from=appmsg "")  
  
  
这个插件目前只在我的知识星球公开，最新版插件可在下方领取优惠券进星球下载，更多适用于后渗透实战的脚本功能正在陆续测试，敬请期待..！  
  
大家在使用过程中如果有遇到啥问题时可以在知识星球或者微信找我反馈、交流！！！  
  
  
**加入知识星球**  
  
仅前1-400名: 99¥，400-600名  
: 128¥，600-800名: 148¥，800-1000+名  
: 168¥。  
  
128¥还有50+名额，已经  
所剩不多了...！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ucYBZicS8b1LEFIxIXPEXBZ6WC4bxVcxhIxewI1MZtcLzicTsLQ7yMibeSwR1JgoqH7rv7aw9ll0sUWg/640?wx_fmt=png&from=appmsg "")  
  
