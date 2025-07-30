#  关于xz核弹级漏洞，看这些就够了？   
fragment1  重生之成为赛博女保安   2024-04-05 00:00  
  
这次  
的xz-  
ut  
il  
s  
后门植入漏洞，公众号  
各家  
都在争相报道。  
其中比较亮眼的内容  
  
需要比较全面的了解情况的看1  
>   
> 公众号：奇安信 CERT[【事件描述修正】XZ Utilѕ 工具库恶意后门植入漏洞(CVE-2024-3094)安全风险通告](https://mp.weixin.qq.com/s/9ITff6IuHLm77vhokYDD1A)  
  
  
  
  
如果是甲方，想了解利用条件以判断影响范围的看2  
> 利用条件：  
  
 TERM环境变量未设置  
  
argv[0] 需要设置为 /usr/sbin/sshd  
  
LD_DEBUG, LD_PROFILE 未设置   
  
需要设置LANG  
  
> 公众号：长亭安全应急响应中心[【正在深入调查】XZ Utils供应链投毒事件的真实影响：可能并不严重？](https://mp.weixin.qq.com/s/FTjN-dtrfOo8mK_1ZN1WZg)  
  
  
  
  
如果是开发、安全人员，想了解具体的事件代码 看3  
> 漏洞分析：受影响版本的liblzma会主动劫持sshd got表内的RSA_public_decrypt函数到Llzma_index_prealloc，但是实际上这个函数就是后门函数，跟lzma一点关系没有，实际执行逻辑为

当公钥满足一定条件时，将发送流量解密并执行隐藏在流量中的C2命令并执行。  
  
> 赛博昆仑，公众号：赛博昆仑[XZ开源项目的漏洞分析与应急](https://mp.weixin.qq.com/s/olc8OpJ75afK5wMWY2R02Q)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FvXdK33azdic32bUHzvZf2CAKGQcaU88yiaXkhZA1h5kWlxqk1fGAqaN5WzdGiaB9hp33J2dZcUZnichEHDJiaSGbRw/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FvXdK33azdic32bUHzvZf2CAKGQcaU88yiaXkhZA1h5kWlxqk1fGAqaN5WzdGiaB9hp33J2dZcUZnichEHDJiaSGbRw/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
其他的文章比较多是描述八卦背景，如果你发现有价值的信息，欢迎在评论区补充。  
  
供应链安全上次这么热闹好像还是在log4j漏洞的时候。感兴趣的可以听下下面的节目了解下历史事件。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1GN61syBFwUEu9AUfSF9sn0YJ14ZqxolBb5Shx29SlibZfFpib6VoprHENayLMtibnkOcmQsgAKdlhibFHJpG3kzww/640?wx_fmt=jpeg&from=appmsg "")  
  
注：如涉及侵权，请联系删除。  
  
​​​  
  
