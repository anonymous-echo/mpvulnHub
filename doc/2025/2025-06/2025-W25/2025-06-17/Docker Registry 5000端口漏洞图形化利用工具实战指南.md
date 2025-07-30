> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NDU3NDA3OQ==&mid=2247491309&idx=1&sn=6178a36525fbb6268e0ad09a12e1a80f

#  Docker Registry 5000端口漏洞图形化利用工具实战指南  
原创 网络丐帮帮主刘  鹏组安全   2025-06-17 07:35  
  
### 由于微信公众号推送机制改变了，快来星标不再迷路，谢谢大家！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/0YvAy5BgkyNJe4vC6qtyDX3vcGgiameZcOwiaYlDgwuutJUicHD1ZWicn2T6WTuuiaLvsAcnHBq2a4f6LkwqGtGOuxw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
前几天写了一个对[DockerApi未授权利用工具使用感受以及开发手记(2375端口)](https://mp.weixin.qq.com/s?__biz=Mzg5NDU3NDA3OQ==&mid=2247491292&idx=1&sn=44f4271661c031110f416df94284425a&scene=21#wechat_redirect)  
，看看Docker还有什么可利用的点。  
  
查询资料发现**5000端口**  
存在**未授权访问**  
。  
由于 Docker Registry 私有仓库搭建  
以后默认其他所有客户端均可以 push、pull 镜像， 如果不设置用户认证方法来对 Docker 仓库进行权限保护，对 Docker Registry 中的数据安全造成隐患。该漏洞会导致 Docker 服务器的数据被泄漏、篡改和删除，配置文件被修改，甚至通过提权来控制服务器，危害十分严重。  
  
于是又写了一个图形化工具，我是小白我喜欢图形化！  
  
这个点在存在还蛮多的，访问：  
http://x.x.x.x/v2/_catalog  
，出现如下界面，说明漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyMTKrpIia0XL3oFzgW0jMMZx6NKjRwA2fzG8uLgCuNhZEYjXcfbqC7uicaqRY08aicQjOTk97JS8VFkg/640?wx_fmt=png&from=appmsg "")  
  
直接一把梭哈：发现存在即可尝试利用  
  
梭哈：  
https://comm.pgpsec.cn/2368.html  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyMTKrpIia0XL3oFzgW0jMMZxB3vyRD3cRlYAiaBkiboEqU6HiaK5eRxkR2g2BQX60Ch6R7dKZ63pRVibhg/640?wx_fmt=png&from=appmsg "")  
  
直接运行图形化工具即可，雀实方便  
  
Docker Registry工具:  
https://comm.pgpsec.cn/2382.html  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyMTKrpIia0XL3oFzgW0jMMZxKZVeMuZ7UJSJmu4dN0DP0ia9iaQmWYZId683BRYvnmdTQ0JQdX9Wk2gw/640?wx_fmt=png&from=appmsg "")  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyMTKrpIia0XL3oFzgW0jMMZx8cAjo2nsBzZD2siazP8BX9MBDwZUnDO7atiaOL6x8olG0KhH2XpJhenQ/640?wx_fmt=png&from=appmsg "")  
  
然后可以手工查找敏感信息或者使用工具  
  
  
手工查找😵‍💫：  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyMTKrpIia0XL3oFzgW0jMMZxDD3Ezpj2paJ0fn2iaLkDywibz6eYyIAqpleucRJKmMKcSicjI1gWNicHkQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyMTKrpIia0XL3oFzgW0jMMZxSJgKNlZmjXMTxLWicPWdRcJly0U2eC1FwG5wIiaCUfGU0IC54iag5pOPA/640?wx_fmt=png&from=appmsg "")  
  
推荐工具-  
searchall：  
https://github.com/Naturehi666/searchall  
  
命令：
```
searchall64.exe search -p 路径
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyMTKrpIia0XL3oFzgW0jMMZxWkbiaJmYs3dQkRrAZXvGoTWDLBRXpDqrpx3SZSj5BvR6VLkGMgRYUBA/640?wx_fmt=png&from=appmsg "")  
  
[鹏组安全社区站：您身边的安全专家-情报 | 攻防 | 渗透 | 线索 | 资源社区](https://mp.weixin.qq.com/s?__biz=Mzg5NDU3NDA3OQ==&mid=2247491205&idx=1&sn=b212739965f6617c84c89726cc85d50c&scene=21#wechat_redirect)  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyNHF1CWPJ9XSApBFhIGwF5Jh0zD2ySOcHvBkYgicU4xZsqvR3XEjUEnfGKH7ya8TgqCibHpYZKcibDBQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**扫码关注**  
  
**社区**  
  
鹏组安全社区：  
comm.pgpsec.cn  
  
  
专注网络技术与骇客的一个综合性技术性交流与资源分享社区  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyN92OtiagxgUpDAeq8RbcPacH8L82CwLzHtvucDrP1RrgfzeUYY8cS4WHk8niap3jKZzys9wK5oHB9w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
免责声明  
  
由于传播、利用本公众号鹏组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号鹏组安全及作者不为  
此  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
