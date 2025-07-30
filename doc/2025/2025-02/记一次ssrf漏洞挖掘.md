#  记一次ssrf漏洞挖掘   
原创 zyxa  众亦信安   2025-02-11 04:57  
  
**文章导读**  
  
**声明：**  
文中涉及到的技术和工具，仅供学习使用，禁止从事任何非法活动，如因此造成的直接或间接损失，均由使用者自行承担责任。  
  
  
**众亦信安，中意你啊！**  
  
  
  
  
**点不了吃亏，点不了上当，设置星标，方能无恙！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaCYxCJKub5bG3w60vxgqrckQwMSg9YrFiaR3PqibBiaZ5YNFIIrAlBTs5l24ysvq3mDX1kYWwvHaeBzA/640 "")  
  
  
1、  
通过在burp中对网站进行搜索看是否有无SSOLogin?、Login?等关键字,因为有些系统它在js中泄露了某些关键接口可以导致用户进行登录其他系统  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaCDZwZ9CYw81FDicsuVlzib8QhzSNAbCyMjHbdiaksiaduU4W3awcJKDg2JibCRjCos6FcGK5eMtCRmzhg/640?wx_fmt=png&from=appmsg "")  
  
  
2. 访问url http://xxxxx.com/SSOLogin?xxxx=xxxxxxxxx可直接跳转登录到某系统  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaCDZwZ9CYw81FDicsuVlzib8QEV7ibEzArJfvRzFe0qLtakYCotUhYadTDXBRia0955hlRlO4NZtwhvEQ/640?wx_fmt=png&from=appmsg "")  
  
  
3、  
后台功能点也是比较单一，想着下载随便下载一个文件看看，发现api接口是由/xxxx/xxx?xxlink=base64编码的路径组成（由于截图不全就文字描述了），通过base64解码发现加密内容为  
http://xxxxx.com/xxx/xxx/1.pdf  
路径组成，然后通过某个actuator漏洞泄露的内网地址进行base64加密可成功全回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaCDZwZ9CYw81FDicsuVlzib8QYAqs5EaFK2k4rdsBP1FqR5G2t4bqwcRK7HSSSmYt8N9pHdRmy6I9mg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
往这里看  
  
  
  
  
点点关注不迷路，每周不定时持续分享各种干货。  
可关注公众号回复"进群"，也可添加管理微信拉你入群。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rl85Sib8ZkaALhRNp0ic9JdTb3u3x0wr8NEKVpvibCaGWymICEcwUbmO3icFAJwSvxbszDKv7OXQwoDjtrmVRvN91Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
