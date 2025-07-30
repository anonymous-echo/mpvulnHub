#  JS中的漏洞信息   
原创 bcloud  蓝云Sec   2025-04-19 04:53  
  
# 声明  
  
本文章所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.   
# 前言  
  
当我们拿到网站，但是又不知道密码，目录扫描也扫不出有效的信息时，我们可以从前端JS源码入手，找找是否有可以利用的点，或者未授权的接口从而一步一步扩大危害，拿到系统源码或者用户信息等。  
# SQL注入  
  
登录框开局必出货，hhh  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFdEWwicricJjbxYflzbgjwb4mQZgJKYXlcZUvojTFOSawezmZrSDvo1aA/640?wx_fmt=png&from=appmsg "")  
  
查看前端源码，发现Identity_Get接口，且存在userid和researchid参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFtRDUOVLddfy1S1koFsukJFS1yD4j6YiaorXrsOPNoZOejdG6WvWyrvw/640?wx_fmt=png&from=appmsg "")  
  
访问该接口抓包，使用burp进行测试，通过单引号重放发生报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFiaHxHRZWwicbovpFhjVNUPZOnPxYAIawxUhiaDeWJezO4GBGEVPbpibwLw/640?wx_fmt=png&from=appmsg "")  
  
SQLMAP直接一键梭哈  
```
```  
  
Oracle数据库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFx3EE6LN0ePOalBYhgTPYxhhe5G7XfEF67VlWg2p3g2lZkYOj6AKy4g/640?wx_fmt=png&from=appmsg "")  
  
查询当前数据库用户  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgF4EIDsagKsOHyCeXxnibOSTrE88Hicj7KrEemP1pahS2ACTMqect8qhxg/640?wx_fmt=png&from=appmsg "")  
# 地图key泄露  
  
这个KEY泄露虽然很常见，但是能用的不多，这个能够利用的我还是第一次遇见  
高德地图key  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgF7dAtVXPGATnIBWiakIiaSbh1RyykFkh84QxuLtpAPCHqh7opFwXGGTGw/640?wx_fmt=png&from=appmsg "")  
  
此key有效，hhh  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFL5SMuiadzONwClSoMLqE62ichVWMJa1MMYicQfvju7lKqZo2lH0uzPw3A/640?wx_fmt=png&from=appmsg "")  
# 文件下载一  
  
访问网站打开插件查看接口信息，发现/xxx/xxx/zipDownload，一看这种就有戏啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFH6VqxLdKbLTYMMnH05KozVEhibmlaS0P769eXYt5icRUUOY1pmcr33Ig/640?wx_fmt=png&from=appmsg "")  
  
访问连接，通过提示信息输入path和type参数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFusUw4VBJ1YFOgGBmGn2icb9Ko5MCGhMEUz26DmA4gicXTD2Eia8mnXB0w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFG6dDIZEa7WaY6C5b4jsdfpVfOo3Od4WJicxnqKtNBcHX5iayrYYAribhA/640?wx_fmt=png&from=appmsg "")  
  
直接目录遍历下载  
```
https://ip/xxx/xxx/zipDownload?type=1&path=/../../../../../../..//etc/passwd
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFVxXicpghad79tuGlTibgdYyvDnk1rLmVdFkiaFokngD2h7bvxf6EAll2g/640?wx_fmt=png&from=appmsg "")  
  
发现shadow密码文件也可以进行下载，猜测网站用户为root权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgF805mrLRQpqv0BPxibOelPjiar6oop8EGHZL0A64Ca9Xic6Ecsq7VOms8A/640?wx_fmt=png&from=appmsg "")  
  
后面就是FUZZ下源码，或者SSH私钥登录，直接拿下shell，美滋滋  
# 文件下载二  
  
访问网站，打开熊猫插件发现一个export的接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFfhvgMicNPdZflQUaM4QjvwaWzAC5fQ7IhUGs0cpIicMkw26ZN53iaUNBA/640?wx_fmt=png&from=appmsg "")  
  
直接使用目录穿越，可把整个网站打包下来，包括数据库备份信息，源码甚至是中间件  
```
http://ip/xxx/Opt/export?path=../../
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFIGIybgiadn4VjyCfp1wbN0EEfyaWsc69Lr1hugpibQus4c0fFEZsfsvg/640?wx_fmt=png&from=appmsg "")  
# 信息泄露  
  
这个其实危害感觉不大，只泄露了用户名，手机号等一些信息，但是这个网站SRC的，所以还有20元子赏金，hhh  
查看前端const.js文件，发现两个管理员用户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFWhFu5j0WFMGB5ibEz6FVxiat5dcBuQ0xC8zbGxvqyy8BVHj4bDsVwLSw/640?wx_fmt=png&from=appmsg "")  
  
直接在找回密码处输入用户名密码，获取到手机号信息  
如下图1：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgFdJHicG52jzBic4oTC6PJ9rkU6UxBlAAwlWQmo8t9br9QjPHicrVI15K6g/640?wx_fmt=png&from=appmsg "")  
  
如下图2：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK7viaptfibH3pFa4G08MAHDgF3RrdtROIA467UwzmXZvw8Q37Iibmd9LteeqNa7ZMTn6PLeX8U37lbRQ/640?wx_fmt=png&from=appmsg "")  
  
只有两个账号，泄露的东西也不多，所以赏金不高，hhh  
  
  
