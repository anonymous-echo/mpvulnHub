#  edu挖掘从弱口令到RCE   
 扫地僧的茶饭日常   2025-01-04 08:02  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  洛川 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
访问某学校官网点击教务在线  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVQHzEZeYjRyTUQ3kakCCpSCmDmDMJPvm5g8I3bqGfUialjaAuJL35JUw/640?wx_fmt=png&from=appmsg "")  
  
找到实践教学管理平台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVickbIg9aOqgXoOtiaEhjyntg5pWXy8TBBnSiajUsGu4jbHLsZlAxjdaUA/640?wx_fmt=png&from=appmsg "")  
  
来到学校的毕业设计系统登录界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVLwZiaVYdTD2JnDKPRnjSsMkibVqKxG9OYfkZKc10YWI13ApWiaQLvwY5g/640?wx_fmt=png&from=appmsg "")  
  
通过弱口令学号学号登录进去，学号直接搜索引擎搜索得到即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCV3dRQGOG6pXItsPRhr65GufSX61S6CX9XQanjk1lCF3wQjIZtP36bZg/640?wx_fmt=png&from=appmsg "")  
  
发现cookie有OA_User，unumber，Powerid字段，OA_User为id号，unumber为用户名，powerid为权限组  
## 水平越权  
  
点击个人信息抓包修改OA_User可以看到返回其他人信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVnR3KPVNCSgzKkiazLAABRW6zUVc7iaAP4Picgk0HCZVmgyXZG5Q4pSWoQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCV3ibGwUIb4bv9lViaSzLKUYl35zJWODyesuy9ZRESLHL9N2Quic4F9SBuA/640?wx_fmt=png&from=appmsg "")  
## 垂直越权  
  
修改OA_User还可返回教师信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCV2qgTGBuUS5ZLciagAEv2QQ0W2Yp48ib6hicSYRCGqApx1bNrbNSzkicx7Q/640?wx_fmt=png&from=appmsg "")  
  
然后我们对powerid进行修改可以看到成功登录教师账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVUJofT3h6whdmyfb8kV8e0aEDXXppicnwmm8iamuxBeBjcxZy8bZBj8Rg/640?wx_fmt=png&from=appmsg "")  
  
通过bp爆破发现管理员id为1 ，powerid为4，所以powerid 6为学生，5为教师，4和1为管理用户。  
  
可以登录管理员账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVrwiaPO7RfP9Hkaz1gVAV6piblu0vobRFeX246yjXsjsGzzRGdjKiciaQyg/640?wx_fmt=png&from=appmsg "")  
## 任意用户添加  
  
构造管理员数据包可以直接添加用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVJZKYYjpB2tQ1O8icqIvuibQQVkY3HZIyNaQTKskAP7VrgIB9socZl7dg/640?wx_fmt=png&from=appmsg "")  
  
可以看到成功添加  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVZSACY664Jsw46LBWGKwKI6IMZqAZZiaxkSpRmNYLWUSGB3HTLwZyVDA/640?wx_fmt=png&from=appmsg "")  
## 任意密码修改  
  
抓包并打开修改密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVkGr4ictia7K5eW1dZic7icTeGSHUsjoodJKRr41sQ2PJxnn4lJ2oFVNV2w/640?wx_fmt=png&from=appmsg "")  
  
随意修改OA_User  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVrOrkny5wbOH3937rn9fFYHryIwhUTbFBMUhP8cIkYMXBWeBj7dxfJg/640?wx_fmt=png&from=appmsg "")  
  
输入新密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCV2Cq6v9Xn9Ub8DyQPtRPZpHE0XhzOTsvib1iadokE6nVR0BBVqxfpflHw/640?wx_fmt=png&from=appmsg "")  
  
抓包并点击提交，将OA_User修改为txtUname对应的即可成功修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVtA4pSgMoSp8G7FicJWT5Y3vWQPb7xmficp67Wd7pW2ibD77QyU5O2hO3A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVsvIYtJRaRnlR62oiaPNiaocJvUlYbiboA7GRcZTu7ysoxM7tALLZIMfPA/640?wx_fmt=png&from=appmsg "")  
## pdfxss  
  
登录管理员账号  
  
来到发布公告功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVkVVOMtLjTmAjudek7qlA4KUbzpeE5MxS3krw3aagASH35Wxdgj0Ugg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVPIGdfn5xy5QS53NBRicQpqHq9N7Tib8rFqkrsSctoZvHHxutRfuUDbibg/640?wx_fmt=png&from=appmsg "")  
  
上传pdf附件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCV5waZ5QyNOwwkQjicu0rPn60776kUfYMjpiccD7MxhqfdsyFfHLOo5ezQ/640?wx_fmt=png&from=appmsg "")  
  
所以查看公告点击附件的学生均会弹窗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVqVphO79vw5x4zlShBJOiaWxvI7LRPetmnAxCfRxiakA0jPsbckCzIteA/640?wx_fmt=png&from=appmsg "")  
## 存储型xss  
  
还是发布公告功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVbibfsicM3DzwUIpYMwDWNAuvgf7mVBC7EXchrHZrFndR1fKr01icKJnVg/640?wx_fmt=png&from=appmsg "")  
  
点击查看公告即可弹窗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVXoZcNZWuvMF3Hubs9yEVicGTU5zN2J2EQb5SlPMTzzD4fgnE14iaJxAA/640?wx_fmt=png&from=appmsg "")  
  
这个危害还是挺大的，所以查看公告的学生或老师或管理员都会弹窗，假如打个危害大的payload可以做到接管所有人账号密码  
## SQL注入  
  
找到个搜索框  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVW2T3icMFFv3RSt7vfyjmhaShMBTIwF2aVfc3k1WWD8q4za5XVQIuhSg/640?wx_fmt=png&from=appmsg "")  
  
抓包点击搜索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVQheDbGeiaB1On2QPUuImIEIRpnqd5QTCH2fVkMtqPKGJ1X7B3sm8tPQ/640?wx_fmt=png&from=appmsg "")  
  
打上payload发现存在时间盲注，直接上sqlmap  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVyY8dJMtNePxghSSZZf5JQibeSMtroavvia6DoBUuk7h8sJ5hTWdbk11g/640?wx_fmt=png&from=appmsg "")  
## RCE  
  
发下存在堆叠注入，那直接os-shell拿下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCVoAPsgnQkJIdvbuctTE1sDlfsSUArKgv0iaz13CmRAaltCOCKicSI8HZA/640?wx_fmt=png&from=appmsg "")  
  
直接拿下system权限  
  
最后提交edu拿下高危  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLoZ6NSqMOQtekOn3STKCV5oBqAh6QicoyubUh0Z4icHicY8FQNltUyfRpVTAY1OfG9FT3yqyomLWxg/640?wx_fmt=png&from=appmsg "")  
```
```  
```
```  
  
  
  
  
