#  一次edu站点从前台sql注入到后台rce   
原创 十二  起凡安全   2025-05-12 09:19  
  
****  
**前台sql注入**  
  
这个网站访问  
http://xxxx/lab/Login/LoginB.aspx是下面这样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPace7Rup7JKKdxFpevOhCiaqIMQmKFOC5UjxIL5kahkXVgn4HkYcpmicn5xQ/640?wx_fmt=png&from=appmsg "")  
  
访问http://xxxx/MIC/Login/LoginB.aspx则是下面这样，这个姓名处存在sql注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPace4V3ROSY118SaIgZPOLNSsNcHD4VHIhGujl70DecLGOUUUZeLr5FVeg/640?wx_fmt=png&from=appmsg "")  
  
抓包，测试payload：  
AND+IIF(1=1,'a’,1/0)=’a  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceqLVBHh4g6ktt0W6HK18GXjv9ibD1AqnnGENIIuXmH64DDhCPISWWKqQ/640?wx_fmt=png&from=appmsg "")  
  
条件改为1=2则返回500，标准的盲注  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceSBIl1rr5ia3KNs9AVkh3FPv0eY9PF1N8tEg074dWTsRHz5nI4lm506Q/640?wx_fmt=png&from=appmsg "")  
  
这里可以直接  
构造一下万能密码，注意前面要是真实的用户名  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPace3gzuHwcfCUqZ0kW2letnSDIMpicLSjV5Qvx31jleiaReHIkPXboYiarfw/640?wx_fmt=png&from=appmsg "")  
  
直接访问这个地址，成功登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceDHGKGCbUGOuNudUTN7xqSRCiaEuxoE5BO3bYcehUP1KHTicWZCvCQBTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPace92Uq533eljOVgiaOtqXQZRRKcWzNXHWYZfcwxyjtvsVd0mibpNGhLtOQ/640?wx_fmt=png&from=appmsg "")  
  
登录老师账号，发现了学生账号，可以用来测一波越权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPacesDK90k9dE8xccDuSCEIE1cBuFYnT9UPsnk2GxH6zv4NFBKYICKib9vg/640?wx_fmt=png&from=appmsg "")  
  
这里因为一开始有两个登录地址，使用老师账号登录这个地址的话：  
http://xxxx.fzu.edu.cn/lab/Login/LoginB.aspx500，功能点则为下面的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPacebWOVTbQ0pjNmxOic6iccQ1CpgQHAcB6tzNevyXPFQbDwG35nSz9hlo8Q/640?wx_fmt=png&from=appmsg "")  
  
**越权**  
  
登录个学生账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceia02LjiaqibGzJMqLLT7UCu7bnBZ1asU3MyBEtxwu9YGGgcCcicgXBJOeQ/640?wx_fmt=png&from=appmsg "")  
  
这里直接  
在路径拼接  
地址即可越权访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceGEAicVjXl1Msy02cYlQafVrXorGJoRMyxLhzRDu0wm7S2GiazXwDU8AA/640?wx_fmt=png&from=appmsg "")  
  
这里拼接那个lab的路径也可以访问，所有高权限功能都可越权访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceDVf7IZKn39tfiaOfmhRqXNV25fgTCibd2CB0ZuENHjuaKeRSYMibwV6iaw/640?wx_fmt=png&from=appmsg "")  
  
**RCE**  
  
随便一个上传文件的地方  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceajTDjhNiafZ507mtoniaLtgIGuwZXEmohp6kcVg5eDIIsLFleGkiakKiaw/640?wx_fmt=png&from=appmsg "")  
  
响应包返回了路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceiaHB8k2QRhKpRxNriaGTuyL6zxkc00DYg2eOpqTicKG7m3NwmwYZSNF7A/640?wx_fmt=png&from=appmsg "")  
  
成功执行命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64luMmLuKTaVPV7aSEgVPaceP6XVh5F1kZriaRYkQSX6HPWdSuqd8UAmlKhASFLOPKicgg8uiapB6jOrQ/640?wx_fmt=png&from=appmsg "")  
  
  
