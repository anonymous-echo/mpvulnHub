#  赏金SRC 某开源社区存在水平越权漏洞  
原创 天启互联网工作室  天启互联网实验室   2025-06-09 13:44  
  
用户A的ID：xxx625A  
  
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XpEvyXAhfbgaicH342lr0W9cLSGH7vmLnz9tOO7jnRkxVnA3eSJnLMtUlCAK3albD8AujWVU6u4ic853icTWn5Upw/640?wx_fmt=png "")  
  
用户B的ID：xxx883A  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XpEvyXAhfbgaicH342lr0W9cLSGH7vmLnlxe24z9ibsQXeDkLAvJlFwLzsP4PbCvnpt5zknJYQ8F3ebzSJ0J5P7Q/640?wx_fmt=png "")  
  
  
点击头像的>功能点 查看个人信息功能点同时抓包的：  
  
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XpEvyXAhfbgaicH342lr0W9cLSGH7vmLnBwicZ7JBibnuusC54Q5ECzGkxMYwuQ5cJBCnpLDTq7UlEtNMo0Liblcnw/640?wx_fmt=png "")  
  
抓到数据包如下，看到customerCode参数为用户A的ID：  
  
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XpEvyXAhfbgaicH342lr0W9cLSGH7vmLnwfLhdA2L8PNO7qGxfiaCytMKNhJwQ6fjmib1bibMRbEkFK7WHf08LPdicQ/640?wx_fmt=png "")  
  
将数据包发送到重放器：  
  
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XpEvyXAhfbgaicH342lr0W9cLSGH7vmLnpddUPM9jCmF9Vlkv7Ets5tGwXOia0ibZBwjweIysAiaGsufTGNrwPicuUg/640?wx_fmt=png "")  
  
点击发送，可以看到用户A的个人信息，用户昵称、城市、省份、身份类型、客户编号、可能为手机号或工号的字段（career）、认证状态、风控状态、粉丝及点赞数等信息，如：  
  
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XpEvyXAhfbgaicH342lr0W9cLSGH7vmLnDg1rJg3cnvDwll32IfI0ADzgJYodiaqXbSepUWbYUAPrTFicSEfCWS6Q/640?wx_fmt=png "")  
  
修改customerCode参数，把customerCode参数修改为用户B的ID，如下图所示：  
  
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XpEvyXAhfbgaicH342lr0W9cLSGH7vmLneAGfDbZ3CwRmOSzEbtgibeUiaJR7jricrOxyh5MiaQiaP5dMUvOwbib3PLTQ/640?wx_fmt=png "")  
  
可以看到另外一个账户的个人信息，如用户昵称、城市、省份、身份类型、客户编号、可能为手机号或工号的字段（career）、认证状态、风控状态、粉丝及点赞数等信息，水平越权漏洞得证。  
  
