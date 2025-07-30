#  Geoserver漏洞复现   
原创 不知江月待何人  掌控安全EDU   2024-04-20 12:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
本文由掌控安全学院 -不知江月待何人 投稿  
## 产品描述  
  
GeoServer是一个开源服务器，用于共享、处理和编辑地理空间数据。它支持多种地图和数据标准，使用户能够通过网络访问和操作地理信息系统（GIS）数据。  
## 漏洞成因  
  
漏洞主要源于其后台文件上传功能的安全缺陷，服务器未能正确验证和过滤上传文件的路径。这个安全缺陷允许经过身份验证的攻击者可以使用上传功能将恶意脚本上传到任意目录，从而获取权限。  
## 漏洞影响  
  
权限提升：攻击者能够在服务器上的任意位置上传覆盖文件，这可能用于篡改现有的GeoServer安全文件获取更高的管理员权限。  
  
代码执行：通过上传特定的脚本或执行文件，攻击者可能获得服务器的进一步控制权。最严重的情况下，这可能导致服务器的完全接管，敏感数据泄露，甚至将服务器转化为发起其他攻击的跳板。  
## 影响版本  
  
GeoServer < 2.23.4  
  
2.24.0 <= GeoServer < 2.24.1  
## 漏洞复现  
  
CVE编号：(CVE-2023-51444)metadata-Hunterquery: web.title=”geoserver”仓库托管地址：https://github.com/geoserver/geoserver下载地址：https://github.com/geoserver/geoserver/releases官网：https://sourceforge.net/projects/geoserver/files/GeoServer/  
  
版本：2.19.0系统：Linux Centos7.6软件：Tomcat、Geoserver2.19.0 War包Tomcat起War包服务可自行百度解决，需将War包解压部署在/webapps目录下重启Tomcat服务即可访问：127.0.0.1:8080/geoserver  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrzTdKsqyBK26AUHkJdfrw6bsnjs8tCazoqkkJOibqynN6DSP6gN0GlJuauBqXXL7wBUsdyibKbwWRg/640?wx_fmt=png&from=appmsg "")  
默认账号密码：admin/geoserver  
## 操作步骤  
  
1、点击工作区新建  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrzTdKsqyBK26AUHkJdfrw69a55YCHRkrvMQj7JfDGLBoY76wblx1vAYFLjRvH8E83EheAz7URCCQ/640?wx_fmt=png&from=appmsg "")  
2、数据源新建，选择 ImageMosaic  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrzTdKsqyBK26AUHkJdfrw6oSESIVRXicUcjQDic778iaOGbqSL5XAEicffibERZ2gyia5TrvP81oZmtxtg/640?wx_fmt=png&from=appmsg "")  
3、添加数据源为新建工作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrzTdKsqyBK26AUHkJdfrw6e5eK8lWhZBtKXdIFYptX4DsI4KtlD6M3HaNQgTR3bSnUb4zlCHC4qA/640?wx_fmt=png&from=appmsg "")  
4、点击保存  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrzTdKsqyBK26AUHkJdfrw6VUpp1xicLpkDIYaJJSkfQeH5lnP1kfubecmVESCRgsXYTnX6QWDRjKA/640?wx_fmt=png&from=appmsg "")  
5、构造上传数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrzTdKsqyBK26AUHkJdfrw6EJ1icYrla2APShASghq7oZUMD8ZmmrCWxM4G0WnCJPCNo81NM1iavnDA/640?wx_fmt=png&from=appmsg "")  
  
验证：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrzTdKsqyBK26AUHkJdfrw6icFIZPFvpjNFBV3QfQEILYrHCVOb3gqzyg11shLQIMnnTXOEK7icwicicg/640?wx_fmt=png&from=appmsg "")  
## 修复建议  
  
官方已发布新版本修复漏洞，建议尽快访问官方github页面（https://github.com/geoserver/geoserver/）获取2.23.4或2.24.1及以上的版本修复漏洞。  
```
```  
  
  
  
