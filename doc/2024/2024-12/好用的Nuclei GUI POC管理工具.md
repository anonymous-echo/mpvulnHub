#  好用的Nuclei GUI POC管理工具   
Perlh  潇湘信安   2024-12-11 00:30  
  
<table><tbody><tr><td width="557" valign="top" height="62" style="word-break: break-all;"><section style="margin-bottom: 15px;"><span style="font-size: 14px;"><span style="color: rgb(217, 33, 66);"><strong>声明：</strong></span>该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。</span></section><section><span style="font-size: 14px;">请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。</span></section></td></tr></tbody></table>  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
潇湘信安  
“  
设为星标  
”，  
否则可能看不到了  
！  
  
  
**工具介绍**  
  
一个好用的nuclei GUI POC模版管理工具。由于没找到一款比较好用的poc管理器，便自己开发了这个，目前仅提供安装包下载。  
  
  
**工具功能**  
  
**已完成功能：**  
```
实现nuclei poc管理的桌面应用，对nuclei模版的增删查改操作
支持nuclei扫描
实现多任务、并行扫描
查看nuclei模版请求响应包
支持自定义nuclei DNSLOG服务器
支持自定义扫描速率
支持http代理（http、https、socks5）
支持MacOS、Windows和Linux操作系统
使用全新nuclei v3检测引擎
兼容yamlv2和yamlv3 nuclei template
支持主题切换
支持多种nuclei模版导入方式
支持nuclei模版去重导入
基本支持简体中文和英文
```  
  
###   
### 后期功能实现  
```
App设置-配置持久化生效
显示扫描进度
POC导出功能
扫描任务暂停功能
```  
  
  
**快速使用**  
  
**POC模版导入**  
###   
### POC模版保存路径  
####   
#### 1. macos  
  
对于MacOS和Linux，首次打开App会在家目录生成模版文件夹  
```
ls /Users/$USER/.wavely/templates # macos
ls /home/$USER/.wavely/templates    # linux
```  
####   
#### 2. windows  
  
会在wavely.exe的同级目录下创建.wavely/templates，将POC放入此文件夹中（请开启显示隐藏文件/文件夹）。  
  
###   
### POC导入  
#### 1. 在App中导入POC（带POC去重）  
  
点击从文件夹中导入按钮，选择nuclei poc文件目录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwuaPDWZyvgD3cwibk5poLapegT8vA2jhgic4Ks3BydA7pHoJmUuQTtW2A/640?wx_fmt=png&from=appmsg "")  
  
####   
#### 2. 手动导入POC（不带POC去重）  
  
1. 打开Wavely  
，将初始化数据库和poc配置目录。  
  
2. 将nuclei poc文件复制到以下文件夹中：  
```
MacOS：/Users/$USER/.wavely/templates
Windows：.wavely/templates
```  
  
3. 打开Wavely  
，进入  
设置->  
模版->点击  
更新按钮图标。  
  
  
**注意：**  
首次打开App将初始化数据库和POC保存路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwkciaPkvI741EqQGKPj0cazLEsftFHUrH8GxWnpfa3ypverpbomjOCjQ/640?wx_fmt=png&from=appmsg "")  
  
  
**功能展示**  
  
**模版管理**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwcykqd6TXDAyiajgWvnGb0lC7mLsH407cGZwDXA1ALdajlQJvhRqIQ2g/640?wx_fmt=png&from=appmsg "")  
  
#####   
##### 扫描任务  
- 选择thinkphp的poc进行扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwfgtckJzfo0qvIluiakmJbPoAy8QWYTO2jiaEY365CFvJFaNhQkTQSM4g/640?wx_fmt=png&from=appmsg "")  
  
#####   
##### 扫描结果  
- 扫描结果  
  
- 可复制扫描结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwchl3o75n4X0WO4xzwc5oPoMm6MoJvtO2TW3AEgWyzzXJGLgwOfWEGA/640?wx_fmt=png&from=appmsg "")  
  
####   
#### 编辑nuclie模版  
- 编辑模版  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScw6twq4mQ9grwMlc8KoboBpWY48M2ib89BYpZp0DPdRcxZxzZs6TtwKzw/640?wx_fmt=png&from=appmsg "")  
  
  
匹配请求包（需扫描匹配POC成功时才可看到请求响应包）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwMnP9cw542xD8EqM1uT96EAjOlA97gWtjVuP8Jkjn1JX1uFVwicdvuYg/640?wx_fmt=png&from=appmsg "")  
  
  
匹配响应包（需扫描匹配POC成功时才可看到请求响应包）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwyWtM5IOt6zibbeiclq9LQCZzlqr2xljylXCOlY7wdSWulgNPyuHk7IDg/640?wx_fmt=png&from=appmsg "")  
  
####   
#### 添加Nuclei模版  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScw9NaFIektDDFQhbl5tkMEsDvoVjMHKh3lQmzoyrGNDMpobjEMrkbRQA/640?wx_fmt=png&from=appmsg "")  
  
###   
### App设置  
- 切换POC编辑器主题  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwMv4apVQyoX786hGn7dg5ogGx9jrWTMhBYlUhASGJDSv25ZIoR6d4fg/640?wx_fmt=png&from=appmsg "")  
  
  
添加HTTP代理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwEutBEVW7NooN51GyOWeyQmzlfWiayxaAGQFfZ8xQYW1iaCjz096zVM1w/640?wx_fmt=png&from=appmsg "")  
  
  
POC扫描参数设置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwnSLjbCnCyEY4Q733cgxyziayPsKJicjwSOGYuklIvNIClZ6pLpZKM2Rg/640?wx_fmt=png&from=appmsg "")  
  
  
模版导入功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udVYiaHU7xL0ANYvJo7xwScwy0eMKZf5kuBhtcpJm2ZFxaZoxUsaY9boLuVQ5UsqZPv6p0oNnuyOicQ/640?wx_fmt=png&from=appmsg "")  
  
  
**常见问题**  
  
**Macos 无法打开App**  
  
由于没有使用apple证书签名app，故不能正常打开，需要手动允许App允许，请参考：执行如下命令即可：  
```
chmod 755 /Users/$USER/Desktop/Wavely_darwin_arm64_1.5.2.app/Contents/MacOS/Wavely
```  
  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【241210****】获取**  
**下载链接**  
  
  
  
**知 识 星 球**  
  
  
  
仅前1-400名: 99¥，400-600名  
: 128¥，  
600-800名  
: 148¥，  
800-1000+名  
: 168¥  
，  
所剩不多了...！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOdma4QtfwXXJ4w35lMtvMcogAnI5u4bWIhxq1EzXI0remsQXFk5uhv0BX4eSyzpzJGYHAybgEYeVA/640?wx_fmt=png&from=appmsg "")  
  
**推 荐 阅 读**  
  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247499188&idx=1&sn=9ce15a0e66b2595285e544aaa0c49c24&chksm=cfa559a7f8d2d0b162f00e0c1b02c85219f2668c282b32967b2530f15051b47b21ee2855a783&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247496043&idx=1&sn=4daa27ade9915de6021fea1c2a21d7bc&chksm=cfa55578f8d2dc6ef887ce27215f942ec233320fa6878bc1666ce0fecb0e7f6c7f96a3ba4e2b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247486327&idx=1&sn=71fc57dc96c7e3b1806993ad0a12794a&chksm=cfa6af64f8d1267259efd56edab4ad3cd43331ec53d3e029311bae1da987b2319a3cb9c0970e&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOdAPjIVeN2ZahG9ibP0Y3wlfg6BO1WO7MZfo1JeW7zDWcLSTQ5Ek8zXAia5w1nMnogpbpXP6OxXXOicA/640?wx_fmt=png "")  
  
