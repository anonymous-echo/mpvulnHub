#  Web版Java Payload生成与漏洞利用工具   
Ar3h  潇湘信安   2024-11-14 14:40  
  
<table><tbody><tr><td width="557" valign="top" height="62" style="word-break: break-all;"><section style="margin-bottom: 15px;"><span style="font-size: 14px;"><span style="color: rgb(217, 33, 66);"><strong>声明：</strong></span>该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。</span></section><section><span style="font-size: 14px;">请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。</span></section></td></tr></tbody></table>  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
潇湘信安  
“  
设为星标  
”，  
否则可能看不到了  
！  
  
  
**工具介绍**  
  
Web版 Java Payload 生成与漏洞利用工具，提供 Java 反序列化、Hessian 1/2 反序列化等 Payload 生成，以及 JNDI Exploit、Fake Mysql Exploit、JRMPListener 等相关利用。  
  
web-chains 项目，又名 java-chains 项目，由   
@Ar3h  
 师傅主导开发，漏洞百出和代码审计星球支持  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6udcwsYGxO1FH2PMCJsWL1hJxS38b6ljkiaCNre621hjNogjhdL20wf3QBQrYI30jEa0cYZAHeYibic5Q/640?wx_fmt=png&from=appmsg "")  
  
  
**工具功能**  
  
web-chains 包含但不限于以下功能：  
```
Java 反序列化原生 Payload 生成
Hessian 1/2 反序列化 Payload 生成
Hessian1 支持生成 HessianServlet 格式反序列化数据
Shiro 数据生成（自定义 KEY 使用 GCM 混淆字符等）
AMF3 数据生成（基于原生数据多种进阶组合）
XStream 数据生成（基于原生数据多种进阶组合）
BCEL 字节码生成（直接执行命令，内存马生成，回显生成，探测字节码，读写文件）
Class 字节码生成（直接执行命令，内存马生成，回显生成，探测字节码，读写文件）
多种数据库 Payload 生成（Derby | H2 | PostgreSql | Sqlite）
Fastjson/SnakeYAML/SpringBeanXML/Velocity/OGNL/MVEL/SPEL/JS/GROOVY
```  
  
  
一些混淆方式：  
```
随机集合混淆
垃圾类插入
去除字节码符号信息
TC_RESET 填充
UTF-8 Overlong Encoding 混淆
```  
  
  
一些高级选项：  
```
自定义类名/定义字节码版本
选择 Commons Beanutils 链的多种 comparator 类型
支持生成 TemplatesImpl 格式
支持生成 SnakeYaml Jar 格式
支持生成 Fastjson Groovy 格式
支持生成 JavaWrapper 格式
支持生成 charsets.jar 格式
支持增强魔改版 JMG/JEG 格式 （java echo generator, java memshell generator)
```  
  
  
Exploit模块：  
```
JNDI (远程加载字节码，高版本反序列化绕过，高版本 ref 绕过，)
Fake Mysql Server (经典 JDBC 攻击必备，基于生成模块多种进阶组合)
JRMPListener / TCP Server（Derby RCE）/ HTTP Server
```  
  
  
正在开发中：  
```
一个完善的插件系统
更多的可用的 gadget 和 payload 生成
字节码混淆（方法名/隐藏方法/花指令/异或混淆等）
多种多样的可能的输出类型指定
覆盖更全面的测试和报告
多种 gadget 排序方式可选
用户自定义偏好 gadget 和 payload 展示
更多功能...
```  
  
  
**快速使用**  
  
你可以通过 docker 一条命令启动 web-chains 项目（这也是推荐做法）  
```
docker run -d \
  --name web-chains \
  --restart=always \
  -p 8011:8011 \
  -p 58080:58080 \
  -p 50389:50389 \
  -p 13999:13999 \
  -p 3308:3308 \
  -p 11527:11527 \
  -p 50000:50000 \
  javachains/webchains:1.1.0
```  
  
  
生成功能仅使用 8011 端口即可，其他端口为 exploit 模块使用  
  
请使用以下命令获得随机的强用户名密码  
```
docker logs $(docker ps | grep javachains/webchains | awk '{print $1}') | grep -E 'username|password'
```  
  
  
输出示例  
```
11-12 06:59:53.301 INFO  [main] c.a.c.w.c.SecurityConfig       |  | generated random username: fBTWDfwlapmq
11-12 06:59:53.301 INFO  [main] c.a.c.w.c.SecurityConfig       |  | generated random password: XSsWerJFGcCjB8FU
```  
  
  
访问 http://your-ip:8011 即可（使用这里的用户名密码登录）  
  
你也可以直接使用 jar 版本，使用 java -jar web-chains.jar 即可启动（推荐使用 docker 方式）  
  
  
**特别注意：****我们只对 8011 端口进行了保护，需要登陆后访问，其他端口可能存在被反制的风险，请自行注意**  
  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**241109****】获取**  
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
  
