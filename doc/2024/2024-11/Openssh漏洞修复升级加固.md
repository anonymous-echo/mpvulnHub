#  Openssh漏洞修复升级加固   
 长风实验室   2024-11-12 17:55  
  
**一、telnet服务安装**  
  
**1、yum安装telnet服务**  
  
telnet  
不是一个独立的服务，是受服务  
xinetd  
管理的子服务，所以使用  
telnet  
服务必须首先安装  
xinetd  
服务  
  
yum  
安装命令：  
yum -y install xinetd telnet telnet-server  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0hyJmM2v9fgpbL6Mqibhy6NfmaibPia3vHo7YbgBibGvRU6cfJqV7Y7Nevw/640?wx_fmt=png&from=appmsg "")  
  
**2、telnet配置**  
  
**2.1、编辑/etc/pam.d/login**  
  
打开文件命令：vim /etc/pam.d/login  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0svE5ficuXnibvoibUVjGGKk5MskWU8N2pN0ncyXkggF7Z5eic5QgWX51zQ/640?wx_fmt=png&from=appmsg "")  
  
文件内修改-  
注释掉：  
# auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0hV1AJZrzF2epadibhMHOqsyKGLccfKT13HZ7I8Zkcyib6fI57l217DFQ/640?wx_fmt=png&from=appmsg "")  
  
**2.2、编辑/etc/pam.d/remote**  
  
打开文件命令：vim /etc/pam.d/remote  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0CM6bJATeP42N1ShK4ia4mYMFrFbicbLU7bR5YPwWiatnuEbNIT3ic1JOsQ/640?wx_fmt=png&from=appmsg "")  
  
文件内修改  
-  
注释掉：  
# auth required pam_securetty.so  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0S3eiaibAhJM9CQLeFUJMGsHuabtuhjjt2mX45Es6Yndz4nVXSPC8Tnng/640?wx_fmt=png&from=appmsg "")  
  
**2.3、配置/etc/securetty**  
  
备份/etc/securetty  
文件：  
cp /etc/securetty /etc/securetty.bak  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0s9yPvTuOGtsbjQNVVJQz2llgtKT8Bp3wGhwkibtSvFkVFRSTSp8zvCw/640?wx_fmt=png&from=appmsg "")  
  
添加超级用户登陆设备至/etc/securetty  
文件：  
  
echo "pts/1" >> /etc/securetty  
  
echo "pts/2" >> /etc/securetty  
  
echo "pts/3" >> /etc/securetty  
  
echo "pts/4" >> /etc/securetty  
  
echo "pts/5" >> /etc/securetty  
  
echo "pts/6" >> /etc/securetty  
  
echo "pts/7" >> /etc/securetty  
  
echo "pts/8" >> /etc/securetty  
  
echo "pts/9" >> /etc/securetty  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0ByXjKm1gSiaibOMX3XO1RAqfg5ibOIeMltiabfml6R1ZlBcQX4cj6Wo0vA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA06C5NKXiavgicVa1oaYdkQqU11gicFq8bTjHpBkrYx0RVc2V7ORC31BRqg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0vRv4m1nic4gl1uVQ8F381M26EcDTmMdNvGto4t6sahJaibSqGzmy5uJg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0ol9k1x6LXNesfpd9Pib5egP4GK9jSRicqRMuuBiaeUp0y3BZmSneRVOVA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0PquHobibFlGXI1OPd6gDJ1mXqJiczZWBkjq21y70hdkgAQLNWOCfChoA/640?wx_fmt=png&from=appmsg "")  
  
打开文件命令：vim /etc/securetty  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0s2QYaL6cnv2EkQZ02bGI5m7JKVn8rmhhAG9opsrntGJoDpePWHTic8w/640?wx_fmt=png&from=appmsg "")  
  
查看文件内终端添加情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0ANGXytlxD8ia53TulTBeHGt9iaCZKPRlcs4Bm82q1sb6ettL0fzoKEFw/640?wx_fmt=png&from=appmsg "")  
  
**3、telnet服务启动并配置开机自启动**  
  
**3.1、telnet服务启动**  
  
启动telnet  
和  
xinetd  
服务：  
  
systemctl start telnet.socket  
  
systemctl start xinetd.service  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0LYibNXeIfSV8YnB0MoGPcGcmic1kp8BapcyvyIUVJ7VxLIsGeZI1439w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA06pUrib1llzCK9r2qcVc94ktgMUibQPIFWURUgfgk6eBpyBTSDuISicjnQ/640?wx_fmt=png&from=appmsg "")  
  
**3.2、telnet服务开机自启动**  
  
xinetd  
和  
telnet  
开机自启动：  
  
systemctl enable xinetd.service  
  
systemctl enable telnet.socket  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0UREvNXqU4IrLgULKsgRcib6FRniasKwRFKTVVrLcQoNsXskXyjiaBpHdA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0hysPYlGicictTFzoNYeDDSzVe8WQLBfZUf95oHGib0eq2WibO9GcgqHg1g/640?wx_fmt=png&from=appmsg "")  
  
查看开机自启动添加成功  
  
systemctl list-unit-files |grep telnet  
  
systemctl list-unit-files |grep xinetd  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0eF2SbiaUeapvMXSkEv0cuQDnKSuN46Gece2BknjV7ERHSB9ichWoRAUw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA09klXelHp1I9FQehq9mcCxFASqoJ1v6Y4JqeOcXo06Qebv89ibhwdlNg/640?wx_fmt=png&from=appmsg "")  
  
**4、使用客户端建立telnet连接登陆成功**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0oBk1NNAtkfUF5f594T97zd0W4NWRLshZWHMNwNENzyicN2LibAbcBOiag/640?wx_fmt=png&from=appmsg "")  
  
**二、OpenSSH及相关升级**  
  
**1、源码下载**  
  
在终端使用命令行下载：  
  
wget http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.0p1.tar.gz && wget http://distfiles.macports.org/openssl/openssl-1.0.2p.tar.gz && wget http://mirror.cogentco.com/pub/openssl/openssl-fips-2.0.16.tar.gz && wget http://www.zlib.net/zlib-1.2.11.tar.gz  
  
（如果是https  
下载，需要加  
--no-check-certificate  
，因为需要  
ssl  
证书认证）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0CWeFBEyxwKfDY4hG76Tc5iaZCyNnic3icTj1BBojbTz2CYIr7qmaVw4mw/640?wx_fmt=png&from=appmsg "")  
  
**2、源码编译安装**  
  
**2.1、检查源码安装时相关组件**  
  
检查源码安装相关组件：rpm -qa | egrep "gcc|make|perl|zlib|zlib-devel|pam|pam-devel"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0xiaDUjCGGG70E5ZGGzhmwriasLTzLG82LCeYzHv62272X0nNJX1IR0Zw/640?wx_fmt=png&from=appmsg "")  
  
缺少zlib-devel  
和  
pam-devel  
，直接  
yum  
安装：  
yum -y install zlib-devel pam-devel  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0r8ZQ0HzJI03XEgSKjkJ0NSuMYiabqDz7GeLWibaE9WDKQKkNlbicGpRZw/640?wx_fmt=png&from=appmsg "")  
  
**2.2、关闭selinux、防火墙、卸载openssh**  
  
查看selinux  
状态，若是开启状态，修改为关闭：  
getenforce  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0oeLdM2yRbDQiaazicmVGgsaGQbYpkYhguMF4ur65Cj0enibibKJ5HtDj2w/640?wx_fmt=png&from=appmsg "")  
  
查看防火墙状态，若是开启状态，修改为关闭：systemctl status firewalld  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0sfM2QsOeOCPicjNSDUdhxXSrvYPbfDKVxNHXK0icrxzwvbauRtTOicLiaQ/640?wx_fmt=png&from=appmsg "")  
  
**2.3、检查卸载openssh**  
  
查看openssh  
状态：  
  
ps -aux | grep ssh  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0AcoicZ3qw1wQld48iazwpwpdDQXzpWcbnHlGT2KDibxacz0yPCHFRb9gw/640?wx_fmt=png&from=appmsg "")  
  
停止ssh  
服务：  
  
systemctl stop sshd  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0m4tRC0iaOUJiav0TuuSMWNpbuNQHJRFDSk9pxZdFiaj3R2w4gJuKaBcpg/640?wx_fmt=png&from=appmsg "")  
  
卸载openssh  
：  
  
rpm -qa | grep openssh  
  
rpm -e --nodeps `rpm -qa | grep openssh`  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0iblnicdeXYfwYiaG1CsqbUxibpjuF0wcs3dmdicX58iauNdFdg8GCG5cicLzw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0n8WH5rnM8kHKDqBk5bW4v0TCW5I0jIBcPp9RBvo2iaJDBn0orAaibDKw/640?wx_fmt=png&from=appmsg "")  
  
**2.4、解压源码并确认解压成功**  
  
源码都解压到/usr/local/src/  
目录下：  
tar -zxvf /root/openssh-8.0p1.tar.gz -C /usr/local/src/ && tar -zxvf /root/openssl-1.0.2p.tar.gz -C /usr/local/src/ && tar -zxvf /root/openssl-fips-2.0.16.tar.gz -C /usr/local/src/ && tar -zxvf /root/zlib-1.2.11.tar.gz -C /usr/local/src/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0eNrte4CXD4hyFfepQmKXX6It99QPBicozG28So9EonLJEgqXr8Ho1ibQ/640?wx_fmt=png&from=appmsg "")  
  
确认解压成功：echo $?  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA03wvWl5EazU7IIsuXtULhXA6Quia60iawf7Q24rsIbjdibRWyiawLeARcUQ/640?wx_fmt=png&from=appmsg "")  
  
**2.5、zlib源码编译安装**  
  
cd /usr/local/src/zlib-1.2.11 && ./configure --prefix=/usr/local/zlib && make && make test && make install  
  
echo $?  
  
ll /usr/local/zlib  
  
echo "/usr/local/zlib/lib" >> /etc/ld.so.conf.d/zlib.conf  
  
ldconfig -v  
  
**2.6、fips模块安装**  
  
export FIPSDIR=/usr/local/src/openssl-fips-2.0.16  
  
cd /usr/local/src/openssl-fips-2.0.16 && ./config --prefix=/usr/local/openssl-fips && make && make install  
  
echo $?  
  
**2.7、openssl安装**  
  
cd /usr/local/src/openssl-1.0.2p && ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl/openssl fips --with-fipsdir=/usr/local/openssl-fips zlib-dynamic shared -fPIC && make && make test && make install  
  
echo $?  
  
mv /usr/bin/openssl /usr/bin/openssl.bak  
  
cp /usr/local/openssl/bin/openssl /usr/bin/openssl  
  
cp -r  /usr/local/openssl/include/openssl /usr/include/openssl  
  
echo "/usr/local/openssl/lib" >> /etc/ld.so.conf.d/openssl.conf  
  
ldconfig -v  
  
**2.8、openssh源码编译安装**  
  
**openssh编译安装：**  
   
  
mv /etc/ssh /etc/ssh.bak  
  
cd /usr/local/src/openssh-8.0p1/ && ./configure --prefix=/usr/local/openssh --sysconfdir=/etc/ssh --with-ssl-dir=/usr/local/openssl --mandir=/usr/share/man --with-zlib=/usr/local/zlib && make && make install  
  
echo $?  
  
/usr/local/openssh/bin/ssh -V  
  
**openssh添加到开机自启动：**  
  
cp /usr/local/src/openssh-8.0p1/contrib/redhat/sshd.init /etc/init.d/sshd  
  
chmod u+x /etc/init.d/sshd  
  
chkconfig --add sshd  
  
chkconfig --list|grep sshd  
  
cp /usr/local/src/openssh-8.0p1/sshd_config /etc/ssh/sshd_config   (y  
确认  
)  
  
**openssh修改配置文件：**  
  
vim /etc/ssh/sshd_config  
  
#Subsystem      sftp    /usr/libexec/sftp-server  
  
注释掉，换为如下一句：  
  
Subsystem      sftp   /usr/local/openssh/libexec/sftp-server  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0yicOBLwicpcflXjQhTUiapsCG8pSPcGgAwzwm7MkG27CuVkaQEKATicViaw/640?wx_fmt=png&from=appmsg "")  
  
**openssh添加bin和sbin目录：**  
  
cp /usr/local/openssh/sbin/sshd /usr/sbin/sshd  
  
cp /usr/local/openssh/bin/ssh /usr/bin/  
  
ssh -V  
  
**openssh修改配置文件：**  
  
cp /usr/local/openssh/bin/ssh-keygen /usr/bin/ssh-keygen  
  
修改配置文件/etc/ssh/sshd_config  
：  
vim /etc/ssh/sshd_config  
  
#PasswordAuthentication yes   
行取消注释  
  
PasswordAuthentication yes  
  
并下面添加  
  
PermitRootLogin yes  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0uZfeFqyFrF0yicVxa12LxciaWMUXhsKIrPHAzzvpiaJIviaE0tMtRscLQg/640?wx_fmt=png&from=appmsg "")  
  
   
  
**3、启动ssh服务**  
  
systemctl start sshd  
  
systemctl status sshd  
  
利用客户端连接ssh  
，登陆成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0W789zltTAIIwVM4FM4yjdTlhvAOq87gXoyTMJT0qUGicC1Skwyl2NsQ/640?wx_fmt=png&from=appmsg "")  
  
**三、关闭telnet服务，卸载telnet**  
  
**1、关闭telnet和xinetd**  
  
systemctl stop telnet.socket  
  
systemctl stop xinetd.service  
  
**2、卸载telnet和xinetd**  
  
yum -y remove telnet-server  
  
yum -y remove telnet  
  
yum -y remove xinetd  
  
**3、恢复telnet相关配置**  
  
**3.1、编辑/etc/pam.d/login**  
  
打开文件命令：vim /etc/pam.d/login  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0svE5ficuXnibvoibUVjGGKk5MskWU8N2pN0ncyXkggF7Z5eic5QgWX51zQ/640?wx_fmt=png&from=appmsg "")  
  
文件内修改-  
取消注释：  
# auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0Kxsl8um3g00ue3zSiajQMNvdfiaOfWV3ka6icoZtg7adzFJkYGx9L1xfQ/640?wx_fmt=png&from=appmsg "")  
  
**3.2、编辑/etc/pam.d/remote**  
  
打开文件命令：vim /etc/pam.d/remote  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0CM6bJATeP42N1ShK4ia4mYMFrFbicbLU7bR5YPwWiatnuEbNIT3ic1JOsQ/640?wx_fmt=png&from=appmsg "")  
  
文件内修改-  
取消注释：  
# auth required pam_securetty.so  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0Bv6cyubOmgvAly5v6PX5axvqXwcVRCoboZKat1FIVbgmkJYuxy3sEQ/640?wx_fmt=png&from=appmsg "")  
  
**3.3、恢复/etc/securetty文件**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqyY0wEbqrkhyZq5aXspUWA0m0sxqqMxRkTTZJq2hlEjI5ib2TC4icjiajZX07jAyibIDyPouquQ8FibrTw/640?wx_fmt=png&from=appmsg "")  
  
  
