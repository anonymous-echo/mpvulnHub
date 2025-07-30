#  Linux的常用持久化手段   
原创 裴伟伟  洞源实验室   2025-01-07 12:50  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gEGSydvbZs6z4Qbkhbiar4lfzdY1az6vEzzEYZnt4QUJJ1Q7BtibXibURKd7XGlcbSJbicIQjTwJo3oAdMHGt8AjKg/640?wx_fmt=gif "")  
  
在网络攻防过程中，Linux系统的持久化技术是指攻击者通过各种手段在目标系统中建立长期存在的访问权限，使其能够在系统重启、更新或其他安全措施下依然保持对系统的控制。持久化的手段包括但不限于通过修改启动脚本、添加定时任务、植入恶意内核模块、创建后门账户等方式。这些技术使得攻击者能够在网络攻击活动中保持对系统的持久控制，并在进行其他攻击操作时不易被发现。  
  
持久化的重要性在于，它极大地提升了攻击者的攻击持续性和隐蔽性。即使防御者发现并清除了一些初期的攻击迹象，持久化机制仍然能保证攻击者可以迅速恢复对目标系统的控制，从而造成更长时间的潜在威胁。因此，在防守过程中，安全团队需要特别关注系统中的持久化迹象，定期检查系统的启动项、用户权限、网络连接等方面，以及时发现并清除这些持久化机制。  
  
根据持久化的手段的不同，本文从浅到深介绍  
Linux  
系统下常见的持久化的方法。  
  
创建  
Linux  
系统账户  
  
Linux  
系统的账户分为  
Root  
账户和  
User  
账户，后者也是系统操作中常用的账户，在服务器被攻击中，攻击者常常会利用漏洞（比如越权、  
RCE  
、  
LFI  
等）查看  
/etc/passwd  
文件，其目的一方面是为了查看漏洞是否可以被利用成功，一方面是为了查看系统中的账户有哪些。  
  
在获取服务器权限后，创建  
Linux  
系统账户有两个命令，一个是  
adduser  
，一个是  
useradd  
，前者是后者封装的结果，使用更为简单，但可设置项不灵活，比如用户分组、家目录、  
Shell  
的设置。因此，为了更隐蔽地创建系统账户，建议使用  
useradd  
命令，比如：  
```
# create a user account without home directory
sudouseradd -M <username>
# set password for account
sudopasswd <username>
```  
  
通过SSH密钥文件  
  
创建账户许多时候往往太多于明显，除了账户之外，还可以通过修改  
authorized_keys  
文件来进行持久化，这个文件位于  
<user-home>/.ssh/authorized_keys  
。  
  
在早年的  
Redis  
未授权漏洞利用中，便是利用  
Redis  
未授权修改该文件，增加了  
SSH  
密钥文件对中的公钥内容，从而可以通过  
SSH  
密钥方式访问服务器。  
```
# Generate key files though SSH command
ssh-keygen -t rsa -b 2048
```  
  
生成后的密钥文件包含私钥文件  
id_rsa  
和公钥文件  
id_rsa.pub  
，将  
id_rsa.pub  
文件内容复制到  
authorized_keys  
文件中即可完成配置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs40GAdlGGnRj9tz3HNn0nhYbWWicYxU7OMoMicheLtCwHsZjZL4CkwkqtcmD6icYD8kDPxenLRL4tufQ/640?wx_fmt=png&from=appmsg "")  
  
公钥内容的最后通常会有生成密钥对主机的信息，比如  
root@kali  
之类，这个内容可以删除或修改为其他主机用户信息。  
  
使用计划任务  
  
在Linux系统中，计划任务是指设置在指定时间或周期自动执行某个命令或脚本。最常见的计划任务工具是  
crontab  
命令，正常情况下，使用  
crontab -e  
命令可以编辑计划任务，这个命令生成的计划任务存放在  
/var/spool/cron/crontabs/<user-name>  
下。  
  
如果获得了系统的  
Root  
权限，除了  
crontab  
命令添加计划任务，还可以通过在  
/etc/cron.d  
目录下添加系统级别的计划任务，比如：  
```
0 0 * * * root /root/bin/backdoor.sh
```  
  
相比  
crontab  
命令，该目录下的计划任务需要在时间后指定执行该脚本的用户，比如上述示例中的  
root  
。  
  
另外，也可以直接将脚本放在  
/etc/cron.daily  
、  
/etc/cron.weekly  
、  
/etc/cron.monthly  
等目录下根据日、周、月定时执行。  
  
另外一种计划任务是  
systemd  
计划任务，这个方法利用的是  
systemd  
服务的  
timer  
模块，类似于在  
Windows  
系统中创建服务（实际上，写一个有迷惑性的服务文件也可以单独作为后门使用），通过  
systemd list-timers  
可以查看当前系统所有这类计划任务：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs40GAdlGGnRj9tz3HNn0nhYWWXcZBhGCDZZuicHoV5JKGANI2YOetDvkPE4w82R5WbRorlicNA6EoLQ/640?wx_fmt=png&from=appmsg "")  
  
创建  
systemd timer  
计划任务需要一个  
.service  
文件和一个  
.timer  
文件，前者是服务文件，后者是定时文件。  
  
比如，在  
/etc/systemd/system  
目录下创建  
test_script.service  
文件：  
```
[Unit]
Description=Thisis a test service
[Service]
ExecStart=/root/test.sh
```  
  
接着，在  
/etc/systemd/system  
目录下创建  
test_timer.timer  
文件：  
```
[Unit]
Description=Thisis a test timer

[Timer]
OnBootSec=60
OnCalendar=daily
OnUnitActiveSec=5m
Unit=test-script.service

[Install]
WantedBy=timers.target
```  
  
上述文件中，  
OnBootSec  
是指系统启动后多少秒开始执行计划，  
OnCalendar  
用于指定任务的触发事件或频率，其值可以是  
daily  
、  
weekly  
、  
monthly  
或  
hourly  
，也可以是类似  
2025-01-03 12:00:00  
这样的具体时间，  
OnUnitActiveSec  
指定任务触发后多长时间开始执行，上面文件中是触发后的  
5  
分钟执行任务，  
Unit  
指定的是对应的服务文件。  
  
最后，通过以下命令启动计划任务：  
```
# reload systemd configuration
systemctldaemon-reload

# enable timer on boot
systemctlenable test_timer.timer

# start timer
systemctlstart test_timer.timer
```  
  
修改Shell环境配置  
  
Linux系统中和Shell环境配置的文件有很多，它们基于用户级或系统级可以在Shell脚本执行前或执行后执行相关的Shell脚本。  
  
常见的配置文件包括用户级的~/.bashrc、~/.bash_profile、~/.profile，以及系统级的/etc/bash.bashrc、/etc/profile、/etc/profile.d，总的来说分为profile、bash_profile和bashrc三类文件，其中profile是登录Shell时候执行的，且适用于所有类型的Shell，bash_profile是登录Shell执行的，bashrc是交互式非登录Shell执行的。  
  
因此，可以将持久化的脚本写在/etc/profile或/etc/profile.d中，亦或者是~/.profile中，这意味着当攻击目标的用户登录服务器Shell时候会执行持久化脚本，当然，也可以利用bashrc等其他文件。  
  
动态链接劫持  
  
在Linux系统中，动态链接（Dynamic Linking）是指程序在运行时通过动态链接库来加载和使用函数和数据，这种机制允许程序在不重新编译的情况下更新或替换库文件，从而能够在不改变程序源代码的前提下进行修复和升级。其中，动态链接器（Dynamic Linker）是负责在程序运行时加载和链接共享库的程序，当程序启动时，其动态链接的部分或共享库引用的部分通过符号进行标识，动态链接器负责程序与共享库的符号解析，并确保程序中的函数调用能够正确指向内存中加载的库。  
  
Linux  
系统中的动态链接器通常指的是  
ld-linux.so  
文件，该文件通常位于  
/lib  
或  
/lib64  
目录下，比如  
/lib64/  
ld-linux-x86-64.so.2。  
  
除此之外，在  
Linux  
系统中还有一个叫  
LD_PRELOAD  
的环境变量与动态链接器密切相关，这个环境变量允许动态链接器在加载程序时候首先加载  
LD_PRELOAD  
中定义的共享库，因此也会覆盖程序真正加载的共享库中的符号信息，这个功能常常用于程序的调试、功能或性能测试，但也会被用于恶意软件的植入。  
  
LD_PRELOAD  
可以通过  
LD_PRELOAD  
环境变量设置，也可以通过  
/etc/ld.so.preload  
文件设置，但默认情况下这两者都是未设置的。  
  
如果要查看一个程序的共享库依赖，可以使用  
ldd  
命令查看，比如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs40GAdlGGnRj9tz3HNn0nhYX8jk0k6ibCjGFwLF9Zmp6qmIbAqTfmlYlue5UPictCSCa3HeIeDDqNfA/640?wx_fmt=png&from=appmsg "")  
  
另外，通过系统调用和信号追踪的  
strace  
命令可以看到  
/etc/ld.so.preload  
是否存在：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs40GAdlGGnRj9tz3HNn0nhYOs63qjelQ3VMibcZ8IwYelk7B7E12qaMFGoLyf5ianc0mZgicfnY3v3ibA/640?wx_fmt=png&from=appmsg "")  
  
我们以在许多程序中常用的  
fopen  
函数为例进行覆盖，首先编写示例的共享库  
preload.c  
：  
```
#include<stdio.h>

__attribute__((constructor))void preload_init() {
    printf("[preload_demo.so] Dynamiclibrary loaded successfully.\n");
}

FILE *fopen(const char *path, const char *mode) {
    printf("THis is evilfopen.\n");
    return NULL;
}
```  
  
上述代码中，__attribute__((constructor))属性将  
preload_init()  
声明为在  
main  
函数之前执行的函数，这样可以通过该函数的执行检查动态链接是否成功，接着是重新定义了  
fopen  
函数，输出“  
THis is evil fopen  
”。  
  
而后通过下面的命令进行编译：  
```
gcc -Wall -fPIC -shared -nostartfile -o preload.so preload.c
```  
  
其中，  
-Wall  
不是必需，是为了方便查看所有编译期间的错误，  
-nostartfiles  
参数为了避免标准启动文件的链接，降低不必要的代码。  
  
再将编译后的文件地址（如  
/home/kali/Desktop/preload.so  
）写入  
LD_PRELOAD  
环境变量（之所以不推荐  
/etc/ld.so.preload  
，是该方法无法恢复动态链接，会导致系统其他操作无法正常）。  
  
假设系统中有另一个正常的程序中也调用了  
fopen  
函数，比如下面的  
normal.c  
：  
```
#include<stdio.h>

int main() {
    printf("Calling the fopen()function.\n");
    
    FILE *fd = fopen("test.txt","r");
    if (!fd) {
        printf("fopen() returnedNULL.\n");
        return 1;
    }
    
    printf("fopen()secceeded.\n");
    
    return 0;
}
```  
  
编译后执行该程序  
normal.o  
，即可看到  
fopen  
函数被替换后的结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs40GAdlGGnRj9tz3HNn0nhYnnyDNU4RIOIlTKhD9Zc0XxZZWevmCF5HhiaWO1hxHyQXMKrYaj1xy6w/640?wx_fmt=png&from=appmsg "")  
  
如果查看  
normal.o  
的共享库的依赖关系，也可以看到其依赖结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs40GAdlGGnRj9tz3HNn0nhYN9sIQEwPMkCZgh5Xy2LZLyia5mH4DQ7xaUdV58qy5UxgNZNWy82Bb9Q/640?wx_fmt=png&from=appmsg "")  
  
LD_PRELOAD  
虽然可以替代函数符号，但是也存在诸多限制，比如不能利用  
SetUID  
进行提权（比如普通用户执行所有权是  
Root  
的程序结合  
LD_PRELOAD  
进行提权），不适用于静态链接、内联函数（如  
printf  
函数）、系统函数（如  
syscall  
函数）以及自定义的函数。  
  
因为  
Linux  
系统中的一切都是文件化，在  
Linux  
系统下可以进行持久化的方法还有很多，结合应用或服务的特性，一切可以执行脚本或有  
hook  
机制的地方都可以隐藏持久化脚本，比如  
Shell  
脚本中的  
trap  
命令，又或者是  
Alias  
命令，甚至是  
MOTD  
信息的修改等等。  
  
