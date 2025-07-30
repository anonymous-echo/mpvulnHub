> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5Mjc3MDM2Mw==&mid=2651142691&idx=1&sn=8aa8493bec0e7681c003aaac23cdbeaa

#  IoT漏洞分析之模拟环境搭建  
原创 吾爱pojie  吾爱破解论坛   2025-06-20 03:20  
  
作者**论****坛账号：A-new**  
  
  
首先声明，也是刚开始玩IoT，学习了解路由器这些固件模拟以及漏洞复现，菜鸟一个，主要是记录一下自己走过的坑。  
- 配置模拟固件运行的依赖环境  
  
其实也有傻瓜化一键工具比如FirmAE 、firmware-analysis-toolkit  
 、firmware-analysis-plus  
 这些工具，有些固件可以一键仿真，好多还需要手动来搭建环境模拟。  
  
手动的话一般就是用查找网上别人做好的直接配合QEMU用就好了，也可以自己折腾找对应镜像用QEMU安装环境。  
  
之前我也就是用这些方法，太折腾，环境没搞好基本就想放弃了。  
  
前一段看一个大佬的文章发现了一个好工具**Buildroot**  
 可以编译各种CPU的环境。  
**下载安装：**  

```
wget https://buildroot.org/downloads/buildroot-2025.02.tar.gz
tar -xzvf buildroot-2025.02.tar.gz
cd buildroot-2025.02
```

  
主要命令：  

```
make list-defconfigs #查看所有默认配置文件
```

  
这里主要关注的就是QEMU相关的这几个  
  
qemu_aarch64_ebbr_defconfig         - Build for qemu_aarch64_ebbr  
  
qemu_aarch64_sbsa_defconfig         - Build for qemu_aarch64_sbsa  
  
qemu_aarch64_virt_defconfig         - Build for qemu_aarch64_virt  
  
qemu_arm_ebbr_defconfig             - Build for qemu_arm_ebbr  
  
qemu_arm_versatile_defconfig        - Build for qemu_arm_versatile  
  
qemu_arm_vexpress_defconfig         - Build for qemu_arm_vexpress  
  
qemu_arm_vexpress_tz_defconfig      - Build for qemu_arm_vexpress_tz  
  
qemu_m68k_mcf5208_defconfig         - Build for qemu_m68k_mcf5208  
  
qemu_m68k_q800_defconfig            - Build for qemu_m68k_q800  
  
qemu_microblazebe_mmu_defconfig     - Build for qemu_microblazebe_mmu  
  
qemu_microblazeel_mmu_defconfig     - Build for qemu_microblazeel_mmu  
  
qemu_mips32r2el_malta_defconfig     - Build for qemu_mips32r2el_malta  
  
qemu_mips32r2_malta_defconfig       - Build for qemu_mips32r2_malta  
  
qemu_mips32r6el_malta_defconfig     - Build for qemu_mips32r6el_malta  
  
qemu_mips32r6_malta_defconfig       - Build for qemu_mips32r6_malta  
  
qemu_mips64el_malta_defconfig       - Build for qemu_mips64el_malta  
  
qemu_mips64_malta_defconfig         - Build for qemu_mips64_malta  
  
qemu_mips64r6el_malta_defconfig     - Build for qemu_mips64r6el_malta  
  
qemu_mips64r6_malta_defconfig       - Build for qemu_mips64r6_malta  
  
qemu_or1k_defconfig                 - Build for qemu_or1k  
  
qemu_ppc64_e5500_defconfig          - Build for qemu_ppc64_e5500  
  
qemu_ppc64le_powernv8_defconfig     - Build for qemu_ppc64le_powernv8  
  
qemu_ppc64le_pseries_defconfig      - Build for qemu_ppc64le_pseries  
  
qemu_ppc64_pseries_defconfig        - Build for qemu_ppc64_pseries  
  
qemu_ppc_bamboo_defconfig           - Build for qemu_ppc_bamboo  
  
qemu_ppc_e500mc_defconfig           - Build for qemu_ppc_e500mc  
  
qemu_ppc_g3beige_defconfig          - Build for qemu_ppc_g3beige  
  
qemu_ppc_mac99_defconfig            - Build for qemu_ppc_mac99  
  
qemu_ppc_mpc8544ds_defconfig        - Build for qemu_ppc_mpc8544ds  
  
qemu_riscv32_nommu_virt_defconfig   - Build for qemu_riscv32_nommu_virt  
  
qemu_riscv32_virt_defconfig         - Build for qemu_riscv32_virt  
  
qemu_riscv64_nommu_virt_defconfig   - Build for qemu_riscv64_nommu_virt  
  
qemu_riscv64_virt_defconfig         - Build for qemu_riscv64_virt  
  
qemu_riscv64_virt_efi_defconfig     - Build for qemu_riscv64_virt_efi  
  
qemu_s390x_defconfig                - Build for qemu_s390x  
  
qemu_sh4eb_r2d_defconfig            - Build for qemu_sh4eb_r2d  
  
qemu_sh4_r2d_defconfig              - Build for qemu_sh4_r2d  
  
qemu_sparc64_sun4u_defconfig        - Build for qemu_sparc64_sun4u  
  
qemu_sparc_ss10_defconfig           - Build for qemu_sparc_ss10  
  
qemu_x86_64_defconfig               - Build for qemu_x86_64  
  
qemu_x86_defconfig                  - Build for qemu_x86  
  
qemu_xtensa_lx60_defconfig          - Build for qemu_xtensa_lx60  
  
qemu_xtensa_lx60_nommu_defconfig    - Build for qemu_xtensa_lx60_nommu  
  
  
比如我有个固件提出来的一个elf  
  
  
  
mips32r2 little endian  
  
就用 qemu_mips32r2el_malta_defconfig     - Build for qemu_mips32r2el_malta 这个  

```
make qemu_mips32r2el_malta_defconfig
```

  
  
  
  

```
make menuconfig #其他一些自定义的东西
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LFPriaSjBUZJAW1p8udCPmQH0aEJ9iaLhxtXffIs9dZyKLYR11vhicfWUXLJia3KVabG2YKeUiaumIn48JtphB1eANQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
环境是Ubuntu20.04 缺少libncurses-dev 安装一下继续  
  
  
  
Target options选择CPU架构这些最开始已经选了qemu_mips32r2el_malta_defconfig查看一下  
  
  
  
Target packages就是配置目软件标包  
  
  
  
主要就是配置网络装上bridge-utils、openssh-server  
  
  
  
  
  
还有就是Filesystem images这里注意一下  
  
  
  
这里默认是60M如果复制整个固件解包空间会不够，我这里改成600M，一般应该够用  
  
别的就看自己需求，保存，退出，然后make下载编译构建，时间要比较久上面这个大概等了两三个小时，  
  
好了之后会在buildroot/output/images下生成三个文件 rootfs.ext2  start-qemu.sh  vmlinux  
  
  
  
start-qemu.sh就是启动脚本，可以直接启动，要与宿主机通信还要加上网络，改进一下脚本  

```
#!/bin/sh


BINARIES_DIR=&#34;${0%/*}/&#34;
# shellcheck disable=SC2164
cd &#34;${BINARIES_DIR}&#34;


#mode_serial=false
mode_serial=true
mode_sys_qemu=false
tap_interface=&#34;tap&#34;  # 默认的TAP接口名称
tap_ip_host=&#34;192.168.100.1&#34;  # 宿主机的IP地址
tap_ip_guest=&#34;192.168.100.2&#34;  # 虚拟机的IP地址


while [ &#34;$1&#34; ]; do
    case &#34;$1&#34; in
    --serial-only|serial-only) mode_serial=true; shift;;
    --use-system-qemu) mode_sys_qemu=true; shift;;
    --tap-interface) tap_interface=&#34;$2&#34;; shift 2;;
    --use-tap) use_tap=true; shift;;
    --) shift; break;;
    *) echo &#34;unknown option: $1&#34; >&2; exit 1;;
    esac
done


if ${mode_serial}; then
    EXTRA_ARGS='-nographic'
else
    EXTRA_ARGS='-serial stdio'
fi


if ! ${mode_sys_qemu}; then
    export PATH=&#34;/home/lubuntu/buildroot/output/host/bin:${PATH}&#34;
fi


if ${use_tap}; then
    # 创建并配置TAP接口
    sudo ip link delete &#34;${tap_interface}&#34; 2>/dev/null  # 如果 TAP 接口已存在，先删除
    sudo ip tuntap add dev &#34;${tap_interface}&#34; mode tap  # 创建 TAP 接口
    sudo ip addr add &#34;${tap_ip_host}/24&#34; dev &#34;${tap_interface}&#34;  # 为 TAP 接口分配宿主机IP地址
    sudo ip link set &#34;${tap_interface}&#34; up  # 启用 TAP 接口


    # 配置 QEMU 使用 TAP 网络
    NET_CONFIG=&#34;-netdev tap,id=net0,ifname=${tap_interface},script=no,downscript=no -device pcnet,netdev=net0&#34;
else
    # 使用用户模式网络
    NET_CONFIG=&#34;-net nic,model=pcnet -net user&#34;
fi


exec qemu-system-mipsel -M malta \
    -kernel vmlinux \
    -drive file=rootfs.ext2,format=raw \
    -append &#34;rootwait root=/dev/sda console=ttyS0 ip=${tap_ip_guest}::${tap_ip_host}:255.255.255.0::eth0:off&#34; \
    ${NET_CONFIG} ${EXTRA_ARGS} &#34;$@&#34;
```

  
可以扔给人工智能再优化一下，  
  
其实还是有问题不会自动配置IP可以每次启动用命令配临时IP  

```
ip addr add 192.168.100.2/24 dev eth0 #模拟环境ip 192.168.100.2
ip link set eth0 up
```

  
也可以直接修改网络配置设置静态IP，修改  

```
# cat /etc/network/interfaces
# interface file auto-generated by buildroot


auto lo
iface lo inet loopback


auto eth0
iface eth0 inet dhcp
  pre-up /etc/network/nfs_check
  wait-delay 15
  hostname $(hostname)
```

  
为  

```
auto lo
iface lo inet loopback


auto eth0
iface eth0 inet static
    address 192.168.100.2
    netmask 255.255.255.0
    gateway 192.168.100.1
    dns-nameservers 8.8.8.8


```

  
这样启动就可以虚拟机与宿主机通信了，如果你物理机用Linux这样就可以了，下面是我这种菜鸟折腾Windows的，虚拟机套虚拟机心累啊{:1_909:} 。  
- Windows环境运行QEMU配置  
  
安装QEMU就不介绍了，主要介绍一下网络配置  
  
Windows要装一个TAP虚拟网卡  
  
直接用openVPN的就好了  
  
  
  
只装这一个玩意就够了，装好就会多出来一个网卡  
  
  
  
改个名TAP，有空格用着麻烦  
  
然后Windows启动脚本  

```
@echo off
cd /d %~dp0


REM QEMU 路径（请根据实际路径修改）
set QEMU_EXE=&#34;D:\Program Files\qemu\qemu-system-mipsel.exe&#34;


REM 镜像文件名
set KERNEL=vmlinux
set ROOTFS=rootfs.ext2


REM 网络参数
set TAP_NAME=TAP
set HOST_IP=192.168.100.1
set VM_IP=192.168.100.2
set NETMASK=255.255.255.0


REM 默认参数
set EXTRA_ARGS=-nographic
set NET_CONFIG=-net nic,model=pcnet -net user


REM 解析命令行参数（仅支持 --use-tap 和 --tap-interface）
:parse_args
if &#34;%1&#34;==&#34;&#34; goto run_qemu
if /i &#34;%1&#34;==&#34;--use-tap&#34; (
    set NET_CONFIG=-netdev tap,id=net0,ifname=%TAP_NAME%,script=no,downscript=no -device pcnet,netdev=net0
)
if /i &#34;%1&#34;==&#34;--tap-interface&#34; (
    set TAP_NAME=%2
    set NET_CONFIG=-netdev tap,id=net0,ifname=%TAP_NAME%,script=no,downscript=no -device pcnet,netdev=net0
    shift
)
if /i &#34;%1&#34;==&#34;--serial-only&#34; set EXTRA_ARGS=-nographic
if /i &#34;%1&#34;==&#34;serial-only&#34; set EXTRA_ARGS=-nographic
shift
goto parse_args


:run_qemu


%QEMU_EXE% -cpu 74Kf -M malta -kernel %KERNEL% -drive file=%ROOTFS%,format=raw ^
    -append &#34;rootwait root=/dev/sda console=ttyS0 ip=%VM_IP%::%HOST_IP%:%NETMASK%::eth0:off&#34; ^
    %NET_CONFIG% %EXTRA_ARGS% %*
```

  
注意这个参数-cpu 74Kf有时候要调一下。  
  
要让qemu虚拟机能访问互联网还要再改一下联网的物理网卡共享这里  
  
  
  
然后设置虚拟网卡IP，这两个顺序别乱不然有问题。  
  
  
  
最后再配置一下nameserver 就可以ping 通域名了  

```
# cat /etc/resolv.conf
nameserver 8.8.8.8
nameserver 114.114.114.114
```

  
  
  
###   
  
  
**-官方论坛**  
  
www.52pojie.cn  
  
  
  
**👆👆👆**  
  
公众号  
**设置“星标”，**  
您  
**不会错过**  
新的消息通知  
  
如**开放注册、精华文章和周边活动**  
等公告  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/LFPriaSjBUZK0l7v6mmrudZKXzpdM1WcomgJQnibvLzBUFRSurSkmIfl0ZrDNvSy3MszKNY3XOkcuUbWp31HMjLQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
