> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2MjU2MzI3MA==&mid=2247484711&idx=1&sn=c2c06fac608791fac01832eab95ab674

#  紧急预警：Linux曝高危Sudo漏洞，普通用户秒变root管理员！（附POC）  
 内存泄漏   2025-07-12 16:00  
  
**“**  
   
两个关键漏洞悄然潜伏，  
**本地用户轻松获取系统最高权限**  
，影响几乎所有主流Linux发行版  
。**”**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPA9bic9zzTydWv4XTTHH2NAiamMp8Kxsh4s2lukPuyuwnia3NiaHkiaU8a3JGFhLvNnYvtLvHTFAd91Rw/640?wx_fmt=png&from=appmsg "")  
  
      
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yPMwVHx9iaPDKDhBJiajRW2DIdq0Wxe7JcpgKDia3zMfgicaaD6Auwn6Q3GGm2vI0eNh1Qic6OUhHMjE7g/640?wx_fmt=png&from=appmsg "")  
  
  
  
PS：有内网web自动化需求可以私信  
  
  
  
  
01  
  
—  
  
  
  
导语  
  
  
    系统管理员注意！近日曝光的两个Sudo权限漏洞正威胁全球Linux系统的安全根基。安全研究人员发现，攻击者可以利用这些漏洞从普通用户  
**轻松升级为root管理员**  
，完全控制你的服务器和工作站。  
  
POC链接：  

```
https://github.com/pr0v3rbs/CVE-2025-32463_chwoot
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/L369x9IF3yMGWTVH0k4W8z3m4pibAVsz0bBzj7BQP7mf0HbhA0u3ZJ2wjHIfwqChUT0TsTntyA3djV21Mu8yJ1w/640?wx_fmt=png&from=appmsg "")  
## 一.漏洞详情：双面威胁  
### CVE-2025-32462：潜伏12年的“时光炸弹”  
  
    这个令人震惊的漏洞在Sudo代码中  
**隐藏了整整12年之久**  
，从2013年引入的host选项功能（-h或--host）就存在设计缺陷。虽然官方文档明确说明该选项应仅用于权限查看（sudo -l），但实际可被用于执行特权命令。  
  
**技术原理**  
：当sudoers文件使用Host或Host_Alias指令配置了特定主机规则时，攻击者可通过指定远程主机名欺骗Sudo应用错误规则。例如：  

```
sudo -h dev.test.local -i
```

  
    即使生产环境明确禁止该用户权限，此命令也会让系统错误应用开发服务器的规则，  
**授予攻击者本不应拥有的root权限**  
。  
### 二.CVE-2025-32463：致命chroot缺陷（CVSS 9.3）  
  
    这个  
**高危漏洞**  
（CVSS评分9.3）影响Sudo的chroot功能（-R选项）。攻击者可诱使Sudo从用户控制的目录加载恶意共享库。  
  
**技术原理**  
：在Sudo 1.9.14版本引入的路径解析变更中，当使用--chroot选项时，程序会从用户指定的根目录中读取/etc/nsswitch.conf文件。攻击者可在此路径放置恶意配置文件，  
**强制Sudo加载恶意库**  
，从而获得root权限。  
  
    更危险的是，  
**默认Sudo配置即存在此漏洞**  
，且不需要为用户定义任何特殊Sudo规则。任何本地非特权用户都可能利用此漏洞提升至root权限。  
## 三.影响范围：几乎全覆盖  
  
这两个漏洞影响范围极广：  
- **操作系统**  
：几乎所有主流Linux发行版（Ubuntu、Debian、RHEL、Fedora、SUSE、AlmaLinux等）以及macOS Sequoia  
  
- **Sudo版本**  
：  
  
- CVE-2025-32462：v1.8.8 到 v1.9.17  
  
- CVE-2025-32463：v1.9.14 到 v1.9.17  
  
已确认受影响的系统包括：  
- Ubuntu 24.04.1（Sudo 1.9.15p5，1.9.16p2）  
  
- macOS Sequoia 15.3.2（Sudo 1.9.13p2）  
  
- Fedora最新版本  
  
## 四.修复方案：立即行动  
### 1. 紧急升级  
  
官方已在Sudo   
**1.9.17p1版本修复**  
这两个漏洞。各发行版已发布安全更新：  
- Ubuntu/Debian：  

```
sudo apt update && sudo apt upgrade
```

  
- RHEL/CentOS：  

```
sudo yum update
```

  
- Fedora：  

```
sudo dnf update
```

  
- openSUSE：  

```
sudo zypper up
```

  
- Arch：  

```
sudo pacman -Syu
```:cite[7]
```

  
### 2. 安全审计  
- 检查sudoers配置：审计/etc/sudoers和/etc/sudoers.d/目录中所有使用Host或Host_Alias的规则  
  
- 对于LDAP存储的sudo策略，使用命令检查：  

```
ldapsearch -x -b 'ou=SUDOers,dc=example,dc=com'
```:cite[5]
```

  
- 监控可疑活动：  

```
sudo journalctl _COMM=sudo
```:cite[7]
```

  
### 3. 权限控制  
- 审查sudo用户组成员：  

```
# Debian/Ubuntu
sudo getent group sudo

# Fedora/Arch
sudo getent group wheel
```

  
- **立即移除**  
不必要的sudo权限：  

```
# Debian/Ubuntu
sudo deluser username sudo

# Fedora/Arch
sudo gpasswd -d username wheel
```:cite[7]
```

  
## 五.长期防护策略  
  
考虑到chroot功能的风险，Sudo维护者Todd Miller已宣布：  
- **立即弃用chroot选项**  
  
- 将在未来版本中  
**完全移除该功能**  
  
    安全专家Rich Mirch建议：“管理员应  
**全面审查环境**  
中所有chroot选项的使用情况。对于企业而言，这种深层漏洞的发现表明需要建立  
**持续漏洞监测机制**  
”。  
## 总结：刻不容缓  
  
    这两个Sudo漏洞打破了Linux系统最根本的安全边界——普通用户与root管理员之间的权限隔离。  
**CVE-2025-32463尤其危险**  
，它使任何本地用户（包括受限的应用程序账户）都能获得完全的系统控制权。  
  
鉴于漏洞利用门槛低且影响广泛，系统管理员必须  
**立即采取行动**  
：  
1. **紧急更新**  
所有系统上的sudo包  
  
1. **审计配置**  
和用户权限  
  
1. **监控特权命令**  
执行日志  
  
1. **限制账户权限**  
至最小必需范围  
  
    在云环境中，即使新创建的虚拟机也可能运行易受攻击的Sudo版本。  
**安全团队应扫描所有系统**  
，包括那些自动扩展组中的实例，确保无一遗漏。  
  
    Linux安全的长城出现裂缝，修补工作刻不容缓。每一次权限漏洞的曝光都在提醒我们：  
**安全不是静态配置，而是持续的战斗**  
。  
  
免责声明：  
### 本人所有文章均为技术分享，均用于防御为目的的记录，所有操作均在实验环境下进行，请勿用于其他用途，否则后果自负。  
  
第二十七条：任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序和工具；明知他人从事危害网络安全的活动，不得为其提供技术支持、广告推广、支付结算等帮助  
  
第十二条：  国家保护公民、法人和其他组织依法使用网络的权利，促进网络接入普及，提升网络服务水平，为社会提供安全、便利的网络服务，保障网络信息依法有序自由流动。  
  
任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得危害网络安全，不得利用网络从事危害国家安全、荣誉和利益，煽动颠覆国家政权、推翻社会主义制度，煽动分裂国家、破坏国家统一，宣扬恐怖主义、极端主义，宣扬民族仇恨、民族歧视，传播暴力、淫秽色情信息，编造、传播虚假信息扰乱经济秩序和社会秩序，以及侵害他人名誉、隐私、知识产权和其他合法权益等活动。  
  
第十三条：  国家支持研究开发有利于未成年人健康成长的网络产品和服务，依法惩治利用网络从事危害未成年人身心健康的活动，为未成年人提供安全、健康的网络环境。  
  
  
  
  
  
