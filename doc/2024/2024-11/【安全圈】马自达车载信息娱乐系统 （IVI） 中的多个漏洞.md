#  【安全圈】马自达车载信息娱乐系统 （IVI） 中的多个漏洞   
 安全圈   2024-11-08 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
在多款车型（如 2014-2021 年款马自达 3）上安装的马自达 Connectivity Master Unit (CMU) 系统中发现了多个漏洞。与许多情况一样，这些漏洞是由于在处理攻击者提供的输入时未进行充分的消毒而造成的。实际存在的攻击者可以通过将特制的 USB 设备（如 iPod 或大容量存储设备）连接到目标系统来利用这些漏洞。成功利用其中一些漏洞可导致以 root 权限执行任意代码。  
  
目标  
  
作为研究目标的特定 CMU 装置由伟世通公司制造，而软件最初由江森自控公司 (JCI) 开发。研究针对最新可用软件版本（74.00.324A）进行。至少 70.x 以下的早期软件版本也可能受到这些漏洞的影响。  
  
值得注意的是，CMU 的 “修改场景 ”非常活跃，社区发布了多种软件 “调整 ”来改变设备的运行。安装这些调整程序通常依赖于软件漏洞。截至发稿时，我们尚未发现最新固件版本中存在任何公开的已知漏洞。  
  
硬件设计  
  
设备外观如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5ZQcZEq3ZdBoKh2Wq7BR938QXpicKU1TNjI28zptFhSEofDVfOfxyIooamdk31TDgOZPESibEup8g/640?wx_fmt=jpeg&from=appmsg "")  
  
底部有一张贴纸，上面有一些关于设备的技术信息。贴纸上注明 CMU 的具体型号为 MAZDA_GEN_65_CMU。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5ZQcZEq3ZdBoKh2Wq7BR9lxfRMOxKVibacxB5oOVSn4PibZWXjuXUT4II6wucuibiaxSF1JT3PMJxaA/640?wx_fmt=jpeg&from=appmsg "")  
  
设备背面有多个连接器，用于连接电源、音频输入/输出、USB 和 CAN 信号以及串行控制台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5ZQcZEq3ZdBoKh2Wq7BR9JVYVqI7L1gEnm4sK08bYNvz3QtTNRx76rxBMcU4ibXEhKoXvA30YOjw/640?wx_fmt=jpeg&from=appmsg "")  
在内部，该装置构建在一块印刷电路板上，其中包含一个应用 SoC（飞思卡尔零件编号 SCIMX06DAVT10AC）、各种存储器 IC（电路板背面的串行闪存、NAND 闪存和 eMMC）、一个辅助 MCU（瑞萨零件编号 R5F35MCEJFF）和一个蓝牙模块（村田零件编号 LBEE6Z2U0C-584）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5ZQcZEq3ZdBoKh2Wq7BR9QPoy3QIjpAYMrccZhUyzYvOCib4Vt5pnIPKSnDZgPaD2Mm35Xe2H2XQ/640?wx_fmt=jpeg&from=appmsg "")  
  
本研究未探讨边缘连接器的可用功能。  
  
通常情况下，在存在多个处理单元的设计中，会实现一定程度的分离。由丰富的操作系统（如 QNX、Linux、Android 等）处理的面向用户的应用程序在应用 SoC 上运行，而 CAN 连接则由通常运行 RTOS 的 MCU 处理。该设备似乎也是这种情况。  
  
软件设计  
  
在软件方面，该设备的主 SoC 正在运行基于 Linux 的操作系统映像，以下通过串行控制台捕获的输出（此处缩写）就是证明：  
```
IBC embedded bootloader 1.68.21 
 
(c) 2012 XS Embedded GmbH 
 
Uncompressing Linux... done, booting the kernel. 
00:00:01.226 LVDS[61] contrast   : 54 -> 54 
00:00:01.227 LVDS[61] (Defaulting) Speed Restriction: Enabled 
00:00:01.227 LVDS[61] (Defaulting) Visteon Display. 
… 
00:00:01.428 LVDS[61] ChangeBrightness_Id: 
00:00:01.433 LVDS[61] brightness : 5000 -> 5000 
00:00:01.433 LVDS[61] BrightNessLevel = 5000. 
 
FGSN: VPGJ3Fxxxxxxxxyy 
cmu login:
```  
  
view rawmazda_connect-0.txt hosted with ❤ by GitHub  
  
虽然有登录提示，但最新软件版本的验证凭据并不公开。控制台继续提供大量日志输出，这对测试漏洞很有用。  
  
完全启动后，系统挂载了以下文件系统：  
```
rootfs on / type rootfs (rw) 
none on /sys type sysfs (rw,relatime) 
none on /proc type proc (rw,relatime) 
none on /dev type devtmpfs (rw,relatime,size=8192k,nr_inodes=95316,mode=755) 
/dev/ffx01p1 on / type relfs (ro,noatime) 
none on /sys type sysfs (rw,relatime) 
none on /proc type proc (rw,relatime) 
none on /dev type devtmpfs (rw,relatime,size=8192k,nr_inodes=95316,mode=755) 
none on /tmp type tmpfs (rw,relatime,size=95232k) 
/dev/ffx01p4 on /tmp/mnt/data type relfs (rw,noatime) 
/dev/mmcblk0p2 on /tmp/mnt/data_persist type relfs (rw,noatime) 
/dev/mtdblock5 on /config-mfg type squashfs (ro,relatime) 
none on /dev/pts type devpts (rw,relatime,mode=600) 
none on /dev/mqueue type mqueue (rw,relatime) 
none on /tmp/mnt/tmp/race/database type tmpfs (rw,relatime,size=30720k) 
/dev/mmcblk0p1 on /tmp/mnt/resources type relfs (ro,noatime)
```  
  
查看由 GitHub ❤ 托管的 rawmazda_connect-1.txt  
  
操作系统可访问所有持久内存存储。串行闪存以 mtdblock 分区的形式存在，NAND 闪存以 ffx01 分区的形式存在，eMMC 闪存以 mmcblk 分区的形式存在。值得注意的是，有几个文件系统是读写加载的，括号中的 rw 字符串表示了这一点。  
  
软件更新过程  
  
可通过诊断菜单更新设备上的软件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg5ZQcZEq3ZdBoKh2Wq7BR9niay2KtPibkEMSULMobQFHiaCYbxk0LMLZQyGOCXKzcT1qdYddpkDkYibw/640?wx_fmt=jpeg&from=appmsg "")  
  
更新过程需要在通过 USB 连接的大容量存储设备上找到扩展名为 .up 的文件。然后，经销商可以进入诊断菜单并启动更新过程。  
  
软件更新文件是受密码保护的 ZIP 压缩文件，包含更新过程中不同步骤的多个目录，以及说明如何执行更新的 “说明 ”文件。最新更新文件中有 21 个步骤。特别值得关注的是以下目录的内容：  
  
– rootfs1upd 包含整个根文件系统的 .tar.gz 压缩包、– linux1 包含 Linux 内核 3.0.35、– ibc1 和 ibc2 包含一个引导加载器、– bootstrap 包含另一个引导程序、– passwdupdate 包含替换的 passwd 文件、– vip 包含辅助 MCU 的更新映像。  
  
更新过程的大部分在几个共享对象中实现。所有业务逻辑都位于 svcjciupdatea.so 和 svcjciupdates.so，它们使用 libjcireflashua.so 和 libjcisecurity.so 中的支持代码。对更新过程的调查仅限于签名验证。进一步的调查将假定能够生成正确签名的更新或绕过签名验证的更新。遗憾的是，前者在本次研究时还不存在，而后者在本次研究中也没有发现。  
  
从高层来看，更新验证过程包含在 svcjciupdates.so:updates_sys_srv_ValidatePackageOperationThread() 函数中，该函数会调用其他函数按指定顺序执行验证步骤：  
  
– updates_sys_srv_LoadUP() 解析指定的更新文件，提取 main_instructions.ini 和 versions.ini 文件，并将其存储在内存中，以便以后使用。– updates_sys_srv_ValidateUPStructure() 验证更新文件的内部结构是否与预期布局一致。当按照正确的更新文件格式创建漏洞时，这不是一个问题。– updates_sys_srv_ExtractCertificates() 从更新文件中提取签名证书链，用于更新验证。该链包含用于签署更新的发布者证书和签发发布者证书的中间 CA 证书。中间 CA 证书由 JCI 根 CA 签发。– updates_sys_sec_VerifyUPCertificates() 会验证提取的证书链，以确保证书链正确终止于存储在设备上的预期根 CA。– updates_sys_sec_VerifyUPSignature() 根据发布者证书验证指定更新文件的签名。本例中的签名位于更新文件的末尾，长度为 256 字节。– updates_sys_srv_RemoveExtractedCertificates() 会在验证过程结束后进行清理。  
  
特别值得注意的是，在对用户提供的文件进行完整性检查之前，ups updates_sys_srv_LoadUP()函数及其调用函数对提供的更新文件执行了多种操作。  
  
漏洞  
  
在我们的研究工作中发现了多个漏洞，这些漏洞可以结合使用，以实现对信息娱乐系统的全面和持续控制。  
  
CVE-2024-8355/ZDI-24-1208: 设备管理器 iAP 序列号 SQL 注入  
  
该漏洞是研究过程中发现的第一个漏洞，引发了对该设备的深入研究。  
  
具体漏洞存在于 /jci/devicemanager/libdevicemanager.so 库的 eInsertDeviceEntry() 函数中。当尝试向 DeviceDatabase.db SQLite 数据库中插入一个新的苹果设备时，会从设备中获取几个值，并在 SQL 语句中使用，而不进行消毒处理。请参见以下 eInsertDeviceEntry() 函数的伪代码实现：  
```
int eInsertDeviceEntry(undefined4 param_1,int param_2) 
{ 
  int iVar1; 
  undefined auStack1052 [1024]; 
  int local_1c; 
   
  local_1c = 0; 
  sqlite3_snprintf(0x400,auStack1052, 
                   "INSERT INTO DeviceInfo (USBSERIAL,MACADDRESS, IAPSERIAL, UIDVALID) VALUES(\'%s\',%Q,\'%s\',%d)" 
                   ,param_2,param_2 + 100,param_2 + 200,*(undefined4 *)(param_2 + 300)); 
  race_print_log(4,0x11,"eInsertDeviceEntry",0x4c0,"DEVMGR_DATABASE","Query is : %s\n",auStack1052); 
  iVar1 = sqlite3_exec(param_1,auStack1052,0,0,&local_1c); 
  if (iVar1 != 0) { 
    race_print_log(1,0x11,"eInsertDeviceEntry",0x4c5,"DEVMGR_DATABASE","SQL error: %s %d\n",local_1c 
                   ,iVar1); 
    if (local_1c != 0) { 
      sqlite3_free(); 
    } 
  } 
  if (iVar1 != 0) { 
    iVar1 = 1; 
  } 
  return iVar1; 
}
```  
  
查看由 GitHub ❤ 托管的 rawmazda_connect-2.c  
  
正因为如此，当信息娱乐系统检测到苹果设备已连接并请求（例如）其 iAP 序列号时，伪造的 iPod 或其他苹果设备可以回复如下字符串：  
```
     ' , 0); [ANY SQL STATEMENT];--
```  
  
查看由 GitHub ❤ 托管的 rawmazda_connect-3.txt  
  
这导致 DeviceManager 以 root 权限在信息娱乐系统上执行注入的 SQL 语句。这可用于操作数据库本身、披露信息、在文件系统上创建任意文件，甚至可能执行代码。由于输入的长度限制为 0x36 字节，因此对该漏洞的利用受到了一定的限制，但这有可能通过让多个伪造的 iPod 相继连接来解决，每个 iPod 都用自己注入的 SQL 语句代替序列号。  
  
CVE-2024-8359/ZDI-24-1191: REFLASH_DDU_FindFile 命令注入 RCE  
  
libjcireflashua.so 共享对象中的 REFLASH_DDU_FindFile() 函数是支持更新过程的众多函数之一。为清晰起见，现将该函数的伪代码复制如下：  
```
undefined4 REFLASH_DDU_FindFile(char *_up_path,char *_file_name,int _is_gzipped) 
{ 
  int iVar1; 
  undefined4 uVar2; 
  char acStack_408 [1023]; 
  undefined local_9; 
   
  memset(acStack_408,0,0x400); 
  if ((_up_path == (char *)0x0) || (_file_name == (char *)0x0)) { 
    REFLASH_UL_WriteLog("Core Reflash",0,0,"reflash_ddu.c","REFLASH_DDU_FindFile",0x181, 
                        "Some of the input parameters are wrong!"); 
    uVar2 = 0xffffd8f0; 
  } 
  else { 
    if (_is_gzipped == 1) { 
      if (reflash_ddu_password == 0) { 
        snprintf(acStack_408,0x400,"%s \"%s\" \"%s.gz\" > /dev/null","unzip -t",_up_path,_file_name) 
        ; 
      } 
      else { 
        snprintf(acStack_408,0x400,"%s %s \"%s\" \"%s.gz\" > /dev/null","unzip -t -P", 
                 reflash_ddu_password,_up_path,_file_name); 
      } 
    } 
    else if (reflash_ddu_password == 0) { 
      snprintf(acStack_408,0x400,"%s \"%s\" \"%s\" > /dev/null","unzip -t",_up_path,_file_name); 
    } 
    else { 
      snprintf(acStack_408,0x400,"%s %s \"%s\" \"%s\" > /dev/null","unzip -t -P", 
               reflash_ddu_password,_up_path,_file_name); 
    } 
    local_9 = 0; 
    iVar1 = system(acStack_408); 
    if (iVar1 == 0) { 
      uVar2 = 0; 
    } 
    else { 
      uVar2 = 0xffffd8fb; 
    } 
  } 
  return uVar2; 
}
```  
  
mazda_connect-4.c 由 GitHub ❤ 托管  
  
该函数尝试在通过提供的文件路径指定的更新包中查找特定文件。这是通过将提供的路径插值到解压缩程序的命令行中来实现的。不幸的是，在此之前没有进行任何消毒处理，攻击者控制的输入（如 /dev/sda1/path/file.up）被传递到 system() 函数。这样，攻击者就可以注入任意操作系统命令，由主机操作系统外壳执行，从而完全入侵系统。攻击者可以控制整个路径中的路径和文件元素。  
  
受影响的函数可通过以下调用图到达：  
  
– svcjciupdates.so 中的 UPDATES_SYS_IPC_INTERFACE_GetPackageInfo_svc– UPDATES_SYS_SRV_GetPackageInfo– Update_sys_srv_GetPackageInfoOperationThread– 更新_sys_srv_LoadUP– libjcireflashua.so 中的 REFLASH_UA_LoadUP– REFLASH_DDU_FindFile  
  
CVE-2024-8360/ZDI-24-1192: REFLASH_DDU_ExtractFile 命令注入 RCE  
  
libjcireflashua.so 共享对象中的 REFLASH_DDU_ExtractFile() 函数是支持更新过程的众多函数之一。为清晰起见，现将该函数的伪代码复制如下：  
```
undefined4 REFLASH_DDU_ExtractFile(char *_up_path,char *_file_name,char *_dest_path,int _is_gzipped) 
{ 
  undefined4 uVar1; 
  char acStack_808 [1023]; 
  undefined local_409; 
  char acStack_408 [1023]; 
  undefined local_9; 
   
  memset(acStack_408,0,0x400); 
  memset(acStack_808,0,0x400); 
  if (((_up_path == (char *)0x0) || (_file_name == (char *)0x0)) || (_dest_path == (char *)0x0)) { 
    REFLASH_UL_WriteLog("Core Reflash",0,0,"reflash_ddu.c","REFLASH_DDU_ExtractFile",0xd4, 
                        "Some of the input parameters are wrong!"); 
    uVar1 = 0xffffd8f0; 
  } 
  else { 
    if (_is_gzipped == 1) { 
      if (reflash_ddu_password == 0) { 
        snprintf(acStack_408,0x400,"%s \"%s\" \"%s.gz\" | %s > \"%s\"","unzip -p",_up_path, 
                 _file_name,"gzip -d -c",_dest_path); 
      } 
      else { 
        snprintf(acStack_408,0x400,"%s %s \"%s\" \"%s.gz\" | %s > \"%s\"","unzip -p -P", 
                 reflash_ddu_password,_up_path,_file_name,"gzip -d -c",_dest_path); 
        snprintf(acStack_808,0x400,"%s %s \"%s\" \"%s.gz\" | %s > \"%s\"","unzip -p -P","<***>", 
                 _up_path,_file_name,"gzip -d -c",_dest_path); 
      } 
    } 
    else if (reflash_ddu_password == 0) { 
      snprintf(acStack_408,0x400,"%s \"%s\" \"%s\" > \"%s\"","unzip -p",_up_path,_file_name, 
               _dest_path); 
    } 
    else { 
      snprintf(acStack_408,0x400,"%s %s \"%s\" \"%s\" > \"%s\"","unzip -p -P",reflash_ddu_password, 
               _up_path,_file_name,_dest_path); 
      snprintf(acStack_808,0x400,"%s %s \"%s\" \"%s\" > \"%s\"","unzip -p -P","<***>",_up_path, 
               _file_name,_dest_path); 
    } 
    local_9 = 0; 
    if (reflash_ddu_password == 0) { 
      uVar1 = REFLASH_ExecuteCommand(acStack_408,0); 
    } 
    else { 
      local_409 = 0; 
      uVar1 = REFLASH_ExecuteCommand(acStack_408,acStack_808); 
    } 
  } 
  return uVar1; 
}
```  
  
mazda_connect-5.c 由 GitHub ❤ 托管  
  
该函数试图从通过 up_path 参数提供的路径指定的更新包中提取特定文件。这会将提供的路径插值到解压缩程序的命令行中。不幸的是，在此之前没有进行任何消毒处理，攻击者控制的输入（例如，/dev/sda1/path/file.up）被传递到 system() 函数。攻击者可以控制整个路径中的路径和文件元素。这样，攻击者就可以注入任意操作系统命令，由主机操作系统外壳执行这些命令，从而全面入侵系统。  
  
可通过以下调用图访问受影响的函数：  
  
– svcjciupdates.so 中的 UPDATES_SYS_IPC_INTERFACE_GetPackageInfo_svc– UPDATES_SYS_SRV_GetPackageInfo– Update_sys_srv_GetPackageInfoOperationThread– 更新_sys_srv_LoadUP– libjcireflashua.so 中的 REFLASH_UA_LoadUP– REFLASH_DDU_ExtractFile  
  
CVE-2024-8358/ZDI-24-1190: UPDATES_ExtractFile 命令注入 RCE  
  
svcjciupdates.so 共享对象中的 UPDATES_ExtractFile() 函数是支持更新过程的各种函数之一。为清楚起见，现将该函数的部分伪代码复制如下：  
```
int UPDATES_ExtractFile(char *up_path,char *file_path,char *destFile,int gzipped,char *password) 
{ 
  int iVar1; 
  size_t sVar2; 
  size_t sVar3; 
  int iVar4; 
  char *pcVar5; 
  char *local_2060 [4]; 
  int gzipped$1; 
  char *destFile$1; 
  char *file_path$1; 
  char *up_path$1; 
  char acStack_203c [4100]; 
  char *pcStack_1038; 
  char cmd [4100]; 
  char *local_30; 
  int local_2c; 
  size_t local_28; 
  int local_24; 
   
  local_24 = 100; 
  gzipped$1 = gzipped; 
  destFile$1 = destFile; 
  file_path$1 = file_path; 
  up_path$1 = up_path; 
  // ... 
  if (local_24 == 100) { 
    snprintf(acStack_203c,0x1001,"%s","unzip -p"); 
  } 
  if ((local_24 == 100) && (password != (char *)0x0)) { 
    // append the unzip option and the password itself 
  } 
  if (local_24 == 100) { 
    if (gzipped$1 == 1) { 
      local_2060[0] = up_path$1; 
      local_2060[1] = file_path$1; 
      local_2060[2] = "gzip -d -c"; 
      local_2060[3] = destFile$1; 
      snprintf(cmd,0x1001,"%s \"%s\" \"%s.gz\" | %s > \"%s\"",acStack_203c); 
    } 
    else { 
      local_2060[0] = up_path$1; 
      local_2060[1] = file_path$1; 
      local_2060[2] = destFile$1; 
      snprintf(cmd,0x1001,"%s \"%s\" \"%s\" > \"%s\"",acStack_203c); 
    } 
    local_24 = UPDATES_ExecuteCommand(cmd,&pcStack_1038); 
    // ...
```  
  
mazda_connect-6.c 由 GitHub ❤ 托管  
  
该函数尝试从通过 up_path 参数提供的路径指定的更新包中提取特定文件。这会将提供的路径插值到解压程序的命令行中。与其他漏洞一样，在这之前没有执行任何消毒处理，攻击者控制的输入（例如，/dev/sda1/path/file.up）被传递给 system() 函数。攻击者可以控制整个路径中的路径和文件元素。这样，攻击者就可以注入任意操作系统命令，由主机操作系统外壳执行这些命令，从而全面入侵系统。  
  
可通过以下调用图访问受影响的函数：  
  
– svcjciupdates.so 中的 UPDATES_SYS_IPC_INTERFACE_GetPackageInfo_svc– UPDATES_SYS_SRV_GetPackageInfo– Update_sys_srv_GetPackageInfoOperationThread– Update_sys_srv_LoadUP– 更新_sys_srv_提取证书– 更新_sys_srv_提取发布证书– UPDATES_ExtractFile(“publisher_cert.pem”, “/tmp/reflash/publisher_cert.pem”)  
  
CVE-2024-8357/ZDI-24-1189: 应用程序 SoC 缺少硬件信任根  
  
如前所述，头显被划分为两个相对独立的系统：运行 Linux 的应用程序 SoC 和运行未指定操作系统的 VIP MCU。应用 SoC 使用板载 SPI 闪存芯片启动。该芯片的分区如下：  
```
/tmp/root # cat /proc/mtd 
dev:    size   erasesize  name 
mtd0: 00010000 00010000 "bootstrap" 
mtd1: 00010000 00010000 "boot-select" 
mtd2: 00020000 00010000 "ibc1" 
mtd3: 00020000 00010000 "ibc2" 
mtd4: 00010000 00010000 "nv-config" 
mtd5: 00060000 00010000 "config" 
mtd6: 00010000 00010000 "jci-boot-diag" 
mtd7: 00700000 00010000 "fail-safe" 
mtd8: 00020000 00010000 "update" 
```  
  
mazda_connect-7.txt 由 GitHub ❤ 托管  
  
在这里，mtd0 分区存储了引导代码，这似乎是系统上执行的第一段代码。我们发现应用程序 SoC 缺少对该引导代码的任何验证。此外，在将控制权传递给下一个启动阶段之前，后续的操作系统启动步骤均未对其执行任何验证。这就为在 Linux 系统上执行代码的攻击者提供了以下机会：  
  
– 操纵根文件系统，更改任意文件并获得系统的持久性、– 操纵驻留在 mtd5 分区中的配置数据，例如安装任意 SSH 密钥，以及– 操纵引导代码，获得在操作系统启动前执行任意代码的能力。  
  
CVE-2024-8356/ZDI-24-1188: VIP MCU 未签名代码  
  
如前所述，头戴式设备被划分为两个相对独立的系统：运行 Linux 的应用 SoC 和运行未指定操作系统的 VIP MCU。MCU 似乎支持多个 CMU 功能，包括与车辆其他部分的 CAN/LIN 连接。该分区还被假定为一个安全边界，即应用 SoC 的破坏将被控制，不会以可能危及安全的方式影响车辆的其他部分。  
  
在 CMU 软件中发现的字符串将有关 MCU 识别为 VIP。通过分析软件更新包，发现 VIP 也在软件更新过程中进行了更新。更新工具和更新映像可在更新包的 vip 子目录中找到。  
  
vcm 工具允许对 VIP 执行以下操作：  
```
/tmp/mnt/sdb1 # ./vcm --help 
***** VCM supports the following options: ***** 
***        Command --write-image argument Required 
***        Command --get-version argument None 
***        Command --write-conf argument Required 
***        Command --reboot argument None 
***        Command --watchdog-enable argument None 
***        Command --watchdog-disable argument None 
***        Command --heartbeat-enable argument None 
***        Command --heartbeat-disable argument None 
***        Command --get-all-version argument None 
***        Command --help argument None 
***        Command --vipmonitor-enable argument None 
***        Command --vipmonitor-disable argument None
```  
  
mazda_connect-8.txt 由 GitHub ❤ 托管  
  
具体来说，–write-image 命令允许将更新映像写入 VIP。该命令通常由更新脚本使用，接收格式为摩托罗拉 S 记录的输入文件。尤其值得注意的是，还可以查询 VIP 软件组件的版本。运行 cmu150_NA_74.00.324A 软件的设备报告如下：  
```
/tmp/mnt/sda1 # ./vcm --get-all-version 
[VIP VersionInfo] 
================= 
 
OEM P/N: YYYYYYY 
SW P/N:  XXXXXXX 
CMU_LIN_CAN_DUAL 
VIP_APP-MAZ150_10.13.012 
VIP_CAN-MAZ140_07.09.020 
VIP_DIAG-MAZ140_02.77.502 
VIP_VBM-MAZ140_15.33.634 
VIP_VFBL-MAZ140_02.00.500 
CPP_VIPALOGMON_08.08.500 
CPP_VIPBTL_05.07.500 
CPP_VIPCFG_06.01.500 
CPP_VIPEEMGR_05.06.501 
CPP_VIPGPIOMON_04.05.502 
CPP_VIPHBMON_04.05.500 
CPP_VIPIUC_08.09.506 
CPP_VIPLINDRVR_05.05.501 
CPP_VIPPWRMON_10.01.507 
CPP_VIPSPIDRVR_02.21.502 
CPP_VIPVOLMGR_06.12.602 
```  
  
mazda_connect-9.txt 由 GitHub ❤ 托管  
  
这些字符串位于更新文件 image-vip_appvfbl.mot，将被编程到 VIP MCU 内存空间中的内存地址 0xC000A，似乎是跨越地址 0xC0000 至 0xFFFFF 的应用映像的一部分。通过修改这些字符串，可以确定映像在编程到内部存储器之前是否经过验证。  
  
我们对原始 S 记录文件进行了处理，修改了一个字符串，以产生不同固件的可见指示，并将生成的映像编程回 VIP MCU：  
```
% diff  ./image-original.mot ./image-haxd-fixd.mot 
457c457 
< S2240C00200000000000000000535720502F4E3A202058585858585858000000000000000036 
--- 
> S2240C00200000000000000000535720502F4E3A202048415844204259205A444900000000B7 
```  
```
/tmp/mnt/sda1 # ./vcm --write-image image-haxd-fixd.mot  
 
 
Data Flashed: 589168 of 589168 bytes 
VIP Rebooted
```  
  
mazda_connect-11.txt 由 GitHub ❤ 托管  
  
使用同一命令进行版本检查，可以确认篡改的图像是否被接受：  
```
/tmp/mnt/sda1 # ./vcm --get-all-version 
[VIP VersionInfo] 
================= 
 
OEM P/N: YYYYYYY 
SW P/N:  HAXD BY ZDI 
CMU_LIN_CAN_DUAL 
VIP_APP-MAZ150_10.13.012 
VIP_CAN-MAZ140_07.09.020 
VIP_DIAG-MAZ140_02.77.502 
VIP_VBM-MAZ140_15.33.634 
VIP_VFBL-MAZ140_02.00.500 
CPP_VIPALOGMON_08.08.500 
CPP_VIPBTL_05.07.500 
CPP_VIPCFG_06.01.500 
CPP_VIPEEMGR_05.06.501 
CPP_VIPGPIOMON_04.05.502 
CPP_VIPHBMON_04.05.500 
CPP_VIPIUC_08.09.506 
CPP_VIPLINDRVR_05.05.501 
CPP_VIPPWRMON_10.01.507 
CPP_VIPSPIDRVR_02.21.502 
CPP_VIPVOLMGR_06.12.602 
```  
  
mazda_connect-12.txt 由 GitHub ❤ 托管  
  
从更广泛的意义上讲，这允许攻击者通过安装伪造的固件版本，从运行 Linux 的受攻击应用 SoC 转到 VIP MCU，并随后直接访问车辆的 CAN 总线。  
  
漏洞利用  
  
操作系统命令注入漏洞的利用相对简单。攻击者只需在 FAT32 格式的 USB 大容量存储设备上创建一个文件，文件名将包含要执行的操作系统命令。文件名必须以 .up 结尾，这样才能被软件更新处理代码识别。虽然所有三个命令注入漏洞都是通过文件名利用的，但最容易利用的是 ZDI-CAN-23420，因为它没有特定的利用要求，如制作的更新文件的有效性。  
  
连接 USB 大容量存储设备后可自动触发软件更新安装，这一 “已知功能 ”只需在存储设备上放置一个名为 jcii-autoupdate 的空文件即可激活，这进一步促进了对所述命令注入漏洞的利用。  
  
一旦实现了初始入侵，攻击者就可以通过操纵根文件系统来获得持久性，例如安装可在系统重启时持续存在的后台系统组件。  
  
此外，攻击者还可以横向移动并安装专门制作的 VIP 微控制器软件，从而可以不受限制地访问车辆网络，对车辆运行和安全造成潜在影响。本研究未调查具体影响（可控制的内容和控制方式）。  
  
用户/车主的相关风险  
  
在实验室环境中，从插入 USB 驱动器到在 VIP 上安装精心设计的更新，整个攻击链只需几分钟时间。目前，没有理由相信针对安装在汽车上的设备的类似攻击会花费更多时间。这就意味着，车辆可以在代客泊车、拼车或通过 USB 恶意软件等情况下被入侵。当然，也可以在没有重大时间压力的车间环境中进行同样的操作。  
  
然后，可以入侵 CMU 并对其进行 “增强”，例如，在有针对性的攻击中试图入侵任何连接设备，从而导致 DoS、瘫痪、勒索软件、安全隐患等。  
  
结论  
  
这项研究工作及其成果凸显了一个事实，即即使是已在市场上销售多年并经过长期安全修复的非常成熟的汽车产品，也可能存在影响巨大的漏洞。迄今为止，供应商仍未对这些漏洞进行修补。  
  
最近，安全社区对语言安全和 “内存安全 ”语言的重要性进行了大量关注和讨论。这组现实世界中的漏洞很好地提醒了我们，只关注一类漏洞或采用一套安全工具（例如静态代码分析）并不能保证部署系统的安全性。在本案例中，固件是用 C 语言开发的，但考虑到所发现漏洞的性质，这并不重要。在这种情况下，任何 “内存安全 ”固件都会受到攻击。  
  
SQL 和操作系统命令注入问题是编程错误，其余漏洞则是安全设计缺陷。确保所有运行阶段和所有组件的系统完整性至关重要。只有这样，才能保证语言及其编译器的下游安全属性。  
  
总之，必须考虑整个系统的安全性，并在所有运行模式下对完整的生产系统进行安全测试。  
  
来源：安全客、https://www.zerodayinitiative.com/blog/2024/11/7/multiple-vulnerabilities-in-the-mazda-in-vehicle-infotainment-ivi-system  
  
  
  END    
  
  
阅读推荐  
  
[【安全圈】Windows 10 将于明年 10 月停止支持 对你我有何影响](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065766&idx=1&sn=20737c81521c2b60c2ae6e68bd85cf08&chksm=f36e63a6c419eab0559b56523c0815b5e760666eb51eaa8a0579237fda5bd619c529c56f24fe&scene=21#wechat_redirect)  
  
  
  
[【安全圈】谷歌云将在2025年底强制实施多因素身份验证](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065766&idx=2&sn=60b2502195278b934474b1c4a7fc49bd&chksm=f36e63a6c419eab08fb88d51ccdbf0cb4bfe5081e8ccfe502ee69577918cb1ada38f8721c993&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客可以随意访问EA公司7亿用户账号](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065766&idx=3&sn=bcdf6497f31db93acd068fb24f76e293&chksm=f36e63a6c419eab04b707515e3ec637038e1f931dd74f1640728e7904bece00c01cfe82fde69&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Schneider Electric 在报告黑客索赔后调查安全“事件”](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652065766&idx=4&sn=792c2e0aa0defbba125b9aeffcfd1210&chksm=f36e63a6c419eab0a561defb5b66ec4b27a9cf4821a910f2d64455a2cb15fdd063a65f35cf94&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
