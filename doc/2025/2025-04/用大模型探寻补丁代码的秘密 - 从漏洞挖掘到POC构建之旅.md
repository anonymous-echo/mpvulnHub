#  用大模型探寻补丁代码的秘密 - 从漏洞挖掘到POC构建之旅   
原创 做安全的小明同学  大山子雪人   2025-04-04 21:38  
  
引言  
  
补丁分析的挑战  
  
详细的漏洞利用步骤  
  
潜在利用方式  
  
具体攻击场景  
  
1. pm 命令的入口  
  
2. 关键调用链（以 pm install 为例）  
  
调用路径如下：  
  
3. 如何通过 pm 直接触发？  
  
方法 1：安装一个声明了 <original-package> 的 APK  
  
方法 2：手动修改 packages.xml 并触发 PMS 重载  
  
4. 验证调用  
  
总结  
  
实战案例分析总结  
  
引言  
  
在漏洞研究领域，通过分析补丁代码来发现和理解漏洞是一项重要且有趣的工作。本文将探讨如何利用大语言模型(LLM)来协助我们更高效地完成这一过程。  
  
补丁分析的挑战  
- 海量代码中定位关键修改点  
  
- 理解漏洞成因和影响范围  
  
- 构建有效的验证程序  
  
让我们一起探索如何借助AI的力量，化繁为简地完成这些任务。  
  
  
```
InstallPackageHelper: fiX the NPE problem.

 Install the renamed apk,use the new name to getPackageLPr may be null,so we should make a null judgment.Test: monkey testFlag: EXEMPT bugfixBug: 386727719Change-Id: Ia41a401bceaa13889ea66f5e3e337b99e3e4b799diff --git a/services/core/java/com/android/server/pm/InstallPackageHelper.java b/services/core/java/com/android/server/pm/InstallPackageHelper.javaindex f449126..d4efb5c 100644--- a/services/core/java/com/android/server/pm/InstallPackageHelper.java+++ b/services/core/java/com/android/server/pm/InstallPackageHelper.java@@ -1387,7 +1387,7 @@         boolean systemApp = false;         boolean replace = false;         synchronized (mPm.mLock) {-            final PackageSetting ps = mPm.mSettings.getPackageLPr(pkgName);+            PackageSetting ps = mPm.mSettings.getPackageLPr(pkgName);             // Check if installing already existing package             if ((installFlags & PackageManager.INSTALL_REPLACE_EXISTING) != 0) {                 String oldName = mPm.mSettings.getRenamedPackageLPr(pkgName);@@ -1398,14 +1398,15 @@                     // name.  We must continue using the original name, so                     // rename the new package here.                     parsedPackage.setPackageName(oldName);-                    pkgName = parsedPackage.getPackageName();-                    replace = true;+                    pkgName = oldName;+                    ps = mPm.mSettings.getPackageLPr(oldName);                     if (DEBUG_INSTALL) {                         Slog.d(TAG, "Replacing existing renamed package: oldName="                                 + oldName + " pkgName=" + pkgName);                     }-                } elseif (ps != null) {-                    // This package, under its official name, already exists+                }+                if (ps != null) {+                    // This package, under its official name or its old name, already exists                     // on the device; we should replace it.                     replace = true;                     if (DEBUG_INSTALL) Slog.d(TAG, "Replace existing package: " + pkgName);
```  
  
  
针对以上补丁代码，我们将这个分析任务交给大语言模型，获得了如下解读：  
  
💡  
  
这是漏洞。  
  
漏洞类型：逻辑漏洞/权限提升漏洞  
  
分析：  
  
这个patch修复了一个在包安装过程中的逻辑漏洞。原始代码在处理重命名的包时存在逻辑缺陷，可能导致权限提升问题。具体问题在于：  
1. 当安装一个已经存在的包时，如果这个包之前被重命名过，原始代码会：  
  
1. 设置新包的包名为旧名称  
  
1. 设置replace标志为true  
  
1. 但没有重新获取PackageSetting对象  
  
1. 这可能导致后续逻辑中使用了错误的PackageSetting对象，可能允许攻击者绕过某些安全检查或导致不一致的状态。  
  
修复方案：  
- 在重命名包后，重新获取PackageSetting对象(ps = mPm.mSettings.getPackageLPr(oldName))  
  
- 将replace标志的判断逻辑分开，确保在两种情况下都能正确设置replace标志  
  
潜在影响：  
  
攻击者可能利用这个漏洞通过精心构造的包安装请求来绕过某些安全检查，可能导致权限提升或包替换攻击。  
  
POC思路：  
1. 安装一个包A  
  
1. 重命名包A为包B  
  
1. 尝试再次安装包A，利用INSTALL_REPLACE_EXISTING标志  
  
1. 观察是否能够绕过某些安全检查或导致不一致的状态  
  
  
  
详细的漏洞利用步骤  
  
通过大模型的分析，现在几乎可以明确这是一个漏洞。但这个漏洞如何复现呢？  
  
我们将这个问题抛给大模型  
  
  
@deepseek:  这段代码是存在漏洞的，如果利用的话应该怎么利用呢  
  
💡  
  
潜在利用方式  
  
攻击者可能通过以下步骤利用此漏洞：  
1. 准备恶意包  
：创建一个与目标系统包同名的恶意APK  
  
1. 利用重命名机制  
：  
  
1. 先安装一个合法包A（包名com.example.app）  
  
1. 然后重命名该包（如改为com.example.app.old）  
  
1. 此时系统会保留原始包名映射关系  
  
1. 触发漏洞逻辑  
：  
  
1. 安装恶意包时使用原始包名（com.example.app）  
  
1. 由于修改后的代码会：  
  
1. 先恢复原始包名（  
pkgName = oldName  
）  
  
1. 重新获取PackageSetting（  
ps = mPm.mSettings.getPackageLPr(oldName)  
）  
  
1. 然后通过独立if检查  
ps != null  
设置replace标志  
  
1. 这样可能绕过某些安全检查  
  
1. 实现提权  
：  
  
1. 如果成功替换系统关键包，可能获得系统权限  
  
1. 或者替换用户已安装应用，实现中间人攻击  
  
  
  
💡  
  
具体攻击场景  
  
假设系统存在一个重命名的系统包：  
1. 原始包名：  
com.android.systemplugin  
  
1. 被重命名为：  
com.android.systemplugin.old  
  
攻击者可以：  
  
# 制作恶意APK使用原始包名  
  
adb install evil.apk # 包名为com.android.systemplugin  
  
利用漏洞可能导致：  
- 恶意包被当作系统包安装  
  
- 绕过签名验证（因为代码路径改变了验证顺序）  
  
- 获取系统级权限  
  
  
  
到目前为止，最关键的是如何触发一个包的rename。和package相关的操作离不开pm命令。  
  
  
❓  
  
@deepseek： 你作为资深的aosp开发者，在aosp的源代码中，分析一条代码调用路径，可通过`pm`命令触达函数`addRenamedPackageLPw`  
  
💡  
  
在 AOSP 的代码库中，  
addRenamedPackageLPw  
 是   
PackageManagerService  
 (PMS) 内部的一个方法，用于处理   
包名重命名  
 的逻辑（通常用于系统升级时兼容旧包名）。  
  
要通过   
pm  
 命令触发该函数，需要分析   
pm  
 命令的调用链  
 和   
PMS 的处理流程  
。以下是完整的代码调用路径分析：  
  
  
1.   
pm  
 命令的入口  
  
pm  
 是 Android 的 Package Manager Shell 命令，实现在：  
  
复制  
  
frameworks/base/cmds/pm/src/com/android/commands/pm/Pm.java  
- 用户执行的   
pm <command>  
 会调用   
Pm.run()  
，进而解析参数并调用   
Pm.onCommand()  
。  
  
2. 关键调用链（以   
pm install  
 为例）  
  
若要通过   
pm  
 间接触发   
addRenamedPackageLPw  
，需关注 PMS 中处理包名重命名的逻辑。典型场景是   
系统预装应用升级时的包名迁移  
（例如旧包名   
com.old.name  
 映射到新包名   
com.new.name  
）。  
  
调用路径如下  
：  
1. pm install  
 触发 PMS 安装流程  
Pm.run()  
 →   
Pm.runInstall()  
 → 通过   
Binder  
 调用   
IPackageManager.installPackageAsUser()  
。  
  
1. PMS 处理安装请求  
PackageManagerService.installPackageAsUser()  
 →   
installPackageTracedLI()  
 →   
installPackageLI()  
。  
  
1. 解析包名重命名规则  
在扫描 APK 时（  
scanPackageTracedLI  
 →   
scanPackageLI  
），PMS 会检查是否需要重命名：  
  
// PackageManagerService.java  
  
private PackageParser.Package scanPackageLI(...) throws PackageManagerException {  
  
// 检查是否存在需要重命名的包  
  
if (mSettings.getRenamedPackages().containsKey(realPackageName)) { String newName = mSettings.getRenamedPackages().get(realPackageName);  
  
// 调用 addRenamedPackageLPw 更新设置  
  
mSettings.addRenamedPackageLPw(realPackageName, newName); } }  
  
1. 最终调用   
addRenamedPackageLPw  
该方法在   
Settings.java  
 中实现，用于持久化包名映射关系：  
  
// frameworks/base/services/core/java/com/android/server/pm/Settings.java  
  
void addRenamedPackageLPw(String oldName, String newName) { mRenamedPackages.put(oldName, newName); writeLPr(); // 写入 packages.xml }  
  
3. 如何通过   
pm  
 直接触发？  
  
默认情况下，  
pm  
 命令   
没有直接暴露重命名包的接口  
，但可以通过以下方式间接触发：  
  
方法 1：安装一个声明了   
<original-package>  
 的 APK  
  
在 APK 的   
AndroidManifest.xml  
 中声明旧包名：  
  
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.new.name">  
  
<original-package android:name="com.old.name" />  
  
</manifest>  
  
运行 HTML  
- 当此 APK 安装时，PMS 会自动调用   
addRenamedPackageLPw  
 记录映射关系。  
  
方法 2：手动修改   
packages.xml  
 并触发 PMS 重载  
1. 修改   
/data/system/packages.xml  
，添加   
<renamed-package>  
 标签：  
<renamed-package new="com.new.name" old="com.old.name" />运行 HTML  
  
1. 通过   
pm  
 强制 PMS 重新读取配置：  
adb shell pm clear com.android.providers.settings  
  
4. 验证调用  
  
在 AOSP 调试时，可以在以下位置添加日志：  
1. Settings.addRenamedPackageLPw()  
添加   
Slog.d(TAG, "Renamed package: " + oldName + " -> " + newName);  
。  
  
1. PackageManagerService.scanPackageLI()  
检查   
mSettings.getRenamedPackages()  
 的调用时机。  
  
总结  
- 直接触发路径  
：  
pm install  
 →   
PMS.installPackageAsUser()  
 →   
scanPackageLI()  
 →   
Settings.addRenamedPackageLPw()  
。  
  
- 必要条件  
：  
需要存在预定义的包名映射（通过   
<original-package>  
 或   
packages.xml  
）。  
  
- 权限要求  
：  
此操作通常需要   
系统权限  
（如   
android.uid.system  
）或 root 访问。  
  
如果需要进一步分析特定场景（如 OTA 升级时的包名迁移），可以深入   
SystemConfig  
 或   
PackageManagerService  
 的启动流程。  
  
实战案例分析总结  
  
本文深入探讨了如何通过分析补丁代码来发现Android系统漏洞，并详细阐述了PackageManagerService中包名重命名机制的完整调用链。文章不仅展示了一个实际的漏洞案例，还系统地分析了如何利用pm命令触发关键函数，对安全研究人员和Android开发者都具有重要的参考价值。通过理解这些底层机制，我们能更好地发现和防范潜在的安全风险。这种由补丁分析到漏洞挖掘的研究方法，为Android系统安全研究提供了一个很好的实践范例。  
  
  
  
