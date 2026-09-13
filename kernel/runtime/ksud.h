#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#include <asm/syscall.h>
#include <linux/types.h>
#include <linux/stat.h>

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init();
void ksu_ksud_exit();

void ksu_execve_hook_ksud(const struct pt_regs *regs);
void ksu_execveat_hook_ksud(const struct pt_regs *regs);
void ksu_stop_input_hook_runtime(void);

// shared with syscall_table_hook_arm64.c (split build)
extern bool ksu_vfs_read_hook;
void ksu_handle_sys_read_fd(unsigned int fd);
void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);

// shared with feature/selinux_hide.c (split build needs extern, unity TU shared static)
extern bool ksu_input_hook;

#endif
