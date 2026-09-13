#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT
#include <asm/ptrace.h>
#include <linux/version.h>
#include <linux/types.h>

extern bool ksu_su_compat_enabled;

void ksu_sucompat_init(void);
void ksu_sucompat_exit(void);

// Handler functions exported for hook_manager (4.19+ pt_regs ABI)
long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs);
long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs);
long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs);
long ksu_handle_execveat_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs);

// Legacy ABI handlers for < 4.19 syscall table hook path (individual args)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
int ksu_handle_execve(const char __user **filename_user, void *argv, void *envp);
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags);
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
#endif

#endif
