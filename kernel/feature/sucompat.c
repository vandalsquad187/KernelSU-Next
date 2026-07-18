#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
#define SUCOMPAT_HOOK_TYPE static __always_inline int
#else
#define SUCOMPAT_HOOK_TYPE int
#endif

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static bool ksu_su_compat_enabled __read_mostly = true;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}
#else
static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	if (!current->mm)
		return NULL;

	volatile unsigned long start_stack = current->mm->start_stack;
	unsigned int step = 32;
	
start_loop:
	;
	char __user *p = (void __user *)(start_stack - step - len);
	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("%s: start_stack: %lx p: %lx len: %zu\n", __func__, start_stack, (unsigned long)p, len );

	if (!copy_to_user(p, d, len))
		return p;

	step = step + step;

	if (step <= 2048)
		goto start_loop;

	return NULL;
}
#endif

static char __user *sh_user_path(void)
{
	static const char sh_path[] = "/system/bin/sh";

	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && defined(KSU_CAN_USE_JUMP_LABEL)
DEFINE_STATIC_KEY_TRUE(ksud_sucompat_key);
static inline void ksu_sucompat_enable_branch()
{
	pr_info("su_compat: enable sucompat branches\n");
	static_branch_enable(&ksud_sucompat_key);
	smp_mb();
}
static inline void ksu_sucompat_disable_branch()
{
	pr_info("su_compat: remove sucompat branches\n");
	static_branch_disable(&ksud_sucompat_key);
	smp_mb();
}
#else
static inline void ksu_sucompat_enable_branch() { } // no-op
static inline void ksu_sucompat_disable_branch() { } // no-op
#endif

static __always_inline bool is_su_allowed(const void **ptr_to_check)
{
#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
#ifdef KSU_CAN_USE_JUMP_LABEL
	// read as: if not 'likely' disabled
	if (!!!static_branch_likely(&ksud_sucompat_key))
		return false;
#else
	if (!ksu_su_compat_enabled)
		return false;
#endif // KSU_CAN_USE_JUMP_LABEL
#endif

	if (likely(test_thread_flag(TIF_SECCOMP)))
		return false;

	// see seccomp check above
	// so if its root but not ksu domain, deny, see __ksu_is_allow_uid_for_current
	// actually, we can likely skip this step?
	uid_t uid = current_uid().val;
	if (!!uid)
		goto uid_check;

	if (!is_ksu_domain())
		return false;
	goto check_ptr;

	// NOTE: shell has its seccomp disabled, so we only need to check for this thing
	// short-circuit if not shell! as we allow apps on setuid lsm by disabling seccomp
uid_check:
	if (likely(uid != 2000))
		goto check_ptr;

	// use internal function, not the macro
	if (!__ksu_is_allow_uid(uid))
		return false;

check_ptr:
	// first check the pointer-to-pointer
	if (unlikely(!ptr_to_check))
		return false;

	// now dereference pointer-to-pointer to check actual pointer
	if (unlikely(!*ptr_to_check))
		return false;

	return true;
}

static __always_inline void ksu_sucompat_user_common(const char __user **filename_user,
				const char *syscall_name,
				const bool escalate,
				const uint8_t sym)
{
	uintptr_t buf;
	const char su[16] = SU_PATH;

	// sugar prep
	uintptr_t *su_p = (uintptr_t *)su;
	uintptr_t __user *fn_p = (uintptr_t *)untagged_addr(*(char **)filename_user);

	// assert /system/bin/su\0 = 15 bytes.
	BUILD_BUG_ON(sizeof(SU_PATH) + 1 != 16);

	/*
	 * it seems this is actually the slowest part, so we peek last word first to speed it up
	 * NOTE: get_user rets EFAULT on err, so if we are copying a pointer
	 * that goes to nothing, we also detect that and ret fast
	 *
	 * first read overreads, reading 8 bytes, "bin/su\0?" /  4 bytes, "su\0?" when we only need 7/3
	 * but this is fine as we are guaranteed alignment, hardware provides trailing garbeg
	 * if it is specially crafted and hits a page guard, we just get EFAULT anyway
	 *
	 * on 64-bit we do this in 2 word compare, 4 on 32-bit, little endian only!
	 *
	 */

#ifdef CONFIG_64BIT
	if (get_user(buf, &fn_p[1]))
		return;

	if (likely((buf & 0x00FFFFFFFFFFFFFFUL) != (su_p[1] & 0x00FFFFFFFFFFFFFFUL)))
		return;

#else
	if (get_user(buf, &fn_p[3]))
		return;

	if (likely((buf & 0x00FFFFFFUL) != (su_p[3] & 0x00FFFFFFUL)))
		return;

	if (unlikely(get_user(buf, &fn_p[2])))
		return;

	if (buf != su_p[2])
		return;

	if (unlikely(get_user(buf, &fn_p[1])))
		return;

	if (unlikely(buf != su_p[1]))
		return;
#endif
	// last word
	if (unlikely(get_user(buf, &fn_p[0])))
		return;

	if (unlikely(buf != su_p[0]))
		return;

	write_sulog(sym);

	if (!escalate)
		goto no_escalate;

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, NULL, GFP_KERNEL);
#endif
	if (!!escape_with_root_profile())
		return;

	// NOTE: we only check file existence, not exec success!
	struct path kpath;
	if (!!kern_path("/data/adb/ksud", 0, &kpath))
		goto no_ksud;

	path_put(&kpath);
	pr_info("%s su->ksud!\n", syscall_name);
	*filename_user = ksud_user_path();
	return;

no_ksud:
no_escalate:
	pr_info("%s su->sh!\n", syscall_name);
	*filename_user = sh_user_path();
	return;

}

// sys_faccessat
SUCOMPAT_HOOK_TYPE ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "faccessat", false, 'a');
	return 0;
}

// sys_newfstatat, sys_fstat64
SUCOMPAT_HOOK_TYPE ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "newfstatat", false, 's');
	return 0;
}

// sys_execve, compat_sys_execve
SUCOMPAT_HOOK_TYPE ksu_handle_execve(const char __user **filename_user, void *argv, void *envp)
{

#ifdef CONFIG_KSU_FEATURE_ADBROOT
	ksu_adb_root_handle_execve((void *)filename_user, (void *)envp);
#endif

	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "sys_execve", true, 'x');
	return 0;
}

#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
static __always_inline void ksu_sucompat_kernel_common(void **restrict filename_ptr, void *restrict argv, void *restrict envp, const char *function_name)
{

#ifdef CONFIG_KSU_FEATURE_ADBROOT
	ksu_adb_root_handle_execveat((void *)filename_ptr, (void *)envp);
#endif

	if (!is_su_allowed((const void **)filename_ptr))
		return;

	// it seems this is actually the slowest part, we peek last word first to speed it up
	// sugar prep
	const char su[16] = SU_PATH;
	uintptr_t *su_p = (uintptr_t *)su;
	uintptr_t *fn_p = (uintptr_t *)*(char **)filename_ptr;

	// getname_flags pads this so nothing to worry about, dereference with confidence!
#ifdef CONFIG_64BIT
	if (likely((fn_p[1] & 0x00FFFFFFFFFFFFFFUL) != (su_p[1] & 0x00FFFFFFFFFFFFFFUL)))
		return;
#else
	if (likely((fn_p[3] & 0x00FFFFFFUL) != (su_p[3] & 0x00FFFFFFUL)))
		return;

	if (fn_p[2] != su_p[2])
		return;

	if (fn_p[1] != su_p[1])
		return;
#endif

	if (unlikely(fn_p[0] != su_p[0]))
		return;

	// we only handle execve here after removing vfs_statx hook for >= 6.1
	write_sulog('x');

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, NULL, GFP_KERNEL);
#endif
	if (!!escape_with_root_profile())
		return;

	// NOTE: we only check file existence, not exec success!
	struct path kpath;
	if (!!kern_path("/data/adb/ksud", 0, &kpath))
		goto no_ksud;

	path_put(&kpath);
	pr_info("%s su->ksud!\n", function_name);
	memcpy(*filename_ptr, KSUD_PATH, sizeof(KSUD_PATH));
	return;

no_ksud:
	pr_info("%s su->sh!\n", function_name);
	memcpy(*filename_ptr, SH_PATH, sizeof(SH_PATH));
	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
// take note: struct filename **filename, for do_execveat_common / do_execve_common on >= 3.14
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	struct filename *filename = *filename_ptr;
	if (IS_ERR(filename)) // see getname_flags
		return 0;

	ksu_sucompat_kernel_common((void **)&filename->name, argv, envp, "do_execveat_common");
	return 0;
}
#else
// take note: char **filename, for do_execve_common on < 3.14
int ksu_legacy_execve_sucompat(const char **filename_ptr, void *argv, void *envp)
{
	ksu_sucompat_kernel_common((void **)filename_ptr, argv, envp, "do_execve_common");
	return 0;
}
#endif
#endif // CONFIG_KSU_TAMPER_SYSCALL_TABLE

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
static void syscall_table_sucompat_enable();
static void syscall_table_sucompat_disable();
#else
static inline void syscall_table_sucompat_enable() { } // no-op
static inline void syscall_table_sucompat_disable() { } // no-op
#endif

static void ksu_sucompat_enable()
{

	ksu_sucompat_enable_branch();
	syscall_table_sucompat_enable();

	ksu_su_compat_enabled = true;
	pr_info("%s: hooks enabled: exec, faccessat, stat\n", __func__);
}

static void ksu_sucompat_disable()
{

	ksu_sucompat_disable_branch();
	syscall_table_sucompat_disable();

	ksu_su_compat_enabled = false;
	pr_info("%s: hooks disabled: exec, faccessat, stat\n", __func__);
}

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	// To avoid having to mmap a page in userspace, just write below the stack
	// pointer.
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static char __user *empty_user_path(void)
{
	return userspace_stack_buffer("", sizeof(""));
}

static const char su_path[] = SU_PATH;

static bool is_ksud_exists()
{
	struct path path;

	if (kern_path(KSUD_PATH, 0, &path) < 0) {
		return false;
	}
	path_put(&path);
	return true;
}

long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		goto do_orig_facessat;
	}

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	char path[sizeof(su_path) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		old_cred = override_creds(ksu_cred);
		if (is_ksud_exists()) {
			ksu_compat_sulog('a');
			pr_info("faccessat su->ksud!\n");
			orig_filename = *filename_user;
			*filename_user = ksud_user_path();
			ret = ksu_syscall_table[orig_nr](regs);
			revert_creds(old_cred);
			*filename_user = orig_filename;
			return ret;
		} else {
			revert_creds(old_cred);
		}
	}

do_orig_facessat:
	return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		goto do_orig_stat;
	}

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	char path[sizeof(su_path) + 1];
	memset(path, 0, sizeof(path));
	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		old_cred = override_creds(ksu_cred);
		if (is_ksud_exists()) {
			ksu_compat_sulog('s');
			pr_info("newfstatat su->ksud!\n");
			orig_filename = *filename_user;
			*filename_user = ksud_user_path();
			ret = ksu_syscall_table[orig_nr](regs);
			revert_creds(old_cred);
			*filename_user = orig_filename;
			return ret;
		} else {
			revert_creds(old_cred);
		}
	}

do_orig_stat:
	return ksu_syscall_table[orig_nr](regs);
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
	const char __user *fn;
	const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM2(regs);
	struct ksu_sulog_pending_event *pending_sucompat = NULL;
	char path[sizeof(su_path) + 1];
	long ret, orig_regs[5];
	unsigned long addr;
	int tmp_fd;
	struct file *ksud_file;
	const struct cred *old_cred;

	if (unlikely(!filename_user))
		goto do_orig_execve;

	if (!ksu_is_allow_uid_for_current(current_uid().val))
		goto do_orig_execve;

	addr = untagged_addr((unsigned long)*filename_user);
	fn = (const char __user *)addr;
	memset(path, 0, sizeof(path));
	ret = strncpy_from_user(path, fn, sizeof(path));

	if (ret < 0) {
		pr_warn("Access filename when execve failed: %ld", ret);
		goto do_orig_execve;
	}

	if (likely(memcmp(path, su_path, sizeof(su_path))))
		goto do_orig_execve;

	ksu_compat_sulog('x');
	pr_info("sys_execve su found\n");

	tmp_fd = get_unused_fd_flags(O_CLOEXEC);
	if (tmp_fd < 0) {
		pr_err("alloc tmp fd err: %d\n", tmp_fd);
		goto do_orig_execve;
	}

	old_cred = override_creds(ksu_cred);
	ksud_file = filp_open(KSUD_PATH, O_PATH, 0);
	revert_creds(old_cred);
	if (IS_ERR(ksud_file)) {
		pr_err("open ksud err: %ld\n", PTR_ERR(ksud_file));
		put_unused_fd(tmp_fd);
		goto do_orig_execve;
	}

	fd_install(tmp_fd, ksud_file);

	pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
	// execve(file, argv, environ)
	// execveat(fd, file, argv, environ, flags)
	orig_regs[0] = regs->__PT_PARM1_REG;
	orig_regs[1] = regs->__PT_PARM2_REG;
	orig_regs[2] = regs->__PT_PARM3_REG;
	orig_regs[3] = regs->__PT_SYSCALL_PARM4_REG;
	orig_regs[4] = regs->__PT_PARM5_REG;
	regs->__PT_PARM5_REG = AT_EMPTY_PATH;
	regs->__PT_SYSCALL_PARM4_REG = regs->__PT_PARM3_REG;
	regs->__PT_PARM3_REG = regs->__PT_PARM2_REG;
	regs->__PT_PARM2_REG = empty_user_path();
	regs->__PT_PARM1_REG = tmp_fd;

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile failed: %ld\n", ret);
	}
	ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);

	ret = ksu_syscall_table[__NR_execveat](regs);
	if (ret < 0) {
		ksu_close_fd(tmp_fd);
		regs->__PT_PARM1_REG = orig_regs[0];
		regs->__PT_PARM2_REG = orig_regs[1];
		regs->__PT_PARM3_REG = orig_regs[2];
		regs->__PT_SYSCALL_PARM4_REG = orig_regs[3];
		regs->__PT_PARM5_REG = orig_regs[4];
	}
	return ret;

do_orig_execve:
	return ksu_syscall_table[orig_nr](regs);
}

// sucompat: permitted process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void __exit ksu_sucompat_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
