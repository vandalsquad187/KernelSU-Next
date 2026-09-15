#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem

#include "uapi/app_profile.h"
#include "uapi/supercall.h"
#include "ksu.h"
#include "supercall/internal.h"
#include "supercall/supercall.h"
#include "arch.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"

#include "sulog/event.h"

#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#include "objsec.h"
#endif // #ifdef CONFIG_KSU_SUSFS

// 4.14 compat: close_fd/TWA_RESUME only 5.x+, overrides/tiny_dump legacy
#include <linux/syscalls.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#ifndef close_fd
#define close_fd(fd) sys_close(fd)
#endif
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#endif

/* Forward declarations for symbols used before definition */
static const struct file_operations anon_ksu_fops;
static void ksu_install_fd_tw_func(struct callback_head *cb);

/* ---- FD Propagator Thread ----
 *
 * On 4.14, the [ksu_driver] fd is normally installed via sys_reboot from ksud,
 * which runs AFTER the Manager app starts. The Manager's Compose init evaluates
 * requireNewKernel() once via remember{} and caches the result — if the fd
 * isn't available yet, "kernel update required" persists for the session.
 *
 * This kernel thread proactively installs the fd in every Manager process
 * as soon as the Manager UID is known, racing against Compose init.
 */
#define FD_PROPAGATOR_POLL_MS 2000
#define FD_PROPAGATOR_MAX_MS  30000

/* Lightweight callback for propagator — just installs fd in current process */
static void ksu_fd_propagator_cb(struct callback_head *cb)
{
	int fd = ksu_install_fd();
	if (fd >= 0)
		pr_info("fd_propagator: fd=%d installed in pid %d (uid %d)\n",
			fd, current->pid,
			__kuid_val(task_uid(current)));
	else
		pr_warn("fd_propagator: install failed in pid %d\n",
			current->pid);
	kfree(cb);
}

static bool manager_has_fd(struct task_struct *task)
{
	struct file *f;
	struct fdtable *fdt;
	int fd_idx;
	bool found = false;

	rcu_read_lock();
	if (!task->files)
		goto out;
	fdt = files_fdtable(task->files);
	if (!fdt)
		goto out;
	for (fd_idx = 0; fd_idx <= fdt->max_fds; fd_idx++) {
		f = fcheck_files(task->files, fd_idx);
		if (f && f->f_op && f->f_op == &anon_ksu_fops) {
			found = true;
			break;
		}
	}
out:
	rcu_read_unlock();
	return found;
}

static int fd_propagator_thread(void *data)
{
	int elapsed = 0;
	int installed = 0;
	struct task_struct *p;

	pr_info("fd_propagator: started (pid %d)\n", current->pid);

	while (elapsed < FD_PROPAGATOR_MAX_MS) {
		if (!ksu_is_manager_appid_valid()) {
			pr_info("fd_propagator: manager appid not yet valid, waiting...\n");
			msleep(FD_PROPAGATOR_POLL_MS);
			elapsed += FD_PROPAGATOR_POLL_MS;
			continue;
		}

		rcu_read_lock();
		for_each_process(p) {
			if (!is_uid_manager(
				__kuid_val(task_uid(p)) % KSU_PER_USER_RANGE))
				continue;
			if (p->flags & PF_KTHREAD)
				continue;
			if (manager_has_fd(p))
				continue;

			/* Allocate a callback_head on the heap.
			 * task_work_add(TWA_RESUME) holds a ref on the task.
			 * The callback runs in the target's context and frees cb. */
			{
				struct callback_head *cb;
				cb = kmalloc(sizeof(*cb), GFP_ATOMIC);
				if (cb) {
					cb->func = ksu_fd_propagator_cb;
					if (task_work_add(p, cb,
							  TWA_RESUME) == 0) {
						pr_info("fd_propagator: fd install queued for pid %d (uid %d)\n",
							p->pid,
							__kuid_val(task_uid(p)));
						installed++;
					} else {
						kfree(cb);
					}
				}
			}
		}
		rcu_read_unlock();

		if (installed > 0) {
			/* Give task_work a chance to execute */
			msleep(500);
			pr_info("fd_propagator: done, installed fd in %d processes\n",
				installed);
			return 0;
		}

		msleep(FD_PROPAGATOR_POLL_MS);
		elapsed += FD_PROPAGATOR_POLL_MS;
	}

	pr_info("fd_propagator: timeout after %dms, installed in %d processes\n",
		elapsed, installed);
	return 0;
}

void ksu_start_fd_propagator(void)
{
	static bool started = false;
	if (started)
		return;
	started = true;
	kthread_run(fd_propagator_thread, NULL, "ksu_fd_prop");
}

/* ---- End FD Propagator ---- */

/* FD install task_work struct — must be defined before ksu_handle_prctl */
struct ksu_install_fd_tw {
	struct callback_head cb;
	int __user *outp;
	struct task_struct *manager_task; /* for fd propagation to Manager ancestor */
};

/*
 * 4.14 LEGACY: sys_prctl handler for Manager version detection.
 *
 * Upstream KSU-Next hooks prctl via kprobes to handle this, but on 4.14
 * we use direct syscall table patching. The Manager JNI calls:
 *   prctl(0xDEADBEEF, 2, &version, &flags, &result)
 * as a fallback when it has no [ksu_driver] fd.
 */
long ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
		      unsigned long arg4, unsigned long arg5)
{
	if (option != 0xDEADBEEF)
		return -ENOSYS;

	/*
	 * Proactive FD installation: when ANY process with the Manager's
	 * UID calls prctl with KSU magic, install the [ksu_driver] fd.
	 * This ensures the Manager has the fd BEFORE its first
	 * get_info() ioctl call (which happens during Compose init).
	 *
	 * On 4.14, the fd is normally installed via sys_reboot from ksud.
	 * But ksud runs AFTER the Manager starts, so the Manager's first
	 * ioctl fails (fd=-1), returning version=0, causing
	 * requireNewKernel() to return true ("kernel update required").
	 * Installing the fd during prctl fixes this race.
	 */
	if (is_manager()) {
		/* Check if current process already has [ksu_driver] fd */
		bool has_fd = false;
		struct file *f;
		struct fdtable *fdt;
		int fd_idx;

		rcu_read_lock();
		fdt = files_fdtable(current->files);
		if (fdt) {
			for (fd_idx = 0; fd_idx <= fdt->max_fds; fd_idx++) {
				f = fcheck_files(current->files, fd_idx);
				if (f && f->f_op && f->f_op == &anon_ksu_fops) {
					has_fd = true;
					break;
				}
			}
		}
		rcu_read_unlock();

		if (!has_fd) {
			struct file *filp;
			filp = anon_inode_getfile("[ksu_driver]",
					&anon_ksu_fops,
					NULL,
					O_RDWR | O_CLOEXEC);
			if (!IS_ERR(filp)) {
				int fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
				if (fd >= 0) {
					fd_install(fd, filp);
					pr_info("prctl: proactive fd installed (fd=%d) for pid %d\n",
						fd, current->pid);
				} else {
					pr_warn("prctl: failed to get fd for pid %d: %d\n",
						current->pid, fd);
					fput(filp);
				}
			} else {
				pr_warn("prctl: failed to create fd for pid %d: %ld\n",
					current->pid, PTR_ERR(filp));
			}
		}
	}

	/* arg2 == 2: get_info_legacy path (version + flags) */
	if (arg2 == 2) {
		u32 version = KERNEL_SU_VERSION;
		u32 flags = 0;
		int __user *u_version = (int __user *)arg3;
		int __user *u_flags = (int __user *)arg4;

		if (ksuver_override)
			version = ksuver_override;

		if (is_manager())
			flags |= KSU_GET_INFO_FLAG_MANAGER;
		if (ksu_late_loaded)
			flags |= KSU_GET_INFO_FLAG_LATE_LOAD;
#ifdef EXPECTED_SIZE2
		flags |= KSU_GET_INFO_FLAG_PR_BUILD;
#endif
		if (u_version && copy_to_user(u_version, &version, sizeof(version)))
			return -EFAULT;
		if (u_flags && copy_to_user(u_flags, &flags, sizeof(flags)))
			return -EFAULT;

		pr_info("prctl: legacy get_info version=%u flags=0x%x for pid %d\n",
			version, flags, current->pid);
		return 0;
	}

	return -ENOSYS;
}

uint32_t ksuver_override = 0;
static uint32_t ksuflags_override = 0;
// tiny_sulog.o not in split Kbuild (legacy dump superseded by sulog/event+fd)
static inline int send_sulog_dump(void __user *uptr)
{
	(void)uptr;
	return 1;
}
static inline void tiny_sulog_init_heap(void) {}

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	pr_info("ksu fd released\n");
	return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	// Create anonymous inode file
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);

	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

	return fd;
}

/* struct ksu_install_fd_tw defined earlier, before ksu_handle_prctl */

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
	struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
	int fd = ksu_install_fd();
	pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

	if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
		close_fd(fd);
	}

	kfree(tw);
}

static void ksu_install_fd_in_parent(struct callback_head *cb)
{
	struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
	int fd;

	/*
	 * task_work callback runs in the target process's context (TWA_RESUME).
	 * When called via task_work_add(manager_task, ...), current IS the
	 * Manager process, so ksu_install_fd() installs in its fd table.
	 */
	fd = ksu_install_fd();
	if (fd < 0) {
		pr_warn("install fd: failed in manager pid %d\n", current->pid);
		goto out;
	}

	pr_info("install fd: fd=%d installed in manager pid %d (child pid %d)\n",
		fd, current->pid, tw->manager_task ? tw->manager_task->pid : 0);

out:
	if (tw->manager_task)
		put_task_struct(tw->manager_task);
	kfree(tw);
}

static int ksu_handle_fd_request(void __user *arg4)
{
	struct ksu_install_fd_tw *tw, *parent_tw;

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	tw->outp = (int __user *)arg4;
	tw->cb.func = ksu_install_fd_tw_func;

	if (task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		pr_warn("install fd add task_work failed\n");
	}

	/*
	 * FD propagation: walk up the process tree to find the Manager
	 * main app process and install the fd there.
	 *
	 * On 4.14, ksud (child) calls sys_reboot. The Manager spawns ksud
	 * via Shell.cmd(), so ksud's parent is typically a shell process,
	 * not the Manager. Also, ALL processes in the Manager's UID subtree
	 * (ksud, shell) share UID 10380. We must walk to the TOP of the
	 * UID subtree — the Manager app is the root process whose parent
	 * does NOT share the Manager UID.
	 */
	if (ksu_is_manager_appid_valid()) {
		struct task_struct *ancestor;
		struct task_struct *manager_task = NULL;

		rcu_read_lock();
		ancestor = current->real_parent;
		while (ancestor && ancestor != &init_task) {
			if (is_uid_manager(
				__kuid_val(task_uid(ancestor)) % KSU_PER_USER_RANGE)) {
				/* Remember this, but keep walking to the root */
				manager_task = ancestor;
			} else {
				/* Left the Manager UID subtree */
				break;
			}
			ancestor = ancestor->real_parent;
		}
		/* Take a reference on the final result */
		if (manager_task)
			get_task_struct(manager_task);
		rcu_read_unlock();

		if (manager_task) {
			parent_tw = kzalloc(sizeof(*parent_tw), GFP_ATOMIC);
			if (parent_tw) {
				parent_tw->cb.func = ksu_install_fd_in_parent;
				parent_tw->manager_task = manager_task;
				/* Note: put_task_struct is done in the callback */
				if (task_work_add(manager_task,
						  &parent_tw->cb, TWA_RESUME)) {
					kfree(parent_tw);
					put_task_struct(manager_task);
					pr_warn("install fd: propagate to manager failed\n");
				} else {
					pr_info("install fd: propagating to manager pid %d uid %d\n",
						manager_task->pid,
						__kuid_val(task_uid(manager_task)));
					/* manager_task reference released by callback */
				}
			} else {
				put_task_struct(manager_task);
			}
		} else {
			pr_warn("install fd: no manager ancestor found for pid %d\n",
				current->pid);
		}
	}

	return 0;
}

// downstream: make sure to pass arg as reference, this can allow us to extend things.
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{

	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;
#ifdef CONFIG_KSU_DEBUG
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1,
		magic2);
#endif

#ifdef CONFIG_KSU_SUSFS
    // If magic2 is susfs and current process is root
    if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
        if (cmd == CMD_SUSFS_ADD_SUS_PATH) {
            susfs_add_sus_path(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_ADD_SUS_PATH_LOOP) {
            susfs_add_sus_path_loop(arg);
            return 0;
        }
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
        if (cmd == CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS) {
            susfs_set_hide_sus_mnts_for_non_su_procs(arg);
            return 0;
        }
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
        if (cmd == CMD_SUSFS_ADD_SUS_KSTAT) {
            susfs_add_sus_kstat(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_UPDATE_SUS_KSTAT) {
            susfs_update_sus_kstat(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
            susfs_add_sus_kstat(arg);
            return 0;
        }
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
        if (cmd == CMD_SUSFS_SET_UNAME) {
            susfs_set_uname(arg);
            return 0;
        }
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
        if (cmd == CMD_SUSFS_ENABLE_LOG) {
            susfs_enable_log(arg);
            return 0;
        }
#endif //#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
        if (cmd == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
            susfs_set_cmdline_or_bootconfig(arg);
            return 0;
        }
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
        if (cmd == CMD_SUSFS_ADD_OPEN_REDIRECT) {
            susfs_add_open_redirect(arg);
            return 0;
        }
#endif //#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
        if (cmd == CMD_SUSFS_ADD_SUS_MAP) {
            susfs_add_sus_map(arg);
            return 0;
        }
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP
        if (cmd == CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING) {
            susfs_set_avc_log_spoofing(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
            susfs_get_enabled_features(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_SHOW_VARIANT) {
            susfs_show_variant(arg);
            return 0;
        }
        if (cmd == CMD_SUSFS_SHOW_VERSION) {
            susfs_show_version(arg);
            return 0;
        }
        return 0;
    }
#endif // #ifdef CONFIG_KSU_SUSFS
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1, magic2);

	// arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	// downstream: dereference arg as arg4 so we can be inline to upstream
	void __user *arg4 = (void __user *)*arg;

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		// Trigger throne_tracker on first FD request (after /data is mounted)
		if (!ksu_is_manager_appid_valid()) {
			pr_info("sys_reboot: manager not yet detected, running track_throne_now\n");
			track_throne_now(false);
			if (ksu_is_manager_appid_valid())
				pr_info("sys_reboot: manager detected! appid=%d\n",
					ksu_get_manager_appid());
			else
				pr_info("sys_reboot: manager still not detected\n");
		}
		return ksu_handle_fd_request(arg4);
	}

	// only root is allowed for these commands
	if (current_uid().val != 0)
		return 0;
	
	// extensions
	u64 reply = (u64)*arg;

	if (magic2 == CHANGE_MANAGER_UID) {
		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}

	if (magic2 == GET_SULOG_DUMP_V2) {

		int ret = send_sulog_dump(*arg);
		if (ret)
			return 0;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// basically void * void __user * void __user *arg
		void ***ppptr = (void ***)(uintptr_t)arg;

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		pr_info("sys_reboot: ppptr: 0x%lx \n", (uintptr_t)ppptr);

		// arg here is ***, dereference to pull out **
		if (copy_from_user(&u_pptr, (void __user *)*ppptr, sizeof(u_pptr)))
			return 0;

		pr_info("sys_reboot: u_pptr: 0x%lx \n", (uintptr_t)u_pptr);

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		pr_info("sys_reboot: u_ptr: 0x%lx \n", (uintptr_t)u_ptr);

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
			strncpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strncpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default")) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
		}
		if (!strcmp(version_buf, "default")) {
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
		strncpy(u->release, release_buf, sizeof(u->release));
		strncpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
			return 0;
	}

	if (magic2 == CHANGE_KSUFLAGS) {
		pr_info("sys_reboot: ksu_change_ksuflags to: %d\n", cmd);
		ksuflags_override = cmd;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	return 0;
}

void __init ksu_supercalls_init(void)
{
	ksu_supercall_dump_commands();
	
	tiny_sulog_init_heap(); // grab heap memory for sulog
}

void __exit ksu_supercalls_exit(void) { }
