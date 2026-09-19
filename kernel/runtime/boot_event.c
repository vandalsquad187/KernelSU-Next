#include "feature/selinux_hide.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/workqueue.h>

#include "policy/allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "manager/manager_observer.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
#include "supercall/supercall.h"

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;

extern void ksu_avc_spoof_late_init(void);

/*
 * Heavy post-fs-data work that must NOT run inside the execve syscall hook.
 * On 4.14, zygote's execve calls on_post_fs_data() synchronously — if
 * track_throne_now() does heavy I/O (filp_open, search_manager), init's
 * execve blocks and the boot hangs at ~95%.
 *
 * Split into light (flags + quick inits) and heavy (I/O + process scan).
 * The heavy part runs in a workqueue thread.
 */
static void post_fs_data_heavy_work(struct work_struct *work)
{
    pr_info("on_post_fs_data: heavy work start\n");

    /* These do file I/O and process scanning — safe in workqueue context */
    ksu_load_allow_list();
    ksu_observer_init();
    ksu_stop_input_hook_runtime();
    ksu_selinux_hide_handle_post_fs_data();

    /* Early Manager UID detection + FD propagation.
     * At post-fs-data, /data is mounted and packages.list is available.
     * track_throne_now() identifies the Manager UID before the Manager
     * app starts (zygote hasn't forked it yet). */
    track_throne_now(false);
    if (ksu_is_manager_appid_valid())
        pr_info("on_post_fs_data: manager detected early, appid=%d\n",
                ksu_get_manager_appid());
    ksu_start_fd_propagator();

    pr_info("on_post_fs_data: heavy work done\n");
}

static DECLARE_WORK(post_fs_data_work, post_fs_data_heavy_work);

static bool post_fs_data_done = false;

void on_post_fs_data(void)
{
    if (post_fs_data_done) {
        pr_info("on_post_fs_data already done\n");
        return;
    }

    post_fs_data_done = true;
    pr_info("on_post_fs_data!\n");

    /*
     * Schedule heavy I/O work asynchronously so we never block the execve
     * syscall that triggers this.  dispatch.c (ksud supercall) also calls
     * this, but by then the work is already queued or finished.
     */
    schedule_work(&post_fs_data_work);
}

/*
 * Async entry point for the execve hook path.
 * Sets the done flag immediately to prevent re-entry, then schedules
 * the heavy work.  Returns instantly so zygote's execve is not blocked.
 */
void on_post_fs_data_async(void)
{
    if (post_fs_data_done) {
        pr_info("on_post_fs_data_async: already done\n");
        return;
    }

    post_fs_data_done = true;
    pr_info("on_post_fs_data (async from execve hook)!\n");

    schedule_work(&post_fs_data_work);
}

extern void ext4_unregister_sysfs(struct super_block *sb);

int nuke_ext4_sysfs(const char *mnt)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);

    if (err) {
        pr_err("nuke path err: %d\n", err);
        return err;
    }

    if (strcmp(path.dentry->d_inode->i_sb->s_type->name, "ext4") != 0) {
        pr_info("nuke but module aren't mounted\n");
        path_put(&path);
        return -EINVAL;
    }

    ext4_unregister_sysfs(path.dentry->d_inode->i_sb);
    path_put(&path);
    return 0;
}

void on_module_mounted(void)
{
    pr_info("on_module_mounted!\n");
    ksu_module_mounted = true;
}

void on_boot_completed(void)
{
	ksu_boot_completed = true;
	pr_info("on_boot_completed!\n");
	track_throne_now(false);
	track_throne(true);
	ksu_selinux_hide_drop_backup_if_unused();
	ksu_avc_spoof_late_init();

	/* Start FD propagator: install [ksu_driver] fd in Manager proactively.
	 * On 4.14, the fd normally comes from ksud sys_reboot which runs AFTER
	 * the Manager starts and evaluates requireNewKernel(). This thread
	 * races Compose init to install the fd before the first evaluation. */
	ksu_start_fd_propagator();
}
