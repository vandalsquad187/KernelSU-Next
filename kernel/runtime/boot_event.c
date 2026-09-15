#include "feature/selinux_hide.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/printk.h>

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

void on_post_fs_data(void)
{
    static bool done = false;

    if (done) {
        pr_info("on_post_fs_data already done\n");
        return;
    }

    done = true;
    pr_info("on_post_fs_data!\n");

    ksu_load_allow_list();
    ksu_observer_init();
    // Sanity check for safe mode only needs early-boot input samples.
    ksu_stop_input_hook_runtime();
    ksu_selinux_hide_handle_post_fs_data();

    /* Early Manager UID detection + FD propagation.
     * At post-fs-data, /data is mounted and packages.list is available.
     * By calling track_throne_now() here, we identify the Manager UID
     * before the Manager app starts (zygote hasn't forked it yet).
     * Then the propagator thread polls for Manager processes and installs
     * the [ksu_driver] fd via task_work(TWA_RESUME), which executes on
     * the Manager's first return to userspace — before any Java code runs.
     * This ensures the fd is available when Compose init calls getVersion(). */
    track_throne_now(false);
    if (ksu_is_manager_appid_valid())
        pr_info("on_post_fs_data: manager detected early, appid=%d\n",
                ksu_get_manager_appid());
    ksu_start_fd_propagator();
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
