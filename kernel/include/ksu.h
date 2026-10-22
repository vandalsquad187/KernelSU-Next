#ifndef __KSU_H_KSU
#define __KSU_H_KSU

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/workqueue.h>

#define KERNEL_SU_VERSION KSU_VERSION
#define KERNEL_SU_VERSION_TAG KSU_VERSION_TAG

extern struct cred *ksu_cred;
extern bool ksu_late_loaded;
/* crown diagnostics bits for the (no-dmesg) user-build case, read via prctl CMD 3 */
#define KSU_CROWN_DIAG_MATCH_SYSINIT (1U << 0)
#define KSU_CROWN_DIAG_MATCH_INIT (1U << 1)
#define KSU_CROWN_DIAG_ARGV_SECOND_STAGE (1U << 2)
#define KSU_CROWN_DIAG_RULES_APPLIED (1U << 3)
#define KSU_CROWN_DIAG_CRED_SETUP (1U << 4)
#define KSU_CROWN_DIAG_ZYGOTE_HIT (1U << 5)
#define KSU_CROWN_DIAG_ZYGOTE_FALLBACK (1U << 6)
#define KSU_CROWN_DIAG_UID_FOUND (1U << 7)
#define KSU_CROWN_DIAG_PKG_LIST_OK (1U << 8)
#define KSU_CROWN_DIAG_ESCAPE_RET0 (1U << 27)
#define KSU_CROWN_DIAG_ESCAPE_FAIL (1U << 26)
#define KSU_CROWN_DIAG_KSUD_EXEC (1U << 29)
#define KSU_CROWN_DIAG_KSUD_ESCAPE (1U << 28)
#define KSU_CROWN_DIAG_TAMPER_INIT (1U << 30)
extern uint32_t ksu_crown_diag;
extern int ksu_throne_diag_errno;
extern uint32_t ksu_patch_diag_ok;
extern uint32_t ksu_patch_diag_fail;
extern bool allow_shell;
#ifdef MODULE
extern bool ksu_bundled;
#endif
extern struct selinux_policy *backup_sepolicy;
extern bool ksu_no_custom_rc;

#ifdef CONFIG_ANDROID
#include <linux/security.h>
#define ksu_security_secctx_to_secid security_secctx_to_secid
#else
int ksu_security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid);
#endif

static inline int startswith(char *s, char *prefix)
{
	return strncmp(s, prefix, strlen(prefix));
}

static inline int endswith(const char *s, const char *t)
{
	size_t slen = strlen(s);
	size_t tlen = strlen(t);
	if (tlen > slen)
		return 1;
	return strcmp(s + slen - tlen, t);
}

#endif
