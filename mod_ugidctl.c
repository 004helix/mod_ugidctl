/*
 * Copyright 2013,2015 Raman Shishniou <rommer@ibuffed.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "unixd.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "mpm_common.h"
#include "apr_strings.h"

#if MODULE_MAGIC_NUMBER_MAJOR >= 20090209
#include "mod_unixd.h"
#endif

#if MODULE_MAGIC_NUMBER_MAJOR < 20081201
#define ap_unixd_config unixd_config
#endif

#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <alloca.h>

#include "ugidctl.h"

module AP_MODULE_DECLARE_DATA ugidctl_module;

struct ugidctl_identity {
	int	isinit;		/* uid, gid and groups are defined */

	int	cpulimit;	/* -1 - undefined, inherit default limit;
				 *  0 - defined, disable any limit;
				 * >0 - defined, set this one */

	int	pdeathsig;	/* -1 - undefined, inherit default signal;
				 *  0 - defined, don't send signal;
				 * >0 - defined, set this one */

	uid_t	uid;
	gid_t	gid;
	int	grcount;
	gid_t	*groups;
};

/* idle and default server identities */
static struct ugidctl_identity idle_identity;
static struct ugidctl_identity default_identity;

/* allowed uid list to be filled during config parse */
static unsigned uid_size;
static unsigned uid_index;
static uid_t *uid_list;

/* allowed gid list to be filled during config parse */
static unsigned gid_size;
static unsigned gid_index;
static gid_t *gid_list;

/* kernel module interface and access key */
static int ugidctl_fd;
static struct ugidctl_key_rq *ugidctl_key;

static void emergecy_oom(void)
{
	ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		     "Cannot allocate memory");
	exit(1);
}

static void emergecy_exit(const char *message)
{
	char errno_desc[128];
	char buffer[256];

	apr_strerror(errno, errno_desc, sizeof(errno_desc));
	apr_snprintf(buffer, sizeof(buffer), "(%d)%s: ugidctl: %s\n",
		     errno, errno_desc, message);
	if (write(STDERR_FILENO, buffer, strlen(buffer)));
	exit(1);
}

static int compare_uids(const void *a, const void *b)
{
	return *(uid_t *)a - *(uid_t *)b;
}

static int compare_gids(const void *a, const void *b)
{
	return *(gid_t *)a - *(gid_t *)b;
}

static void push_uid(uid_t uid)
{
	if (uid_index >= uid_size) {
		uid_size = uid_size ? uid_size << 1 : 1024;
		uid_list = realloc(uid_list, uid_size * sizeof(uid_t));
		if (!uid_list)
			emergecy_oom();
	}
	uid_list[uid_index++] = uid;
}

static void push_gid(uid_t gid)
{
	if (gid_index >= gid_size) {
		gid_size = gid_size ? gid_size << 1 : 1024;
		gid_list = realloc(gid_list, gid_size * sizeof(gid_t));
		if (!gid_list)
			emergecy_oom();
	}
	gid_list[gid_index++] = gid;
}

#define ugidctl_adduidlist(fd, req) \
	ugidctl_addlist(fd, UGIDCTLIO_ADDUIDLIST, req)

#define ugidctl_addgidlist(fd, req) \
	ugidctl_addlist(fd, UGIDCTLIO_ADDGIDLIST, req)

static int ugidctl_addlist(int fd, int cmd, struct ugidctl_add_rq *req)
{
	if (ioctl(fd, cmd, req)) {
		ap_log_error(APLOG_MARK, APLOG_STARTUP, errno, NULL,
			     "ugidctl: cannot set gid/uid list");
		return -1;
	}
	return 0;
}

static void exec_identity(struct ugidctl_identity *identity)
{
	struct ugidctl_setgroups_rq *setgroups_rq;
	struct ugidctl_setid_rq *setid_rq;

	/* set or reset CPU limit */
	if (identity->cpulimit >= 0) {
		struct rlimit rl;
		rlim_t limit;

		getrlimit(RLIMIT_CPU, &rl);

		if (identity->cpulimit > 0) {
			struct rusage ru;
			long used, usec;

			getrusage(RUSAGE_SELF, &ru);

			usec = ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;
			used = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec;
			if (usec >= 1000000) {
				usec -= 1000000;
				used++;
			}
			if (usec) {
				used++;
			}

			limit = used + identity->cpulimit;
		} else {
			limit = rl.rlim_max;
		}

		if (limit != rl.rlim_cur) {
			rl.rlim_cur = limit;
			setrlimit(RLIMIT_CPU, &rl);
		}
	}

	/* setgroups(), setgid(), setuid() */
	ap_assert(identity->isinit);

	setgroups_rq = alloca(sizeof(*setgroups_rq) +
			      identity->grcount * sizeof(gid_t));

	setgroups_rq->count = identity->grcount;
	memcpy(setgroups_rq->key, ugidctl_key, sizeof(*ugidctl_key));
	memcpy(setgroups_rq->list, identity->groups,
	       sizeof(gid_t) * identity->grcount);

	if (ioctl(ugidctl_fd, UGIDCTLIO_SETGROUPS, setgroups_rq))
		emergecy_exit("setgroups()");

	setid_rq = (struct ugidctl_setid_rq *) setgroups_rq;

	setid_rq->gid = identity->gid;
	if (ioctl(ugidctl_fd, UGIDCTLIO_SETGID, setid_rq))
		emergecy_exit("setgid()");

	setid_rq->uid = identity->uid;
	if (ioctl(ugidctl_fd, UGIDCTLIO_SETUID, setid_rq))
		emergecy_exit("setuid()");

	memset(setid_rq, 0, sizeof(*setid_rq));

	/* set or reset parent death signal */
	ap_assert(identity->pdeathsig >= 0);

	prctl(PR_SET_PDEATHSIG, identity->pdeathsig);
}

static void init_identity(apr_pool_t *p, struct ugidctl_identity *identity,
			  const char *username, gid_t gid)
{
	int i, size, index = 0;
	gid_t *groups, *tmp;
	struct group *g;

	identity->isinit = 1;
	identity->uid = ap_uname2id(username);
	identity->gid = gid;

	push_uid(identity->uid);

	setgrent();

	size = 2;
	tmp = malloc(size * sizeof(gid_t));
	if (!tmp)
		emergecy_oom();

	tmp[index++] = gid;

	while (index < NGROUPS_MAX && ((g = getgrent()) != NULL)) {
		char **names;

		if (g->gr_gid == gid)
			continue;

		if (index >= size) {
			size <<= 1;
			tmp = realloc(tmp, size * sizeof(gid_t));
			if (!tmp)
				emergecy_oom();
		}

		for (names = g->gr_mem; *names != NULL; ++names) {
			if (!strcmp(*names, username))
				tmp[index++] = g->gr_gid;
		}
	}

	endgrent();

	groups = apr_palloc(p, sizeof(gid_t) * index);
	if (!groups)
		emergecy_oom();

	for (i = 0; i < index; i++) {
		groups[i] = tmp[i];
		push_gid(tmp[i]);
	}

	free(tmp);

	identity->groups = groups;
	identity->grcount = index;
}

static apr_status_t ugidctl_close_fd(void *dummy)
{
	memset(ugidctl_key, 0, sizeof(*ugidctl_key));
	munlock(ugidctl_key, sizeof(*ugidctl_key));
	close(ugidctl_fd);
	return APR_SUCCESS;
}

static int ugidctl_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
			      apr_pool_t *ptemp)
{
	idle_identity.isinit = 0;
	idle_identity.cpulimit = 0;
	idle_identity.pdeathsig = SIGTERM;

	default_identity.isinit = 0;
	default_identity.cpulimit = 0;
	default_identity.pdeathsig = SIGKILL;

	uid_size = 0;
	uid_index = 0;
	uid_list = NULL;

	gid_size = 0;
	gid_index = 0;
	gid_list = NULL;

	return OK;
}

static int ugidctl_post_config(apr_pool_t *pconf, apr_pool_t *plog,
			       apr_pool_t *ptemp, server_rec *s)
{
	unsigned total_uids = 0;
	unsigned total_gids = 0;

	init_identity(pconf, &idle_identity,
		      ap_unixd_config.user_name,
		      ap_unixd_config.group_id);

	if (!default_identity.isinit)
		init_identity(pconf, &default_identity,
			      ap_unixd_config.user_name,
			      ap_unixd_config.group_id);

	/* ugidctl kernel module requires linux kernel version >= 2.6.32,
	 * so use O_CLOEXEC here makes sense
	 */
	ugidctl_fd = open("/dev/ugidctl", O_RDONLY | O_CLOEXEC);
	if (ugidctl_fd == -1) {
		ap_log_error(APLOG_MARK, APLOG_STARTUP, errno, NULL,
			     "ugidctl: cannot open /dev/ugidctl");
		return DONE;
	}

	ugidctl_key = apr_palloc(pconf, sizeof(*ugidctl_key));
	if (!ugidctl_key)
		emergecy_oom();

	if (mlock(ugidctl_key, sizeof(*ugidctl_key))) {
		ap_log_error(APLOG_MARK, APLOG_STARTUP, errno, NULL,
			     "ugidctl: cannot mlock()");
		return DONE;
	}

	/* init uid list */
	if (uid_index) {
		struct ugidctl_add_rq *req;
		unsigned i, uid_count = 0;
		uid_t uid = -1;

		req = alloca(sizeof(struct ugidctl_add_rq) +
			     1000 * sizeof(uid_t));

		qsort(uid_list, uid_index, sizeof(uid_t), compare_uids);

		for (i = 0; i < uid_index; i++) {
			if (uid != uid_list[i]) {
				uid = uid_list[i];
				req->uid_list[uid_count++] = uid;
			}
			if (uid_count == 1000) {
				uid_count = 0;
				req->count = 1000;
				total_uids += 1000;
				if (ugidctl_adduidlist(ugidctl_fd, req))
					return DONE;
			}
		}

		if (uid_count > 0) {
			req->count = (__u32) uid_count;
			total_uids += uid_count;
			if (ugidctl_adduidlist(ugidctl_fd, req))
				return DONE;
		}

		free(uid_list);

		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
			     "ugidctl: allowed %u uid(s)", total_uids);
	}

	/* init gid list */
	if (gid_index) {
		struct ugidctl_add_rq *req;
		unsigned i, gid_count = 0;
		gid_t gid = -1;

		req = alloca(sizeof(struct ugidctl_add_rq) +
			     1000 * sizeof(gid_t));

		qsort(gid_list, gid_index, sizeof(gid_t), compare_gids);

		for (i = 0; i < gid_index; i++) {
			if (gid != gid_list[i]) {
				gid = gid_list[i];
				req->gid_list[gid_count++] = gid;
			}
			if (gid_count == 1000) {
				gid_count = 0;
				req->count = 1000;
				total_gids += 1000;
				if (ugidctl_addgidlist(ugidctl_fd, req))
					return DONE;
			}
		}

		if (gid_count > 0) {
			req->count = (__u32) gid_count;
			total_gids += gid_count;
			if (ugidctl_addgidlist(ugidctl_fd, req))
				return DONE;
		}

		free(gid_list);

		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
			     "ugidctl: allowed %u gid(s)", total_gids);
	}

	/* set pid check type */
	if (ioctl(ugidctl_fd, UGIDCTLIO_SETPIDCHKTYPE, UGIDCTL_PIDTYPE_PGID)) {
		ap_log_error(APLOG_MARK, APLOG_STARTUP, errno, NULL,
			     "ugidctl: cannot set pid check type");
		return DONE;
	}

	/* get access key */
	if (ioctl(ugidctl_fd, UGIDCTLIO_GETKEY, ugidctl_key)) {
		ap_log_error(APLOG_MARK, APLOG_STARTUP, errno, NULL,
			     "ugidctl: cannot get access key");
		return DONE;
	}

	apr_pool_pre_cleanup_register(pconf, NULL, ugidctl_close_fd);

	return OK;
}

static struct ugidctl_identity *ugidctl_get_server_identity(server_rec *s)
{
	struct ugidctl_identity *identity;

	identity = ap_get_module_config(s->module_config, &ugidctl_module);

	if (!identity->isinit) {
		/* copy default identity */
		identity->isinit = 1;
		identity->uid = default_identity.uid;
		identity->gid = default_identity.gid;
		identity->groups = default_identity.groups;
		identity->grcount = default_identity.grcount;
	}

	if (identity->cpulimit == -1)
		/* copy default cpu limit */
		identity->cpulimit = default_identity.cpulimit;

	if (identity->pdeathsig == -1)
		/* copy default parent death signal */
		identity->pdeathsig = default_identity.pdeathsig;

	return identity;
}

static void *ugidctl_create_server_identity(apr_pool_t *p, server_rec *s)
{
	struct ugidctl_identity *identity;

	identity = apr_palloc(p, sizeof(struct ugidctl_identity));
	if (!identity)
		emergecy_oom();

	identity->isinit = 0;
	identity->cpulimit = -1;
	identity->pdeathsig = -1;

	return identity;
}

static const char *ugidctl_set_server_identity(cmd_parms *cmd, void *dummy,
					       const char *user,
					       const char *group)
{
	struct ugidctl_identity *identity;
	const char *err;

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
	if (err)
		return err;

	if (ap_check_cmd_context(cmd, NOT_IN_VIRTUALHOST) == NULL) {
		init_identity(cmd->server->process->pconf,
			      &default_identity, user,
			      ap_gname2id(group));
	} else {
		identity = ap_get_module_config(cmd->server->module_config,
						&ugidctl_module);
		init_identity(cmd->server->process->pconf,
			      identity, user,
			      ap_gname2id(group));
	}

	return NULL;
}

static const char *ugidctl_set_server_cpulimit(cmd_parms *cmd, void *dummy,
					       const char *str)
{
	struct ugidctl_identity *identity;
	const char *err;
	int limit;

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
	if (err)
		return err;

	limit = atoi(str);

	if (limit < 0) {
		ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
			     "detected ServerRequestLimitCPU set to "
			     "non-positive");
		ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
			     "Resetting ServerRequestLimitCPU to 0");
		limit = 0;
	}

	if (ap_check_cmd_context(cmd, NOT_IN_VIRTUALHOST) == NULL) {
		default_identity.cpulimit = limit;
	} else {
		identity = ap_get_module_config(cmd->server->module_config,
						&ugidctl_module);
		identity->cpulimit = limit;
	}

	return NULL;
}

static const char *ugidctl_set_server_pdeathsig(cmd_parms *cmd, void *dummy,
						const char *str)
{
	struct ugidctl_identity *identity;
	const char *err;
	int signal;

	err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
	if (err)
		return err;

	if (strspn(str, "1234567890") == strlen(str)) {
		signal = atoi(str);
	} else if (!strcasecmp("None", str) || !strcasecmp("Off", str)) {
		signal = 0;
	} else if (!strcasecmp("KILL", str) || !strcasecmp("SIGKILL", str)) {
		signal = SIGKILL;
	} else if (!strcasecmp("TERM", str) || !strcasecmp("SIGTERM", str)) {
		signal = SIGTERM;
	} else if (!strcasecmp("QUIT", str) || !strcasecmp("SIGQUIT", str)) {
		signal = SIGQUIT;
	} else if (!strcasecmp("INT", str) || !strcasecmp("SIGINT", str)) {
		signal = SIGINT;
	} else {
		return apr_psprintf(cmd->pool,
				    "Unknown signal name or number: %s", str);
	}

	if (ap_check_cmd_context(cmd, NOT_IN_VIRTUALHOST) == NULL) {
		default_identity.pdeathsig = signal;
	} else {
		identity = ap_get_module_config(cmd->server->module_config,
						&ugidctl_module);
		identity->pdeathsig = signal;
	}

	return NULL;
}

static void ugidctl_child_init(apr_pool_t *p, server_rec *s)
{
	exec_identity(&idle_identity);
}

static int ugidctl_quick_handler(request_rec *r, int lookup)
{
	struct ugidctl_identity *identity;

	if (!ap_is_initial_req(r))
		return DECLINED;

	identity = ugidctl_get_server_identity(r->server);

	exec_identity(identity);

	return DECLINED;
}

static int ugidctl_log_handler(request_rec *r)
{
	exec_identity(&idle_identity);

	return DECLINED;
}

static void ugidctl_register_hooks(apr_pool_t *p) {
	ap_hook_child_init(ugidctl_child_init, NULL, NULL, APR_HOOK_LAST);
	ap_hook_pre_config(ugidctl_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(ugidctl_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_quick_handler(ugidctl_quick_handler, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_log_transaction(ugidctl_log_handler, NULL, NULL, APR_HOOK_LAST);
}

static const command_rec ugidctl_cmds[] = {
	AP_INIT_TAKE2("ServerUserGroup", ugidctl_set_server_identity,
		      NULL, RSRC_CONF, "User and group for server"),
	AP_INIT_TAKE1("ServerRequestLimitCPU", ugidctl_set_server_cpulimit,
		      NULL, RSRC_CONF, "Maximum CPU time per request"),
	AP_INIT_TAKE1("ServerParentDeathSignal", ugidctl_set_server_pdeathsig,
		      NULL, RSRC_CONF, "Set the parent process death signal "
		      "for a child"),
	{ NULL },
};

module AP_MODULE_DECLARE_DATA ugidctl_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	ugidctl_create_server_identity,
	NULL,
	ugidctl_cmds,
	ugidctl_register_hooks,
};
