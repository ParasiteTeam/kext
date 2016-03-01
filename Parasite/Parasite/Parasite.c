//
//  Parasite.c
//  Parasite
//
//  Created by Timm Kandziora on 01.03.16.
//  Copyright © 2016 Timm Kandziora. All rights reserved.
//

#include <mach/mach_port.h>
#include <security/mac_framework.h>
#include <security/mac_policy.h>

static int Parasite_vnode_check_exec_t(kauth_cred_t cred, struct vnode *vp, struct label *label, struct label *execlabel, struct componentname *cnp, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen )
{
    return 0;
}

static struct mac_policy_ops Parasite_policy_ops =
{
    .mpo_vnode_check_exec = (void *)Parasite_vnode_check_exec_t,
};

static struct mac_policy_conf Parasite_policy_conf =
{
    .mpc_name            = "Parasite",
    .mpc_fullname        = "Parasite Kernel Extension",
    .mpc_labelnames      = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops             = &Parasite_policy_ops,
    .mpc_loadtime_flags  = 0,
    .mpc_field_off       = NULL,
    .mpc_runtime_flags   = 0
};

static mac_policy_handle_t Parasite_policy_handle_t;

kern_return_t Parasite_start(kmod_info_t * ki, void *d);
kern_return_t Parasite_stop(kmod_info_t *ki, void *d);

kern_return_t Parasite_start(kmod_info_t * ki, void *d)
{
    return mac_policy_register(&Parasite_policy_conf, &Parasite_policy_handle_t, d);
}

kern_return_t Parasite_stop(kmod_info_t *ki, void *d)
{
    return mac_policy_unregister(Parasite_policy_handle_t);
}
