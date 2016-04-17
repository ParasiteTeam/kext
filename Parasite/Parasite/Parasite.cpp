#include <IOKit/IOLib.h>

extern "C" {
    
#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/imgact.h>
#include <sys/proc.h>
#define CONFIG_MACF 1
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
    
#include "Parasite.hpp"
    
#include "config.h"
#include "kernel_symbols.h"
#include "library_injector.h"
    
struct kernel_info g_kinfo;
static boolean_t kernel_symbols_solved = FALSE;
static kauth_listener_t listener = NULL;
    
#define BLACKLIST(PROCESS) if (_strstr(path, #PROCESS)) return KAUTH_RESULT_DEFER;
    
char* _strstr(const char *in, const char *str)
{
    char c;
    size_t len;
    
    c = *str++;
    if (!c)
        return (char *) in;	// Trivial empty string case
    
    len = strlen(str);
    do {
        char sc;
        
        do {
            sc = *in++;
            if (!sc)
                return (char *) 0;
        } while (sc != c);
    } while (strncmp(in, str, len) != 0);
    
    return (char *) (in - 1);
}

static int infection_overwatch(kauth_cred_t credential, void *idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    if (action == KAUTH_FILEOP_EXEC) {
        char *path = (char *)arg1;
        
        BLACKLIST(Hopper);
        
        if (path != NULL) {
            printf("[Parasite] %s\n", path);
            
            vm_map_t task_map = _get_task_map(current_task());
            vm_map_offset_t base_address = _get_map_min(task_map);
            
            inject_library(task_map, base_address, path, sizeof(path));
        }
    }
    
    return KAUTH_RESULT_DEFER;
}
    
int parasite_cred_label_update_execve(kauth_cred_t old_cred, kauth_cred_t new_cred, struct proc *p, struct vnode *vp, off_t offset, struct vnode *scriptvp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, u_int *csflags, void *macpolicyattr, size_t macpolicyattrlen, int *disjointp)
{
    if (!kernel_symbols_solved) {
        if (init_kernel_info()) return 0;
        
        SOLVE_KERNEL_SYMBOL("_get_map_min", _get_map_min)
        SOLVE_KERNEL_SYMBOL("_get_task_map", _get_task_map)
        SOLVE_KERNEL_SYMBOL("_mach_vm_region", _mach_vm_region)
        SOLVE_KERNEL_SYMBOL("_mach_vm_protect", _mach_vm_protect)
        SOLVE_KERNEL_SYMBOL("_vm_map_read_user", _vm_map_read_user)
        SOLVE_KERNEL_SYMBOL("_vm_map_write_user", _vm_map_write_user)
        
        kernel_symbols_solved = TRUE;
    }
    
    return 0;
}

static mac_policy_handle_t handle = 0;

static struct mac_policy_ops ops =
{
    .mpo_cred_label_update_execve = parasite_cred_label_update_execve
};

static struct mac_policy_conf conf = {
    .mpc_name            = "parasite",
    .mpc_fullname        = "Parasite Kernel Extension",
    .mpc_ops             = &ops,
    .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK
};

kern_return_t Parasite_start(kmod_info_t * ki, void *d);
kern_return_t Parasite_stop(kmod_info_t *ki, void *d);

kern_return_t Parasite_start(kmod_info_t * ki, void *d)
{
    listener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, &infection_overwatch, NULL);
    
    if (listener == NULL) {
        printf("[Parasite] Damn, could not create listener.\n");
    } else {
        printf("[Parasite] Successfully created listener.\n");
    }
    
    return mac_policy_register(&conf, &handle, d);
}

kern_return_t Parasite_stop(kmod_info_t *ki, void *d)
{
    if (listener != NULL) {
        kauth_unlisten_scope(listener);
        listener = NULL;
    }
    
    return mac_policy_unregister(handle);
}
}
// This required macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires.
OSDefineMetaClassAndStructors(com_shinvou_driver_Parasite, IOService)

// Define the driver's superclass.
#define super IOService

bool com_shinvou_driver_Parasite::init(OSDictionary *dict)
{
    bool result = super::init(dict);
    return result;
}

void com_shinvou_driver_Parasite::free(void)
{
    super::free();
}

IOService *com_shinvou_driver_Parasite::probe(IOService *provider,
                                                SInt32 *score)
{
    IOService *result = super::probe(provider, score);
    return result;
}

bool com_shinvou_driver_Parasite::start(IOService *provider)
{
    bool result = super::start(provider);
    return result;
}

void com_shinvou_driver_Parasite::stop(IOService *provider)
{
    super::stop(provider);
}
