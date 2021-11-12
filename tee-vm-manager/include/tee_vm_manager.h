#ifndef OPTEE_CLIENT_KVM_TEE_VM_MANAGER_H
#define OPTEE_CLIENT_KVM_TEE_VM_MANAGER_H

/**
 *
 */
int start_vm(char *elf_name);

/**
 *
 */
int run_vm();

/**
 *
 */
void close_vm();

#endif //OPTEE_CLIENT_KVM_TEE_VM_MANAGER_H
