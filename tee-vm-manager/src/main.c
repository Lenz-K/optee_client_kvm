#include "tee_vm_manager.h"

int main(int argc, char **argv) {
    int ret = 0;
    start_vm("./bin/tee.elf");

    while (ret != 1)
        ret = run_vm();

    return 0;
}

