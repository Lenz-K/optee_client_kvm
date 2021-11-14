all: tee_vm_manager
SRC_DIR := ../tee-supplicant/src

tee_vm_manager:
	$(CC) -o tee_vm_manager src/main.c $(SRC_DIR)/tee_vm_manager.c $(SRC_DIR)/elf_loader.c -I $(SRC_DIR)

clean:
	rm -f tee_vm_manager
