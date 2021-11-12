all: tee_vm_manager

tee_vm_manager:
	$(CC) -o tee_vm_manager src/main.c src/tee_vm_manager.c src/elf_loader.c -lelf -I ./include

clean:
	rm -f tee_vm_manager
