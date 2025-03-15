#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux Kernel Process Monitor");
MODULE_AUTHOR("Your Name");

// Data structure to store process information
struct process_info {
    pid_t pid;
    char name[TASK_COMM_LEN];
    int state;
    struct list_head list;
};

// List to store process information
static LIST_HEAD(process_list);
static DEFINE_SPINLOCK(process_list_lock);

// Kprobe for process creation
static struct kprobe create_probe = {
    .symbol_name = "sched_process_fork",
};

// Kprobe for process termination
static struct kprobe exit_probe = {
    .symbol_name = "do_exit",
};

// Function to add a process to the list
static void add_process(struct task_struct *task) {
    struct process_info *info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info) return;

    info->pid = task->pid;
    strncpy(info->name, task->comm, TASK_COMM_LEN);
    info->state = task->state;

    spin_lock(&process_list_lock);
    list_add_tail(&info->list, &process_list);
    spin_unlock(&process_list_lock);
}

// Function to remove a process from the list
static void remove_process(pid_t pid) {
    struct process_info *info, *tmp;
    spin_lock(&process_list_lock);
    list_for_each_entry_safe(info, tmp, &process_list, list) {
        if (info->pid == pid) {
            list_del(&info->list);
            kfree(info);
            break;
        }
    }
    spin_unlock(&process_list_lock);
}

// Kprobe handler for process creation
static int create_handler(struct kprobe *kp, struct pt_regs *regs) {
    struct task_struct *task = (struct task_struct *)regs->di;
    add_process(task);
    return 0;
}

// Kprobe handler for process termination
static int exit_handler(struct kprobe *kp, struct pt_regs *regs) {
    struct task_struct *task = current;
    remove_process(task->pid);
    return 0;
}

// Procfs read operation
static int proc_show(struct seq_file *m, void *v) {
    struct process_info *info;
    spin_lock(&process_list_lock);
    list_for_each_entry(info, &process_list, list) {
        seq_printf(m, "%d\t%s\t%d\n", info->pid, info->name, info->state);
    }
    spin_unlock(&process_list_lock);
    return 0;
}

// Procfs open operation
static int proc_open(struct inode *inode, struct file *file) {
    return single_open(file, proc_show, NULL);
}

static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .open = proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

// Module initialization
static int __init process_monitor_init(void) {
    register_kprobe(&create_probe);
    register_kprobe(&exit_probe);
    create_probe.pre_handler = create_handler;
    exit_probe.pre_handler = exit_handler;

    proc_create("process_monitor", 0, NULL, &proc_fops);
    printk(KERN_INFO "Process Monitor: Module loaded\n");
    return 0;
}

// Module cleanup
static void __exit process_monitor_exit(void) {
    unregister_kprobe(&create_probe);
    unregister_kprobe(&exit_probe);
    remove_proc_entry("process_monitor", NULL);
    printk(KERN_INFO "Process Monitor: Module unloaded\n");
}

module_init(process_monitor_init);
module_exit(process_monitor_exit);