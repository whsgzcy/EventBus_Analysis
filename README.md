# First Of All

<!--![MacDown logo](https://avatars1.githubusercontent.com/u/7877933?s=400&u=64953636998411d1947b76d5e7af4c63fde924b5&v=4)-->

本库是为了分析EventBus的源码，为什么去分析，原因有以下几点：

1、有能力继续深入

2、所用即所得

3、自己的github需要点新的素材

## EventBus中的AndroidLogger & Android‘s’log

```
1.1代码 org.greenrobot.eventbus.android.AndroidLogger.java
static {
        boolean android = false;
        try {
            android = Class.forName("android.util.Log") != null;
        } catch (ClassNotFoundException e) {
            // OK
        }
        ANDROID_LOG_AVAILABLE = android;
    }
```
像这种写法我以后会用，好处是如果用getXXX去获取，每次都会运算一遍，造成不必要的内存开支,这样写会好一点

```
Class.forName("android.util.Log")
```
这让我想起了，ClassNotFoundException异常

Android log 的层级 以及 流行的框架 比较熟知的东西 可以点击这个
[here](https://www.baidu.com/).

###日志系统驱动程序Logger源代码分析

**pre:**

**Logger驱动程序的相关数据结构**

在Android系统中，提供了一个轻量级的日志系统，这个日志系统是以驱动程序的形式实现在内核空间的，而在用户空间分别提供了Java接口和C/C++接口来使用这个日志系统，取决于你编写的是Android应用程序还是系统组件。我们将更进一步对Android日志系统有一个深刻的认识

Logger驱动程序主要由两个文件构成，分别是：

       kernel/common/drivers/staging/android/logger.h

       kernel/common/drivers/staging/android/logger.c
       
logger.h

```
#ifndef _LINUX_LOGGER_H
#define _LINUX_LOGGER_H
 
#include <linux/types.h>
#include <linux/ioctl.h>
 
struct logger_entry {
	__u16		len;	/* length of the payload */
	__u16		__pad;	/* no matter what, we get 2 bytes of padding */
	__s32		pid;	/* generating process's pid */
	__s32		tid;	/* generating process's tid */
	__s32		sec;	/* seconds since Epoch */
	__s32		nsec;	/* nanoseconds */
	char		msg[0];	/* the entry's payload */
};
 
#define LOGGER_LOG_RADIO	"log_radio"	/* radio-related messages */
#define LOGGER_LOG_EVENTS	"log_events"	/* system/hardware events */
#define LOGGER_LOG_MAIN		"log_main"	/* everything else */
 
#define LOGGER_ENTRY_MAX_LEN		(4*1024)
#define LOGGER_ENTRY_MAX_PAYLOAD	\
	(LOGGER_ENTRY_MAX_LEN - sizeof(struct logger_entry))
 
#define __LOGGERIO	0xAE
 
#define LOGGER_GET_LOG_BUF_SIZE		_IO(__LOGGERIO, 1) /* size of log */
#define LOGGER_GET_LOG_LEN		_IO(__LOGGERIO, 2) /* used log len */
#define LOGGER_GET_NEXT_ENTRY_LEN	_IO(__LOGGERIO, 3) /* next entry len */
#define LOGGER_FLUSH_LOG		_IO(__LOGGERIO, 4) /* flush log */
 
#endif /* _LINUX_LOGGER_H */

```

<font color=red size=5>struct logger_entry是一个用于描述一条Log记录的结构体</font>。len成员变量记录了这条记录的有效负载的长度，有效负载指定的日志记录本身的长度，但是不包括用于描述这个记录的struct logger_entry结构体。我们调用android.util.Log接口来使用日志系统时，会指定日志的优先级别<font color=red size=5>Priority、Tag字符串以及Msg字符串，Priority + Tag + Msg</font>三者内容的长度加起来就是记录的有效负载长度了。__pad成员变量是用来对齐结构体的。pid和tid成员变量分别用来记录是哪条进程写入了这条记录。sec和nsec成员变量记录日志写的时间。msg成员变量记录的就有效负载的内容了，它的大小由len成员变量来确定。

       接着定义两个宏：

       #define LOGGER_ENTRY_MAX_LEN             (4*1024)

       #define LOGGER_ENTRY_MAX_PAYLOAD   \

                         (LOGGER_ENTRY_MAX_LEN - sizeof(struct logger_entry))
                         
      每条日志记录的有效负载长度加上结构体logger_entry的长度不能超过4K个字节。

      logger.h文件中还定义了其它宏，读者可以自己分析，在下面的分析中，碰到时，我们也会详细解释。
      

再来看logger.c文件中，其它相关数据结构的定义：

```
/*
 * struct logger_log - represents a specific log, such as 'main' or 'radio'
 *
 * This structure lives from module insertion until module removal, so it does
 * not need additional reference counting. The structure is protected by the
 * mutex 'mutex'.
 */
struct logger_log {
	unsigned char *		buffer;	/* the ring buffer itself */
	struct miscdevice	misc;	/* misc device representing the log */
	wait_queue_head_t	wq;	/* wait queue for readers */
	struct list_head	readers; /* this log's readers */
	struct mutex		mutex;	/* mutex protecting buffer */
	size_t			w_off;	/* current write head offset */
	size_t			head;	/* new readers start here */
	size_t			size;	/* size of the log */
};
 
/*
 * struct logger_reader - a logging device open for reading
 *
 * This object lives from open to release, so we don't need additional
 * reference counting. The structure is protected by log->mutex.
 */
struct logger_reader {
	struct logger_log *	log;	/* associated log */
	struct list_head	list;	/* entry in logger_log's list */
	size_t			r_off;	/* current read head offset */
};
 
/* logger_offset - returns index 'n' into the log via (optimized) modulus */
#define logger_offset(n)	((n) & (log->size - 1))
```

结构体struct logger_log就是真正用来保存日志的地方了。buffer成员变量变是用保存日志信息的内存缓冲区，它的大小由size成员变量确定。从misc成员变量可以看出，logger驱动程序使用的设备属于misc类型的设备，通过在Android模拟器上执行cat /proc/devices命令，可以看出，misc类型设备的主设备号是10。关于主设备号的相关知识，<font color=red size=5>wq成员变量是一个等待队列，用于保存正在等待读取日志的进程  ???这里着实不能理解 ，等待队列 怎么保护进程？？？需求是什么样的？</font>。readers成员变量用来保存当前正在读取日志的进程，正在读取日志的进程由结构体logger_reader来描述。mutex成员变量是一个互斥量，<font color=red size=5>用来保护log的并发访问</font>。可以看出，这里的日志系统的读写问题，其实是<font color=red size=5>一个生产者-消费者的问题，因此，需要互斥量来保护log的并发访问</font>。 w_off成员变量用来记录下一条日志应该从哪里开始写。head成员变量用来表示打开日志文件中，应该从哪一个位置开始读取日志。

       结构体struct logger_reader用来表示一个读取日志的进程，log成员变量指向要读取的日志缓冲区。list成员变量用来连接其它读者进程。r_off成员变量表示当前要读取的日志在缓冲区中的位置。
       
       struct logger_log结构体中用于保存日志信息的内存缓冲区buffer是一个循环使用的<font color=red size=5>环形缓冲区</font>，缓冲区中保存的内容是以struct logger_entry为单位的，每个单位的组成为：

       struct logger_entry | priority | tag | msg

       由于是内存缓冲区buffer是一个循环使用的环形缓冲区，给定一个偏移值，它在buffer中的位置由下logger_offset来确定：

       #define logger_offset(n)          ((n) & (log->size - 1))
       
       

**日志系统驱动程序Logger源代码分析**

logger.c

```
/*
 * Defines a log structure with name 'NAME' and a size of 'SIZE' bytes, which
 * must be a power of two, greater than LOGGER_ENTRY_MAX_LEN, and less than
 * LONG_MAX minus LOGGER_ENTRY_MAX_LEN.
 */
#define DEFINE_LOGGER_DEVICE(VAR, NAME, SIZE) \
static unsigned char _buf_ ## VAR[SIZE]; \
static struct logger_log VAR = { \
	.buffer = _buf_ ## VAR, \
	.misc = { \
		.minor = MISC_DYNAMIC_MINOR, \
		.name = NAME, \
		.fops = &logger_fops, \
		.parent = NULL, \
	}, \
	.wq = __WAIT_QUEUE_HEAD_INITIALIZER(VAR .wq), \
	.readers = LIST_HEAD_INIT(VAR .readers), \
	.mutex = __MUTEX_INITIALIZER(VAR .mutex), \
	.w_off = 0, \
	.head = 0, \
	.size = SIZE, \
};
DEFINE_LOGGER_DEVICE(log_main, LOGGER_LOG_MAIN, 64*1024)
DEFINE_LOGGER_DEVICE(log_events, LOGGER_LOG_EVENTS, 256*1024)
DEFINE_LOGGER_DEVICE(log_radio, LOGGER_LOG_RADIO, 64*1024)

```

分别是log_main、log_events和log_radio，名称分别LOGGER_LOG_MAIN、LOGGER_LOG_EVENTS和LOGGER_LOG_RADIO，它们的次设备号为MISC_DYNAMIC_MINOR，即为在注册时动态分配。在logger.h文件中，有这三个宏的定义：

_#define LOGGER_LOG_RADIO	"log_radio"

/* radio-related messages */

       
_#define LOGGER_LOG_EVENTS	"log_events"
       
/* system/hardware events */

       	
_#define LOGGER_LOG_MAIN	"log_main"

       
/* everything else */


注释说明了这三个日志设备的用途。注册的日志设备文件操作方法为logger_fops

```
static struct file_operations logger_fops = {
	.owner = THIS_MODULE,
	.read = logger_read,
	.aio_write = logger_aio_write,
	.poll = logger_poll,
	.unlocked_ioctl = logger_ioctl,
	.compat_ioctl = logger_ioctl,
	.open = logger_open,
	.release = logger_release,
};
```

日志驱动程序模块的初始化函数为logger_init：

```
static int __init logger_init(void)
{
	int ret;
 
	ret = init_log(&log_main);
	if (unlikely(ret))
		goto out;
 
	ret = init_log(&log_events);
	if (unlikely(ret))
		goto out;
 
	ret = init_log(&log_radio);
	if (unlikely(ret))
		goto out;
 
out:
	return ret;
}
device_initcall(logger_init);
```

logger_init函数通过调用init_log函数来初始化了上述提到的三个日志设备：

```
static int __init init_log(struct logger_log *log)
{
	int ret;
 
	ret = misc_register(&log->misc);
	if (unlikely(ret)) {
		printk(KERN_ERR "logger: failed to register misc "
		       "device for log '%s'!\n", log->misc.name);
		return ret;
	}
 
	printk(KERN_INFO "logger: created %luK log '%s'\n",
	       (unsigned long) log->size >> 10, log->misc.name);
 
	return 0;
}
```

init_log函数主要调用了misc_register函数来注册misc设备，misc_register函数定义在kernel/common/drivers/char/misc.c文件中：

```
/**
 *      misc_register   -       register a miscellaneous device
 *      @misc: device structure
 *
 *      Register a miscellaneous device with the kernel. If the minor
 *      number is set to %MISC_DYNAMIC_MINOR a minor number is assigned
 *      and placed in the minor field of the structure. For other cases
 *      the minor number requested is used.
 *
 *      The structure passed is linked into the kernel and may not be
 *      destroyed until it has been unregistered.
 *
 *      A zero is returned on success and a negative errno code for
 *      failure.
 */
 
int misc_register(struct miscdevice * misc)
{
        struct miscdevice *c;
        dev_t dev;
        int err = 0;
 
        INIT_LIST_HEAD(&misc->list);
 
        mutex_lock(&misc_mtx);
        list_for_each_entry(c, &misc_list, list) {
                if (c->minor == misc->minor) {
                        mutex_unlock(&misc_mtx);
                        return -EBUSY;
                }
        }
 
        if (misc->minor == MISC_DYNAMIC_MINOR) {
                int i = DYNAMIC_MINORS;
                while (--i >= 0)
                        if ( (misc_minors[i>>3] & (1 << (i&7))) == 0)
                                break;
                if (i<0) {
                        mutex_unlock(&misc_mtx);
                        return -EBUSY;
                }
                misc->minor = i;
        }
 
        if (misc->minor < DYNAMIC_MINORS)
                misc_minors[misc->minor >> 3] |= 1 << (misc->minor & 7);
        dev = MKDEV(MISC_MAJOR, misc->minor);
 
        misc->this_device = device_create(misc_class, misc->parent, dev, NULL,
                                          "%s", misc->name);
        if (IS_ERR(misc->this_device)) {
                err = PTR_ERR(misc->this_device);
                goto out;
        }
 
        /*
         * Add it to the front, so that later devices can "override"
         * earlier defaults
         */
        list_add(&misc->list, &misc_list);
 out:
        mutex_unlock(&misc_mtx);
        return err;
}
```

注册完成后，通过device_create创建设备文件节点。这里，将创建/dev/log/main、/dev/log/events和/dev/log/radio三个设备文件，这样，用户空间就可以通过读写这三个文件和驱动程序进行交互。

**Logger驱动程序的日志记录读取过程分析**

logger.c 文件，注册的读取日志设备文件的方法为logger_read：

```
/*
 * logger_read - our log's read() method
 *
 * Behavior:
 *
 * 	- O_NONBLOCK works
 * 	- If there are no log entries to read, blocks until log is written to
 * 	- Atomically reads exactly one log entry
 *
 * Optimal read size is LOGGER_ENTRY_MAX_LEN. Will set errno to EINVAL if read
 * buffer is insufficient to hold next entry.
 */
static ssize_t logger_read(struct file *file, char __user *buf,
			   size_t count, loff_t *pos)
{
	struct logger_reader *reader = file->private_data;
	struct logger_log *log = reader->log;
	ssize_t ret;
	DEFINE_WAIT(wait);
 
start:
	while (1) {
		prepare_to_wait(&log->wq, &wait, TASK_INTERRUPTIBLE);
 
		mutex_lock(&log->mutex);
		ret = (log->w_off == reader->r_off);
		mutex_unlock(&log->mutex);
		if (!ret)
			break;
 
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
 
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
 
		schedule();
	}
 
	finish_wait(&log->wq, &wait);
	if (ret)
		return ret;
 
	mutex_lock(&log->mutex);
 
	/* is there still something to read or did we race? */
	if (unlikely(log->w_off == reader->r_off)) {
		mutex_unlock(&log->mutex);
		goto start;
	}
 
	/* get the size of the next entry */
	ret = get_entry_len(log, reader->r_off);
	if (count < ret) {
		ret = -EINVAL;
		goto out;
	}
 
	/* get exactly one entry from the log */
	ret = do_read_log_to_user(log, reader, buf, ret);
 
out:
	mutex_unlock(&log->mutex);
 
	return ret;
}
```

注意，在函数开始的地方，表示读取日志上下文的struct logger_reader是保存在文件指针的private_data成员变量里面的，这是在打开设备文件时设置的，设备文件打开方法为logger_open：

```
/*
 * logger_open - the log's open() file operation
 *
 * Note how near a no-op this is in the write-only case. Keep it that way!
 */
static int logger_open(struct inode *inode, struct file *file)
{
	struct logger_log *log;
	int ret;
 
	ret = nonseekable_open(inode, file);
	if (ret)
		return ret;
 
	log = get_log_from_minor(MINOR(inode->i_rdev));
	if (!log)
		return -ENODEV;
 
	if (file->f_mode & FMODE_READ) {
		struct logger_reader *reader;
 
		reader = kmalloc(sizeof(struct logger_reader), GFP_KERNEL);
		if (!reader)
			return -ENOMEM;
 
		reader->log = log;
		INIT_LIST_HEAD(&reader->list);
 
		mutex_lock(&log->mutex);
		reader->r_off = log->head;
		list_add_tail(&reader->list, &log->readers);
		mutex_unlock(&log->mutex);
 
		file->private_data = reader;
	} else
		file->private_data = log;
 
	return 0;
}

```

新打开日志设备文件时，是从log->head位置开始读取日志的，保存在struct logger_reader的成员变量r_off中。
       start标号处的while循环是在等待日志可读，如果已经没有新的日志可读了，那么就要读进程就要进入休眠状态，等待新的日志写入后再唤醒，这是通过prepare_wait和schedule两个调用来实现的。如果没有新的日志可读，并且设备文件不是以非阻塞O_NONBLOCK的方式打开或者这时有信号要处理（signal_pending(current)），那么就直接返回，不再等待新的日志写入。判断当前是否有新的日志可读的方法是：

       ret = (log->w_off == reader->r_off);

即判断当前缓冲区的写入位置和当前读进程的读取位置是否相等，如果不相等，则说明有新的日志可读。

继续向下看，如果有新的日志可读，那么就，首先通过get_entry_len来获取下一条可读的日志记录的长度，从这里可以看出，日志读取进程是以日志记录为单位进行读取的，一次只读取一条记录。get_entry_len的函数实现如下：


```
static ssize_t do_read_log_to_user(struct logger_log *log,
				   struct logger_reader *reader,
				   char __user *buf,
				   size_t count)
{
	size_t len;
 
	/*
	 * We read from the log in two disjoint operations. First, we read from
	 * the current read head offset up to 'count' bytes or to the end of
	 * the log, whichever comes first.
	 */
	len = min(count, log->size - reader->r_off);
	if (copy_to_user(buf, log->buffer + reader->r_off, len))
		return -EFAULT;

	/*
	 * Second, we read any remaining bytes, starting back at the head of
	 * the log.
	 */
	if (count != len)
		if (copy_to_user(buf + len, log->buffer, count - len))
			return -EFAULT;
 
	reader->r_off = logger_offset(reader->r_off + count);
	return count;
}
```

**Logger驱动程序的日志记录写入过程分析**

logger.c 文件，注册的写入日志设备文件的方法为logger_aio_write：

```
/*
 * logger_aio_write - our write method, implementing support for write(),
 * writev(), and aio_write(). Writes are our fast path, and we try to optimize
 * them above all else.
 */
ssize_t logger_aio_write(struct kiocb *iocb, const struct iovec *iov,
			 unsigned long nr_segs, loff_t ppos)
{
	struct logger_log *log = file_get_log(iocb->ki_filp);
	size_t orig = log->w_off;
	struct logger_entry header;
	struct timespec now;
	ssize_t ret = 0;
 
	now = current_kernel_time();
 
	header.pid = current->tgid;
	header.tid = current->pid;
	header.sec = now.tv_sec;
	header.nsec = now.tv_nsec;
	header.len = min_t(size_t, iocb->ki_left, LOGGER_ENTRY_MAX_PAYLOAD);
 
	/* null writes succeed, return zero */
	if (unlikely(!header.len))
		return 0;
 
	mutex_lock(&log->mutex);
 
	/*
	 * Fix up any readers, pulling them forward to the first readable
	 * entry after (what will be) the new write offset. We do this now
	 * because if we partially fail, we can end up with clobbered log
	 * entries that encroach on readable buffer.
	 */
	fix_up_readers(log, sizeof(struct logger_entry) + header.len);
 
	do_write_log(log, &header, sizeof(struct logger_entry));
 
	while (nr_segs-- > 0) {
		size_t len;
		ssize_t nr;
 
		/* figure out how much of this vector we can keep */
		len = min_t(size_t, iov->iov_len, header.len - ret);
 
		/* write out this segment's payload */
		nr = do_write_log_from_user(log, iov->iov_base, len);
		if (unlikely(nr < 0)) {
			log->w_off = orig;
			mutex_unlock(&log->mutex);
			return nr;
		}
 
		iov++;
		ret += nr;
	}
 
	mutex_unlock(&log->mutex);
 
	/* wake up any blocked readers */
	wake_up_interruptible(&log->wq);
 
	return ret;
}

```

输入的参数iocb表示io上下文，iov表示要写入的内容，长度为nr_segs，表示有nr_segs个段的内容要写入。我们知道，每个要写入的日志的结构形式为：
        struct logger_entry | priority | tag | msg

        其中， priority、tag和msg这三个段的内容是由iov参数从用户空间传递下来的，分别对应iov里面的三个元素。而logger_entry是由内核空间来构造的：

        struct logger_entry header;
struct timespec now;

now = current_kernel_time();

header.pid = current->tgid;
header.tid = current->pid;
header.sec = now.tv_sec;
header.nsec = now.tv_nsec;
header.len = min_t(size_t, iocb->ki_left, LOGGER_ENTRY_MAX_PAYLOAD);

        然后调用do_write_log首先把logger_entry结构体写入到日志缓冲区中：

```
/*
 * do_write_log - writes 'len' bytes from 'buf' to 'log'
 *
 * The caller needs to hold log->mutex.
 */
static void do_write_log(struct logger_log *log, const void *buf, size_t count)
{
	size_t len;
 
	len = min(count, log->size - log->w_off);
	memcpy(log->buffer + log->w_off, buf, len);
 
	if (count != len)
		memcpy(log->buffer, buf + len, count - len);
 
	log->w_off = logger_offset(log->w_off + count);
 
}

```

由于logger_entry是内核堆栈空间分配的，直接用memcpy拷贝就可以了。
       接着，通过一个while循环把iov的内容写入到日志缓冲区中，也就是日志的优先级别priority、日志Tag和日志主体Msg：
 
 ```
 while (nr_segs-- > 0) {
		size_t len;
		ssize_t nr;
 
		/* figure out how much of this vector we can keep */
		len = min_t(size_t, iov->iov_len, header.len - ret);
 
		/* write out this segment's payload */
		nr = do_write_log_from_user(log, iov->iov_base, len);
		if (unlikely(nr < 0)) {
			log->w_off = orig;
			mutex_unlock(&log->mutex);
			return nr;
		}
 
		iov++;
		ret += nr;
}

 ```
 
 由于iov的内容是由用户空间传下来的，需要调用do_write_log_from_user来写入：
 
 ```
 static ssize_t do_write_log_from_user(struct logger_log *log,
				      const void __user *buf, size_t count)
{
	size_t len;
 
	len = min(count, log->size - log->w_off);
	if (len && copy_from_user(log->buffer + log->w_off, buf, len))
		return -EFAULT;
 
	if (count != len)
		if (copy_from_user(log->buffer, buf + len, count - len))
			return -EFAULT;
 
	log->w_off = logger_offset(log->w_off + count);
 
	return count;
}

 ```
 
 这里，我们还漏了一个重要的步骤：
 
 ```
  /*
  * Fix up any readers, pulling them forward to the first readable
  * entry after (what will be) the new write offset. We do this now
  * because if we partially fail, we can end up with clobbered log
  * entries that encroach on readable buffer.
  */
fix_up_readers(log, sizeof(struct logger_entry) + header.len);

 ```
 
 为什么要调用fix_up_reader这个函数呢？这个函数又是作什么用的呢？是这样的，由于日志缓冲区是循环使用的，即旧的日志记录如果没有及时读取，而缓冲区的内容又已经用完时，就需要覆盖旧的记录来容纳新的记录。而这部分将要被覆盖的内容，有可能是某些reader的下一次要读取的日志所在的位置，以及为新的reader准备的日志开始读取位置head所在的位置。因此，需要调整这些位置，使它们能够指向一个新的有效的位置。我们来看一下fix_up_reader函数的实现：
 
 ```
 /*
 * fix_up_readers - walk the list of all readers and "fix up" any who were
 * lapped by the writer; also do the same for the default "start head".
 * We do this by "pulling forward" the readers and start head to the first
 * entry after the new write head.
 *
 * The caller needs to hold log->mutex.
 */
static void fix_up_readers(struct logger_log *log, size_t len)
{
	size_t old = log->w_off;
	size_t new = logger_offset(old + len);
	struct logger_reader *reader;
 
	if (clock_interval(old, new, log->head))
		log->head = get_next_entry(log, log->head, len);
 
	list_for_each_entry(reader, &log->readers, list)
		if (clock_interval(old, new, reader->r_off))
			reader->r_off = get_next_entry(log, reader->r_off, len);
}

 ```
 
 判断log->head和所有读者reader的当前读偏移reader->r_off是否在被覆盖的区域内，如果是，就需要调用get_next_entry来取得下一个有效的记录的起始位置来调整当前位置：
 
 ```
 /*
 * get_next_entry - return the offset of the first valid entry at least 'len'
 * bytes after 'off'.
 *
 * Caller must hold log->mutex.
 */
static size_t get_next_entry(struct logger_log *log, size_t off, size_t len)
{
	size_t count = 0;
 
	do {
		size_t nr = get_entry_len(log, off);
		off = logger_offset(off + nr);
		count += nr;
	} while (count < len);
 
	return off;
}

 ```
 
 而判断log->head和所有读者reader的当前读偏移reader->r_off是否在被覆盖的区域内，是通过clock_interval函数来实现的：
 
 ```
 /*
 * clock_interval - is a < c < b in mod-space? Put another way, does the line
 * from a to b cross c?
 */
static inline int clock_interval(size_t a, size_t b, size_t c)
{
	if (b < a) {
		if (a < c || b >= c)
			return 1;
	} else {
		if (a < c && b >= c)
			return 1;
	}
 
	return 0;
}

 ```

最后，日志写入完毕，还需要唤醒正在等待新日志的reader进程:
        /* wake up any blocked readers */
wake_up_interruptible(&log->wq);

###Android应用程序框架层和系统运行库层日志系统源代码分析

**pre:**

**应用程序框架层日志系统Java接口的实现**

frameworks/base/core/java/android/util/Log.java

``` 
public final class Log {
  
	/**
	 * Priority constant for the println method; use Log.v.
         */
	public static final int VERBOSE = 2;
 
	/**
	 * Priority constant for the println method; use Log.d.
         */
	public static final int DEBUG = 3;
 
	/**
	 * Priority constant for the println method; use Log.i.
         */
	public static final int INFO = 4;
 
	/**
	 * Priority constant for the println method; use Log.w.
         */
	public static final int WARN = 5;
 
	/**
	 * Priority constant for the println method; use Log.e.
         */
	public static final int ERROR = 6;
 
	/**
	 * Priority constant for the println method.
         */
	public static final int ASSERT = 7;
  
	public static int v(String tag, String msg) {
		return println_native(LOG_ID_MAIN, VERBOSE, tag, msg);
	}
 
	public static int v(String tag, String msg, Throwable tr) {
		return println_native(LOG_ID_MAIN, VERBOSE, tag, msg + '\n' + getStackTraceString(tr));
	}
 
	public static int d(String tag, String msg) {
		return println_native(LOG_ID_MAIN, DEBUG, tag, msg);
	}
 
	public static int d(String tag, String msg, Throwable tr) {
		return println_native(LOG_ID_MAIN, DEBUG, tag, msg + '\n' + getStackTraceString(tr));
	}
 
	public static int i(String tag, String msg) {
		return println_native(LOG_ID_MAIN, INFO, tag, msg);
	}
 
	public static int i(String tag, String msg, Throwable tr) {
		return println_native(LOG_ID_MAIN, INFO, tag, msg + '\n' + getStackTraceString(tr));
	}
 
	public static int w(String tag, String msg) {
		return println_native(LOG_ID_MAIN, WARN, tag, msg);
	}
 
	public static int w(String tag, String msg, Throwable tr) {
		return println_native(LOG_ID_MAIN, WARN, tag, msg + '\n' + getStackTraceString(tr));
	}
 
	public static int w(String tag, Throwable tr) {
		return println_native(LOG_ID_MAIN, WARN, tag, getStackTraceString(tr));
	}
	
	public static int e(String tag, String msg) {
		return println_native(LOG_ID_MAIN, ERROR, tag, msg);
	}
 
	public static int e(String tag, String msg, Throwable tr) {
		return println_native(LOG_ID_MAIN, ERROR, tag, msg + '\n' + getStackTraceString(tr));
	}
 
	/** @hide */ public static native int LOG_ID_MAIN = 0;
	/** @hide */ public static native int LOG_ID_RADIO = 1;
	/** @hide */ public static native int LOG_ID_EVENTS = 2;
	/** @hide */ public static native int LOG_ID_SYSTEM = 3;
 
	/** @hide */ public static native int println_native(int bufID,
		int priority, String tag, String msg);
}
```
定义了2~7一共6个日志优先级别ID和4个日志缓冲区ID。在Logger驱动程序模块中，定义了<font color=red size=5>log_main、log_events、log_radio </font>分别对应三个设备文件<font color=red size=5>dev/log/main、/dev/log/events/dev/log/radio</font>。这里的4个日志缓冲区的前面3个ID就是对应这三个设备文件的文件描述符了，在下面的章节中，我们将看到这三个文件描述符是如何创建的。在下载下来的Android内核源代码中，第4个日志缓冲区LOG_ID_SYSTEM并没有对应的设备文件，在这种情况下，它和LOG_ID_MAIN对应同一个缓冲区ID，在下面的章节中，我们同样可以看到这两个ID是如何对应到同一个设备文件的。在整个Log接口中，最关键的地方声明了<font color=red size=5>println _ native</font>本地方法，所有的Log接口都是通过调用这个本地方法来实现Log的定入。下面我们就继续分析这个本地方法println_native。


**应用程序框架层日志系统JNI方法的实现**

在frameworks/base/core/jni/android_util_Log.cpp文件中，实现JNI方法println_native：

```
/* //device/libs/android_runtime/android_util_Log.cpp
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/
 
#define LOG_NAMESPACE "log.tag."
#define LOG_TAG "Log_println"
 
#include <assert.h>
#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/String8.h>
 
#include "jni.h"
#include "utils/misc.h"
#include "android_runtime/AndroidRuntime.h"
 
#define MIN(a,b) ((a<b)?a:b)
 
namespace android {
 
struct levels_t {
    jint verbose;
    jint debug;
    jint info;
    jint warn;
    jint error;
    jint assert;
};
static levels_t levels;
 
static int toLevel(const char* value) 
{
    switch (value[0]) {
        case 'V': return levels.verbose;
        case 'D': return levels.debug;
        case 'I': return levels.info;
        case 'W': return levels.warn;
        case 'E': return levels.error;
        case 'A': return levels.assert;
        case 'S': return -1; // SUPPRESS
    }
    return levels.info;
}
 
static jboolean android_util_Log_isLoggable(JNIEnv* env, jobject clazz, jstring tag, jint level)
{
#ifndef HAVE_ANDROID_OS
    return false;
#else /* HAVE_ANDROID_OS */
    int len;
    char key[PROPERTY_KEY_MAX];
    char buf[PROPERTY_VALUE_MAX];
 
    if (tag == NULL) {
        return false;
    }
    
    jboolean result = false;
    
    const char* chars = env->GetStringUTFChars(tag, NULL);
 
    if ((strlen(chars)+sizeof(LOG_NAMESPACE)) > PROPERTY_KEY_MAX) {
        jclass clazz = env->FindClass("java/lang/IllegalArgumentException");
        char buf2[200];
        snprintf(buf2, sizeof(buf2), "Log tag \"%s\" exceeds limit of %d characters\n",
                chars, PROPERTY_KEY_MAX - sizeof(LOG_NAMESPACE));
 
        // release the chars!
        env->ReleaseStringUTFChars(tag, chars);
 
        env->ThrowNew(clazz, buf2);
        return false;
    } else {
        strncpy(key, LOG_NAMESPACE, sizeof(LOG_NAMESPACE)-1);
        strcpy(key + sizeof(LOG_NAMESPACE) - 1, chars);
    }
    
    env->ReleaseStringUTFChars(tag, chars);
 
    len = property_get(key, buf, "");
    int logLevel = toLevel(buf);
    return (logLevel >= 0 && level >= logLevel) ? true : false;
#endif /* HAVE_ANDROID_OS */
}
 
/*
 * In class android.util.Log:
 *  public static native int println_native(int buffer, int priority, String tag, String msg)
 */
static jint android_util_Log_println_native(JNIEnv* env, jobject clazz,
        jint bufID, jint priority, jstring tagObj, jstring msgObj)
{
    const char* tag = NULL;
    const char* msg = NULL;
 
    if (msgObj == NULL) {
        jclass npeClazz;
 
        npeClazz = env->FindClass("java/lang/NullPointerException");
        assert(npeClazz != NULL);
 
        env->ThrowNew(npeClazz, "println needs a message");
        return -1;
    }
 
    if (bufID < 0 || bufID >= LOG_ID_MAX) {
        jclass npeClazz;
 
        npeClazz = env->FindClass("java/lang/NullPointerException");
        assert(npeClazz != NULL);
 
        env->ThrowNew(npeClazz, "bad bufID");
        return -1;
    }
 
    if (tagObj != NULL)
        tag = env->GetStringUTFChars(tagObj, NULL);
    msg = env->GetStringUTFChars(msgObj, NULL);
 
    int res = __android_log_buf_write(bufID, (android_LogPriority)priority, tag, msg);
 
    if (tag != NULL)
        env->ReleaseStringUTFChars(tagObj, tag);
    env->ReleaseStringUTFChars(msgObj, msg);
 
    return res;
}
 
/*
 * JNI registration.
 */
static JNINativeMethod gMethods[] = {
    /* name, signature, funcPtr */
    { "isLoggable",      "(Ljava/lang/String;I)Z", (void*) android_util_Log_isLoggable },
    { "println_native",  "(IILjava/lang/String;Ljava/lang/String;)I", (void*) android_util_Log_println_native },
};
 
int register_android_util_Log(JNIEnv* env)
{
    jclass clazz = env->FindClass("android/util/Log");
 
    if (clazz == NULL) {
        LOGE("Can't find android/util/Log");
        return -1;
    }
    
    levels.verbose = env->GetStaticIntField(clazz, env->GetStaticFieldID(clazz, "VERBOSE", "I"));
    levels.debug = env->GetStaticIntField(clazz, env->GetStaticFieldID(clazz, "DEBUG", "I"));
    levels.info = env->GetStaticIntField(clazz, env->GetStaticFieldID(clazz, "INFO", "I"));
    levels.warn = env->GetStaticIntField(clazz, env->GetStaticFieldID(clazz, "WARN", "I"));
    levels.error = env->GetStaticIntField(clazz, env->GetStaticFieldID(clazz, "ERROR", "I"));
    levels.assert = env->GetStaticIntField(clazz, env->GetStaticFieldID(clazz, "ASSERT", "I"));
                
    return AndroidRuntime::registerNativeMethods(env, "android/util/Log", gMethods, NELEM(gMethods));
}
 
}; // namespace android

```

 在gMethods变量中，定义了println_native本地方法对应的函数调用是android_util_Log_println_native。在android_util_Log_println_native函数中，通过了各项参数验证正确后，就调用运行时库函数__android_log_buf_write来实现Log的写入操作。__android_log_buf_write函实实现在liblog库中，它有4个参数，分别缓冲区ID、优先级别ID、Tag字符串和Msg字符串。下面运行时库liblog中的__android_log_buf_write的实现。
 

**系统运行库层日志系统的实现**

在系统运行库层liblog库的实现中，内容比较多，这里，我们只关注日志写入操作__android_log_buf_write的相关实现：

```
int __android_log_buf_write(int bufID, int prio, const char *tag, const char *msg)
{
    struct iovec vec[3];
 
    if (!tag)
        tag = "";
 
    /* XXX: This needs to go! */
    if (!strcmp(tag, "HTC_RIL") ||
        !strncmp(tag, "RIL", 3) || /* Any log tag with "RIL" as the prefix */
        !strcmp(tag, "AT") ||
        !strcmp(tag, "GSM") ||
        !strcmp(tag, "STK") ||
        !strcmp(tag, "CDMA") ||
        !strcmp(tag, "PHONE") ||
        !strcmp(tag, "SMS"))
            bufID = LOG_ID_RADIO;
 
    vec[0].iov_base   = (unsigned char *) &prio;
    vec[0].iov_len    = 1;
    vec[1].iov_base   = (void *) tag;
    vec[1].iov_len    = strlen(tag) + 1;
    vec[2].iov_base   = (void *) msg;
    vec[2].iov_len    = strlen(msg) + 1;
 
    return write_to_log(bufID, vec, 3);
}

```

函数首先是检查传进来的tag参数是否是为HTC_RIL、RIL、AT、GSM、STK、CDMA、PHONE和SMS中的一个，如果是，就无条件地使用ID为LOG_ID_RADIO的日志缓冲区作为写入缓冲区，接着，把传进来的参数prio、tag和msg分别存放在一个向量数组中，调用write_to_log函数来进入下一步操作。write_to_log是一个函数指针，定义在文件开始的位置上：

```
static int __write_to_log_init(log_id_t, struct iovec *vec, size_t nr);
static int (*write_to_log)(log_id_t, struct iovec *vec, size_t nr) = __write_to_log_init;

```

并且初始化为__write_to_log_init函数：

```
static int __write_to_log_init(log_id_t log_id, struct iovec *vec, size_t nr)
{
#ifdef HAVE_PTHREADS
    pthread_mutex_lock(&log_init_lock);
#endif
 
    if (write_to_log == __write_to_log_init) {
        log_fds[LOG_ID_MAIN] = log_open("/dev/"LOGGER_LOG_MAIN, O_WRONLY);
        log_fds[LOG_ID_RADIO] = log_open("/dev/"LOGGER_LOG_RADIO, O_WRONLY);
        log_fds[LOG_ID_EVENTS] = log_open("/dev/"LOGGER_LOG_EVENTS, O_WRONLY);
        log_fds[LOG_ID_SYSTEM] = log_open("/dev/"LOGGER_LOG_SYSTEM, O_WRONLY);
 
        write_to_log = __write_to_log_kernel;
 
        if (log_fds[LOG_ID_MAIN] < 0 || log_fds[LOG_ID_RADIO] < 0 ||
                log_fds[LOG_ID_EVENTS] < 0) {
            log_close(log_fds[LOG_ID_MAIN]);
            log_close(log_fds[LOG_ID_RADIO]);
            log_close(log_fds[LOG_ID_EVENTS]);
            log_fds[LOG_ID_MAIN] = -1;
            log_fds[LOG_ID_RADIO] = -1;
            log_fds[LOG_ID_EVENTS] = -1;
            write_to_log = __write_to_log_null;
        }
 
        if (log_fds[LOG_ID_SYSTEM] < 0) {
            log_fds[LOG_ID_SYSTEM] = log_fds[LOG_ID_MAIN];
        }
    }
 
#ifdef HAVE_PTHREADS
    pthread_mutex_unlock(&log_init_lock);
#endif
 
    return write_to_log(log_id, vec, nr);
}

```

这里我们可以看到，如果是第一次调write_to_log函数，write_to_log == __write_to_log_init判断语句就会true，于是执行log_open函数打开设备文件，并把文件描述符保存在log_fds数组中。如果打开/dev/LOGGER_LOG_SYSTEM文件失败，即log_fds[LOG_ID_SYSTEM] < 0，就把log_fds[LOG_ID_SYSTEM]设置为log_fds[LOG_ID_MAIN]，这就是我们上面描述的如果不存在ID为LOG_ID_SYSTEM的日志缓冲区，就把LOG_ID_SYSTEM设置为和LOG_ID_MAIN对应的日志缓冲区了。LOGGER_LOG_MAIN、LOGGER_LOG_RADIO、LOGGER_LOG_EVENTS和LOGGER_LOG_SYSTEM四个宏定义在system/core/include/cutils/logger.h文件中：

```
#define LOGGER_LOG_MAIN		"log/main"
#define LOGGER_LOG_RADIO	"log/radio"
#define LOGGER_LOG_EVENTS	"log/events"
#define LOGGER_LOG_SYSTEM	"log/system"

```

接着，把write_to_log函数指针指向__write_to_log_kernel函数：

```
static int __write_to_log_kernel(log_id_t log_id, struct iovec *vec, size_t nr)
{
    ssize_t ret;
    int log_fd;
 
    if (/*(int)log_id >= 0 &&*/ (int)log_id < (int)LOG_ID_MAX) {
        log_fd = log_fds[(int)log_id];
    } else {
        return EBADF;
    }
 
    do {
        ret = log_writev(log_fd, vec, nr);
    } while (ret < 0 && errno == EINTR);
 
    return ret;
}

```

函数调用log_writev来实现Log的写入，注意，这里通过一个循环来写入Log，直到写入成功为止。这里log_writev是一个宏，在文件开始的地方定义为

```
#if FAKE_LOG_DEVICE
// This will be defined when building for the host.
#define log_open(pathname, flags) fakeLogOpen(pathname, flags)
#define log_writev(filedes, vector, count) fakeLogWritev(filedes, vector, count)
#define log_close(filedes) fakeLogClose(filedes)
#else
#define log_open(pathname, flags) open(pathname, flags)
#define log_writev(filedes, vector, count) writev(filedes, vector, count)
#define log_close(filedes) close(filedes)
#endif

```

这些，整个调用过程就结束了。总结一下，首先是从应用程序层调用应用程序框架层的Java接口，应用程序框架层的Java接口通过调用本层的JNI方法进入到系统运行库层的C接口，系统运行库层的C接口通过设备文件来访问内核空间层的Logger驱动程序。这是一个典型的调用过程，很好地诠释Android的系统架构，希望读者好好领会。


************************************************************
1、java 层抛出的异常 在C层，都是对指针类型进行匹配 如果为null 则抛出NullPointerException 等

2、log_radio 特别是这个，adb 中有这样的命令，可以看到所有通信的log，比如微信，qq等

3、wq成员变量是一个等待队列，用于保存正在等待读取日志的进程  ???这里着实不能理解 ，等待队列 怎么保护进程？？？需求是什么样的？结构体的应用场景是什么样的？

4、对于log，java层只是调用，真正的实现确是在C


## EventBus 源码分析

从一开始的注释我们可以看出，这是一个单例，一个process-wide范围的单例，锁了一下

这句代码其实是连续复制了

instance = EventBus.defaultInstance = new EventBus();

```
/** Convenience singleton for apps using a process-wide EventBus instance. */
    public static EventBus getDefault() {
        EventBus instance = defaultInstance;
        if (instance == null) {
            synchronized (EventBus.class) {
                instance = EventBus.defaultInstance;
                if (instance == null) {
                    instance = EventBus.defaultInstance = new EventBus();
                }
            }
        }
        return instance;
    }
```
从使用的角度来说，在这里就是把event post出去，仔细分析一下，

```
 /** Posts the given event to the event bus. */
    public void post(Object event) {
        PostingThreadState postingState = currentPostingThreadState.get();
        List<Object> eventQueue = postingState.eventQueue;
        eventQueue.add(event);

        if (!postingState.isPosting) {
            postingState.isMainThread = isMainThread();
            postingState.isPosting = true;
            if (postingState.canceled) {
                throw new EventBusException("Internal error. Abort state was not reset");
            }
            try {
                while (!eventQueue.isEmpty()) {
                    postSingleEvent(eventQueue.remove(0), postingState);
                }
            } finally {
                postingState.isPosting = false;
                postingState.isMainThread = false;
            }
        }
    }
```
PostingThreadState postingState = currentPostingThreadState.get();

ThreadLocal：
java.lang.ThreadLocal<T> 类是Java提供的用来保存线程本地变量的机制。
说道线程本地变量很容易和和线程栈帧里的本地变量表联系起来。不过ThreadLocal的最普遍的用途是避免线程安全问题和框架代码实现模板模式。
说道线程安全又要温习一下多线程知识了。线程安全就是多线程访问下程序的不变约束、后验条件等不被破坏程序保持正确性，原子性、可见性、重排序等情况更靠近使用层，Java中引起并发问题的最基本的是共享可变变量。所以避免线程安全问题有几种思路

不共享
不可变
使用正确的同步
不同享的一种方式就是使用线程私有变量，例如方法中创建的对象只要没有泄露都在本线程栈的引用上，其他线程无法引用到，而一个线程的内执行是线程安全的。
ThreadLocal变量可以让每个线程都拥有自己私有的变量而不会互相访问到，从而实现线程安全。另外一些框架比如spring-jdbc，因为java.sql.Connection不是线程安全的，会将jdbc的Connection保存在ThreadLocal中，然后在框架层负责Connection的获取、使用、释放等操作，将底层的细节向用户屏蔽，当然这是基于Javaweb服务通常都是一链接一线程的前提下。另外一些服务跟踪代码也可以利用ThreadLocal获取调用信息，这样就能把分散的跟踪日志绑定到一起。

```
private final ThreadLocal<PostingThreadState> currentPostingThreadState = new ThreadLocal<PostingThreadState>() {
        @Override
        protected PostingThreadState initialValue() {
            return new PostingThreadState();
        }
    };
```

```
/** For ThreadLocal, much faster to set (and get multiple values). */
    final static class PostingThreadState {
        final List<Object> eventQueue = new ArrayList<>();
        boolean isPosting;
        boolean isMainThread;
        Subscription subscription;
        Object event;
        boolean canceled;
    }
```

这里的 isMainThread 是由 MainThreadSupport 负责，我也纳闷，这怎么判断是主线程还是子线程的？ 通过注释可以看出，通常android是android main线程

是不是Main线程：return looper == Looper.myLooper();看到这里，我的想法，这里的实现是不是又在kernel实现的？

从官网上看，就暂且理解为Thread.currentThread().getName()，Looper不为null都为Main Thread

Looper.myLooper()

Return the Looper object associated with the current thread. Returns null if the calling thread is not associated with a Looper.


```
/**
 * Interface to the "main" thread, which can be whatever you like. Typically on Android, Android's main thread is used.
 */
public interface MainThreadSupport {

    boolean isMainThread();

    Poster createPoster(EventBus eventBus);

    class AndroidHandlerMainThreadSupport implements MainThreadSupport {

        private final Looper looper;

        public AndroidHandlerMainThreadSupport(Looper looper) {
            this.looper = looper;
        }

        @Override
        public boolean isMainThread() {
            return looper == Looper.myLooper();
        }

        @Override
        public Poster createPoster(EventBus eventBus) {
            return new HandlerPoster(eventBus, looper, 10);
        }
    }

}
```



************************************************************
1、Java中引起并发问题的最基本的是共享可变变量。所以避免线程安全问题有几种思路，不共享，不可变，使用正确的同步，对于并发，从java层或业务层的描述，我认为描述到的本质，我认为这段话可以背下来，开发中天天都接触到的东西，可是用语言描述，就变得有失水准，要学会忽悠嘛

java.lang.ThreadLocal<T> 类是Java提供的用来保存线程本地变量的机制。
说道线程本地变量很容易和和线程栈帧里的本地变量表联系起来。不过ThreadLocal的最普遍的用途是避免线程安全问题和框架代码实现模板模式。
说道线程安全又要温习一下多线程知识了。线程安全就是多线程访问下程序的不变约束、后验条件等不被破坏程序保持正确性，原子性、可见性、重排序等情况更靠近使用层，Java中引起并发问题的最基本的是共享可变变量。所以避免线程安全问题有几种思路

不共享
不可变
使用正确的同步
不同享的一种方式就是使用线程私有变量，例如方法中创建的对象只要没有泄露都在本线程栈的引用上，其他线程无法引用到，而一个线程的内执行是线程安全的。
ThreadLocal变量可以让每个线程都拥有自己私有的变量而不会互相访问到，从而实现线程安全。另外一些框架比如spring-jdbc，因为java.sql.Connection不是线程安全的，会将jdbc的Connection保存在ThreadLocal中，然后在框架层负责Connection的获取、使用、释放等操作，将底层的细节向用户屏蔽，当然这是基于Javaweb服务通常都是一链接一线程的前提下。另外一些服务跟踪代码也可以利用ThreadLocal获取调用信息，这样就能把分散的跟踪日志绑定到一起。


参考资料：

https://www.cnblogs.com/dolphin0520/p/3799052.html

https://www.cnblogs.com/sunzn/p/3187868.html

https://blog.csdn.net/luoshengyang/article/details/6581828

https://blog.csdn.net/Luoshengyang/article/details/6598703

https://blog.csdn.net/luoshengyang/article/details/6595744

https://liuzhengyang.github.io/2017/11/02/thread-local/

https://developer.android.com/reference/android/os/Looper
