/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/cdev.h>
#include <linux/fs.h>  // file_operations
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "aesd_ioctl.h"
#include "aesdchar.h"

int aesd_major = 0;  // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("ED automation"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode* inode, struct file* filp)
{
    struct aesd_dev* dev = NULL;

    PDEBUG("open");
    /**
     * TODO: handle open
     */

    // Our device is global and persistent -> no need to do any particular device handling.
    // Only store a pointer to our device in the file structure for ease of access

    // NOTE: struct file represents a file descriptor, whereas struct inode represents the file
    // itself => there can be multiple struct file representing multiple open descriptors
    // on a single file, but they all point to the same inode structure.
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;  // store a pointer to our global device
    mutex_init(&dev->lock);

    return 0;
}

int aesd_release(struct inode* inode, struct file* filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */

    // Nothing to do here
    return 0;
}

ssize_t aesd_read(struct file* filp, char __user* buf, size_t count,
                  loff_t* f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev* dev = NULL;
    struct aesd_circular_buffer* circ_buffer = NULL;
    struct aesd_buffer_entry* entry = NULL;
    size_t offset_in_entry = 0;
    /**
     * TODO: handle read
     */

    // Get pointer to our circular buffer
    dev = filp->private_data;
    circ_buffer = &dev->circ_buffer;

    if (mutex_lock_interruptible(&dev->lock))
    {
        return -ERESTARTSYS;
    }

    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    // Read from circular buffer
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(circ_buffer, *f_pos, &offset_in_entry);
    if (NULL != entry)
    {
        size_t available_len = (entry->size - offset_in_entry);
        size_t read_len = 0;
        if (available_len <= count)
        {
            read_len = available_len;
        }
        else
        {
            read_len = count;  // read less than the available length
        }

        if (read_len > 0)
        {
            int res = copy_to_user(buf, &entry->buffptr[offset_in_entry], read_len);
            if (res)
            {
                PDEBUG("Could not copy memory to user space!");
                retval = -EFAULT;
            }
            else
            {
                PDEBUG("Writing %lu bytes to user space, new position is %llu", read_len, *f_pos + read_len);
                retval = read_len;           // # of bytes actually read
                *f_pos = *f_pos + read_len;  // update the position in the "file"
            }
        }
        else
        {
            retval = 0;  // Finished reading
            *f_pos = 0;  // Reset position to beginning of file
        }
    }

    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file* filp, const char __user* buf, size_t count,
                   loff_t* f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev* dev;
    struct aesd_circular_buffer* circ_buffer;
    char* kbuffer = NULL;

    /**
     * TODO: handle write
     */

    // Get circular buffer
    dev = filp->private_data;
    circ_buffer = &dev->circ_buffer;
    if (mutex_lock_interruptible(&dev->lock))
    {
        return -ERESTARTSYS;
    }

    if (0 == count)
    {
        return 0;
    }

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    // Allocate memory for new entry
    kbuffer = kmalloc(count, GFP_KERNEL);
    if (NULL == kbuffer)
    {
        PDEBUG("Cannot allocate memory!");
        goto out;
    }

    // We will manipulate memory in the kernel space
    if (copy_from_user(kbuffer, buf, count))
    {
        PDEBUG("Could not copy from user space!");
        kfree(kbuffer);
        retval = -EFAULT;
        goto out;
    }

    // Is there already data temporarily stored?
    if (NULL == dev->tmp_entry.buffptr)
    {
        // NO -> store it
        PDEBUG("New tmp entry");
        dev->tmp_entry.size = count;
        dev->tmp_entry.buffptr = kbuffer;
    }
    else
    {
        // YES -> append data to tmp entry
        char* new_buff = krealloc(dev->tmp_entry.buffptr, dev->tmp_entry.size + count, GFP_KERNEL);
        if (NULL == new_buff)
        {
            retval = -ENOMEM;
            kfree(kbuffer);
            goto out;
        }
        else
        {
            size_t i = 0;
            PDEBUG("Appending data to tmp entry");
            for (i = 0; i < count; i++)
            {
                dev->tmp_entry.buffptr[dev->tmp_entry.size + i] = kbuffer[i];
            }
            dev->tmp_entry.size += count;
            kfree(kbuffer);
        }
    }

    // Copy to circular buffer if last received char is a new line
    if (dev->tmp_entry.buffptr[dev->tmp_entry.size - 1] == '\n')
    {
        char* entry_to_free = NULL;
        PDEBUG("New line-> write to buffer");
        entry_to_free = aesd_circular_buffer_add_entry(circ_buffer, &dev->tmp_entry);
        if (entry_to_free)
        {
            PDEBUG("Freeing memory for kicked out entry.");
            kfree(entry_to_free);
        }
        dev->tmp_entry.buffptr = NULL;  // Reset for next entry
        // Memory will be freed when circular buffer is cleaned up
    }

    retval = count;

out:
    mutex_unlock(&dev->lock);
    return retval;
}

loff_t aesd_seek(struct file* filp, loff_t offset, int whence)
{
    loff_t retval = 0;
    struct aesd_dev* dev = filp->private_data;
    struct aesd_circular_buffer* circ_buffer = &dev->circ_buffer;
    size_t buffer_size = 0;
    uint8_t i = 0;

    if (mutex_lock_interruptible(&dev->lock))
    {
        return -ERESTARTSYS;
    }

    PDEBUG("seek offset %lld, whence %d", offset, whence);

    for (; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        buffer_size += circ_buffer->entry[i].size;
    }

    switch (whence)
    {
        case SEEK_SET:
            retval = offset;
            break;
        case SEEK_CUR:
            retval = filp->f_pos + offset;
            break;
        case SEEK_END:
            retval = buffer_size + offset;
            break;
        default:
            retval = -EINVAL;
            goto out;
    }

    if ((retval >= buffer_size) || (retval < 0))
    {
        retval = -EINVAL;
    }
    else
    {
        filp->f_pos = retval;
    }

out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_ioctl(struct file* filp, unsigned int cmd, unsigned long arg)
{
    uint8_t i = 0;
    uint32_t start_offset = 0;
    uint32_t buffer_size = 0;
    struct aesd_seekto seekto;
    struct aesd_dev* dev = filp->private_data;
    struct aesd_circular_buffer* circ_buffer = &dev->circ_buffer;

    // Check if command is supported
    if (AESDCHAR_IOCSEEKTO != cmd)
    {
        return -ENOTTY;
    }

    // We are working in the kernel space -> need to copy memory
    if (copy_from_user(&seekto, (void __user*)arg, sizeof(seekto)))
    {
        return -EFAULT;
    }

    // Command id sanity check
    if (seekto.write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
    {
        return -EINVAL;
    }

    // From here on we are reading the circular buffer. Lock it so it is not modified during our reads
    if (mutex_lock_interruptible(&dev->lock))
    {
        return -ERESTARTSYS;
    }

    // Offset sanity check
    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++)
    {
        buffer_size += circ_buffer->entry[i].size;
    }
    if (seekto.write_cmd_offset >= buffer_size)
    {
        mutex_unlock(&dev->lock);  // Clean-up
        return -EINVAL;
    }

    // Get array index of command
    for (i = 0; i < seekto.write_cmd; i++)
    {
        uint32_t entry_index = (circ_buffer->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        start_offset += circ_buffer->entry[entry_index].size;
    }

    // Update file position with offset within the command
    filp->f_pos = start_offset + seekto.write_cmd_offset;
    PDEBUG("Seek to command %u, offset %u, new position %lld\n", seekto.write_cmd, seekto.write_cmd_offset, filp->f_pos);

    mutex_unlock(&dev->lock);  // Clean-up
    return 0;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .llseek = aesd_seek,
    .unlocked_ioctl = aesd_ioctl,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev* dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
                                 "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&aesd_device.circ_buffer);

    result = aesd_setup_cdev(&aesd_device);

    if (result)
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    uint8_t index = 0;

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific portions here as necessary
     */
    for (index = 0; index < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; index++)
    {
        char* mem = aesd_device.circ_buffer.entry[index].buffptr;
        if (NULL != mem)
        {
            PDEBUG("freeing memory");
            kfree(mem);
        }
    }

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
