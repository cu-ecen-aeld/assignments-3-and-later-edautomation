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
    char* entry_to_free = NULL;

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

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    // Allocate memory for new entry
    kbuffer = kmalloc(count, GFP_KERNEL);
    if (NULL != kbuffer)
    {
        // Add new entry to circular buffer
        struct aesd_buffer_entry new_entry = {
            .size = count,
            .buffptr = kbuffer,
        };
        if (copy_from_user(new_entry.buffptr, buf, count))
        {
            PDEBUG("Could not copy from user space!");
        }
        else
        {
            // Check if the new entry contains a new line
            bool is_new_line = false;
            size_t i = 0;
            for (i = 0; i < count; i++)
            {
                if (new_entry.buffptr[i] == '\n')
                {
                    is_new_line = true;
                    break;
                }
            }

            // Is there already data temporarily stored?
            if (NULL == dev->tmp_entry.buffptr)
            {
                // NO -> copy only if no new line
                if (!is_new_line)
                {
                    PDEBUG("New entry without new line");
                    dev->tmp_entry = new_entry;
                }
                else
                {
                    // New line, no tmp data -> add to buffer right away
                    entry_to_free = aesd_circular_buffer_add_entry(circ_buffer, &new_entry);
                }
            }
            else
            {
                // YES -> append data to tmp entry

                char* new_buff = krealloc(dev->tmp_entry.buffptr, dev->tmp_entry.size + count, GFP_KERNEL);
                if (NULL == new_buff)
                {
                    retval = -ENOMEM;
                    goto out;
                }
                else
                {
                    size_t i = 0;
                    PDEBUG("Appending data to tmp entry");
                    for (i = 0; i < count; i++)
                    {
                        dev->tmp_entry.buffptr[dev->tmp_entry.size + i] = new_entry.buffptr[i];
                    }
                    dev->tmp_entry.size += count;
                    kfree(new_entry.buffptr);  // New entry will not be written to the buffer -> free it
                }

                // New line -> add tmp entry containing all past and new data to buffer, reset tmp
                if (is_new_line)
                {
                    PDEBUG("New line-> write to buffer");
                    entry_to_free = aesd_circular_buffer_add_entry(circ_buffer, &dev->tmp_entry);
                    dev->tmp_entry.buffptr = NULL;
                    // Memory will be freed when circular buffer is cleaned up
                }
            }

            if (entry_to_free)
            {
                PDEBUG("Freeing memory for kicked out entry.");
                kfree(entry_to_free);
            }
            retval = count;
        }
    }
    else
    {
        PDEBUG("Cannot allocate memory!");
    }

out:
    mutex_unlock(&dev->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
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
