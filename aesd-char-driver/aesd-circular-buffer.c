/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer implementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/printk.h>
#include <linux/string.h>
#define PRINT(...) printk(__VA_ARGS__)

#else
#include <stdio.h>
#include <string.h>
#define PRINT(...) printf(__VA_ARGS__)
#endif

#include "aesd-circular-buffer.h"

#define BUFFER_END_INDEX (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)

/**
 * Same as below, but looks only at a portion of the buffer specified by start_index and end_index.
 * Also, modifies the char_offset so it can be called multiple times in a row
 */
static struct aesd_buffer_entry* find_entry_offset_for_fpos(struct aesd_circular_buffer* buffer,
                                                            uint8_t start_index, uint8_t end_index,
                                                            size_t* p_char_offset, size_t* entry_offset_byte_rtn)
{
    struct aesd_buffer_entry* entry = NULL;
    uint8_t i = start_index;

    if ((end_index < start_index) ||
        (NULL == p_char_offset) ||
        (end_index >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED))
    {
        PRINT("CIRCULAR_BUFFER: Invalid inputs\n");
        return NULL;
    }

    while ((i <= end_index) && (*p_char_offset > (buffer->entry[i].size - 1)))
    {
        PRINT("CIRCULAR_BUFFER: Offset too big %lu > %lu, substracting %lu\n", *p_char_offset, buffer->entry[i].size - 1, buffer->entry[i].size);
        *p_char_offset -= buffer->entry[i].size;
        i++;
    }
    if (i <= end_index)
    {
        PRINT("CIRCULAR_BUFFER: Found entry at index %u, offset %lu\n", i, *p_char_offset);
        entry = &buffer->entry[i];
        *entry_offset_byte_rtn = *p_char_offset;
    }
    else
    {
        // entry stays NULL and nothing is written to entry_offset_byte_rtn.
        PRINT("CIRCULAR_BUFFER: No entry found between index %u and %u\n", start_index, end_index);
    }
    return entry;
}

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry* aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer* buffer,
                                                                          size_t char_offset, size_t* entry_offset_byte_rtn)
{
    /**
     * TODO: implement per description
     */

    struct aesd_buffer_entry* entry = NULL;
    if ((NULL == buffer) || (NULL == entry_offset_byte_rtn))
    {
        PRINT("CIRCULAR_BUFFER: Invalid inputs\n");
        return NULL;
    }

    PRINT("CIRCULAR_BUFFER: Searching for entry at char_offset %lu\n", char_offset);

    if (buffer->in_offs == buffer->out_offs)
    {
        PRINT("CIRCULAR_BUFFER: in==out==%u\n", buffer->in_offs);
        if (buffer->full)
        {
            PRINT("CIRCULAR_BUFFER: Searching from indexes %u to %u\n", buffer->out_offs, BUFFER_END_INDEX);
            entry = find_entry_offset_for_fpos(buffer, buffer->in_offs, BUFFER_END_INDEX, &char_offset, entry_offset_byte_rtn);
            if ((NULL == entry) && (buffer->out_offs > 0))
            {
                PRINT("CIRCULAR_BUFFER: Searching from indexes 0 to %u\n", buffer->out_offs - 1);
                entry = find_entry_offset_for_fpos(buffer, 0, buffer->out_offs - 1, &char_offset, entry_offset_byte_rtn);
            }
        }
        else
        {
            PRINT("CIRCULAR_BUFFER: Buffer empty, nothing to search for\n");
            // Nothing to do, leave entry NULL
        }
    }
    else if (buffer->in_offs > buffer->out_offs)
    {
        // 0   out.........in     end
        // --------------------------
        PRINT("CIRCULAR_BUFFER: Searching from indexes 0 to %u\n", BUFFER_END_INDEX);
        entry = find_entry_offset_for_fpos(buffer, buffer->out_offs, buffer->in_offs - 1, &char_offset, entry_offset_byte_rtn);
    }
    else
    {
        // 0    in     out.........end
        // ---------------------------

        entry = find_entry_offset_for_fpos(buffer, buffer->out_offs, BUFFER_END_INDEX, &char_offset, entry_offset_byte_rtn);
        if (NULL == entry)
        {
            // 0....in     out         end
            // ---------------------------
            entry = find_entry_offset_for_fpos(buffer, 0, buffer->in_offs - 1, &char_offset, entry_offset_byte_rtn);
        }
    }

    return entry;
}

/**
 * Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
 * If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
 * new start location.
 * Any necessary locking must be handled by the caller
 * Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
 * @return NULL or, if an entry was overwritten by a new one, a pointer to the memory buffer for the overwritten entry.
 */
char* aesd_circular_buffer_add_entry(struct aesd_circular_buffer* buffer, const struct aesd_buffer_entry* add_entry)
{
    /**
     * TODO: implement per description
     */

    char* retval = NULL;

    if ((NULL == buffer) || (NULL == add_entry))
    {
        PRINT("CIRCULAR_BUFFER: Invalid inputs\n");
        return retval;
    }

    // When buffer full, return memory of entry to be replaced
    if (buffer->full)
    {
        PRINT("CIRCULAR_BUFFER: Buffer full, overwriting\n");
        retval = buffer->entry[buffer->out_offs].buffptr;                                     // Memory to be freed
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;  // Move read pointer
    }

    // Add new entry
    PRINT("CIRCULAR_BUFFER: Adding entry at in=%u with size %lu\n", buffer->in_offs, add_entry->size);
    buffer->entry[buffer->in_offs] = *add_entry;
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    // write catches read -> buffer full
    if (buffer->in_offs == buffer->out_offs)
    {
        buffer->full = true;
    }
    else
    {
        buffer->full = false;
    }

    PRINT("CIRCULAR BUFFER: Indexes for next add are in=%u, out=%u\n", buffer->in_offs, buffer->out_offs);
    return retval;
}

/**
 * Initializes the circular buffer described by @param buffer to an empty struct
 */
void aesd_circular_buffer_init(struct aesd_circular_buffer* buffer)
{
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}