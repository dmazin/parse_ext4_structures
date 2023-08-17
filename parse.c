#include <stdio.h>
#include <stdint.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <ext2fs/ext2fs.h>
#include "hexdump.h"
#include "types.h"

#define BUF_LEN 8096

// Note that this was made with the aid of GPT4.

ext2_filsys fs;

void print_unexplained_bytes(int count, size_t offset)
{
    if (count > 0)
    {
        printf("%d unexplained bytes at offset %zu\n", count, offset);
    }
}

int is_valid_inode(struct ext4_inode *inode)
{
    errcode_t retval;
    ext2_ino_t ino;
    struct ext2_inode ext2_inode;

    for (ino = 1; ino <= fs->super->s_inodes_count; ++ino)
    {
        if (ext2fs_fast_test_inode_bitmap2(fs->inode_map, ino))
        {
            retval = ext2fs_read_inode(fs, ino, &ext2_inode);
            if (retval)
            {
                fprintf(stderr, "Error reading inode\n");
                return 0;
            }

            if (ext2_inode.osd2.linux2.l_i_checksum_lo == inode->osd2.linux2.l_i_checksum_lo)
            {
                if (ext2_inode.i_atime == inode->i_atime &&
                    ext2_inode.i_ctime == inode->i_ctime &&
                    ext2_inode.i_mtime == inode->i_mtime &&
                    ext2_inode.i_dtime == inode->i_dtime &&
                    ext2_inode.i_mode == inode->i_mode &&
                    ext2_inode.i_uid == inode->i_uid &&
                    ext2_inode.i_size == inode->i_size_lo &&
                    ext2_inode.i_gid == inode->i_gid &&
                    ext2_inode.i_links_count == inode->i_links_count &&
                    ext2_inode.i_blocks == inode->i_blocks_lo &&
                    ext2_inode.i_flags == inode->i_flags &&
                    ext2_inode.i_generation == inode->i_generation &&
                    ext2_inode.i_file_acl == inode->i_file_acl_lo &&
                    ext2_inode.i_size_high == inode->i_size_high)
                {
                    return ino;
                }
            }
        }
    }
    return 0;
}

struct dir_iterate_struct
{
    void *target_dir_entry; // Directory entry to compare against
    int type;               // 1 for ext2_dir_entry, 2 for ext2_dir_entry_2
    int found;              // Flag indicating if the entry was found
};

static int dir_iterate_callback(struct ext2_dir_entry *dirent,
                                int offset, int blocksize,
                                char *buf, void *priv_data)
{
    struct dir_iterate_struct *data = (struct dir_iterate_struct *)priv_data;

    if (data->type == 1)
    {
        struct ext2_dir_entry *entry = (struct ext2_dir_entry *)data->target_dir_entry;

        if (entry->inode == dirent->inode &&
            entry->rec_len == dirent->rec_len &&
            entry->name_len == dirent->name_len &&
            strncmp(entry->name, dirent->name, entry->name_len) == 0)
        {
            data->found = 1;
            return DIRENT_ABORT; // Stop the iteration
        }
    }
    else if (data->type == 2)
    {
        struct ext2_dir_entry_2 *entry_2 = (struct ext2_dir_entry_2 *)data->target_dir_entry;

        if (entry_2->inode == dirent->inode &&
            entry_2->rec_len == dirent->rec_len &&
            entry_2->name_len == dirent->name_len &&
            strncmp(entry_2->name, dirent->name, entry_2->name_len) == 0) // Additional checks for ext2_dir_entry_2 might be needed
        {
            data->found = 1;
            return DIRENT_ABORT; // Stop the iteration
        }
    }

    return 0; // Continue the iteration
}

int is_valid_dir_entry(union ext4_struct *entry)
{
    struct dir_iterate_struct data;
    if (entry->dir_entry.name_len != 0)
    {
        data.target_dir_entry = &entry->dir_entry;
        data.type = 1;
    }
    else
    {
        data.target_dir_entry = &entry->dir_entry_2;
        data.type = 2;
    }
    data.found = 0;

    ext2fs_dir_iterate(fs, EXT2_ROOT_INO, 0, NULL, dir_iterate_callback, &data);

    return data.found;
}

int is_valid_sb(struct ext4_super_block *sb)
{
    struct ext2_super_block *super = fs->super;
    // for some reason the checksums don't match, so we'll use the inode count
    // if (super->s_inodes_count == sb->s_inodes_count) {
    //     printf("candidate inodes: %d; sb inodes: %d\n", sb->s_inodes_count, super->s_inodes_count);
    //     printf("candidate checksum: %d; sb checksum: %d\n", sb->s_checksum, super->s_checksum);
    // }
    int is_valid = super->s_inodes_count == sb->s_inodes_count;

    // if (is_valid)
    // {
        // printf("detected valid super block!\n");
        // printf("first inode: %d\n", sb->s_first_ino);
        // printf("volume name: %s\n", sb->s_volume_name);
        // printf("mount location: %s\n", sb->s_last_mounted);
    // }

    return is_valid;
}

int is_valid_group_description(struct ext4_group_desc *gdesc)
{
    errcode_t retval;
    dgrp_t group;
    struct ext2_group_desc *fs_gdesc;

    for (group = 0; group < fs->group_desc_count; ++group)
    {
        fs_gdesc = ext2fs_group_desc(fs, NULL, group);

        if (fs_gdesc->bg_checksum == gdesc->bg_checksum &&
            fs_gdesc->bg_free_blocks_count == gdesc->bg_free_blocks_count &&
            fs_gdesc->bg_free_inodes_count == gdesc->bg_free_inodes_count)
        {
            // printf("Group number: %d\n", group);
            // printf("Group descriptor checksum: %d\n", fs_gdesc->bg_checksum);
            // printf("Free blocks count: %d\n", fs_gdesc->bg_free_blocks_count);
            // printf("Free inodes count: %d\n", fs_gdesc->bg_free_inodes_count);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "Specify the directory containing .bin files and the ext2 filesystem\n");
        return 1;
    }

    errcode_t retval;

    retval = ext2fs_open(argv[2], EXT2_FLAG_RW, 0, 0, unix_io_manager, &fs);
    if (retval)
    {
        fprintf(stderr, "Error opening filesystem\n");
        return 1;
    }

    retval = ext2fs_read_inode_bitmap(fs);
    if (retval)
    {
        fprintf(stderr, "Error reading inode bitmap\n");
        return 1;
    }

    DIR *d;
    struct dirent *dir;
    d = opendir(argv[1]);
    if (!d)
    {
        fprintf(stderr, "Failed to open directory\n");
        return 1;
    }

    char buf[BUF_LEN] = {0};
    int buf_counter = 0;
    size_t starting_unexplained_byte_offset;

    while ((dir = readdir(d)) != NULL)
    {
        if (strstr(dir->d_name, ".bin") != NULL)
        {
            char filepath[1024];
            sprintf(filepath, "%s/%s", argv[1], dir->d_name);
            FILE *file = fopen(filepath, "rb");
            if (!file)
            {
                fprintf(stderr, "Failed to open file %s\n", filepath);
                continue;
            }

            printf("%s\n", dir->d_name);

            union ext4_struct struct_buffer;
            size_t offset = 0;

            while (fseek(file, offset, SEEK_SET) == 0)
            {
                size_t read = fread(&struct_buffer, sizeof(struct ext4_inode), 1, file);
                if (read != 1)
                    break;

                int ino = is_valid_inode(&(struct_buffer.inode));
                if (ino)
                {
                    print_unexplained_bytes(buf_counter, starting_unexplained_byte_offset);
                    buf_counter = 0;

                    char hex_dump_description[128];
                    sprintf(hex_dump_description, "inode %d found at offset %zu", ino, offset);
                    hex_dump(hex_dump_description, &struct_buffer, sizeof(struct ext4_inode), 16, offset);

                    offset += sizeof(struct ext4_inode);
                }
                else if (is_valid_sb(&(struct_buffer.sb)))
                {
                    print_unexplained_bytes(buf_counter, starting_unexplained_byte_offset);
                    buf_counter = 0;

                    char hex_dump_description[128];
                    sprintf(hex_dump_description, "superblock found at offset %zu", offset);
                    hex_dump(hex_dump_description, &struct_buffer, sizeof(struct ext4_super_block), 16, offset);

                    offset += sizeof(struct ext4_super_block);
                }
                else if (is_valid_group_description(&(struct_buffer.group_desc)))
                {
                    print_unexplained_bytes(buf_counter, starting_unexplained_byte_offset);
                    buf_counter = 0;

                    char hex_dump_description[128];
                    sprintf(hex_dump_description, "group description found at offset %zu", offset);
                    hex_dump(hex_dump_description, &struct_buffer, sizeof(struct ext4_group_desc), 16, offset);

                    offset += sizeof(struct ext4_group_desc);
                }
                else if (is_valid_dir_entry(&struct_buffer))
                {
                    print_unexplained_bytes(buf_counter, starting_unexplained_byte_offset);
                    buf_counter = 0;

                    char hex_dump_description[128];
                    sprintf(hex_dump_description, "directory entry found at offset %zu", offset);
                    hex_dump(hex_dump_description, &struct_buffer, sizeof(union ext4_struct), 16, offset);

                    offset += sizeof(struct ext2_dir_entry);  // sizeof ext2_dir_entry == sizeof ext2_dir_entry_2
                }
                else
                {
                    if (buf_counter == 0)
                    {
                        starting_unexplained_byte_offset = offset;
                    }

                    if (buf_counter == (BUF_LEN - 1))
                    {
                        print_unexplained_bytes(BUF_LEN, starting_unexplained_byte_offset);
                        buf_counter = 0;
                    }

                    char *first_byte = (char *)&struct_buffer;
                    buf[buf_counter] = *first_byte;
                    buf_counter += 1;

                    offset += 1;
                }
            }

            print_unexplained_bytes(buf_counter, starting_unexplained_byte_offset);
            buf_counter = 0;

            fclose(file);
        }
    }

    closedir(d);
    ext2fs_close(fs);

    return 0;
}
