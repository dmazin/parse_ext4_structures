#include <stdint.h>

#define EXT4_N_BLOCKS 15

// typedef uint16_t __le16;
// typedef uint32_t __le32;
// typedef uint16_t __u16;
// typedef uint32_t __u32;
// typedef uint64_t __u64;
// typedef uint8_t __u8;

struct ext4_inode
{
    __le16 i_mode;
    __le16 i_uid;
    __le32 i_size_lo;
    __le32 i_atime;
    __le32 i_ctime;
    __le32 i_mtime;
    __le32 i_dtime;
    __le16 i_gid;
    __le16 i_links_count;
    __le32 i_blocks_lo;
    __le32 i_flags;
    union
    {
        struct
        {
            __le32 l_i_version;
        } linux1;
        struct
        {
            __u32 h_i_translator;
        } hurd1;
        struct
        {
            __u32 m_i_reserved1;
        } masix1;
    } osd1;
    __le32 i_block[EXT4_N_BLOCKS];
    __le32 i_generation;
    __le32 i_file_acl_lo;
    __le32 i_size_high;
    __le32 i_obso_faddr;
    union
    {
        struct
        {
            __le16 l_i_blocks_high;
            __le16 l_i_file_acl_high;
            __le16 l_i_uid_high;
            __le16 l_i_gid_high;
            __le16 l_i_checksum_lo;
            __le16 l_i_reserved;
        } linux2;
        struct
        {
            __le16 h_i_reserved1;
            __u16 h_i_mode_high;
            __u16 h_i_uid_high;
            __u16 h_i_gid_high;
            __u32 h_i_author;
        } hurd2;
        struct
        {
            __le16 h_i_reserved1;
            __le16 m_i_file_acl_high;
            __u32 m_i_reserved2[2];
        } masix2;
    } osd2;
    __le16 i_extra_isize;
    __le16 i_checksum_hi;
    __le32 i_ctime_extra;
    __le32 i_mtime_extra;
    __le32 i_atime_extra;
    __le32 i_crtime;
    __le32 i_crtime_extra;
    __le32 i_version_hi;
    __le32 i_projid;
};

struct ext4_super_block
{
    __le32 s_inodes_count;           /* Inodes count */
    __le32 s_blocks_count_lo;        /* Blocks count */
    __le32 s_r_blocks_count_lo;      /* Reserved blocks count */
    __le32 s_free_blocks_count_lo;   /* Free blocks count */
    __le32 s_free_inodes_count;      /* Free inodes count */
    __le32 s_first_data_block;       /* First Data Block */
    __le32 s_log_block_size;         /* Block size */
    __le32 s_log_cluster_size;       /* Allocation cluster size */
    __le32 s_blocks_per_group;       /* # Blocks per group */
    __le32 s_clusters_per_group;     /* # Clusters per group */
    __le32 s_inodes_per_group;       /* # Inodes per group */
    __le32 s_mtime;                  /* Mount time */
    __le32 s_wtime;                  /* Write time */
    __le16 s_mnt_count;              /* Mount count */
    __le16 s_max_mnt_count;          /* Maximal mount count */
    __le16 s_magic;                  /* Magic signature */
    __le16 s_state;                  /* File system state */
    __le16 s_errors;                 /* Behaviour when detecting errors */
    __le16 s_minor_rev_level;        /* minor revision level */
    __le32 s_lastcheck;              /* time of last check */
    __le32 s_checkinterval;          /* max. time between checks */
    __le32 s_creator_os;             /* OS */
    __le32 s_rev_level;              /* Revision level */
    __le16 s_def_resuid;             /* Default uid for reserved blocks */
    __le16 s_def_resgid;             /* Default gid for reserved blocks */
    __le32 s_first_ino;              /* First non-reserved inode */
    __le16 s_inode_size;             /* size of inode structure */
    __le16 s_block_group_nr;         /* block group # of this superblock */
    __le32 s_feature_compat;         /* compatible feature set */
    __le32 s_feature_incompat;       /* incompatible feature set */
    __le32 s_feature_ro_compat;      /* readonly-compatible feature set */
    __u8 s_uuid[16];                 /* 128-bit uuid for volume */
    char s_volume_name[16];          /* volume name */
    char s_last_mounted[64];         /* directory where last mounted */
    __le32 s_algorithm_usage_bitmap; /* For compression */
    __u8 s_prealloc_blocks;          /* Nr of blocks to try to preallocate */
    __u8 s_prealloc_dir_blocks;      /* Nr to preallocate for dirs */
    __le16 s_reserved_gdt_blocks;    /* Per group desc for online growth */
    __u8 s_journal_uuid[16];         /* uuid of journal superblock */
    __le32 s_journal_inum;           /* inode number of journal file */
    __le32 s_journal_dev;            /* device number of journal file */
    __le32 s_last_orphan;            /* start of list of inodes to delete */
    __le32 s_hash_seed[4];           /* HTREE hash seed */
    __u8 s_def_hash_version;         /* Default hash version to use */
    __u8 s_jnl_backup_type;
    __le16 s_desc_size; /* size of group descriptor */
    __le32 s_default_mount_opts;
    __le32 s_first_meta_bg;           /* First metablock block group */
    __le32 s_mkfs_time;               /* When the filesystem was created */
    __le32 s_jnl_blocks[17];          /* Backup of the journal inode */
    __le32 s_blocks_count_hi;         /* Blocks count */
    __le32 s_r_blocks_count_hi;       /* Reserved blocks count */
    __le32 s_free_blocks_count_hi;    /* Free blocks count */
    __le16 s_min_extra_isize;         /* All inodes have at least # bytes */
    __le16 s_want_extra_isize;        /* New inodes should reserve # bytes */
    __le32 s_flags;                   /* Miscellaneous flags */
    __le16 s_raid_stride;             /* RAID stride */
    __le16 s_mmp_update_interval;     /* # seconds to wait in MMP checking */
    __le64 s_mmp_block;               /* Block for multi-mount protection */
    __le32 s_raid_stripe_width;       /* blocks on all data disks (N*stride)*/
    __u8 s_log_groups_per_flex;       /* FLEX_BG group size */
    __u8 s_checksum_type;             /* metadata checksum algorithm used */
    __u8 s_encryption_level;          /* versioning level for encryption */
    __u8 s_reserved_pad;              /* Padding to next 32bits */
    __le64 s_kbytes_written;          /* nr of lifetime kilobytes written */
    __le32 s_snapshot_inum;           /* Inode number of active snapshot */
    __le32 s_snapshot_id;             /* sequential ID of active snapshot */
    __le64 s_snapshot_r_blocks_count; /* reserved blocks for active snapshot's future use */
    __le32 s_snapshot_list;           /* inode number of the head of the on-disk snapshot list */
    __le32 s_error_count;             /* number of fs errors */
    __le32 s_first_error_time;        /* first time an error happened */
    __le32 s_first_error_ino;         /* inode involved in first error */
    __le64 s_first_error_block;       /* block involved of first error */
    __u8 s_first_error_func[32];      /* function where the error happened */
    __le32 s_first_error_line;        /* line number where error happened */
    __le32 s_last_error_time;         /* most recent time of an error */
    __le32 s_last_error_ino;          /* inode involved in last error */
    __le32 s_last_error_line;         /* line number where error happened */
    __le64 s_last_error_block;        /* block involved of last error */
    __u8 s_last_error_func[32];       /* function where the error happened */
    __u8 s_mount_opts[64];
    __le32 s_usr_quota_inum;    /* inode for tracking user quota */
    __le32 s_grp_quota_inum;    /* inode for tracking group quota */
    __le32 s_overhead_clusters; /* overhead blocks/clusters in fs */
    __le32 s_backup_bgs[2];     /* groups with sparse_super2 SBs */
    __u8 s_encrypt_algos[4];    /* Encryption algorithms in use  */
    __u8 s_encrypt_pw_salt[16]; /* Salt used for string2key algorithm */
    __le32 s_lpf_ino;           /* Location of the lost+found inode */
    __le32 s_prj_quota_inum;    /* inode for tracking project quota */
    __le32 s_checksum_seed;     /* crc32c(uuid) if csum_seed set */
    __u8 s_wtime_hi;
    __u8 s_mtime_hi;
    __u8 s_mkfs_time_hi;
    __u8 s_lastcheck_hi;
    __u8 s_first_error_time_hi;
    __u8 s_last_error_time_hi;
    __u8 s_first_error_errcode;
    __u8 s_last_error_errcode;
    __le16 s_encoding;         /* Filename charset encoding */
    __le16 s_encoding_flags;   /* Filename charset encoding flags */
    __le32 s_orphan_file_inum; /* Inode for tracking orphan inodes */
    __le32 s_reserved[93];     /* Padding to the end of the block */
    __le32 s_checksum;         /* crc32c(superblock) */
};

// no need to define ext4_group_desc because we import it from e2fsprogs

union ext4_struct
{
    struct ext4_super_block sb;
    struct ext4_inode inode;
    struct ext4_group_desc group_desc;
    struct ext2_dir_entry dir_entry;
    struct ext2_dir_entry_2 dir_entry_2;
};
