#ifndef __COMMON__H
#define __COMMON__H

#include <stdbool.h>

#include <xenevtchn.h>

#include <xen/vm_event.h>

#include "xg_private.h"
#include "xg_save_restore.h"
#include "xc_dom.h"
#include "xc_bitops.h"

#include "xc_sr_stream_format.h"

/* String representation of Domain Header types. */
const char *dhdr_type_to_str(uint32_t type);

/* String representation of Record types. */
const char *rec_type_to_str(uint32_t type);

struct xc_sr_context;
struct xc_sr_record;

/**
 * Save operations.  To be implemented for each type of guest, for use by the
 * common save algorithm.
 *
 * Every function must be implemented, even if only with a no-op stub.
 */
struct xc_sr_save_ops
{
    /* Convert a PFN to GFN.  May return ~0UL for an invalid mapping. */
    xen_pfn_t (*pfn_to_gfn)(const struct xc_sr_context *ctx, xen_pfn_t pfn);

    /**
     * Optionally transform the contents of a page from being specific to the
     * sending environment, to being generic for the stream.
     *
     * The page of data at the end of 'page' may be a read-only mapping of a
     * running guest; it must not be modified.  If no transformation is
     * required, the callee should leave '*pages' untouched.
     *
     * If a transformation is required, the callee should allocate themselves
     * a local page using malloc() and return it via '*page'.
     *
     * The caller shall free() '*page' in all cases.  In the case that the
     * callee encounters an error, it should *NOT* free() the memory it
     * allocated for '*page'.
     *
     * It is valid to fail with EAGAIN if the transformation is not able to be
     * completed at this point.  The page shall be retried later.
     *
     * @returns 0 for success, -1 for failure, with errno appropriately set.
     */
    int (*normalise_page)(struct xc_sr_context *ctx, xen_pfn_t type,
                          void **page);

    /**
     * Set up local environment to save a domain. (Typically querying
     * running domain state, setting up mappings etc.)
     *
     * This is called once before any common setup has occurred, allowing for
     * guest-specific adjustments to be made to common state.
     */
    int (*setup)(struct xc_sr_context *ctx);

    /**
     * Send records which need to be at the start of the stream.  This is
     * called once, after the Image and Domain headers are written.
     */
    int (*start_of_stream)(struct xc_sr_context *ctx);

    /**
     * Send records which need to be at the start of a checkpoint.  This is
     * called once, or once per checkpoint in a checkpointed stream, and is
     * ahead of memory data.
     */
    int (*start_of_checkpoint)(struct xc_sr_context *ctx);

    /**
     * Send records which need to be at the end of the checkpoint.  This is
     * called once, or once per checkpoint in a checkpointed stream, and is
     * after the memory data.
     */
    int (*end_of_checkpoint)(struct xc_sr_context *ctx);

    /**
     * Check state of guest to decide whether it makes sense to continue
     * migration.  This is called in each iteration or checkpoint to check
     * whether all criteria for the migration are still met.  If that's not
     * the case either migration is cancelled via a bad rc or the situation
     * is handled, e.g. by sending appropriate records.
     */
    int (*check_vm_state)(struct xc_sr_context *ctx);

    /**
     * Clean up the local environment.  Will be called exactly once, either
     * after a successful save, or upon encountering an error.
     */
    int (*cleanup)(struct xc_sr_context *ctx);
};


/**
 * Restore operations.  To be implemented for each type of guest, for use by
 * the common restore algorithm.
 *
 * Every function must be implemented, even if only with a no-op stub.
 */
struct xc_sr_restore_ops
{
    /* Convert a PFN to GFN.  May return ~0UL for an invalid mapping. */
    xen_pfn_t (*pfn_to_gfn)(const struct xc_sr_context *ctx, xen_pfn_t pfn);

    /* Check to see whether a PFN is valid. */
    bool (*pfn_is_valid)(const struct xc_sr_context *ctx, xen_pfn_t pfn);

    /* Set the GFN of a PFN. */
    void (*set_gfn)(struct xc_sr_context *ctx, xen_pfn_t pfn, xen_pfn_t gfn);

    /* Set the type of a PFN. */
    void (*set_page_type)(struct xc_sr_context *ctx, xen_pfn_t pfn,
                          xen_pfn_t type);

    /**
     * Optionally transform the contents of a page from being generic in the
     * stream, to being specific to the restoring environment.
     *
     * 'page' is expected to be modified in-place if a transformation is
     * required.
     *
     * @returns 0 for success, -1 for failure, with errno appropriately set.
     */
    int (*localise_page)(struct xc_sr_context *ctx, uint32_t type, void *page);

    /**
     * Set up local environment to restore a domain.
     *
     * This is called once before any common setup has occurred, allowing for
     * guest-specific adjustments to be made to common state.
     */
    int (*setup)(struct xc_sr_context *ctx);

    /**
     * Process an individual record from the stream.  The caller shall take
     * care of processing common records (e.g. END, PAGE_DATA).
     *
     * @return 0 for success, -1 for failure, or the following sentinels:
     *  - RECORD_NOT_PROCESSED
     *  - BROKEN_CHANNEL: under Remus/COLO, this means master may be dead, and
     *    a failover is needed.
     */
#define RECORD_NOT_PROCESSED 1
#define BROKEN_CHANNEL 2
    int (*process_record)(struct xc_sr_context *ctx, struct xc_sr_record *rec);

    /**
     * Perform any actions required after the stream has been finished. Called
     * after the END record has been received.
     */
    int (*stream_complete)(struct xc_sr_context *ctx);

    /**
     * Clean up the local environment.  Will be called exactly once, either
     * after a successful restore, or upon encountering an error.
     */
    int (*cleanup)(struct xc_sr_context *ctx);
};

/* x86 PV per-vcpu storage structure for blobs heading Xen-wards. */
struct xc_sr_x86_pv_restore_vcpu
{
    void *basic, *extd, *xsave, *msr;
    size_t basicsz, extdsz, xsavesz, msrsz;
};

struct xc_sr_context
{
    xc_interface *xch;
    uint32_t domid;
    int fd;

    xc_dominfo_t dominfo;

    union /* Common save or restore data. */
    {
        struct /* Save data. */
        {
            int recv_fd;

            struct xc_sr_save_ops ops;
            const struct save_callbacks *callbacks;

            /* Live migrate vs non live suspend. */
            bool live;

            /* Plain VM, or checkpoints over time. */
            int checkpointed;

            /* Further debugging information in the stream. */
            bool debug;

            unsigned long p2m_size;

            enum {
                XC_SAVE_PHASE_PRECOPY,
                XC_SAVE_PHASE_STOP_AND_COPY,
                XC_SAVE_PHASE_POSTCOPY
            } phase;

            struct precopy_stats stats;
            int policy_decision;

            enum {
                XC_SR_SAVE_BATCH_PRECOPY_PAGE,
                XC_SR_SAVE_BATCH_POSTCOPY_PFN,
                XC_SR_SAVE_BATCH_POSTCOPY_PAGE
            } batch_type;
            xen_pfn_t *batch_pfns;
            unsigned nr_batch_pfns;
            unsigned long *deferred_pages;
            unsigned long nr_deferred_pages;
            xc_hypercall_buffer_t dirty_bitmap_hbuf;
            unsigned long nr_final_dirty_pages;
        } save;

        struct /* Restore data. */
        {
            struct xc_sr_restore_ops ops;
            const struct restore_callbacks *callbacks;

            int send_back_fd;
            unsigned long p2m_size;
            xc_hypercall_buffer_t dirty_bitmap_hbuf;

            /* From Image Header. */
            uint32_t format_version;

            /* From Domain Header. */
            uint32_t guest_type;
            uint32_t guest_page_size;

            /* Is this a postcopy live migration? */
            bool postcopy;

            struct xc_sr_restore_paging
            {
                xenevtchn_handle *xce_handle;
                int port;
                vm_event_back_ring_t back_ring;
                uint32_t evtchn_port;
                void *ring_page;
                void *buffer;

                struct xc_sr_pending_postcopy_request
                {
                    xen_pfn_t pfn; /* == INVALID_PFN when not in use */

                    /* As from vm_event_request_t */
                    uint32_t flags;
                    uint32_t vcpu_id;
                } *pending_requests;

                /*
                 * The total count of outstanding and requested pfns.  The
                 * postcopy phase is complete when this reaches 0.
                 */
                unsigned int nr_pending_pfns;

                /*
                 * Prior to the receipt of the first POSTCOPY_PFNS record, all
                 * pfns are 'invalid', meaning that we don't (yet) believe that
                 * they need to be migrated as part of the postcopy phase.
                 *
                 * Pfns received in POSTCOPY_PFNS records become 'outstanding',
                 * meaning that they must be migrated but haven't yet been
                 * requested, received or dropped.
                 *
                 * A pfn transitions from outstanding to requested when we
                 * receive a request for it on the paging ring and request it
                 * from the sender, before having received it.  There is at
                 * least one valid entry in pending_requests for each requested
                 * pfn.
                 *
                 * A pfn transitions from either outstanding or requested to
                 * ready when its contents are received.  Responses to all
                 * previous pager requests for this pfn are pushed at this time,
                 * and subsequent pager requests for this pfn can be responded
                 * to immediately.
                 *
                 * A pfn transitions from outstanding to dropped if we're
                 * notified on the ring of the drop.  We track this explicitly
                 * so that we don't panic upon subsequently receiving the
                 * contents of this page from the sender.
                 *
                 * In summary, the per-pfn postcopy state machine is:
                 *
                 * invalid -> outstanding -> requested -> ready
                 *                |                        ^
                 *                +------------------------+
                 *                |
                 *                +------ -> dropped
                 *
                 * The state of each pfn is tracked using these four bitmaps.
                 */
                unsigned long *outstanding_pfns;
                unsigned long *requested_pfns;
                unsigned long *ready_pfns;
                unsigned long *dropped_pfns;

                /*
                 * Used to accumulate batches of pfns for which we must forward
                 * paging requests to the sender.
                 */
                uint64_t *request_batch;

                /* For teardown. */
                bool evtchn_bound, evtchn_opened, paging_enabled, buffer_locked;

                /*
                 * So we can sanity-check the sequence of postcopy records in
                 * the stream.
                 */
                bool ready;
            } paging;

            /* Plain VM, or checkpoints over time. */
            int checkpointed;

            /* Currently buffering records between a checkpoint */
            bool buffer_all_records;

/*
 * With Remus/COLO, we buffer the records sent by the primary at checkpoint,
 * in case the primary will fail, we can recover from the last
 * checkpoint state.
 * This should be enough for most of the cases because primary only send
 * dirty pages at checkpoint.
 */
#define DEFAULT_BUF_RECORDS 1024
            struct xc_sr_record *buffered_records;
            unsigned allocated_rec_num;
            unsigned buffered_rec_num;

            /*
             * Xenstore and Console parameters.
             * INPUT:  evtchn & domid
             * OUTPUT: gfn
             */
            xen_pfn_t    xenstore_gfn,    console_gfn,    paging_ring_gfn;
            unsigned int xenstore_evtchn, console_evtchn;
            domid_t      xenstore_domid,  console_domid;

            /* Bitmap of currently populated PFNs during restore. */
            unsigned long *populated_pfns;
            xen_pfn_t max_populated_pfn;

            /* Sender has invoked verify mode on the stream. */
            bool verify;
        } restore;
    };

    union /* Guest-arch specific data. */
    {
        struct /* x86 PV guest. */
        {
            /* 4 or 8; 32 or 64 bit domain */
            unsigned int width;
            /* 3 or 4 pagetable levels */
            unsigned int levels;

            /* Maximum Xen frame */
            xen_pfn_t max_mfn;
            /* Read-only machine to phys map */
            xen_pfn_t *m2p;
            /* first mfn of the compat m2p (Only needed for 32bit PV guests) */
            xen_pfn_t compat_m2p_mfn0;
            /* Number of m2p frames mapped */
            unsigned long nr_m2p_frames;

            /* Maximum guest frame */
            xen_pfn_t max_pfn;

            /* Number of frames making up the p2m */
            unsigned int p2m_frames;
            /* Guest's phys to machine map.  Mapped read-only (save) or
             * allocated locally (restore).  Uses guest unsigned longs. */
            void *p2m;
            /* The guest pfns containing the p2m leaves */
            xen_pfn_t *p2m_pfns;

            /* Read-only mapping of guests shared info page */
            shared_info_any_t *shinfo;

            /* p2m generation count for verifying validity of local p2m. */
            uint64_t p2m_generation;

            union
            {
                struct
                {
                    /* State machine for the order of received records. */
                    bool seen_pv_info;

                    /* Types for each page (bounded by max_pfn). */
                    uint32_t *pfn_types;

                    /* Vcpu context blobs. */
                    struct xc_sr_x86_pv_restore_vcpu *vcpus;
                    unsigned nr_vcpus;
                } restore;
            };
        } x86_pv;

        struct /* x86 HVM guest. */
        {
            union
            {
                struct
                {
                    /* Whether qemu enabled logdirty mode, and we should
                     * disable on cleanup. */
                    bool qemu_enabled_logdirty;
                } save;

                struct
                {
                    /* HVM context blob. */
                    void *context;
                    size_t contextsz;
                } restore;
            };
        } x86_hvm;
    };
};

extern struct xc_sr_save_ops save_ops_x86_pv;
extern struct xc_sr_save_ops save_ops_x86_hvm;

extern struct xc_sr_restore_ops restore_ops_x86_pv;
extern struct xc_sr_restore_ops restore_ops_x86_hvm;

struct xc_sr_record
{
    uint32_t type;
    uint32_t length;
    void *data;
};

/*
 * Writes a split record to the stream, applying correct padding where
 * appropriate.  It is common when sending records containing blobs from Xen
 * that the header and blob data are separate.  This function accepts a second
 * buffer and length, and will merge it with the main record when sending.
 *
 * Records with a non-zero length must provide a valid data field; records
 * with a 0 length shall have their data field ignored.
 *
 * Returns 0 on success and non0 on failure.
 */
int write_split_record(struct xc_sr_context *ctx, int fd,
                       struct xc_sr_record *rec, void *buf, size_t sz);

/*
 * Writes a record to the stream, applying correct padding where appropriate.
 * Records with a non-zero length must provide a valid data field; records
 * with a 0 length shall have their data field ignored.
 *
 * Returns 0 on success and non0 on failure.
 */
static inline int write_record(struct xc_sr_context *ctx, int fd,
                               struct xc_sr_record *rec)
{
    return write_split_record(ctx, fd, rec, NULL, 0);
}

/*
 * Reads a record from the stream, and fills in the record structure.
 *
 * Returns 0 on success and non-0 on failure.
 *
 * On success, the records type and size shall be valid.
 * - If size is 0, data shall be NULL.
 * - If size is non-0, data shall be a buffer allocated by malloc() which must
 *   be passed to free() by the caller.
 *
 * On failure, the contents of the record structure are undefined.
 */
int read_record(struct xc_sr_context *ctx, int fd, struct xc_sr_record *rec);

/*
 * try_read_record() (prototype below) reads a record from a _non-blocking_
 * stream over the course of one or more invocations.  Context for the record
 * read is maintained in an xc_sr_read_record_context.
 *
 * The protocol is:
 * - call read_record_init() on an uninitialized or previously-destroyed
 *   read-record context prior to using it to read a record
 * - call try_read_record() with this initialized context one or more times
 *   - rc < 0 and errno == EAGAIN/EWOULDBLOCK => try again
 *   - rc < 0 otherwise => failure
 *   - rc == 0 => a complete record has been read, and is filled into
 *     try_read_record()'s rec argument
 * - after either failure or completion of a record, destroy the context with
 *   read_record_destroy()
 */
struct xc_sr_read_record_context
{
    struct xc_sr_context *ctx;
    size_t offset;
    struct xc_sr_rhdr rhdr;
    void *data;
};

static inline void read_record_init(struct xc_sr_read_record_context *rrctx,
                                    struct xc_sr_context *ctx)
{
    *rrctx = (struct xc_sr_read_record_context) { .ctx = ctx };
}

int try_read_record(struct xc_sr_read_record_context *rrctx, int fd,
                    struct xc_sr_record *rec);

static inline void read_record_destroy(struct xc_sr_read_record_context *rrctx)
{
    free(rrctx->data);
    rrctx->data = NULL;
}

/*
 * Given a record of one of the page data types, validate it by:
 * - checking its actual type against its specific expected type
 * - sanity checking its actual length against its claimed length
 *
 * Returns 0 on success and non-0 on failure.
 */
int validate_pages_record(struct xc_sr_context *ctx, struct xc_sr_record *rec,
                          uint32_t expected_type);

/*
 * This would ideally be private in restore.c, but is needed by
 * x86_pv_localise_page() if we receive pagetables frames ahead of the
 * contents of the frames they point at.
 */
int populate_pfns(struct xc_sr_context *ctx, unsigned count,
                  const xen_pfn_t *original_pfns, const uint32_t *types);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
