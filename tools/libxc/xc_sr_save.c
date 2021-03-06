#include <assert.h>
#include <arpa/inet.h>

#include "xc_sr_common.h"

#define MAX_BATCH_SIZE \
    max(max(MAX_PRECOPY_BATCH_SIZE, MAX_PFN_BATCH_SIZE), MAX_POSTCOPY_BATCH_SIZE)

static const unsigned int batch_sizes[] =
{
    [XC_SR_SAVE_BATCH_PRECOPY_PAGE]  = MAX_PRECOPY_BATCH_SIZE,
    [XC_SR_SAVE_BATCH_POSTCOPY_PFN]  = MAX_PFN_BATCH_SIZE,
    [XC_SR_SAVE_BATCH_POSTCOPY_PAGE] = MAX_POSTCOPY_BATCH_SIZE
};

static const bool batch_includes_contents[] =
{
    [XC_SR_SAVE_BATCH_PRECOPY_PAGE]  = true,
    [XC_SR_SAVE_BATCH_POSTCOPY_PFN]  = false,
    [XC_SR_SAVE_BATCH_POSTCOPY_PAGE] = true
};

static const uint32_t batch_rec_types[] =
{
    [XC_SR_SAVE_BATCH_PRECOPY_PAGE]  = REC_TYPE_PAGE_DATA,
    [XC_SR_SAVE_BATCH_POSTCOPY_PFN]  = REC_TYPE_POSTCOPY_PFNS,
    [XC_SR_SAVE_BATCH_POSTCOPY_PAGE] = REC_TYPE_POSTCOPY_PAGE_DATA
};

/*
 * Writes an Image header and Domain header into the stream.
 */
static int write_headers(struct xc_sr_context *ctx, uint16_t guest_type)
{
    xc_interface *xch = ctx->xch;
    int32_t xen_version = xc_version(xch, XENVER_version, NULL);
    struct xc_sr_ihdr ihdr =
        {
            .marker  = IHDR_MARKER,
            .id      = htonl(IHDR_ID),
            .version = htonl(IHDR_VERSION),
            .options = htons(IHDR_OPT_LITTLE_ENDIAN),
        };
    struct xc_sr_dhdr dhdr =
        {
            .type       = guest_type,
            .page_shift = XC_PAGE_SHIFT,
            .xen_major  = (xen_version >> 16) & 0xffff,
            .xen_minor  = (xen_version)       & 0xffff,
        };

    if ( xen_version < 0 )
    {
        PERROR("Unable to obtain Xen Version");
        return -1;
    }

    if ( write_exact(ctx->fd, &ihdr, sizeof(ihdr)) )
    {
        PERROR("Unable to write Image Header to stream");
        return -1;
    }

    if ( write_exact(ctx->fd, &dhdr, sizeof(dhdr)) )
    {
        PERROR("Unable to write Domain Header to stream");
        return -1;
    }

    return 0;
}

/*
 * Writes an END record into the stream.
 */
static int write_end_record(struct xc_sr_context *ctx)
{
    struct xc_sr_record end = { REC_TYPE_END, 0, NULL };

    return write_record(ctx, ctx->fd, &end);
}

/*
 * Writes a CHECKPOINT record into the stream.
 */
static int write_checkpoint_record(struct xc_sr_context *ctx)
{
    struct xc_sr_record checkpoint = { REC_TYPE_CHECKPOINT, 0, NULL };

    return write_record(ctx, ctx->fd, &checkpoint);
}

/*
 * Writes a POSTCOPY_BEGIN record into the stream.
 */
static int write_postcopy_begin_record(struct xc_sr_context *ctx)
{
    struct xc_sr_record postcopy_begin = { REC_TYPE_POSTCOPY_BEGIN, 0, NULL };

    return write_record(ctx, ctx->fd, &postcopy_begin);
}

/*
 * Writes a POSTCOPY_PFNS_BEGIN record into the stream.
 */
static int write_postcopy_pfns_begin_record(struct xc_sr_context *ctx)
{
    struct xc_sr_record postcopy_pfns_begin =
        { REC_TYPE_POSTCOPY_PFNS_BEGIN, 0, NULL };

    return write_record(ctx, ctx->fd, &postcopy_pfns_begin);
}

/*
 * Writes a POSTCOPY_TRANSITION record into the stream.
 */
static int write_postcopy_transition_record(struct xc_sr_context *ctx)
{
    struct xc_sr_record postcopy_transition =
        { REC_TYPE_POSTCOPY_TRANSITION, 0, NULL };

    return write_record(ctx, ctx->fd, &postcopy_transition);
}

/*
 * This function:
 * - maps each pfn in the current batch to its gfn
 * - gets the type of each pfn in the batch.
 */
static int get_batch_info(struct xc_sr_context *ctx, xen_pfn_t *gfns,
                          xen_pfn_t *types)
{
    int rc;
    unsigned int nr_pfns = ctx->save.nr_batch_pfns;
    xc_interface *xch = ctx->xch;
    unsigned int i;

    for ( i = 0; i < nr_pfns; ++i )
        types[i] = gfns[i] = ctx->save.ops.pfn_to_gfn(ctx,
                                                      ctx->save.batch_pfns[i]);

    /*
     * The type query domctl accepts batches of at most 1024 pfns, so we need to
     * break our batch here into appropriately-sized sub-batches.
     */
    for ( i = 0; i < nr_pfns; i += 1024 )
    {
        rc = xc_get_pfn_type_batch(xch, ctx->domid, min(1024U, nr_pfns - i),
                                   &types[i]);
        if ( rc )
        {
            PERROR("Failed to get types for pfn batch");
            return rc;
        }
    }

    return 0;
}

/*
 * Writes a batch of memory as a PAGE_DATA record into the stream.  The batch
 * is constructed in ctx->save.batch_pfns.
 *
 * This function:
 * - for each pfn with real data:
 *   - maps and attempts to localise the pages.
 * - construct and writes a PAGE_DATA record into the stream.
 */
static int write_batch(struct xc_sr_context *ctx, xen_pfn_t *gfns,
                       xen_pfn_t *types)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t *bgfns = NULL;
    void *guest_mapping = NULL;
    void **guest_data = NULL;
    void **local_pages = NULL;
    int *errors = NULL, rc = -1;
    unsigned i, p, nr_pages = 0, nr_pages_mapped = 0;
    unsigned nr_pfns = ctx->save.nr_batch_pfns;
    void *page, *orig_page;
    uint64_t *rec_pfns = NULL;
    struct iovec *iov = NULL; int iovcnt = 0;
    struct xc_sr_rec_pages_header hdr = { 0 };
    bool send_page_contents = batch_includes_contents[ctx->save.batch_type];
    struct xc_sr_record rec =
    {
        .type = batch_rec_types[ctx->save.batch_type],
    };

    assert(nr_pfns != 0);

    /* The subset of gfns that are physically-backed. */
    bgfns = malloc(nr_pfns * sizeof(*bgfns));
    /* Errors from attempting to map the gfns. */
    errors = malloc(nr_pfns * sizeof(*errors));
    /* Pointers to page data to send.  Mapped gfns or local allocations. */
    guest_data = calloc(nr_pfns, sizeof(*guest_data));
    /* Pointers to locally allocated pages.  Need freeing. */
    local_pages = calloc(nr_pfns, sizeof(*local_pages));
    /* iovec[] for writev(). */
    iov = malloc((nr_pfns + 4) * sizeof(*iov));

    if ( !bgfns || !errors || !guest_data || !local_pages || !iov )
    {
        ERROR("Unable to allocate arrays for a batch of %u pages",
              nr_pfns);
        goto err;
    }

    /* Mark likely-ballooned pages as deferred. */
    for ( i = 0; i < nr_pfns; ++i )
    {
        if ( gfns[i] == INVALID_MFN )
        {
            set_bit(ctx->save.batch_pfns[i], ctx->save.deferred_pages);
            ++ctx->save.nr_deferred_pages;
        }
    }

    if ( send_page_contents )
    {
        for ( i = 0; i < nr_pfns; ++i )
        {
            switch ( types[i] )
            {
            case XEN_DOMCTL_PFINFO_BROKEN:
            case XEN_DOMCTL_PFINFO_XALLOC:
            case XEN_DOMCTL_PFINFO_XTAB:
                continue;
            }

            bgfns[nr_pages++] = gfns[i];
        }

        if ( nr_pages > 0 )
        {
            guest_mapping = xenforeignmemory_map(xch->fmem,
                ctx->domid, PROT_READ, nr_pages, bgfns, errors);
            if ( !guest_mapping )
            {
                PERROR("Failed to map guest pages");
                goto err;
            }
            nr_pages_mapped = nr_pages;

            for ( i = 0, p = 0; i < nr_pfns; ++i )
            {
                switch ( types[i] )
                {
                case XEN_DOMCTL_PFINFO_BROKEN:
                case XEN_DOMCTL_PFINFO_XALLOC:
                case XEN_DOMCTL_PFINFO_XTAB:
                    continue;
                }

                if ( errors[p] )
                {
                    ERROR("Mapping of pfn %#"PRIpfn" (mfn %#"PRIpfn") failed %d",
                          ctx->save.batch_pfns[i], bgfns[p], errors[p]);
                    goto err;
                }

                orig_page = page = guest_mapping + (p * PAGE_SIZE);
                rc = ctx->save.ops.normalise_page(ctx, types[i], &page);

                if ( orig_page != page )
                    local_pages[i] = page;

                if ( rc )
                {
                    if ( rc == -1 && errno == EAGAIN )
                    {
                        set_bit(ctx->save.batch_pfns[i],
                                ctx->save.deferred_pages);
                        ++ctx->save.nr_deferred_pages;
                        types[i] = XEN_DOMCTL_PFINFO_XTAB;
                        --nr_pages;
                    }
                    else
                        goto err;
                }
                else
                    guest_data[i] = page;

                rc = -1;
                ++p;
            }
        }
    }

    rec_pfns = malloc(nr_pfns * sizeof(*rec_pfns));
    if ( !rec_pfns )
    {
        ERROR("Unable to allocate %zu bytes of memory for page data pfn list",
              nr_pfns * sizeof(*rec_pfns));
        goto err;
    }

    hdr.count = nr_pfns;

    rec.length = sizeof(hdr);
    rec.length += nr_pfns * sizeof(*rec_pfns);
    rec.length += nr_pages * PAGE_SIZE;

    for ( i = 0; i < nr_pfns; ++i )
        rec_pfns[i] = ((uint64_t)(types[i]) << 32) | ctx->save.batch_pfns[i];

    iov[0].iov_base = &rec.type;
    iov[0].iov_len = sizeof(rec.type);

    iov[1].iov_base = &rec.length;
    iov[1].iov_len = sizeof(rec.length);

    iov[2].iov_base = &hdr;
    iov[2].iov_len = sizeof(hdr);

    iov[3].iov_base = rec_pfns;
    iov[3].iov_len = nr_pfns * sizeof(*rec_pfns);

    iovcnt = 4;

    if ( nr_pages )
    {
        for ( i = 0; i < nr_pfns; ++i )
        {
            if ( guest_data[i] )
            {
                iov[iovcnt].iov_base = guest_data[i];
                iov[iovcnt].iov_len = PAGE_SIZE;
                iovcnt++;
                --nr_pages;
            }
        }
    }

    if ( writev_exact(ctx->fd, iov, iovcnt) )
    {
        PERROR("Failed to write page data to stream");
        goto err;
    }

    /* Sanity check we have sent all the pages we expected to. */
    assert(nr_pages == 0);
    rc = ctx->save.nr_batch_pfns = 0;

 err:
    free(rec_pfns);
    if ( guest_mapping )
        xenforeignmemory_unmap(xch->fmem, guest_mapping, nr_pages_mapped);
    for ( i = 0; local_pages && i < nr_pfns; ++i )
        free(local_pages[i]);
    free(iov);
    free(local_pages);
    free(guest_data);
    free(errors);
    free(bgfns);

    return rc;
}

/*
 * Test if the batch is full.
 */
static bool batch_full(const struct xc_sr_context *ctx)
{
    return ctx->save.nr_batch_pfns == batch_sizes[ctx->save.batch_type];
}

/*
 * Test if the batch is empty.
 */
static bool batch_empty(struct xc_sr_context *ctx)
{
    return ctx->save.nr_batch_pfns == 0;
}

/*
 * Flush a batch of pfns into the stream.
 */
static int flush_batch(struct xc_sr_context *ctx)
{
    int rc = 0;
    xc_interface *xch = ctx->xch;
    xen_pfn_t *gfns = NULL, *types = NULL;
    unsigned int nr_pfns = ctx->save.nr_batch_pfns;

    if ( batch_empty(ctx) )
        goto out;

    gfns = malloc(nr_pfns * sizeof(*gfns));
    types = malloc(nr_pfns * sizeof(*types));

    if ( !gfns || !types )
    {
        ERROR("Unable to allocate arrays for a batch of %u pages",
              nr_pfns);
        rc = -1;
        goto out;
    }

    rc = get_batch_info(ctx, gfns, types);
    if ( rc )
        goto out;

    rc = write_batch(ctx, gfns, types);
    if ( !rc )
    {
        VALGRIND_MAKE_MEM_UNDEFINED(ctx->save.batch_pfns,
                                    MAX_BATCH_SIZE *
                                    sizeof(*ctx->save.batch_pfns));
    }

 out:
    free(gfns);
    free(types);

    return rc;
}

/*
 * Add a single pfn to the batch.
 */
static void add_to_batch(struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    assert(ctx->save.nr_batch_pfns < batch_sizes[ctx->save.batch_type]);
    ctx->save.batch_pfns[ctx->save.nr_batch_pfns++] = pfn;
}

/*
 * This function:
 * - flushes the current batch of postcopy pfns into the migration stream
 * - clears the dirty bits of all pfns with no migrateable backing data
 * - counts the number of pfns that _do_ have migrateable backing data, adding
 *   it to nr_final_dirty_pfns
 */
static int flush_postcopy_pfns_batch(struct xc_sr_context *ctx)
{
    int rc = 0;
    xc_interface *xch = ctx->xch;
    xen_pfn_t *pfns = ctx->save.batch_pfns, *gfns = NULL, *types = NULL;
    unsigned int i, nr_pfns = ctx->save.nr_batch_pfns;

    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    assert(ctx->save.batch_type == XC_SR_SAVE_BATCH_POSTCOPY_PFN);

    if ( batch_empty(ctx) )
        goto out;

    gfns = malloc(nr_pfns * sizeof(*gfns));
    types = malloc(nr_pfns * sizeof(*types));

    if ( !gfns || !types )
    {
        ERROR("Unable to allocate arrays for a batch of %u pages",
              nr_pfns);
        rc = -1;
        goto out;
    }

    rc = get_batch_info(ctx, gfns, types);
    if ( rc )
        goto out;

    /*
     * Consider any pages not backed by a physical page of data to have been
     * 'cleaned' at this point - there's no sense wasting room in a subsequent
     * postcopy batch to duplicate the type information.
     */
    for ( i = 0; i < nr_pfns; ++i )
    {
        switch ( types[i] )
        {
        case XEN_DOMCTL_PFINFO_BROKEN:
        case XEN_DOMCTL_PFINFO_XALLOC:
        case XEN_DOMCTL_PFINFO_XTAB:
            clear_bit(pfns[i], dirty_bitmap);
            continue;
        }

        ++ctx->save.nr_final_dirty_pages;
    }

    rc = write_batch(ctx, gfns, types);
    if ( !rc )
    {
        VALGRIND_MAKE_MEM_UNDEFINED(ctx->save.batch_pfns,
                                    MAX_BATCH_SIZE *
                                    sizeof(*ctx->save.batch_pfns));
    }

 out:
    free(gfns);
    free(types);

    return rc;
}

/*
 * This function:
 * - writes a POSTCOPY_PFNS_BEGIN record into the stream
 * - writes 0 or more POSTCOPY_PFNS records specifying the subset of domain
 *   memory that must be migrated during the upcoming postcopy phase of the
 *   migration
 * - counts the number of pfns in this subset, storing it in
 *   nr_final_dirty_pages
 */
static int send_postcopy_pfns(struct xc_sr_context *ctx)
{
    xen_pfn_t p;
    int rc;

    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    /*
     * The true nr_final_dirty_pages is iteratively computed by
     * flush_postcopy_pfns_batch(), which counts only pages actually backed by
     * data we need to migrate.
     */
    ctx->save.nr_final_dirty_pages = 0;

    rc = write_postcopy_pfns_begin_record(ctx);
    if ( rc )
        return rc;

    assert(batch_empty(ctx));
    ctx->save.batch_type = XC_SR_SAVE_BATCH_POSTCOPY_PFN;
    for ( p = 0; p < ctx->save.p2m_size; ++p )
    {
        if ( !test_bit(p, dirty_bitmap) )
            continue;

        if ( batch_full(ctx) )
        {
            rc = flush_postcopy_pfns_batch(ctx);
            if ( rc )
                return rc;
        }

        add_to_batch(ctx, p);
    }

    return flush_postcopy_pfns_batch(ctx);
}

/*
 * Pause/suspend the domain, and refresh ctx->dominfo if required.
 */
static int suspend_domain(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;

    /* TODO: Properly specify the return value from this callback.  All
     * implementations currently appear to return 1 for success, whereas
     * the legacy code checks for != 0. */
    int cb_rc = ctx->save.callbacks->suspend(ctx->save.callbacks->data);

    if ( cb_rc == 0 )
    {
        ERROR("save callback suspend() failed: %d", cb_rc);
        return -1;
    }

    /* Refresh domain information. */
    if ( (xc_domain_getinfo(xch, ctx->domid, 1, &ctx->dominfo) != 1) ||
         (ctx->dominfo.domid != ctx->domid) )
    {
        PERROR("Unable to refresh domain information");
        return -1;
    }

    /* Confirm the domain has actually been paused. */
    if ( !ctx->dominfo.shutdown ||
         (ctx->dominfo.shutdown_reason != SHUTDOWN_suspend) )
    {
        ERROR("Domain has not been suspended: shutdown %d, reason %d",
              ctx->dominfo.shutdown, ctx->dominfo.shutdown_reason);
        return -1;
    }

    xc_report_progress_single(xch, "Domain now suspended");

    return 0;
}

/*
 * Send a subset of pages in the guests p2m, according to the dirty bitmap.
 * Used for each subsequent iteration of the live migration loop.
 *
 * During the precopy stage of a live migration, test the user-supplied
 * policy function after each batch of pages and cut off the operation
 * early if indicated (the dirty pages remaining in this round are transferred
 * into the deferred_pages bitmap).  This function writes observed precopy
 * policy decisions to ctx->save.policy_decision; callers must check this upon
 * return.
 *
 * Bitmap is bounded by p2m_size.
 */
static int send_dirty_pages(struct xc_sr_context *ctx,
                            unsigned long entries)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t p = 0;
    unsigned long written = 0;
    int rc;
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    int (*precopy_policy)(struct precopy_stats, void *) =
        ctx->save.callbacks->precopy_policy;
    void *data = ctx->save.callbacks->data;

    assert(batch_empty(ctx));
    ctx->save.batch_type = XC_SR_SAVE_BATCH_PRECOPY_PAGE;
    while ( p < ctx->save.p2m_size )
    {
        if ( ctx->save.phase == XC_SAVE_PHASE_PRECOPY )
        {
            ctx->save.policy_decision = precopy_policy(ctx->save.stats, data);

            if ( ctx->save.policy_decision == XGS_POLICY_ABORT )
            {
                IPRINTF("Precopy policy has requested we abort, cleaning up");
                return -1;
            }
            else if ( ctx->save.policy_decision != XGS_POLICY_CONTINUE_PRECOPY )
            {
                /*
                 * Any outstanding dirty pages are now deferred until the next
                 * phase of the migration.
                 */
                bitmap_or(ctx->save.deferred_pages, dirty_bitmap,
                          ctx->save.p2m_size);
                if ( entries > written )
                    ctx->save.nr_deferred_pages += entries - written;

                goto done;
            }
        }

        for ( ; p < ctx->save.p2m_size && !batch_full(ctx); ++p )
        {
            if ( test_and_clear_bit(p, dirty_bitmap) )
            {
                add_to_batch(ctx, p);
                ++written;
                ++ctx->save.stats.total_written;
            }
        }

        rc = flush_batch(ctx);
        if ( rc )
            return rc;

        /* Update progress after every batch (4MB) worth of memory sent. */
        xc_report_progress_step(xch, written, entries);
    }

    if ( written > entries )
        DPRINTF("Bitmap contained more entries than expected...");

    xc_report_progress_step(xch, entries, entries);

 done:
    return ctx->save.ops.check_vm_state(ctx);
}

/*
 * Send all pages in the guests p2m.  Used as the first iteration of the live
 * migration loop, and for a non-live save.
 */
static int send_all_pages(struct xc_sr_context *ctx)
{
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    bitmap_set(dirty_bitmap, ctx->save.p2m_size);

    return send_dirty_pages(ctx, ctx->save.p2m_size);
}

static int enable_logdirty(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int on1 = 0, off = 0, on2 = 0;
    int rc;

    /* This juggling is required if logdirty is enabled for VRAM tracking. */
    rc = xc_shadow_control(xch, ctx->domid,
                           XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
                           NULL, 0, NULL, 0, NULL);
    if ( rc < 0 )
    {
        on1 = errno;
        rc = xc_shadow_control(xch, ctx->domid, XEN_DOMCTL_SHADOW_OP_OFF,
                               NULL, 0, NULL, 0, NULL);
        if ( rc < 0 )
            off = errno;
        else {
            rc = xc_shadow_control(xch, ctx->domid,
                                   XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
                                   NULL, 0, NULL, 0, NULL);
            if ( rc < 0 )
                on2 = errno;
        }
        if ( rc < 0 )
        {
            PERROR("Failed to enable logdirty: %d,%d,%d", on1, off, on2);
            return rc;
        }
    }

    return 0;
}

static int update_progress_string(struct xc_sr_context *ctx,
                                  char **str, unsigned iter)
{
    xc_interface *xch = ctx->xch;
    char *new_str = NULL;

    if ( asprintf(&new_str, "Frames iteration %u", iter) == -1 )
    {
        PERROR("Unable to allocate new progress string");
        return -1;
    }

    free(*str);
    *str = new_str;

    xc_set_progress_prefix(xch, *str);
    return 0;
}

/*
 * Send memory while guest is running.
 */
static int send_memory_live(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    xc_shadow_op_stats_t stats = { 0, ctx->save.p2m_size };
    char *progress_str = NULL;
    int rc;

    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    int (*precopy_policy)(struct precopy_stats, void *) =
        ctx->save.callbacks->precopy_policy;
    void *data = ctx->save.callbacks->data;

    rc = update_progress_string(ctx, &progress_str, 0);
    if ( rc )
        goto out;

    ctx->save.stats = (struct precopy_stats)
        {
            .iteration     = 0,
            .total_written = 0,
            .dirty_count   = -1
        };

    /* This has the side-effect of priming ctx->save.policy_decision. */
    rc = send_all_pages(ctx);
    if ( rc )
        goto out;

    for ( ctx->save.stats.iteration = 1;
          ctx->save.policy_decision == XGS_POLICY_CONTINUE_PRECOPY;
          ++ctx->save.stats.iteration )
    {
        if ( xc_shadow_control(
                 xch, ctx->domid, XEN_DOMCTL_SHADOW_OP_CLEAN,
                 &ctx->save.dirty_bitmap_hbuf, ctx->save.p2m_size,
                 NULL, 0, &stats) != ctx->save.p2m_size )
        {
            PERROR("Failed to retrieve logdirty bitmap");
            rc = -1;
            goto out;
        }

        /* Check the new dirty_count against the policy. */
        ctx->save.stats.dirty_count = stats.dirty_count;
        ctx->save.policy_decision = precopy_policy(ctx->save.stats, data);
        if ( ctx->save.policy_decision == XGS_POLICY_ABORT )
        {
            IPRINTF("Precopy policy has requested we abort, cleaning up");
            rc = -1;
            goto out;
        }
        else if ( ctx->save.policy_decision != XGS_POLICY_CONTINUE_PRECOPY )
        {
            bitmap_or(ctx->save.deferred_pages, dirty_bitmap,
                      ctx->save.p2m_size);
            ctx->save.nr_deferred_pages += stats.dirty_count;
            rc = 0;
            goto out;
        }

        /*
         * After this point we won't know how many pages are really dirty until
         * the next iteration.
         */
        ctx->save.stats.dirty_count = -1;

        rc = update_progress_string(ctx, &progress_str,
                                    ctx->save.stats.iteration);
        if ( rc )
            goto out;

        rc = send_dirty_pages(ctx, stats.dirty_count);
        if ( rc )
            goto out;
    }

 out:
    xc_set_progress_prefix(xch, NULL);
    free(progress_str);
    return rc;
}

static int colo_merge_secondary_dirty_bitmap(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_record rec = { 0, 0, NULL };
    uint64_t *pfns = NULL;
    uint64_t pfn;
    unsigned count, i;
    int rc;
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    rc = read_record(ctx, ctx->save.recv_fd, &rec);
    if ( rc )
        goto err;

    if ( rec.type != REC_TYPE_CHECKPOINT_DIRTY_PFN_LIST )
    {
        PERROR("Expect dirty bitmap record, but received %u", rec.type );
        rc = -1;
        goto err;
    }

    if ( rec.length % sizeof(*pfns) )
    {
        PERROR("Invalid dirty pfn list record length %u", rec.length );
        rc = -1;
        goto err;
    }

    count = rec.length / sizeof(*pfns);
    pfns = rec.data;

    for ( i = 0; i < count; i++ )
    {
        pfn = pfns[i];
        if (pfn > ctx->save.p2m_size)
        {
            PERROR("Invalid pfn 0x%" PRIx64, pfn);
            rc = -1;
            goto err;
        }

        set_bit(pfn, dirty_bitmap);
    }

    rc = 0;

 err:
    free(rec.data);
    return rc;
}

/*
 * Suspend the domain and determine the final set of dirty pages.
 */
static int suspend_and_check_dirty(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    xc_shadow_op_stats_t stats = { 0, ctx->save.p2m_size };
    int rc;
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    ctx->save.phase = (ctx->save.policy_decision == XGS_POLICY_POSTCOPY)
        ? XC_SAVE_PHASE_POSTCOPY
        : XC_SAVE_PHASE_STOP_AND_COPY;

    rc = suspend_domain(ctx);
    if ( rc )
        goto out;

    if ( xc_shadow_control(
             xch, ctx->domid, XEN_DOMCTL_SHADOW_OP_CLEAN,
             HYPERCALL_BUFFER(dirty_bitmap), ctx->save.p2m_size,
             NULL, XEN_DOMCTL_SHADOW_LOGDIRTY_FINAL, &stats) !=
         ctx->save.p2m_size )
    {
        PERROR("Failed to retrieve logdirty bitmap");
        rc = -1;
        goto out;
    }

    bitmap_or(dirty_bitmap, ctx->save.deferred_pages, ctx->save.p2m_size);

    if ( !ctx->save.live && ctx->save.checkpointed == XC_MIG_STREAM_COLO )
    {
        rc = colo_merge_secondary_dirty_bitmap(ctx);
        if ( rc )
        {
            PERROR("Failed to get secondary vm's dirty pages");
            goto out;
        }
    }

    if ( !ctx->save.live || ctx->save.policy_decision != XGS_POLICY_POSTCOPY )
    {
        /*
         * If we aren't transitioning to a postcopy live migration, then rather
         * than explicitly counting the number of final dirty pages, simply
         * (somewhat crudely) estimate it as this sum to save time.  If we _are_
         * about to begin postcopy then we don't bother, since our count must in
         * that case be exact and we'll work it out later on.
         */
        ctx->save.nr_final_dirty_pages =
            stats.dirty_count + ctx->save.nr_deferred_pages;
    }

    bitmap_clear(ctx->save.deferred_pages, ctx->save.p2m_size);
    ctx->save.nr_deferred_pages = 0;

 out:
    return rc;
}

static int suspend_and_send_dirty(struct xc_sr_context *ctx)
{
    int rc;

    rc = suspend_and_check_dirty(ctx);
    if ( rc )
        return rc;

    return send_dirty_pages(ctx, ctx->save.nr_final_dirty_pages);
}

static int verify_frames(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    xc_shadow_op_stats_t stats = { 0, ctx->save.p2m_size };
    int rc;
    struct xc_sr_record rec =
    {
        .type = REC_TYPE_VERIFY,
        .length = 0,
    };

    DPRINTF("Enabling verify mode");

    rc = write_record(ctx, ctx->fd, &rec);
    if ( rc )
        goto out;

    xc_set_progress_prefix(xch, "Frames verify");
    rc = send_all_pages(ctx);
    if ( rc )
        goto out;

    if ( xc_shadow_control(
             xch, ctx->domid, XEN_DOMCTL_SHADOW_OP_PEEK,
             &ctx->save.dirty_bitmap_hbuf, ctx->save.p2m_size,
             NULL, 0, &stats) != ctx->save.p2m_size )
    {
        PERROR("Failed to retrieve logdirty bitmap");
        rc = -1;
        goto out;
    }

    DPRINTF("  Further stats: faults %u, dirty %u",
            stats.fault_count, stats.dirty_count);

 out:
    return rc;
}

/*
 * Send all domain memory, modulo postcopy pages.  This is the heart of the live
 * migration loop.
 */
static int send_domain_memory_live(struct xc_sr_context *ctx)
{
    int rc;
    xc_interface *xch = ctx->xch;

    rc = enable_logdirty(ctx);
    if ( rc )
        goto out;

    rc = send_memory_live(ctx);
    if ( rc )
        goto out;

    rc = suspend_and_check_dirty(ctx);
    if ( rc )
        goto out;

    if ( ctx->save.policy_decision == XGS_POLICY_STOP_AND_COPY )
    {
        xc_set_progress_prefix(xch, "Final precopy iteration");
        rc = send_dirty_pages(ctx, ctx->save.nr_final_dirty_pages);
        xc_set_progress_prefix(xch, NULL);
        if ( rc )
            goto out;
    }

    if ( ctx->save.debug && ctx->save.checkpointed != XC_MIG_STREAM_NONE )
    {
        rc = verify_frames(ctx);
        if ( rc )
            goto out;
    }

  out:
    return rc;
}

static int handle_postcopy_faults(struct xc_sr_context *ctx,
                                  struct xc_sr_record *rec,
                                  /* OUT */ unsigned long *nr_new_fault_pfns,
                                  /* OUT */ xen_pfn_t *last_fault_pfn)
{
    int rc;
    unsigned int i;
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_pages_header *fault_pages = rec->data;

    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    assert(nr_new_fault_pfns);
    *nr_new_fault_pfns = 0;

    rc = validate_pages_record(ctx, rec, REC_TYPE_POSTCOPY_FAULT);
    if ( rc )
        return rc;

    DBGPRINTF("Handling a batch of %"PRIu32" faults!", fault_pages->count);

    assert(ctx->save.batch_type == XC_SR_SAVE_BATCH_POSTCOPY_PAGE);
    for ( i = 0; i < fault_pages->count; ++i )
    {
        if ( test_and_clear_bit(fault_pages->pfn[i], dirty_bitmap) )
        {
            if ( batch_full(ctx) )
            {
                rc = flush_batch(ctx);
                if ( rc )
                    return rc;
            }

            add_to_batch(ctx, fault_pages->pfn[i]);
            ++(*nr_new_fault_pfns);
        }
    }

    /* _Don't_ flush yet - fill out the rest of the batch. */

    assert(fault_pages->count);
    *last_fault_pfn = fault_pages->pfn[fault_pages->count - 1];
    return 0;
}

/*
 * Now that the guest has resumed at the destination, send all of the remaining
 * dirty pages.  Periodically check for pages needed by the destination to make
 * progress.
 */
static int postcopy_domain_memory(struct xc_sr_context *ctx)
{
    int rc;
    xc_interface *xch = ctx->xch;
    int recv_fd = ctx->save.recv_fd;
    int old_flags;
    struct xc_sr_read_record_context rrctx;
    struct xc_sr_record rec = { 0, 0, NULL };
    unsigned long nr_new_fault_pfns;
    unsigned long pages_remaining = ctx->save.nr_final_dirty_pages;
    xen_pfn_t last_fault_pfn, p;
    bool received_postcopy_complete = false;

    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    read_record_init(&rrctx, ctx);

    /*
     * First, configure the receive stream as non-blocking so we can
     * periodically poll it for fault requests.
     */
    old_flags = fcntl(recv_fd, F_GETFL);
    if ( old_flags == -1 )
    {
        rc = old_flags;
        goto err;
    }

    assert(!(old_flags & O_NONBLOCK));

    rc = fcntl(recv_fd, F_SETFL, old_flags | O_NONBLOCK);
    if ( rc == -1 )
    {
        goto err;
    }

    xc_set_progress_prefix(xch, "Postcopy phase");

    assert(batch_empty(ctx));
    ctx->save.batch_type = XC_SR_SAVE_BATCH_POSTCOPY_PAGE;

    p = 0;
    while ( pages_remaining )
    {
        /*
         * Between (small) batches, poll the receive stream for new
         * POSTCOPY_FAULT messages.
         */
        for ( ; ; )
        {
            rc = try_read_record(&rrctx, recv_fd, &rec);
            if ( rc )
            {
                if ( (errno == EAGAIN) || (errno == EWOULDBLOCK) )
                {
                    break;
                }

                goto err;
            }
            else
            {
                /*
                 * Tear down and re-initialize the read record context for the
                 * next request record.
                 */
                read_record_destroy(&rrctx);
                read_record_init(&rrctx, ctx);

                if ( rec.type == REC_TYPE_POSTCOPY_COMPLETE )
                {
                    /*
                     * The restore side may ultimately not need all of the pages
                     * we think it does - for example, the guest may release
                     * some outstanding pages.  If this occurs, we'll receive
                     * this record before we'd otherwise expect to.
                     */
                    received_postcopy_complete = true;
                    goto done;
                }

                rc = handle_postcopy_faults(ctx, &rec, &nr_new_fault_pfns,
                                            &last_fault_pfn);
                if ( rc )
                    goto err;

                free(rec.data);
                rec.data = NULL;

                assert(pages_remaining >= nr_new_fault_pfns);
                pages_remaining -= nr_new_fault_pfns;

                /*
                 * To take advantage of any locality present in the postcopy
                 * faults, continue the background copy process from the newest
                 * page in the fault batch.
                 */
                p = (last_fault_pfn + 1) % ctx->save.p2m_size;
            }
        }

        /*
         * Now that we've serviced all of the POSTCOPY_FAULT requests we know
         * about for now, fill out the current batch with background pages.
         */
        for ( ;
              pages_remaining && !batch_full(ctx);
              p = (p + 1) % ctx->save.p2m_size )
        {
            if ( test_and_clear_bit(p, dirty_bitmap) )
            {
                add_to_batch(ctx, p);
                --pages_remaining;
            }
        }

        rc = flush_batch(ctx);
        if ( rc )
            goto err;

        xc_report_progress_step(
            xch, ctx->save.nr_final_dirty_pages - pages_remaining,
            ctx->save.nr_final_dirty_pages);
    }

 done:
    /* Revert the receive stream to the (blocking) state we found it in. */
    rc = fcntl(recv_fd, F_SETFL, old_flags);
    if ( rc == -1 )
        goto err;

    if ( !received_postcopy_complete )
    {
        /*
         * Flush any outstanding POSTCOPY_FAULT requests from the migration
         * stream by reading until a POSTCOPY_COMPLETE is received.
         */
        do
        {
            rc = read_record(ctx, recv_fd, &rec);
            if ( rc )
                goto err;
        } while ( rec.type != REC_TYPE_POSTCOPY_COMPLETE );
    }

 err:
    xc_set_progress_prefix(xch, NULL);
    free(rec.data);
    read_record_destroy(&rrctx);
    return rc;
}

/*
 * Checkpointed save.
 */
static int send_domain_memory_checkpointed(struct xc_sr_context *ctx)
{
    int rc;
    xc_interface *xch = ctx->xch;

    xc_set_progress_prefix(xch, "Checkpointed save");
    rc = suspend_and_send_dirty(ctx);
    xc_set_progress_prefix(xch, NULL);

    return rc;
}

/*
 * Send all domain memory, pausing the domain first.  Generally used for
 * suspend-to-file.
 */
static int send_domain_memory_nonlive(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc;

    rc = suspend_domain(ctx);
    if ( rc )
        goto err;

    xc_set_progress_prefix(xch, "Frames");

    rc = send_all_pages(ctx);
    if ( rc )
        goto err;

 err:
    return rc;
}

static int setup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc;
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);

    ctx->save.phase = ctx->save.live ? XC_SAVE_PHASE_PRECOPY
                                     : XC_SAVE_PHASE_STOP_AND_COPY;

    rc = ctx->save.ops.setup(ctx);
    if ( rc )
        goto err;

    dirty_bitmap = xc_hypercall_buffer_alloc_pages(
                   xch, dirty_bitmap, NRPAGES(bitmap_size(ctx->save.p2m_size)));
    ctx->save.batch_pfns = malloc(MAX_BATCH_SIZE *
                                  sizeof(*ctx->save.batch_pfns));
    ctx->save.deferred_pages = calloc(1, bitmap_size(ctx->save.p2m_size));

    if ( !ctx->save.batch_pfns || !dirty_bitmap || !ctx->save.deferred_pages )
    {
        ERROR("Unable to allocate memory for dirty bitmaps, batch pfns and"
              " deferred pages");
        rc = -1;
        errno = ENOMEM;
        goto err;
    }

    rc = 0;

 err:
    return rc;
}

static void cleanup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->save.dirty_bitmap_hbuf);


    xc_shadow_control(xch, ctx->domid, XEN_DOMCTL_SHADOW_OP_OFF,
                      NULL, 0, NULL, 0, NULL);

    if ( ctx->save.ops.cleanup(ctx) )
        PERROR("Failed to clean up");

    xc_hypercall_buffer_free_pages(xch, dirty_bitmap,
                                   NRPAGES(bitmap_size(ctx->save.p2m_size)));
    free(ctx->save.deferred_pages);
    free(ctx->save.batch_pfns);
}

/*
 * Save a domain.
 */
static int save(struct xc_sr_context *ctx, uint16_t guest_type)
{
    xc_interface *xch = ctx->xch;
    int rc, saved_rc = 0, saved_errno = 0;

    IPRINTF("Saving domain %d, type %s",
            ctx->domid, dhdr_type_to_str(guest_type));

    rc = setup(ctx);
    if ( rc )
        goto err;

    xc_report_progress_single(xch, "Start of stream");

    rc = write_headers(ctx, guest_type);
    if ( rc )
        goto err;

    rc = ctx->save.ops.start_of_stream(ctx);
    if ( rc )
        goto err;

    do {
        rc = ctx->save.ops.start_of_checkpoint(ctx);
        if ( rc )
            goto err;

        rc = ctx->save.ops.check_vm_state(ctx);
        if ( rc )
            goto err;

        if ( ctx->save.live )
            rc = send_domain_memory_live(ctx);
        else if ( ctx->save.checkpointed != XC_MIG_STREAM_NONE )
            rc = send_domain_memory_checkpointed(ctx);
        else
            rc = send_domain_memory_nonlive(ctx);

        if ( rc )
            goto err;

        if ( !ctx->dominfo.shutdown ||
             (ctx->dominfo.shutdown_reason != SHUTDOWN_suspend) )
        {
            ERROR("Domain has not been suspended");
            rc = -1;
            goto err;
        }

        /*
         * End-of-checkpoint records are handled differently in the case of
         * postcopy migration, so we need to alert the destination before
         * sending them.
         */
        if ( ctx->save.live &&
             ctx->save.policy_decision == XGS_POLICY_POSTCOPY )
        {
            rc = write_postcopy_begin_record(ctx);
            if ( rc )
                goto err;
        }

        rc = ctx->save.ops.end_of_checkpoint(ctx);
        if ( rc )
            goto err;

        if ( ctx->save.live &&
             ctx->save.policy_decision == XGS_POLICY_POSTCOPY )
        {
            xc_report_progress_single(xch, "Beginning postcopy transition");

            rc = send_postcopy_pfns(ctx);
            if ( rc )
                goto err;

            rc = write_postcopy_transition_record(ctx);
            if ( rc )
                goto err;

            /*
             * Yield control to libxl to finish the transition.  Note that this
             * callback returns _non-zero_ upon success.
             */
            rc = ctx->save.callbacks->postcopy_transition(
                ctx->save.callbacks->data);
            if ( !rc )
            {
                rc = -1;
                goto err;
            }

            /* When libxl is done, we can begin the postcopy loop. */
            rc = postcopy_domain_memory(ctx);
            if ( rc )
                goto err;
        }
        else if ( ctx->save.checkpointed != XC_MIG_STREAM_NONE )
        {
            /*
             * We have now completed the initial live portion of the checkpoint
             * process. Therefore switch into periodically sending synchronous
             * batches of pages.
             */
            ctx->save.live = false;

            rc = write_checkpoint_record(ctx);
            if ( rc )
                goto err;

            if ( ctx->save.checkpointed == XC_MIG_STREAM_COLO )
            {
                rc = ctx->save.callbacks->checkpoint(ctx->save.callbacks->data);
                if ( !rc )
                {
                    rc = -1;
                    goto err;
                }
            }

            rc = ctx->save.callbacks->aftercopy(ctx->save.callbacks->data);
            if ( rc <= 0 )
                goto err;

            if ( ctx->save.checkpointed == XC_MIG_STREAM_COLO )
            {
                rc = ctx->save.callbacks->wait_checkpoint(
                    ctx->save.callbacks->data);
                if ( rc <= 0 )
                    goto err;
            }
            else if ( ctx->save.checkpointed == XC_MIG_STREAM_REMUS )
            {
                rc = ctx->save.callbacks->checkpoint(ctx->save.callbacks->data);
                if ( rc <= 0 )
                    goto err;
            }
            else
            {
                ERROR("Unknown checkpointed stream");
                rc = -1;
                goto err;
            }
        }
    } while ( ctx->save.checkpointed != XC_MIG_STREAM_NONE );

    xc_report_progress_single(xch, "End of stream");

    rc = write_end_record(ctx);
    if ( rc )
        goto err;

    xc_report_progress_single(xch, "Complete");
    goto done;

 err:
    saved_errno = errno;
    saved_rc = rc;
    PERROR("Save failed");

 done:
    cleanup(ctx);

    if ( saved_rc )
    {
        rc = saved_rc;
        errno = saved_errno;
    }

    return rc;
};

int xc_domain_save(xc_interface *xch, const struct domain_save_params *params,
                   const struct save_callbacks* callbacks)
{
    struct xc_sr_context ctx =
        {
            .xch = xch,
            .fd = params->save_fd,
        };

    /* GCC 4.4 (of CentOS 6.x vintage) can' t initialise anonymous unions. */
    ctx.save.callbacks = callbacks;
    ctx.save.live  = params->live;
    ctx.save.debug = params->debug;
    ctx.save.checkpointed = params->stream_type;
    ctx.save.recv_fd = params->recv_fd;

    /* If altering migration_stream update this assert too. */
    assert(params->stream_type == XC_MIG_STREAM_NONE ||
           params->stream_type == XC_MIG_STREAM_REMUS ||
           params->stream_type == XC_MIG_STREAM_COLO);

    if ( xc_domain_getinfo(xch, params->dom, 1, &ctx.dominfo) != 1 )
    {
        PERROR("Failed to get domain info");
        return -1;
    }

    if ( ctx.dominfo.domid != params->dom )
    {
        ERROR("Domain %u does not exist", params->dom);
        return -1;
    }

    /* Sanity checks for callbacks. */
    if ( ctx.dominfo.hvm )
        assert(callbacks->switch_qemu_logdirty);
    if ( ctx.save.checkpointed )
        assert(callbacks->checkpoint && callbacks->aftercopy);
    if ( ctx.save.checkpointed == XC_MIG_STREAM_COLO )
        assert(callbacks->wait_checkpoint);

    ctx.domid = params->dom;

    DPRINTF("fd %d, dom %u, live %d, debug %d, type %d, hvm %d", ctx.fd,
            ctx.domid, ctx.save.live, ctx.save.debug, ctx.save.checkpointed,
            ctx.dominfo.hvm);

    if ( ctx.dominfo.hvm )
    {
        ctx.save.ops = save_ops_x86_hvm;
        return save(&ctx, DHDR_TYPE_X86_HVM);
    }
    else
    {
        ctx.save.ops = save_ops_x86_pv;
        return save(&ctx, DHDR_TYPE_X86_PV);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
