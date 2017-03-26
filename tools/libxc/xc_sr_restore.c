#include <arpa/inet.h>

#include <assert.h>
#include <poll.h>

#include "xc_sr_common.h"

/*
 * Read and validate the Image and Domain headers.
 */
static int read_headers(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_ihdr ihdr;
    struct xc_sr_dhdr dhdr;

    if ( read_exact(ctx->fd, &ihdr, sizeof(ihdr)) )
    {
        PERROR("Failed to read Image Header from stream");
        return -1;
    }

    ihdr.id      = ntohl(ihdr.id);
    ihdr.version = ntohl(ihdr.version);
    ihdr.options = ntohs(ihdr.options);

    if ( ihdr.marker != IHDR_MARKER )
    {
        ERROR("Invalid marker: Got 0x%016"PRIx64, ihdr.marker);
        return -1;
    }
    else if ( ihdr.id != IHDR_ID )
    {
        ERROR("Invalid ID: Expected 0x%08x, Got 0x%08x", IHDR_ID, ihdr.id);
        return -1;
    }
    else if ( ihdr.version != IHDR_VERSION )
    {
        ERROR("Invalid Version: Expected %d, Got %d",
              ihdr.version, IHDR_VERSION);
        return -1;
    }
    else if ( ihdr.options & IHDR_OPT_BIG_ENDIAN )
    {
        ERROR("Unable to handle big endian streams");
        return -1;
    }

    ctx->restore.format_version = ihdr.version;

    if ( read_exact(ctx->fd, &dhdr, sizeof(dhdr)) )
    {
        PERROR("Failed to read Domain Header from stream");
        return -1;
    }

    ctx->restore.guest_type = dhdr.type;
    ctx->restore.guest_page_size = (1U << dhdr.page_shift);

    if ( dhdr.xen_major == 0 )
    {
        IPRINTF("Found %s domain, converted from legacy stream format",
                dhdr_type_to_str(dhdr.type));
        DPRINTF("  Legacy conversion script version %u", dhdr.xen_minor);
    }
    else
        IPRINTF("Found %s domain from Xen %u.%u",
                dhdr_type_to_str(dhdr.type), dhdr.xen_major, dhdr.xen_minor);
    return 0;
}

/*
 * Is a pfn populated?
 */
static bool pfn_is_populated(const struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    if ( pfn > ctx->restore.max_populated_pfn )
        return false;
    return test_bit(pfn, ctx->restore.populated_pfns);
}

static int pfn_bitmap_realloc(struct xc_sr_context *ctx, unsigned long **bitmap,
                              size_t old_sz, size_t new_sz)
{
    xc_interface *xch = ctx->xch;
    unsigned long *p;

    assert(bitmap);
    if ( *bitmap )
    {
        p = realloc(*bitmap, new_sz);
        if ( !p )
        {
            ERROR("Failed to realloc restore bitmap");
            errno = ENOMEM;
            return -1;
        }

        memset((uint8_t *)p + old_sz, 0x00, new_sz - old_sz);
        *bitmap = p;
    }

    return 0;
}

/*
 * Set a pfn as populated, expanding the tracking structures if needed. To
 * avoid realloc()ing too excessively, the size increased to the nearest power
 * of two large enough to contain the required pfn.
 */
static int pfn_set_populated(struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    int rc;

    if ( pfn > ctx->restore.max_populated_pfn )
    {
        xen_pfn_t new_max;
        size_t old_sz, new_sz;
        unsigned i;
        unsigned long **bitmaps[] =
        {
            &ctx->restore.populated_pfns,
            &ctx->restore.paging.outstanding_pfns,
            &ctx->restore.paging.requested_pfns,
            &ctx->restore.paging.ready_pfns,
            &ctx->restore.paging.dropped_pfns
        };

        /* Round up to the nearest power of two larger than pfn, less 1. */
        new_max = pfn;
        new_max |= new_max >> 1;
        new_max |= new_max >> 2;
        new_max |= new_max >> 4;
        new_max |= new_max >> 8;
        new_max |= new_max >> 16;
#ifdef __x86_64__
        new_max |= new_max >> 32;
#endif

        old_sz = bitmap_size(ctx->restore.max_populated_pfn + 1);
        new_sz = bitmap_size(new_max + 1);

        for ( i = 0; i < ARRAY_SIZE(bitmaps) && !rc; ++i )
            rc = pfn_bitmap_realloc(ctx, bitmaps[i], old_sz, new_sz);

        if ( rc )
            return rc;

        ctx->restore.max_populated_pfn = new_max;
    }

    assert(!test_bit(pfn, ctx->restore.populated_pfns));
    set_bit(pfn, ctx->restore.populated_pfns);

    return 0;
}

/*
 * Given a set of pfns, obtain memory from Xen to fill the physmap for the
 * unpopulated subset.  If types is NULL, no page type checking is performed
 * and all unpopulated pfns are populated.
 */
int populate_pfns(struct xc_sr_context *ctx, unsigned count,
                  const xen_pfn_t *original_pfns, const uint32_t *types)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t *mfns = malloc(count * sizeof(*mfns)),
        *pfns = malloc(count * sizeof(*pfns));
    unsigned i, nr_pfns = 0;
    int rc = -1;

    if ( !mfns || !pfns )
    {
        ERROR("Failed to allocate %zu bytes for populating the physmap",
              2 * count * sizeof(*mfns));
        goto err;
    }

    for ( i = 0; i < count; ++i )
    {
        if ( (!types || (types &&
                         (types[i] != XEN_DOMCTL_PFINFO_XTAB &&
                          types[i] != XEN_DOMCTL_PFINFO_BROKEN))) &&
             !pfn_is_populated(ctx, original_pfns[i]) )
        {
            rc = pfn_set_populated(ctx, original_pfns[i]);
            if ( rc )
                goto err;
            pfns[nr_pfns] = mfns[nr_pfns] = original_pfns[i];
            ++nr_pfns;
        }
    }

    if ( nr_pfns )
    {
        rc = xc_domain_populate_physmap_exact(
            xch, ctx->domid, nr_pfns, 0, 0, mfns);
        if ( rc )
        {
            PERROR("Failed to populate physmap");
            goto err;
        }

        for ( i = 0; i < nr_pfns; ++i )
        {
            if ( mfns[i] == INVALID_MFN )
            {
                ERROR("Populate physmap failed for pfn %u", i);
                rc = -1;
                goto err;
            }

            ctx->restore.ops.set_gfn(ctx, pfns[i], mfns[i]);
        }
    }

    rc = 0;

 err:
    free(pfns);
    free(mfns);

    return rc;
}

static void set_page_types(struct xc_sr_context *ctx, unsigned count,
                           xen_pfn_t *pfns, uint32_t *types)
{
    unsigned i;

    for ( i = 0; i < count; ++i )
        ctx->restore.ops.set_page_type(ctx, pfns[i], types[i]);
}

/*
 * Given count pfns and their types, allocate and fill in buffer bpfns with only
 * those pfns that are 'backed' by real page data that needs to be migrated.
 * The caller must later free() *bpfns.
 *
 * Returns 0 on success and non-0 on failure.  *bpfns can be free()ed even after
 * failure.
 */
static int filter_pages(struct xc_sr_context *ctx,
                        unsigned count,
                        xen_pfn_t *pfns,
                        uint32_t *types,
                        /* OUT */ unsigned *nr_pages,
                        /* OUT */ xen_pfn_t **bpfns)
{
    xc_interface *xch = ctx->xch;
    unsigned i;

    *nr_pages = 0;
    *bpfns = malloc(count * sizeof(*bpfns));
    if ( !(*bpfns) )
    {
        ERROR("Failed to allocate %zu bytes to process page data",
              count * (sizeof(*bpfns)));
        return -1;
    }

    for ( i = 0; i < count; ++i )
    {
        switch ( types[i] )
        {
        case XEN_DOMCTL_PFINFO_NOTAB:

        case XEN_DOMCTL_PFINFO_L1TAB:
        case XEN_DOMCTL_PFINFO_L1TAB | XEN_DOMCTL_PFINFO_LPINTAB:

        case XEN_DOMCTL_PFINFO_L2TAB:
        case XEN_DOMCTL_PFINFO_L2TAB | XEN_DOMCTL_PFINFO_LPINTAB:

        case XEN_DOMCTL_PFINFO_L3TAB:
        case XEN_DOMCTL_PFINFO_L3TAB | XEN_DOMCTL_PFINFO_LPINTAB:

        case XEN_DOMCTL_PFINFO_L4TAB:
        case XEN_DOMCTL_PFINFO_L4TAB | XEN_DOMCTL_PFINFO_LPINTAB:

            (*bpfns)[(*nr_pages)++] = pfns[i];
            break;
        }
    }

    return 0;
}

/*
 * Given a list of pfns, their types, and a block of page data from the
 * stream, populate and record their types, map the relevant subset and copy
 * the data into the guest.
 */
static int process_page_data(struct xc_sr_context *ctx, unsigned count,
                             xen_pfn_t *pfns, uint32_t *types, void *page_data)
{
    xc_interface *xch = ctx->xch;
    xen_pfn_t *mfns = NULL;
    int *map_errs = malloc(count * sizeof(*map_errs));
    int rc;
    void *mapping = NULL, *guest_page = NULL;
    unsigned i,    /* i indexes the pfns from the record. */
        j,         /* j indexes the subset of pfns we decide to map. */
        nr_pages = 0;

    if ( !map_errs )
    {
        rc = -1;
        ERROR("Failed to allocate %zu bytes to process page data",
              count * sizeof(*map_errs));
        goto err;
    }

    rc = populate_pfns(ctx, count, pfns, types);
    if ( rc )
    {
        ERROR("Failed to populate pfns for batch of %u pages", count);
        goto err;
    }

    set_page_types(ctx, count, pfns, types);

    rc = filter_pages(ctx, count, pfns, types, &nr_pages, &mfns);
    if ( rc )
    {
        ERROR("Failed to filter mfns for batch of %u pages", count);
        goto err;
    }

    /* Map physically-backed pfns ('bpfns') to their gmfns. */
    for ( i = 0; i < nr_pages; ++i )
        mfns[i] = ctx->restore.ops.pfn_to_gfn(ctx, mfns[i]);

    /* Nothing to do? */
    if ( nr_pages == 0 )
        goto done;

    mapping = guest_page = xenforeignmemory_map(xch->fmem,
        ctx->domid, PROT_READ | PROT_WRITE,
        nr_pages, mfns, map_errs);
    if ( !mapping )
    {
        rc = -1;
        PERROR("Unable to map %u mfns for %u pages of data",
               nr_pages, count);
        goto err;
    }

    for ( i = 0, j = 0; i < count; ++i )
    {
        switch ( types[i] )
        {
        case XEN_DOMCTL_PFINFO_XTAB:
        case XEN_DOMCTL_PFINFO_BROKEN:
        case XEN_DOMCTL_PFINFO_XALLOC:
            /* No page data to deal with. */
            continue;
        }

        if ( map_errs[j] )
        {
            rc = -1;
            ERROR("Mapping pfn %#"PRIpfn" (mfn %#"PRIpfn", type %#"PRIx32") failed with %d",
                  pfns[i], mfns[j], types[i], map_errs[j]);
            goto err;
        }

        /* Undo page normalisation done by the saver. */
        rc = ctx->restore.ops.localise_page(ctx, types[i], page_data);
        if ( rc )
        {
            ERROR("Failed to localise pfn %#"PRIpfn" (type %#"PRIx32")",
                  pfns[i], types[i] >> XEN_DOMCTL_PFINFO_LTAB_SHIFT);
            goto err;
        }

        if ( ctx->restore.verify )
        {
            /* Verify mode - compare incoming data to what we already have. */
            if ( memcmp(guest_page, page_data, PAGE_SIZE) )
                ERROR("verify pfn %#"PRIpfn" failed (type %#"PRIx32")",
                      pfns[i], types[i] >> XEN_DOMCTL_PFINFO_LTAB_SHIFT);
        }
        else
        {
            /* Regular mode - copy incoming data into place. */
            memcpy(guest_page, page_data, PAGE_SIZE);
        }

        ++j;
        guest_page += PAGE_SIZE;
        page_data += PAGE_SIZE;
    }

 done:
    rc = 0;

 err:
    if ( mapping )
        xenforeignmemory_unmap(xch->fmem, mapping, nr_pages);

    free(map_errs);
    free(mfns);

    return rc;
}

/*
 * Given a PAGE_DATA record, decode each packed entry into its encoded pfn and
 * type, storing the results in newly-allocated pfns and types buffers that the
 * caller must later free().  *pfns and *types may safely be free()ed even after
 * failure.
 */
static int decode_pages_record(struct xc_sr_context *ctx,
                               struct xc_sr_rec_pages_header *pages,
                               /* OUT */ xen_pfn_t **pfns,
                               /* OUT */ uint32_t **types,
                               /* OUT */ unsigned *pages_of_data)
{
    xc_interface *xch = ctx->xch;
    unsigned i;
    xen_pfn_t pfn;
    uint32_t type;

    *pfns = malloc(pages->count * sizeof(*pfns));
    *types = malloc(pages->count * sizeof(*types));
    *pages_of_data = 0;
    if ( !pfns || !types )
    {
        ERROR("Unable to allocate enough memory for %u pfns",
              pages->count);
        goto err;
    }

    for ( i = 0; i < pages->count; ++i )
    {
        pfn = pages->pfn[i] & REC_PFINFO_PFN_MASK;
        if ( !ctx->restore.ops.pfn_is_valid(ctx, pfn) )
        {
            ERROR("pfn %#"PRIpfn" (index %u) outside domain maximum", pfn, i);
            goto err;
        }

        type = (pages->pfn[i] & REC_PFINFO_TYPE_MASK) >> 32;
        if ( ((type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT) >= 5) &&
             ((type >> XEN_DOMCTL_PFINFO_LTAB_SHIFT) <= 8) )
        {
            ERROR("Invalid type %#"PRIx32" for pfn %#"PRIpfn" (index %u)",
                  type, pfn, i);
            goto err;
        }
        else if ( type < XEN_DOMCTL_PFINFO_BROKEN )
            /* NOTAB and all L1 through L4 tables (including pinned) require the
             * migration of a page of real data. */
            (*pages_of_data)++;

        (*pfns)[i] = pfn;
        (*types)[i] = type;
    }

    return 0;

 err:
    free(*pfns);
    *pfns = NULL;

    free(*types);
    *types = NULL;

    *pages_of_data = 0;

    return -1;
}

/*
 * Validate a PAGE_DATA record from the stream, and pass the results to
 * process_page_data() to actually perform the legwork.
 */
static int handle_page_data(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_pages_header *pages = rec->data;
    unsigned pages_of_data;
    int rc = -1;

    xen_pfn_t *pfns = NULL;
    uint32_t *types = NULL;

    rc = validate_pages_record(ctx, rec, REC_TYPE_PAGE_DATA);
    if ( rc )
        goto err;

    rc = decode_pages_record(ctx, pages, &pfns, &types, &pages_of_data);
    if ( rc )
        goto err;

    if ( rec->length != (sizeof(*pages) +
                         (sizeof(uint64_t) * pages->count) +
                         (PAGE_SIZE * pages_of_data)) )
    {
        ERROR("PAGE_DATA record wrong size: length %u, expected "
              "%zu + %zu + %lu", rec->length, sizeof(*pages),
              (sizeof(uint64_t) * pages->count), (PAGE_SIZE * pages_of_data));
        goto err;
    }

    rc = process_page_data(ctx, pages->count, pfns, types,
                           &pages->pfn[pages->count]);
 err:
    free(types);
    free(pfns);

    return rc;
}

/*
 * To prepare for entry to the postcopy phase of live migration:
 * - enable paging on the domain, and set up the paging ring and event channel
 * - allocate a locked and aligned paging buffer
 * - allocate the postcopy page bookkeeping structures
 */
static int postcopy_paging_setup(struct xc_sr_context *ctx)
{
    int rc;
    unsigned i;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    xc_interface *xch = ctx->xch;

    /* Sanity-check the migration stream. */
    if ( !ctx->restore.postcopy )
    {
        ERROR("Received POSTCOPY_PFNS_BEGIN before POSTCOPY_BEGIN");
        return -1;
    }

    paging->ring_page = xc_vm_event_enable(xch, ctx->domid,
                                           HVM_PARAM_PAGING_RING_PFN,
                                           &paging->evtchn_port);
    if ( !paging->ring_page )
    {
        PERROR("Failed to enable paging");
        return -1;
    }
    paging->paging_enabled = true;

    paging->xce_handle = xenevtchn_open(NULL, 0);
    if (!paging->xce_handle )
    {
        ERROR("Failed to open paging evtchn");
        return -1;
    }
    paging->evtchn_opened = true;

    rc = xenevtchn_bind_interdomain(paging->xce_handle, ctx->domid,
                                    paging->evtchn_port);
    if ( rc < 0 )
    {
        ERROR("Failed to bind paging evtchn");
        return rc;
    }
    paging->evtchn_bound = true;
    paging->port = rc;

    SHARED_RING_INIT((vm_event_sring_t *)paging->ring_page);
    BACK_RING_INIT(&paging->back_ring, (vm_event_sring_t *)paging->ring_page,
                   PAGE_SIZE);

    errno = posix_memalign(&paging->buffer, PAGE_SIZE, PAGE_SIZE);
    if ( errno != 0 )
    {
        PERROR("Failed to allocate paging buffer");
        return -1;
    }

    rc = mlock(paging->buffer, PAGE_SIZE);
    if ( rc < 0 )
    {
        PERROR("Failed to lock paging buffer");
        return rc;
    }
    paging->buffer_locked = true;

    paging->outstanding_pfns = bitmap_alloc(ctx->restore.max_populated_pfn + 1);
    paging->requested_pfns = bitmap_alloc(ctx->restore.max_populated_pfn + 1);
    paging->ready_pfns = bitmap_alloc(ctx->restore.max_populated_pfn + 1);
    paging->dropped_pfns = bitmap_alloc(ctx->restore.max_populated_pfn + 1);

    paging->pending_requests = malloc(RING_SIZE(&paging->back_ring) *
                                      sizeof(*paging->pending_requests));
    paging->request_batch = malloc(RING_SIZE(&paging->back_ring) *
                                   sizeof(*paging->request_batch));
    if ( !paging->outstanding_pfns ||
         !paging->requested_pfns ||
         !paging->ready_pfns ||
         !paging->dropped_pfns ||
         !paging->pending_requests ||
         !paging->request_batch )
    {
        PERROR("Failed to allocate pfn state tracking buffers");
        return -1;
    }

    /* All slots are initially empty. */
    for ( i = 0; i < RING_SIZE(&paging->back_ring); ++i )
        paging->pending_requests[i].pfn = INVALID_PFN;

    paging->ready = true;

    return 0;
}

static void postcopy_paging_cleanup(struct xc_sr_context *ctx)
{
    int rc;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    xc_interface *xch = ctx->xch;

    if ( paging->ring_page )
        munmap(paging->ring_page, PAGE_SIZE);

    if ( paging->paging_enabled )
    {
        rc = xc_vm_event_control(xch, ctx->domid, XEN_VM_EVENT_DISABLE,
                                 XEN_DOMCTL_VM_EVENT_OP_PAGING, NULL);
        if ( rc != 0 )
            ERROR("Failed to disable paging");
    }

    if ( paging->evtchn_bound )
    {
        rc = xenevtchn_unbind(paging->xce_handle, paging->port);
        if ( rc != 0 )
            ERROR("Failed to unbind event port");
    }

    if ( paging->evtchn_opened )
    {
        rc = xenevtchn_close(paging->xce_handle);
        if ( rc != 0 )
            ERROR("Failed to close event channel");
    }

    if ( paging->buffer )
    {
        if ( paging->buffer_locked )
            munlock(paging->buffer, PAGE_SIZE);

        free(paging->buffer);
    }

    free(paging->outstanding_pfns);
    free(paging->requested_pfns);
    free(paging->ready_pfns);
    free(paging->dropped_pfns);
    free(paging->pending_requests);
    free(paging->request_batch);
}

/* Helpers to query and transition the state of postcopy pfns. */
#define CHECK_STATE_BITMAP_FN(state)                                      \
    static inline bool postcopy_pfn_ ## state (struct xc_sr_context *ctx, \
                                               xen_pfn_t pfn)             \
    {                                                                     \
        assert(pfn <= ctx->restore.max_populated_pfn);                    \
        return test_bit(pfn, ctx->restore.paging. state ## _pfns);        \
    }

CHECK_STATE_BITMAP_FN(outstanding);
CHECK_STATE_BITMAP_FN(requested);
CHECK_STATE_BITMAP_FN(ready);
CHECK_STATE_BITMAP_FN(dropped);

static inline bool postcopy_pfn_invalid(struct xc_sr_context *ctx,
                                        xen_pfn_t pfn)
{
    return !postcopy_pfn_outstanding(ctx, pfn) &&
           !postcopy_pfn_requested(ctx, pfn) &&
           !postcopy_pfn_ready(ctx, pfn) &&
           !postcopy_pfn_dropped(ctx, pfn);
}

static inline void mark_postcopy_pfn_outstanding(struct xc_sr_context *ctx,
                                                 xen_pfn_t pfn)
{
    assert(pfn <= ctx->restore.max_populated_pfn);
    assert(postcopy_pfn_invalid(ctx, pfn));

    set_bit(pfn, ctx->restore.paging.outstanding_pfns);
}

static inline void mark_postcopy_pfn_requested(struct xc_sr_context *ctx,
                                               xen_pfn_t pfn)
{
    assert(pfn <= ctx->restore.max_populated_pfn);
    assert(postcopy_pfn_outstanding(ctx, pfn));

    clear_bit(pfn, ctx->restore.paging.outstanding_pfns);
    set_bit(pfn, ctx->restore.paging.requested_pfns);
}

static inline void mark_postcopy_pfn_ready(struct xc_sr_context *ctx,
                                           xen_pfn_t pfn)
{
    assert(pfn <= ctx->restore.max_populated_pfn);
    assert(postcopy_pfn_outstanding(ctx, pfn) ||
           postcopy_pfn_requested(ctx, pfn));

    clear_bit(pfn, ctx->restore.paging.outstanding_pfns);
    clear_bit(pfn, ctx->restore.paging.requested_pfns);
    set_bit(pfn, ctx->restore.paging.ready_pfns);
}

static inline void mark_postcopy_pfn_dropped(struct xc_sr_context *ctx,
                                             xen_pfn_t pfn)
{
    assert(pfn <= ctx->restore.max_populated_pfn);
    assert(postcopy_pfn_outstanding(ctx, pfn));

    clear_bit(pfn, ctx->restore.paging.outstanding_pfns);
    set_bit(pfn, ctx->restore.paging.dropped_pfns);
}

static int process_postcopy_pfns(struct xc_sr_context *ctx, unsigned count,
                                 xen_pfn_t *pfns, uint32_t *types)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    xen_pfn_t *bpfns = NULL, bpfn;
    int rc;
    unsigned i, nr_pages;

    rc = populate_pfns(ctx, count, pfns, types);
    if ( rc )
    {
        ERROR("Failed to populate pfns for batch of %u pages", count);
        goto err;
    }

    set_page_types(ctx, count, pfns, types);

    rc = filter_pages(ctx, count, pfns, types, &nr_pages, &bpfns);
    if ( rc )
    {
        ERROR("Failed to filter mfns for batch of %u pages", count);
        goto err;
    }

    /* Nothing to do? */
    if ( nr_pages == 0 )
        goto done;

    /* Fully evict all backed pages in the batch. */
    for ( i = 0; i < nr_pages; ++i )
    {
        bpfn = bpfns[i];
        rc = -1;

        /* We should never see the same pfn twice at this stage.  */
        if ( !postcopy_pfn_invalid(ctx, bpfn) )
        {
            ERROR("Duplicate postcopy pfn %"PRI_xen_pfn, bpfn);
            goto err;
        }

        /* We now consider this pfn 'outstanding' - pending, and not yet
         * requested. */
        mark_postcopy_pfn_outstanding(ctx, bpfn);
        ++paging->nr_pending_pfns;

        /* Neither nomination nor eviction can be permitted to fail - the guest
         * isn't yet running, so a failure would imply a foreign or hypervisor
         * mapping on the page, and that would be bogus because the migration
         * isn't yet complete. */
        rc = xc_mem_paging_nominate(xch, ctx->domid, bpfn);
        if ( rc < 0 )
        {
            PERROR("Error nominating postcopy pfn %"PRI_xen_pfn, bpfn);
            goto err;
        }

        rc = xc_mem_paging_evict(xch, ctx->domid, bpfn);
        if ( rc < 0 )
        {
            PERROR("Error evicting postcopy pfn %"PRI_xen_pfn, bpfn);
            goto err;
        }
    }

 done:
    rc = 0;

 err:
    free(bpfns);

    return rc;
}

static int handle_postcopy_pfns(struct xc_sr_context *ctx,
                                struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_pages_header *pages = rec->data;
    unsigned pages_of_data;
    int rc;
    xen_pfn_t *pfns = NULL;
    uint32_t *types = NULL;

    /* Sanity-check the migration stream. */
    if ( !ctx->restore.paging.ready )
    {
        ERROR("Received POSTCOPY_PFNS record before POSTCOPY_PFNS_BEGIN");
        rc = -1;
        goto err;
    }

    rc = validate_pages_record(ctx, rec, REC_TYPE_POSTCOPY_PFNS);
    if ( rc )
        goto err;

    rc = decode_pages_record(ctx, pages, &pfns, &types, &pages_of_data);
    if ( rc )
        goto err;

    if ( rec->length != (sizeof(*pages) + (sizeof(uint64_t) * pages->count)) )
    {
        ERROR("POSTCOPY_PFNS record wrong size: length %u, expected "
              "%zu + %zu", rec->length, sizeof(*pages),
              (sizeof(uint64_t) * pages->count));
        goto err;
    }

    rc = process_postcopy_pfns(ctx, pages->count, pfns, types);

 err:
    free(types);
    free(pfns);

    return rc;
}

static int write_postcopy_complete_record(struct xc_sr_context *ctx,
                                          uint32_t result);
static int handle_postcopy_transition(struct xc_sr_context *ctx)
{
    int rc;
    xc_interface *xch = ctx->xch;
    void *data = ctx->restore.callbacks->data;

    /* Sanity-check the migration stream. */
    if ( !ctx->restore.paging.ready )
    {
        ERROR("Received POSTCOPY_TRANSITION record before POSTCOPY_PFNS_BEGIN");
        return -1;
    }

    rc = ctx->restore.ops.stream_complete(ctx);
    if ( rc )
        goto err;

    ctx->restore.callbacks->restore_results(ctx->restore.xenstore_gfn,
                                            ctx->restore.console_gfn,
                                            data);

    /* Asynchronously resume the guest.  We'll return when we've been handed
     * back control of the stream, so that we can begin filling in the
     * outstanding postcopy page data and forwarding guest requests for specific
     * pages. */
    IPRINTF("Postcopy transition: resuming guest");
    rc = ctx->restore.callbacks->postcopy_transition(data) ? 0 : -1;
    if ( rc )
        goto err;

    return 0;

 err:
    /* Attempt to signal to the sender than they can safely try to recover
     * on their end, then take the normal error path out. */
    (void)write_postcopy_complete_record(ctx,
                                         POSTCOPY_COMPLETE_FAILED_PRERESUME);

    return rc;
}

static int postcopy_load_page(struct xc_sr_context *ctx, xen_pfn_t pfn,
                              void *page_data)
{
    int rc;
    unsigned i;
    xc_interface *xch = ctx->xch;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    struct xc_sr_pending_postcopy_request *preq;
    vm_event_response_t rsp;
    vm_event_back_ring_t *back_ring = &paging->back_ring;

    assert(postcopy_pfn_outstanding(ctx, pfn) ||
           postcopy_pfn_requested(ctx, pfn));

    memcpy(paging->buffer, page_data, PAGE_SIZE);
    rc = xc_mem_paging_load(ctx->xch, ctx->domid, pfn, paging->buffer);
    if ( rc < 0 )
    {
        PERROR("Failed to paging load pfn %"PRI_xen_pfn, pfn);
        return rc;
    }

    if ( postcopy_pfn_requested(ctx, pfn) )
    {
        for ( i = 0; i < RING_SIZE(back_ring); ++i )
        {
            preq = &paging->pending_requests[i];
            if ( preq->pfn != pfn )
                continue;

            /* Put the response on the ring. */
            rsp = (vm_event_response_t)
            {
                .version = VM_EVENT_INTERFACE_VERSION,
                .vcpu_id = preq->vcpu_id,
                .flags   = (preq->flags & VM_EVENT_FLAG_VCPU_PAUSED),
                .reason  = VM_EVENT_REASON_MEM_PAGING,
                .u       = { .mem_paging = { .gfn = pfn } }
            };

            memcpy(RING_GET_RESPONSE(back_ring, back_ring->rsp_prod_pvt),
                   &rsp, sizeof(rsp));
		    ++back_ring->rsp_prod_pvt;

            /* And free the pending request slot. */
            preq->pfn = INVALID_PFN;
        }
    }

    --paging->nr_pending_pfns;
    mark_postcopy_pfn_ready(ctx, pfn);
    return 0;
}

static int process_postcopy_page_data(struct xc_sr_context *ctx, unsigned count,
                                      xen_pfn_t *pfns, uint32_t *types,
                                      void *page_data)
{
    int rc;
    unsigned i;
    xc_interface *xch = ctx->xch;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    bool push_responses = false;

    for ( i = 0; i < count; ++i )
    {
        switch ( types[i] )
        {
        case XEN_DOMCTL_PFINFO_XTAB:
        case XEN_DOMCTL_PFINFO_BROKEN:
        case XEN_DOMCTL_PFINFO_XALLOC:
            ERROR("Received postcopy pfn %"PRI_xen_pfn
                  " with invalid type %"PRIu32, pfns[i], types[i]);
            return -1;
        default:
            if ( postcopy_pfn_invalid(ctx, pfns[i]) )
            {
                ERROR("Expected pfn %"PRI_xen_pfn" to be invalid", pfns[i]);
                return -1;
            }
            else if ( postcopy_pfn_ready(ctx, pfns[i]) )
            {
                ERROR("pfn %"PRI_xen_pfn" already received", pfns[i]);
                return -1;
            }
            else if ( postcopy_pfn_dropped(ctx, pfns[i]) )
            {
                /* Nothing to do - move on to the next page. */
                page_data += PAGE_SIZE;
            }
            else
            {
                if ( postcopy_pfn_requested(ctx, pfns[i]) )
                {
                    DBGPRINTF("Received requested pfn %"PRI_xen_pfn, pfns[i]);
                    push_responses = true;
                }

                rc = postcopy_load_page(ctx, pfns[i], page_data);
                if ( rc )
                    return rc;

                page_data += PAGE_SIZE;
            }
            break;
        }
    }

    if ( push_responses )
    {
        /* We put at least one response on the ring as a result of processing
         * this batch of pages, so we need to push them and kick the ring event
         * channel. */
        RING_PUSH_RESPONSES(&paging->back_ring);

        rc = xenevtchn_notify(paging->xce_handle, paging->port);
        if ( rc )
        {
            ERROR("Failed to notify paging event channel");
            return rc;
        }
    }

    return 0;
}

static int handle_postcopy_page_data(struct xc_sr_context *ctx,
                                     struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_rec_pages_header *pages = rec->data;
    unsigned pages_of_data;
    int rc = -1;

    xen_pfn_t *pfns = NULL;
    uint32_t *types = NULL;

    rc = validate_pages_record(ctx, rec, REC_TYPE_POSTCOPY_PAGE_DATA);
    if ( rc )
        goto err;

    rc = decode_pages_record(ctx, pages, &pfns, &types, &pages_of_data);
    if ( rc )
        goto err;

    if ( rec->length != (sizeof(*pages) +
                         (sizeof(uint64_t) * pages->count) +
                         (PAGE_SIZE * pages_of_data)) )
    {
        ERROR("POSTCOPY_PAGE_DATA record wrong size: length %u, expected "
              "%zu + %zu + %lu", rec->length, sizeof(*pages),
              (sizeof(uint64_t) * pages->count), (PAGE_SIZE * pages_of_data));
        goto err;
    }

    rc = process_postcopy_page_data(ctx, pages->count, pfns, types,
                                    &pages->pfn[pages->count]);
 err:
    free(types);
    free(pfns);

    return rc;
}

static int forward_postcopy_paging_requests(struct xc_sr_context *ctx,
                                            unsigned nr_batch_requests)
{
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    size_t batchsz = nr_batch_requests * sizeof(*paging->request_batch);
    struct xc_sr_rec_pages_header phdr =
    {
        .count = nr_batch_requests
    };
    struct xc_sr_record rec =
    {
        .type   = REC_TYPE_POSTCOPY_FAULT,
        .length = sizeof(phdr),
        .data   = &phdr
    };

    return write_split_record(ctx, ctx->restore.send_back_fd, &rec,
                              paging->request_batch, batchsz);
}

static int handle_postcopy_paging_requests(struct xc_sr_context *ctx)
{
    int rc;
    xc_interface *xch = ctx->xch;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    struct xc_sr_pending_postcopy_request *preq;
    vm_event_back_ring_t *back_ring = &paging->back_ring;
    vm_event_request_t req;
    vm_event_response_t rsp;
    xen_pfn_t pfn;
    bool put_responses = false, drop_requested;
    unsigned i, nr_batch_requests = 0;

    while ( RING_HAS_UNCONSUMED_REQUESTS(back_ring) )
    {
        RING_COPY_REQUEST(back_ring, back_ring->req_cons, &req);
        ++back_ring->req_cons;

        drop_requested = !!(req.u.mem_paging.flags & MEM_PAGING_DROP_PAGE);
        pfn = req.u.mem_paging.gfn;

        DBGPRINTF("Postcopy page fault! %"PRI_xen_pfn, pfn);

        if ( postcopy_pfn_invalid(ctx, pfn) )
        {
            ERROR("pfn %"PRI_xen_pfn" does not need to be migrated", pfn);
            rc = -1;
            goto err;
        }
        else if ( postcopy_pfn_ready(ctx, pfn) || drop_requested )
        {
            if ( drop_requested )
            {
                if ( postcopy_pfn_outstanding(ctx, pfn) )
                {
                    mark_postcopy_pfn_dropped(ctx, pfn);
                    --paging->nr_pending_pfns;
                }
                else
                {
                    ERROR("Pager requesting we drop non-paged "
                          "(or previously-requested) pfn %"PRI_xen_pfn, pfn);
                    rc = -1;
                    goto err;
                }
            }

            /* This page has already been loaded (or has been dropped), so we can
             * respond immediately. */
            rsp = (vm_event_response_t)
            {
                .version = VM_EVENT_INTERFACE_VERSION,
                .vcpu_id = req.vcpu_id,
                .flags   = (req.flags & VM_EVENT_FLAG_VCPU_PAUSED),
                .reason  = VM_EVENT_REASON_MEM_PAGING,
                .u       = { .mem_paging = { .gfn = pfn } }
            };

            memcpy(RING_GET_RESPONSE(back_ring, back_ring->rsp_prod_pvt),
                   &rsp, sizeof(rsp));
		    ++back_ring->rsp_prod_pvt;

			put_responses = true;
        }
        else /* implies not dropped AND either outstanding or requested */
        {
            if ( postcopy_pfn_outstanding(ctx, pfn) )
            {
                /* This is the first time this pfn has been requested. */
                mark_postcopy_pfn_requested(ctx, pfn);

                paging->request_batch[nr_batch_requests] = pfn;
                ++nr_batch_requests;
            }

            /* Find a free pending_requests slot. */
            for ( i = 0; i < RING_SIZE(back_ring); ++i )
            {
                preq = &paging->pending_requests[i];
                if ( preq->pfn == INVALID_PFN )
                {
                    /* Claim this slot. */
                    preq->pfn = pfn;

                    preq->flags = req.flags;
                    preq->vcpu_id = req.vcpu_id;
                    break;
                }
            }

            /* We _must_ find a free slot - there cannot be more outstanding
             * requests than there are slots in the ring. */
            assert(i < RING_SIZE(back_ring));
        }
    }

    if ( put_responses )
    {
        RING_PUSH_RESPONSES(back_ring);

        rc = xenevtchn_notify(paging->xce_handle, paging->port);
        if ( rc )
        {
            ERROR("Failed to notify paging event channel");
            goto err;
        }
    }

    if ( nr_batch_requests )
    {
        rc = forward_postcopy_paging_requests(ctx, nr_batch_requests);
        if ( rc )
        {
            ERROR("Failed to forward postcopy paging requests");
            goto err;
        }
    }

    rc = 0;

 err:
    return rc;
}

static int write_postcopy_complete_record(struct xc_sr_context *ctx,
                                          uint32_t result)
{
    struct xc_sr_rec_postcopy_complete complete =
    {
        .result = result
    };
    struct xc_sr_record rec =
    {
        .type   = REC_TYPE_POSTCOPY_COMPLETE,
        .length = sizeof(complete),
        .data   = &complete
    };

    return write_record(ctx, ctx->restore.send_back_fd, &rec);
}

static int postcopy_restore(struct xc_sr_context *ctx)
{
    int rc;
    int recv_fd = ctx->fd;
    int old_flags;
    int port;
    uint32_t result;
    xc_interface *xch = ctx->xch;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    struct xc_sr_read_record_context rrctx;
    struct xc_sr_record rec = { 0, 0, NULL };
    struct pollfd pfds[] =
    {
        { .fd = xenevtchn_fd(paging->xce_handle), .events = POLLIN },
        { .fd = recv_fd,                          .events = POLLIN }
    };

    assert(ctx->restore.postcopy);
    assert(paging->xce_handle);

    read_record_init(&rrctx, ctx);

    /* For the duration of the postcopy loop, configuring the receive stream as
     * non-blocking. */
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

    while ( paging->nr_pending_pfns )
    {
        rc = poll(pfds, ARRAY_SIZE(pfds), -1);
        if ( rc < 0 )
        {
            if ( errno == EINTR )
                continue;

            PERROR("Failed to poll the pager event channel/restore stream");
            goto err;
        }

        /* Fill in any newly received page data first, on the off chance that
         * new pager requests are for that data. */
        if ( rc && pfds[1].revents & POLLIN )
        {
            rc = try_read_record(&rrctx, recv_fd, &rec);
            if ( rc && (errno != EAGAIN) && (errno != EWOULDBLOCK) )
            {
                goto err;
            }
            else if ( !rc )
            {
                read_record_destroy(&rrctx);
                read_record_init(&rrctx, ctx);

                rc = handle_postcopy_page_data(ctx, &rec);
                if ( rc )
                    goto err;

                free(rec.data);
                rec.data = NULL;
            }
        }

        if ( rc && pfds[0].revents & POLLIN )
        {
            port = xenevtchn_pending(paging->xce_handle);
            if ( port == -1 )
            {
                ERROR("Failed to read port from pager event channel");
                rc = -1;
                goto err;
            }

            rc = xenevtchn_unmask(paging->xce_handle, port);
            if ( rc != 0 )
            {
                ERROR("Failed to unmask pager event channel port");
                goto err;
            }

            rc = handle_postcopy_paging_requests(ctx);
            if ( rc )
                goto err;
        }
    }

    /* At this point, all oustanding postcopy pages have been loaded.  We now
     * need only flush any outstanding requests that may have accumulated in the
     * ring while we were processing the final POSTCOPY_PAGE_DATA records. */
    rc = handle_postcopy_paging_requests(ctx);
    if ( rc )
        goto err;

    /* Having come this far, it _looks_ like everything has gone well for us, so
     * now we'll wait for the domain resumption to complete and report the
     * aggregate result to the sender. */
    rc = ctx->restore.callbacks->postcopy_synchronize(
        ctx->restore.callbacks->data);
    if ( rc < 0 )
        goto err;

    result = (uint32_t)rc;
    rc = write_postcopy_complete_record(ctx, result);
    if ( rc || result == POSTCOPY_COMPLETE_FAILED_PRERESUME )
    {
        /* If we reported failure they're going to hang up. */
        rc = -1;
        goto err;
    }

    /* Otherwise, make the receive stream blocking again, and wait to receive
     * what must be the END record. */
    rc = fcntl(recv_fd, F_SETFL, old_flags);
    if ( rc == -1 )
        goto err;

    rc = read_record(ctx, recv_fd, &rec);
    if ( rc )
    {
        goto err;
    }
    else if ( rec.type != REC_TYPE_END )
    {
        ERROR("Expected end of stream, received %s", rec_type_to_str(rec.type));
        rc = -1;
        goto err;
    }

 err:
    /* If _we_ fail here, we can't safely synchronize with the completion of
     * domain resumption because it might be waiting for us (to fulfill a pager
     * request).  Since we therefore can't know whether or not the domain was
     * unpaused, just abruptly bail and let the sender assume the worst. */
    free(rec.data);
    read_record_destroy(&rrctx);

    return rc;
}

/*
 * Send checkpoint dirty pfn list to primary.
 */
static int send_checkpoint_dirty_pfn_list(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc = -1;
    unsigned count, written;
    uint64_t i, *pfns = NULL;
    xc_shadow_op_stats_t stats = { 0, ctx->restore.p2m_size };
    struct xc_sr_record rec =
    {
        .type = REC_TYPE_CHECKPOINT_DIRTY_PFN_LIST,
    };
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->restore.dirty_bitmap_hbuf);

    if ( xc_shadow_control(
             xch, ctx->domid, XEN_DOMCTL_SHADOW_OP_CLEAN,
             HYPERCALL_BUFFER(dirty_bitmap), ctx->restore.p2m_size,
             NULL, 0, &stats) != ctx->restore.p2m_size )
    {
        PERROR("Failed to retrieve logdirty bitmap");
        goto err;
    }

    for ( i = 0, count = 0; i < ctx->restore.p2m_size; i++ )
    {
        if ( test_bit(i, dirty_bitmap) )
            count++;
    }


    pfns = malloc(count * sizeof(*pfns));
    if ( !pfns )
    {
        ERROR("Unable to allocate %zu bytes of memory for dirty pfn list",
              count * sizeof(*pfns));
        goto err;
    }

    for ( i = 0, written = 0; i < ctx->restore.p2m_size; ++i )
    {
        if ( !test_bit(i, dirty_bitmap) )
            continue;

        if ( written > count )
        {
            ERROR("Dirty pfn list exceed");
            goto err;
        }

        pfns[written++] = i;
    }

    rec.data = pfns;
    rec.length = count * sizeof(*pfns);

    rc = write_record(ctx, ctx->restore.send_back_fd, &rec);
    if ( rc )
        goto err;

    rc = 0;

 err:
    free(pfns);
    return rc;
}

static int process_record(struct xc_sr_context *ctx, struct xc_sr_record *rec);
static int handle_checkpoint(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc = 0, ret;
    unsigned i;

    if ( !ctx->restore.checkpointed )
    {
        ERROR("Found checkpoint in non-checkpointed stream");
        rc = -1;
        goto err;
    }

    ret = ctx->restore.callbacks->checkpoint(ctx->restore.callbacks->data);
    switch ( ret )
    {
    case XGR_CHECKPOINT_SUCCESS:
        break;

    case XGR_CHECKPOINT_FAILOVER:
        if ( ctx->restore.buffer_all_records )
            rc = BROKEN_CHANNEL;
        else
            /* We don't have a consistent state */
            rc = -1;
        goto err;

    default: /* Other fatal error */
        rc = -1;
        goto err;
    }

    if ( ctx->restore.buffer_all_records )
    {
        IPRINTF("All records buffered");

        for ( i = 0; i < ctx->restore.buffered_rec_num; i++ )
        {
            rc = process_record(ctx, &ctx->restore.buffered_records[i]);
            if ( rc )
                goto err;
        }
        ctx->restore.buffered_rec_num = 0;
        IPRINTF("All records processed");
    }
    else
        ctx->restore.buffer_all_records = true;

    if ( ctx->restore.checkpointed == XC_MIG_STREAM_COLO )
    {
#define HANDLE_CALLBACK_RETURN_VALUE(ret)                   \
    do {                                                    \
        if ( ret == 1 )                                     \
            rc = 0; /* Success */                           \
        else                                                \
        {                                                   \
            if ( ret == 2 )                                 \
                rc = BROKEN_CHANNEL;                        \
            else                                            \
                rc = -1; /* Some unspecified error */       \
            goto err;                                       \
        }                                                   \
    } while (0)

        /* COLO */

        /* We need to resume guest */
        rc = ctx->restore.ops.stream_complete(ctx);
        if ( rc )
            goto err;

        ctx->restore.callbacks->restore_results(ctx->restore.xenstore_gfn,
                                                ctx->restore.console_gfn,
                                                ctx->restore.callbacks->data);

        /* Resume secondary vm */
        ret = ctx->restore.callbacks->aftercopy(ctx->restore.callbacks->data);
        HANDLE_CALLBACK_RETURN_VALUE(ret);

        /* Wait for a new checkpoint */
        ret = ctx->restore.callbacks->wait_checkpoint(
                                                ctx->restore.callbacks->data);
        HANDLE_CALLBACK_RETURN_VALUE(ret);

        /* suspend secondary vm */
        ret = ctx->restore.callbacks->suspend(ctx->restore.callbacks->data);
        HANDLE_CALLBACK_RETURN_VALUE(ret);

#undef HANDLE_CALLBACK_RETURN_VALUE

        rc = send_checkpoint_dirty_pfn_list(ctx);
        if ( rc )
            goto err;
    }

 err:
    return rc;
}

static int buffer_record(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    unsigned new_alloc_num;
    struct xc_sr_record *p;

    if ( ctx->restore.buffered_rec_num >= ctx->restore.allocated_rec_num )
    {
        new_alloc_num = ctx->restore.allocated_rec_num + DEFAULT_BUF_RECORDS;
        p = realloc(ctx->restore.buffered_records,
                    new_alloc_num * sizeof(struct xc_sr_record));
        if ( !p )
        {
            ERROR("Failed to realloc memory for buffered records");
            return -1;
        }

        ctx->restore.buffered_records = p;
        ctx->restore.allocated_rec_num = new_alloc_num;
    }

    memcpy(&ctx->restore.buffered_records[ctx->restore.buffered_rec_num++],
           rec, sizeof(*rec));

    return 0;
}

static int process_record(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    xc_interface *xch = ctx->xch;
    int rc = 0;

    switch ( rec->type )
    {
    case REC_TYPE_END:
        break;

    case REC_TYPE_PAGE_DATA:
        rc = handle_page_data(ctx, rec);
        break;

    case REC_TYPE_VERIFY:
        DPRINTF("Verify mode enabled");
        ctx->restore.verify = true;
        break;

    case REC_TYPE_CHECKPOINT:
        rc = handle_checkpoint(ctx);
        break;

    case REC_TYPE_POSTCOPY_BEGIN:
        if ( ctx->restore.postcopy )
            rc = -1;
        else
            ctx->restore.postcopy = true;
        break;

    case REC_TYPE_POSTCOPY_PFNS_BEGIN:
        rc = postcopy_paging_setup(ctx);
        break;

    case REC_TYPE_POSTCOPY_PFNS:
        rc = handle_postcopy_pfns(ctx, rec);
        break;

    case REC_TYPE_POSTCOPY_TRANSITION:
        rc = handle_postcopy_transition(ctx);
        break;

    default:
        rc = ctx->restore.ops.process_record(ctx, rec);
        break;
    }

    free(rec->data);
    rec->data = NULL;

    return rc;
}

static int setup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    int rc;
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->restore.dirty_bitmap_hbuf);

    if ( ctx->restore.checkpointed == XC_MIG_STREAM_COLO )
    {
        dirty_bitmap = xc_hypercall_buffer_alloc_pages(xch, dirty_bitmap,
                                NRPAGES(bitmap_size(ctx->restore.p2m_size)));

        if ( !dirty_bitmap )
        {
            ERROR("Unable to allocate memory for dirty bitmap");
            rc = -1;
            goto err;
        }
    }

    rc = ctx->restore.ops.setup(ctx);
    if ( rc )
        goto err;

    ctx->restore.max_populated_pfn = (32 * 1024 / 4) - 1;
    ctx->restore.populated_pfns = bitmap_alloc(
        ctx->restore.max_populated_pfn + 1);
    if ( !ctx->restore.populated_pfns )
    {
        ERROR("Unable to allocate memory for populated_pfns bitmap");
        rc = -1;
        goto err;
    }

    ctx->restore.buffered_records = malloc(
        DEFAULT_BUF_RECORDS * sizeof(struct xc_sr_record));
    if ( !ctx->restore.buffered_records )
    {
        ERROR("Unable to allocate memory for buffered records");
        rc = -1;
        goto err;
    }
    ctx->restore.allocated_rec_num = DEFAULT_BUF_RECORDS;

 err:
    return rc;
}

static void cleanup(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    unsigned i;
    DECLARE_HYPERCALL_BUFFER_SHADOW(unsigned long, dirty_bitmap,
                                    &ctx->restore.dirty_bitmap_hbuf);

    for ( i = 0; i < ctx->restore.buffered_rec_num; i++ )
        free(ctx->restore.buffered_records[i].data);

    if ( ctx->restore.checkpointed == XC_MIG_STREAM_COLO )
        xc_hypercall_buffer_free_pages(xch, dirty_bitmap,
                                   NRPAGES(bitmap_size(ctx->restore.p2m_size)));

    if ( ctx->restore.postcopy )
        postcopy_paging_cleanup(ctx);

    free(ctx->restore.buffered_records);
    free(ctx->restore.populated_pfns);
    if ( ctx->restore.ops.cleanup(ctx) )
        PERROR("Failed to clean up");
}

/*
 * Restore a domain.
 */
static int restore(struct xc_sr_context *ctx)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_record rec;
    int rc, saved_rc = 0, saved_errno = 0;

    IPRINTF("Restoring domain");

    rc = setup(ctx);
    if ( rc )
        goto err;

    do
    {
        rc = read_record(ctx, ctx->fd, &rec);
        if ( rc )
        {
            if ( ctx->restore.buffer_all_records )
                goto remus_failover;
            else
                goto err;
        }

        if ( ctx->restore.buffer_all_records &&
             rec.type != REC_TYPE_END &&
             rec.type != REC_TYPE_CHECKPOINT )
        {
            rc = buffer_record(ctx, &rec);
            if ( rc )
                goto err;
        }
        else
        {
            rc = process_record(ctx, &rec);
            if ( rc == RECORD_NOT_PROCESSED )
            {
                if ( rec.type & REC_TYPE_OPTIONAL )
                    DPRINTF("Ignoring optional record %#x (%s)",
                            rec.type, rec_type_to_str(rec.type));
                else
                {
                    ERROR("Mandatory record %#x (%s) not handled",
                          rec.type, rec_type_to_str(rec.type));
                    rc = -1;
                    goto err;
                }
            }
            else if ( rc == BROKEN_CHANNEL )
                goto remus_failover;
            else if ( rc )
                goto err;
        }

    } while ( rec.type != REC_TYPE_END &&
              rec.type != REC_TYPE_POSTCOPY_TRANSITION );

 remus_failover:

    if ( ctx->restore.checkpointed == XC_MIG_STREAM_COLO )
    {
        /* With COLO, we have already called stream_complete */
        rc = 0;
        IPRINTF("COLO Failover");
        goto done;
    }
    else if ( ctx->restore.postcopy )
    {
        rc = postcopy_restore(ctx);
        if ( rc )
            goto err;

        goto done;
    }

    /*
     * With Remus, if we reach here, there must be some error on primary,
     * failover from the last checkpoint state.
     */
    rc = ctx->restore.ops.stream_complete(ctx);
    if ( rc )
        goto err;

    IPRINTF("Restore successful");
    goto done;

 err:
    saved_errno = errno;
    saved_rc = rc;
    PERROR("Restore failed");

 done:
    cleanup(ctx);

    if ( saved_rc )
    {
        rc = saved_rc;
        errno = saved_errno;
    }

    return rc;
}

int xc_domain_restore(xc_interface *xch, int io_fd, uint32_t dom,
                      unsigned int store_evtchn, unsigned long *store_mfn,
                      domid_t store_domid, unsigned int console_evtchn,
                      unsigned long *console_gfn, domid_t console_domid,
                      unsigned int hvm, unsigned int pae, int superpages,
                      xc_migration_stream_t stream_type,
                      struct restore_callbacks *callbacks, int send_back_fd)
{
    xen_pfn_t nr_pfns;
    struct xc_sr_context ctx =
        {
            .xch = xch,
            .fd = io_fd,
        };

    /* GCC 4.4 (of CentOS 6.x vintage) can' t initialise anonymous unions. */
    ctx.restore.console_evtchn = console_evtchn;
    ctx.restore.console_domid = console_domid;
    ctx.restore.xenstore_evtchn = store_evtchn;
    ctx.restore.xenstore_domid = store_domid;
    ctx.restore.checkpointed = stream_type;
    ctx.restore.callbacks = callbacks;
    ctx.restore.send_back_fd = send_back_fd;

    /* Sanity checks for callbacks. */
    if ( stream_type )
        assert(callbacks->checkpoint);

    if ( ctx.restore.checkpointed == XC_MIG_STREAM_COLO )
    {
        /* this is COLO restore */
        assert(callbacks->suspend &&
               callbacks->aftercopy &&
               callbacks->wait_checkpoint &&
               callbacks->restore_results);
    }

    DPRINTF("fd %d, dom %u, hvm %u, pae %u, superpages %d"
            ", stream_type %d", io_fd, dom, hvm, pae,
            superpages, stream_type);

    if ( xc_domain_getinfo(xch, dom, 1, &ctx.dominfo) != 1 )
    {
        PERROR("Failed to get domain info");
        return -1;
    }

    if ( ctx.dominfo.domid != dom )
    {
        ERROR("Domain %u does not exist", dom);
        return -1;
    }

    ctx.domid = dom;

    if ( read_headers(&ctx) )
        return -1;

    if ( xc_domain_nr_gpfns(xch, dom, &nr_pfns) < 0 )
    {
        PERROR("Unable to obtain the guest p2m size");
        return -1;
    }

    ctx.restore.p2m_size = nr_pfns;

    if ( ctx.dominfo.hvm )
    {
        ctx.restore.ops = restore_ops_x86_hvm;
        if ( restore(&ctx) )
            return -1;
    }
    else
    {
        ctx.restore.ops = restore_ops_x86_pv;
        if ( restore(&ctx) )
            return -1;
    }

    IPRINTF("XenStore: mfn %#"PRIpfn", dom %d, evt %u",
            ctx.restore.xenstore_gfn,
            ctx.restore.xenstore_domid,
            ctx.restore.xenstore_evtchn);

    IPRINTF("Console: mfn %#"PRIpfn", dom %d, evt %u",
            ctx.restore.console_gfn,
            ctx.restore.console_domid,
            ctx.restore.console_evtchn);

    *console_gfn = ctx.restore.console_gfn;
    *store_mfn = ctx.restore.xenstore_gfn;

    return 0;
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
