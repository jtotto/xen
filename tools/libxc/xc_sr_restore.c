#include <arpa/inet.h>

#include <assert.h>

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

/*
 * Set a pfn as populated, expanding the tracking structures if needed. To
 * avoid realloc()ing too excessively, the size increased to the nearest power
 * of two large enough to contain the required pfn.
 */
static int pfn_set_populated(struct xc_sr_context *ctx, xen_pfn_t pfn)
{
    xc_interface *xch = ctx->xch;

    if ( pfn > ctx->restore.max_populated_pfn )
    {
        xen_pfn_t new_max;
        size_t old_sz, new_sz;
        unsigned long *p;

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
        p = realloc(ctx->restore.populated_pfns, new_sz);
        if ( !p )
        {
            ERROR("Failed to realloc populated bitmap");
            errno = ENOMEM;
            return -1;
        }

        memset((uint8_t *)p + old_sz, 0x00, new_sz - old_sz);

        ctx->restore.populated_pfns    = p;
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

static int filter_pages(struct xc_sr_context *ctx, unsigned count,
                        xen_pfn_t *pfns, uint32_t *types,
                        /* OUT */ unsigned *nr_pages,
                        /* OUT */ xen_pfn_t **bpfns)
{
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

            *bpfns[*nr_pages++] = pfns[i];
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
        nr_pages;

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

    /* Map physically backed pfns ('bpfns') to their gmfns. */
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
 * Given a PAGE_DATA or POSTCOPY_PFNS record, decode each packed entry into its
 * encoded pfn and type.
 */
static int decode_pages_record(struct xc_sr_context *ctx,
                               struct xc_sr_rec_pages_header *pages,
                               /* OUT */ xen_pfn_t **pfns,
                               /* OUT */ uint32_t **types,
                               /* OUT */ unsigned *pages_of_data)
{
    unsigned i;
    int rc = -1;
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
        pfn = pages->pfn[i] & PAGE_DATA_PFN_MASK;
        if ( !ctx->restore.ops.pfn_is_valid(ctx, pfn) )
        {
            ERROR("pfn %#"PRIpfn" (index %u) outside domain maximum", pfn, i);
            goto err;
        }

        type = (pages->pfn[i] & PAGE_DATA_TYPE_MASK) >> 32;
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
            *pages_of_data++;

        pfns[i] = pfn;
        types[i] = type;
    }

 err:
    free(*pfns);
    free(*types);

    return rc;
}

/*
 * Validate a PAGE_DATA record from the stream, and pass the results to
 * process_page_data() to actually perform the legwork.
 */
static int handle_page_data(struct xc_sr_context *ctx, struct xc_sr_record *rec)
{
    struct xc_sr_rec_pages_header *pages = rec->data;
    unsigned pages_of_data;
    int rc;

    xen_pfn_t *pfns = NULL;
    uint32_t *types = NULL;

    rc = validate_pages_record(rec);
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

/* The address of this structure is used as a sentinel entry in
 * paging->pending_pfns to indicate that the backing page for the entry pfn is
 * outstanding and no request for it has yet been made. */
static struct xc_sr_pending_postcopy_request outstanding_sentinel;

/* The address of this structure is used as a sentinel entry in
 * paging->pending_pfns to indicate that the page is ready and requests for it
 * can be satisfied immediately. */
static struct xc_sr_pending_postcopy_requests ready_sentinel;

/* An empty list is used in paging->pending_pfns to indicate that the given pfn
 * never at any point needed to be postcopy-migrated. */

static inline bool ppfn_outstanding(
    struct xc_sr_pending_postcopy_requests *ppfn)
{
    return LIBXC_SLIST_FIRST(ppfn) == &outstanding_sentinel;
}

static inline bool ppfn_ready(struct xc_sr_pending_postcopy_requests *ppfn)
{
    return LIBXC_SLIST_FIRST(ppfn) == &ready_sentinel;
}

static inline bool ppfn_invalid(struct xc_sr_pending_postcopy_requests *ppfn)
{
    return LIBXC_SLIST_EMPTY(ppfn);
}

static inline bool ppfn_requested(struct xc_sr_pending_postcopy_requests *ppfn)
{
    return !ppfn_invalid(ppfn) &&
           !ppfn_outstanding(ppfn) &&
           !ppfn_ready(ppfn);
}

static void mark_ppfn_outstanding(struct xc_sr_pending_postcopy_requests *ppfn)
{
    assert(ppfn_invalid(ppfn));
    LIBXC_SLIST_INSERT_HEAD(ppfn, &outstanding_sentinel, link);
}

/* Trust the caller to have appropriately cleaned up the request list first. */
static void mark_ppfn_ready(struct xc_sr_pending_postcopy_requests *ppfn)
{
    assert(ppfn_outstanding(ppfn) || ppfn_requested(ppfn));
    LIBXC_SLIST_INIT(ppfn);
    LIBXC_SLIST_INSERT_HEAD(ppfn, &ready_sentinel);
}

/* XXX postcopy begins */
static int postcopy_paging_setup(struct xc_sr_context *ctx)
{
    int rc;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    xc_interface *xch = ctx->xch;

    /* Sanity-check the migration stream. */
    if ( !ctx->postcopy )
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
                   XC_PAGE_SIZE);

    errno = posix_memalign(&paging->buffer, XC_PAGE_SIZE, XC_PAGE_SIZE);
    if ( errno != 0 )
    {
        PERROR("Failed to allocate paging buffer");
        return -1;
    }

    rc = mlock(paging->buffer, XC_PAGE_SIZE);
    if ( rc < 0 )
    {
        PERROR("Failed to lock paging buffer");
        return rc;
    }
    paging->buffer_locked = true;

    /* This assumes for convenience that a zeroed-out LIBXC_SLIST_HEAD is used
     * to represent an empty list. */
    paging->pending_pfns = calloc(ctx->restore.p2m_size,
                                  sizeof(*paging->pending_pfns));
    if ( !paging->pending_pfns )
    {
        PERROR("Failed to allocate pending pfns table");
        return -1;
    }

    paging->ready = true;

    return 0;
}

static void postcopy_paging_cleanup(struct xc_sr_context *ctx)
{
    int rc;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    xc_interface *xch = ctx->xch;
    struct xc_sr_pending_postcopy_requests *ppfn;
    struct xc_sr_pending_postcopy_request *preq, *next_preq;
    xen_pfn_t p;

    if ( paging->ring_page )
        munmap(paging->ring_page, XC_PAGE_SIZE);

    if ( paging->paging_enabled )
    {
        rc = xc_vm_event_control(xch, ctx->domid, XC_VM_EVENT_DISABLE,
                                 XEN_DOMCTL_VM_EVENT_OP_PAGING, paging->port);
        if ( rc != 0 )
            ERROR("Failed to disable paging");
    }

    if ( paging->evtchn_bound )
    {
        rc = xenevtchn_unbind(xch, paging->port);
        if ( rc != 0 )
            ERROR("Failed to unbind event port");
    }

    if ( paging->evtchn_opened )
    {
        rc = xenevtchn_close(xch);
        if ( rc != 0 )
            ERROR("Failed to close event channel");
    }

    if ( paging->buffer )
    {
        if ( paging->buffer_locked )
            munlock(paging->buffer, PAGE_SIZE);

        free(paging->buffer);
    }

    /* In the unhappy case, we need to scan the entire pending_pfns table to
     * clean up any contained pending request lists. */
    if ( paging->nr_pending_pfns )
    {
        for ( p = 0; p < ctx->restore.p2m_size; ++p )
        {
            ppfn = &paging->pending_pfns[p];
            if ( ppfn_requested(ppfn) )
            {
                LIBXC_SLIST_FOREACH_SAFE(preq, ppfn, link, next_preq)
                {
                    free(preq);
                }
            }
        }
    }
}

static int process_postcopy_pfns(struct xc_sr_context *ctx, unsigned count,
                                 xen_pfn_t *pfns, uint32_t *types)
{
    xc_interface *xch = ctx->xch;
    struct xc_sr_restore_paging *paging = &ctx->restore.paging;
    struct xc_sr_pending_postcopy_requests *ppfn;
    xen_pfn_t *bpfns = NULL, bpfn;
    int rc;
    unsigned i, nr_pages;

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

        if ( bpfn >= ctx->restore.p2m_size )
        {
            ERROR("Impossibly high postcopy pfn %"PRI_xen_pfn, bpfn);
            goto err;
        }

        ppfn = &paging->pending_pfns[bpfn];

        /* We should never see the same pfn twice at this stage.  */
        if ( !ppfn_invalid(ppfn) )
        {
            ERROR("Duplicate postcopy pfn %"PRI_xen_pfn, bpfn);
            goto err;
        }

        /* We now consider this pfn 'outstanding' - pending, and not yet
         * requested. */
        mark_ppfn_outstanding(ppfn);
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

    rc = validate_pages_record(rec);
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

static int handle_postcopy_transition(struct xc_sr_context *ctx)
{
    /* Sanity-check the migration stream. */
    if ( !ctx->restore.paging.ready )
    {
        ERROR("Received POSTCOPY_TRANSITION record before POSTCOPY_PFNS_BEGIN");
        return -1;
    }

    /* XXX */
}

static void get_request(struct xc_sr_restore_paging *paging, vm_event_request_t *req)
{
    vm_event_back_ring_t *back_ring;
    RING_IDX req_cons;

    back_ring = paging->back_ring;
    req_cons = back_ring->req_cons;

    /* Copy request */
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(*req));
    req_cons++;

    /* Update ring */
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;
}

static void put_response(struct xc_sr_restore_paging *paging, vm_event_response_t *rsp)
{
    vm_event_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    back_ring = paging->back_ring;
    rsp_prod = back_ring->rsp_prod_pvt;

    /* Copy response */
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(*rsp));
    rsp_prod++;

    /* Update ring */
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);
}

static int notify_page_populated(struct xc_sr_restore_paging *paging,
                                 uint64_t pfn, uint32_t flags,
                                 uint32_t vcpu_id)
{
    struct vm_event_response_t rsp;
    rsp.u.mem_paging.gfn = req.u.mem_paging.gfn;
    rsp.flags = flags;
    rsp.vcpu_id = vcpu_id;
    put_response(paging, &rsp);
    return xenevtchn_notify(paging->xce_handle, paging->port);
}

static int process_postcopy_page_data(struct xc_sr_context *ctx, unsigned count,
                                      xen_pfn_t *pfns, uint32_t *types,
                                      void *page_data)
{
    struct xc_sr_restore_paging *paging = ctx->restore.paging;
    int rc, i;
    struct xc_sr_pending_postcopy_requests *ppfn;
    struct xc_sr_pending_postcopy_request *request;

    for ( i = 0; i < count; ++i )
    {
        ppfn = paging->pending_pfns[pfns[i]];

        switch ( types[i] )
        {
        case XEN_DOMCTL_PFINFO_XTAB:
        case XEN_DOMCTL_PFINFO_BROKEN:
        case XEN_DOMCTL_PFINFO_XALLOC:
            if ( !ppfn_invalid(ppfn) )
            {
                ERROR("Expected pfn %"PRI_xen_pfn" to be valid but received type %d",
                      pfns[i], types[i]);
                rc = -1;
                goto err;
            }
            break;

        default:
            if ( ppfn_ready(ppfn) )
            {
                ERROR("pfn %"PRI_xen_pfn" already received", pfns[i]);
                rc = -1;
                goto err;
            }
            else if ( ppfn_invalid(ppfn) )
            {
                ERROR("Expected pfn %"PRI_xen_pfn" to be invalid but received type %d",
                      pfns[i], types[i]);
                rc = -1;
                goto err;
            }
            else
            {
                /* Copy the data in */
                memcpy(paging->buffer, page_data, PAGE_SIZE);
                rc = xc_mem_paging_load(ctx->xch, ctx->domid, pfn,
                                        paging->buffer);
                if ( rc < 0 )
                {
                    PERROR("Failed to load page pfn %"PRI_xen_pfn, pfn);
                    rc = -1;
                    goto err;
                }

                /* Notify the waiting vcpus */
                if ( ppfn_requested(ppfn) )
                {
                    while ( !LIBXC_SLIST_EMPTY(paging->pending_pfns[pfns[i]]) )
                    {
                        request = LIBXC_SLIST_FIRST(ppfn);
                        LIBXC_SLIST_REMOVE_HEAD(paging->pending_pfns[pfns[i]],
                                                link);
                        rc = notify_page_populated(paging,
                                                   pfns[i],
                                                   request.flags,
                                                   request.vcpu_id);
                        if ( rc < 0 )
                        {
                            ERROR("Failed to notify page poulated for pfn %"PRI_xen_pfn,
                                  pfns[i]);
                            free(request);
                            rc = -1;
                            goto err;
                        }
                        free(request);
                    }
                }
                mark_ppfn_ready(paging->pending_pfns[pfns[i]]);
            }
            break;
        }
    }

 err:
    return rc;
}

static int handle_postcopy_page_data(struct xc_sr_context *ctx,
                                     struct xc_sr_record *rec)
{
    struct xc_sr_rec_pages_header *pages = rec->data;
    unsigned pages_of_data;
    int rc;

    xen_pfn_t *pfns = NULL;
    uint32_t *types = NULL;

    rc = validate_pages_record(rec);
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

    rc = process_postcopy_page_data(ctx, pages->count, pfns, types,
                                    &pages->pfn[pages->count]);
 err:
    free(types);
    free(pfns);

    return rc;
}

static int process_paging_request(struct xc_sr_restore_paging *paging,
                                  struct vm_event_req *req)
{
    uint64_t pfn = vm_event_req.u.mem_paging.gfn;
    struct xc_sr_pending_postcopy_request *ppfn;
    int rc;

    if ( ppfn_invalid(paging->pending_pfns[pfn]) )
    {
        ERROR("PFN does not need to be migrated %"PRI_xen_pfn, pfn);
        rc = -1;
    }
    else if ( ppfn_ready(paging->pending_pfns[pfn]) )
    {
        /* Page has already been populated, unpause the vcpu immediately */
        return notify_page_populated(paging, req.u.mem_paging.gfn,
                                     req.u.mem_paging.flags, req.vcpu_id);
    }
    else if ( ppfn_outstanding(paging->pending_pfns[pfn]) )
    {
        /* This is the first time the page has been requested */
        ppfn = malloc(sizeof(struct xc_sr_pending_postcopy_request));
        ppfn->flags = req.u.mem_paging.flags;
        ppfn->vcpu_id = req.vcpu_id;

        LIBXC_SLIST_INIT(paging->pending_pfns[pfn]);
        LIBXC_SLIST_INSERT_HEAD(paging->pending_pfns[pfn], ppfn, link);

        /* XXX FIRE THE REQUEST */
    }
    else if ( ppfn_requested(paging->pending_pfns[pfn]) )
    {
        /* A request for this page has already been sent */
        ppfn = malloc(sizeof(struct xc_sr_pending_postcopy_request));
        ppfn->flags = req.u.mem_paging.flags;
        ppfn->vcpu_id = req.vcpu_id;

        LIBXC_SLIST_INSERT_HEAD(paging->pending_pfns[pfn], ppfn, link);
        rc = 0;
    }
    return rc;
}

/*
 * Populate the remaining pages using postcopy. The domain is already running.
 * We need to respond to paging events from the guest by sending requests to
 * the source host. We also continue to recieve records from the source.
 */
static int restore_postcopy(struct xc_sr_context* ctx)
{
    int fd_flags = 0;
    fdset readfds;
    xen_pfn_t fault_buffer[GUEST_MAX_VCPUS];
    unsigned int buffer_start = 0, buffer_end = 0;
    int rc, fault_fd, max_fd;
    vm_event_request_t vm_event_req;
    vm_event_response_t vm_event_rsp;
    struct xc_sr_restore_paging *paging = ctx->restore.paging;
    struct xc_sr_read_record_context rrctx;
    struct xc_sr_record rec = { 0, 0, NULL };

    read_record_init(&rrctx);

    assert(paging->xce_handle);
    fault_fd = xenevtchn_fd(xce_handle);

    fd_flags = fcntl(ctx->fd, F_GETFL);
    if (fd_flags == -1)
    {
        PERROR("fcntl(,F_GETFL) failed");
        rc = -1;
        goto err;
    }
    fd_flags |= O_NONBLOCK;
    rc = fcntl(ctx->fd, F_SETFL, fd_flags);
    if (rc == -1)
    {
        PERROR("fcntl(,F_SETFL) failed");
        goto err;
    }
    max_fd = ctx->fd > fault_fd ? ctx->fd : fault_fd;

    FD_ZERO(&readfds);

    do
    {
        FD_SET(ctx->fd, &readfds);
        FD_SET(fault_fd, &readfds);
        rc = select(max, &readfds, &writefds, NULL, NULL);
        if ( rc == -1 )
        {
            PERROR("Failed to select");
            goto err;
        }

        if ( FD_ISSET(ctx->fd, &readfds) )
        {
            /* Read incoming page data */
            rc = try_read_record(&rrctx, ctx->fd, &rec);
            if ( rc && (errno != EAGAIN) && (errno != EWOULDBLOCK) )
                goto err;
            }
            else if ( !rc ) {
                /* Populate the pages and notify for each waiting vcpu */
                read_record_destroy(&rrctx);
                read_record_init(&rrctx);
                handle_page_data_record(ctx, &rec);
            }
        }
        else if ( FD_ISSET(fault_fd, &readfds) )
        {
            /* Handle access to unmigrated page */
            rc = xenevtchn_pending(paging->xce);
            if ( rc == -1 )
            {
                PERROR("Failed to read port from event channel");
                rc = -1;
                goto err;
            }

            rc = xenevtchn_unmask(paging->xce, port);
            if ( rc < 0 )
            {
                PERROR("Failed to unmask event channel port");
            }
            while ( RING_HAS_UNCONSUMED_REQUESTS(paging->back_ring) )
            {
                get_request(paging, &vm_event_req);
                rc = process_paging_request(paging, &vm_event_req);
            }
        }

    }

    /* return socket to nonblocking mode */
    fd_flags = fcntl(paging->fd, F_GETFL);
    if ( fd_flags == -1 )
    {
        PERROR("fcntl(,F_GETFL) failed");
        rc = -1;
        goto err;
    }
    fd_flags &= ~O_NONBLOCK;
    rc = fcntl(paging->fd, F_SETFL, fd_flags);
    if ( rc == -1 )
    {
        PERROR("fcntl(,F_SETFL) failed");
        goto err;
    }

 err:
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
    struct iovec *iov = NULL;
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

    /* iovec[] for writev(). */
    iov = malloc(3 * sizeof(*iov));
    if ( !iov )
    {
        ERROR("Unable to allocate memory for sending dirty bitmap");
        goto err;
    }

    rec.length = count * sizeof(*pfns);

    iov[0].iov_base = &rec.type;
    iov[0].iov_len = sizeof(rec.type);

    iov[1].iov_base = &rec.length;
    iov[1].iov_len = sizeof(rec.length);

    iov[2].iov_base = pfns;
    iov[2].iov_len = count * sizeof(*pfns);

    if ( writev_exact(ctx->restore.send_back_fd, iov, 3) )
    {
        PERROR("Failed to write dirty bitmap to stream");
        goto err;
    }

    rc = 0;
 err:
    free(pfns);
    free(iov);
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
        if ( ctx->postcopy )
            rc = -1;
        else
            ctx->postcopy = true;
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

    if ( ctx->postcopy )
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

    } while ( rec.type != REC_TYPE_END );

 remus_failover:

    if ( ctx->restore.checkpointed == XC_MIG_STREAM_COLO )
    {
        /* With COLO, we have already called stream_complete */
        rc = 0;
        IPRINTF("COLO Failover");
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
