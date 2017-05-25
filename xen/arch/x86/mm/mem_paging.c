/******************************************************************************
 * arch/x86/mm/mem_paging.c
 *
 * Memory paging support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */


#include <asm/p2m.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xsm/xsm.h>

long mem_paging_memop(unsigned long cmd,
                      XEN_GUEST_HANDLE_PARAM(xen_mem_paging_op_t) arg)
{
    long rc;
    unsigned long start_gfn = cmd >> MEMOP_EXTENT_SHIFT;
    xen_pfn_t gfn;
    xen_mem_paging_op_t mpo;
    struct domain *d;
    bool_t copyback = 0;

    if ( copy_from_guest(&mpo, arg, 1) )
        return -EFAULT;

    rc = rcu_lock_live_remote_domain_by_id(mpo.domain, &d);
    if ( rc )
        return rc;

    rc = xsm_mem_paging(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    rc = -ENODEV;
    if ( unlikely(!d->vm_event->paging.ring_page) )
        goto out;

    switch( mpo.op )
    {
    case XENMEM_paging_op_nominate:
        rc = p2m_mem_paging_nominate(d, mpo.u.single.gfn);
        break;

    case XENMEM_paging_op_evict:
        rc = p2m_mem_paging_evict(d, mpo.u.single.gfn);
        break;

    case XENMEM_paging_op_populate_evicted:
        while ( start_gfn < mpo.u.batch.nr )
        {
            if ( copy_from_guest_offset(&gfn, mpo.u.batch.gfns, start_gfn, 1) )
            {
                rc = -EFAULT;
                goto out;
            }

            rc = p2m_mem_paging_populate_evicted(d, gfn);
            if ( rc )
                goto out;

            if ( mpo.u.batch.nr > ++start_gfn && hypercall_preempt_check() )
            {
                cmd = XENMEM_paging_op | (start_gfn << MEMOP_EXTENT_SHIFT);
                rc = hypercall_create_continuation(__HYPERVISOR_memory_op, "lh",
                                                   cmd, arg);
                goto out;
            }
        }

        rc = 0;
        break;

    case XENMEM_paging_op_prep:
        rc = p2m_mem_paging_prep(d, mpo.u.single.gfn, mpo.u.single.buffer);
        if ( !rc )
            copyback = 1;
        break;

    default:
        rc = -ENOSYS;
        break;
    }

    if ( copyback && __copy_to_guest(arg, &mpo, 1) )
        rc = -EFAULT;

out:
    rcu_unlock_domain(d);
    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
