/*******************************************************************************
 * Copyright 2022 MINRES Technologies GmbH
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

#ifndef DBT_RISE_UNICORN_SRC_CORE_IMPL_H_
#define DBT_RISE_UNICORN_SRC_CORE_IMPL_H_

#include "unicorn_sc.h"
#include "target_adapter.h"
#include <unicorn/unicorn.h>
#include <iss/debugger_if.h>
#include <memory>

struct target_adapter;
struct core_impl
        : public tlm::tlm_bw_transport_if<tlm::tlm_base_protocol_types>
, public iss::debugger_if
{
    unicorn_sc& owner;
    uc_engine *uc{nullptr};
    uc_hook code_hnd{0};
    uc_hook count_hndl{0};
    uc_hook mem_alloc{0};
    uc_hook mem_read{0};
    uint64_t limit{0};
    uint64_t count{0};
    std::unique_ptr<target_adapter> tgt_adapt;

    std::vector<std::pair<core_impl*, uint64_t>> handler;

    explicit core_impl(unicorn_sc& owner): owner(owner) { }

    ~core_impl();

    tlm::tlm_sync_enum nb_transport_bw(tlm::tlm_generic_payload& trans,
            tlm::tlm_phase& phase,
            sc_core::sc_time& t) override;

    void invalidate_direct_mem_ptr(sc_dt::uint64 start_range,
            sc_dt::uint64 end_range) override;

    static void hook_code(struct uc_struct *uc, uint64_t address, uint32_t size, void *user_data);

    static bool hook_memalloc(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

    static bool hook_memread(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

    static uint64_t read_cb(uc_engine *uc, uint64_t offset, unsigned size, void *user_data);

    static void write_cb(uc_engine *uc, uint64_t offset,  unsigned size, uint64_t value, void *user_data);

    void beoe();

    iss::status set_pc(uint64_t pc);

    uint64_t get_pc();

    iss::debugger::target_adapter_if *accquire_target_adapter(iss::debugger::server_if *server) override;
};



#endif /* DBT_RISE_UNICORN_SRC_CORE_IMPL_H_ */
