# Frozen numeric tables for DESIGN v0.3.4 Appendix A (codes.hpp). Values are FROZEN at M0: never renumber, only append.
FAIL_REASONS = [  # e_* (stored e.g. in GENESIS.count for reason 3); 0 = none
 "e_none","e_magic","e_version","e_rec_type","e_event_code","e_rec_len","e_reason","e_actor","e_reserved","e_seq","e_epoch",
 "e_field","e_flag","e_dmethod","e_dmode","e_ts_gran","e_link","e_tag","e_sig","e_crc","e_counter","e_nv_regress","e_short",
 "e_no_genesis","e_behind_anchor","e_anchor_mismatch","e_ckpt_range","e_epoch_handover","e_unexpected_chain_id","e_file_order",
 "e_fork","e_nv_epoch","e_xfer_overlap","e_tpmrec","e_genesis","e_allowlist","e_gap_range","e_gap_count","e_ack_ref","e_level","e_dagg"]
OUTCOME = {1: "ok", 2: "failed"}
CODES = {  # code: (rec_type, name, {reason: name})   rec_type 1 GENESIS 2 EVENT 3 CHECKPOINT 4 EPOCH_START
 1: (1, "genesis", {1:"provisioning",2:"operator_init",3:"fail_successor",4:"missing_successor",5:"predecessor_unknown",6:"tpm_cleared"}),
 2: (3, "checkpoint", {1:"cadence_time",2:"cadence_count",3:"shutdown",4:"pre_export",5:"recovery",6:"chain_creation",7:"epoch_pre",
                       8:"epoch_post",9:"level4_entry",10:"level4_exit",11:"successor"}),
 3: (4, "epoch_start", {1:"scheduled",2:"tpm_or_firmware_change",3:"post_compromise",4:"dmode_change"}),
 16: (2, "recv_group_delivered", {0:"normal",1:"recovered_unacked",2:"rerecorded_after_chain_fail"}),
 17: (2, "recv_void", {0:"normal"}),
 18: (2, "recv_export_intent", {0:"intent"}), 19: (2, "recv_export_outcome", OUTCOME),
 20: (2, "recv_log_fault", {1:"rollback_truncate_failed",2:"seal_failed",3:"io"}),
 21: (2, "recv_log_torn_tail", {0:"normal"}),
 22: (2, "recv_transfer_start", {0:"normal",1:"reseed"}),
 23: (2, "recv_transfer_end", {0:"normal"}),
 32: (2, "buffer_open", {0:"normal"}),
 33: (2, "ack_purge_intent", {0:"intent"}), 34: (2, "ack_purge_outcome", OUTCOME),
 35: (2, "record_erase_intent", {0:"intent"}), 36: (2, "record_erase_outcome", OUTCOME),
 37: (2, "factory_reset_intent", {0:"intent"}), 38: (2, "factory_reset_outcome", OUTCOME),
 39: (2, "buffer_fault", {i:n for i,n in enumerate(["none","fill_warn","outage_warn","fill_fault","outage_fault","full","retention",
                          "crypto","io","tpm","kek_unavailable","mem_lock"]) if i}),   # = ct01_buf_reason values (ct01_buffer.h:40-53)
 48: (2, "contingency_pass_through", {0:"normal"}), 49: (2, "nack_gap_replay", {0:"normal"}), 50: (2, "void_acked", {0:"normal"}),
 51: (2, "kek_unavailable", {0:"normal"}), 52: (2, "mem_lock_failed", {0:"normal"}),
 64: (2, "chain_torn_tail_recovered", {0:"normal"}),
 65: (2, "chain_predecessor", {1:"old_chain",2:"holder_checkpoint",3:"unknown"}),
 66: (2, "chain_gap", {1:"fail_successor",2:"unrecordable",3:"audit_space",4:"count_unknown"}),
 67: (2, "holder_ack", {0:"normal"}),
 68: (2, "recv_coverage", {1:"coverage_mismatch",2:"group_rolled_back",3:"recvlog_sync_failed",4:"duplicate_content_mismatch"}),
 69: (2, "fault_ack", {1:"fault",2:"gap"}),
 70: (2, "config_mismatch", {1:"config_off",2:"dir_missing",3:"nv_tampered"}),
 71: (2, "tpm_recovered", {0:"normal",1:"saturated"}),
 72: (2, "recv_groups_compacted", {1:"normal",2:"rebuilt"}),
 73: (2, "commissioning_verified", {0:"normal"}),
 74: (2, "lockdown", {1:"failed",2:"restored"}),
 75: (2, "audit_space_level", {1:"level1",2:"level2",3:"level3",4:"level4",5:"reserve_tampered"}),
}
# Exit effect per code (F64/F66): "none" means NO exit effect (field rules only)
EXIT = {1:"bit1 set (reasons 3-6, or 2 on a provisioned device) -> 6", 2:"via counters/flags it carries -> 6", 64:"recoveries_total -> 6", 66:"gaps_total -> 6",
        16:"dmethod 4 -> bit2 -> 6", 72:"dmethod 4 (incl. rebuilt) -> bit2 -> 6", 75:"none itself (level-4 entry CKP gaps_total += 1 -> 6); gap_open warning",
        74:"none (JSON warning lockdown_failed)", 73:"none (JSON info)"}
FAULT_RAISING = {(1,3),(1,4),(1,5),(1,6),(20,None),(21,None),(39,None),(51,None),(52,None),(64,None),(66,None),(68,None),(70,None),
                 (74,1),(75,2),(75,3),(75,4),(75,5)}   # plus any EVENT with dmethod 4
if __name__ == "__main__":
    assert len(FAIL_REASONS) == len(set(FAIL_REASONS)) == 41
    assert all(0 < c < 65536 for c in CODES) and len({v[1] for v in CODES.values()}) == len(CODES)
    for c,(rt,n,r) in CODES.items():
        assert rt in (1,2,3,4) and all(0 <= k < 65536 for k in r)
    assert all(c in CODES for c,_ in FAULT_RAISING)
    assert CODES[39][2][11] == "mem_lock" and CODES[39][2][10] == "kek_unavailable"
    print("codes tables: %d FAIL reasons (0..%d), %d event codes, all unique" % (len(FAIL_REASONS), len(FAIL_REASONS)-1, len(CODES)))
