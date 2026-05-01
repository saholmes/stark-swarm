// dns_record_chain.cairo
//
// Cairo 0 illustration of the DNS record-set commitment AIR.  Each DNS
// record is hashed off-chain into a 32-byte SHA3-256 digest and packed
// into 4 u64 felts; this program shows the absorption chain that the
// HashRollup AIR enforces:
//
//   state' = state² + leaf
//
// over the packed leaves of a zone shard.  In production, the host-side
// `DnsRecord::pack_to_leaves()` in `crates/api/tests/dns_rollup.rs`
// produces the leaves; this Cairo program is the human-readable version
// of the constraint logic.
//
// Compile:  cairo-compile dns_record_chain.cairo --output dns_record_chain.json
// Run:      cairo-run --program dns_record_chain.json --print_output \
//               --trace_file dns_record_chain.trace --memory_file dns_record_chain.memory

%builtins output

from starkware.cairo.common.serialize import serialize_word

// state' = state² + leaf
func absorb_one(state: felt, leaf: felt) -> (felt) {
    return (state * state + leaf,);
}

// Walk a flat array of `n` packed-hash leaves (4 felts per DNS record).
func absorb_all(state: felt, idx: felt, n: felt, leaves: felt*) -> (felt) {
    if idx == n {
        return (state,);
    }
    let (next_state) = absorb_one(state, leaves[idx]);
    return absorb_all(next_state, idx + 1, n, leaves);
}

func main{output_ptr: felt*}() {
    // 5 DNS records × 4 leaves each = 20 active leaves, padded to 32.
    // Replace these placeholders with your actual SHA3-256-packed values.
    tempvar leaves = new (
        // record 0: A   example.com → 93.184.216.34
        0xa1b2c3d4_e5f60718, 0x1122334455667788, 0xaabbccddeeff0011, 0x2233445566778899,
        // record 1: AAAA example.com
        0xdeadbeef_cafef00d, 0x0123456789abcdef, 0xfedcba9876543210, 0x1357924680acebdf,
        // record 2: MX   example.com  10 mail.example.com
        0xfeed_face_abad_cafe, 0xdeadc0de_baadf00d, 0x8badf00d_decafbad, 0xfacefeed_cafed00d,
        // record 3: TXT  example.com  "v=spf1 -all"
        0x1111111122222222, 0x3333333344444444, 0x5555555566666666, 0x7777777788888888,
        // record 4: A    www.example.com → 93.184.216.34
        0x0102030405060708, 0x090a0b0c0d0e0f10, 0x1112131415161718, 0x191a1b1c1d1e1f20,
        // padding (zone shard < 8 records of slack)
        0,0,0,0, 0,0,0,0, 0,0,0,0,
    );

    const N = 32;  // power-of-2 trace length
    let (zone_root) = absorb_all(0, 0, N, leaves);
    serialize_word(zone_root);
    return ();
}
