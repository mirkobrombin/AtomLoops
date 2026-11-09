// Sealed log, loader side: the loader's records of one boot, encrypted to the
// reader public key and written straight onto the sectors of the ring file
// through BlockIo, before any kernel exists. Same block format as the Go
// package internal/sealedlog; the ESP carries the ring map (sealedlog.map) and
// the reader key (sealedlog.pub) that the running system wrote there.
const std = @import("std");
const uefi = std.os.uefi;
const File = uefi.protocol.File;
const BlockIo = uefi.protocol.BlockIo;
const DevicePath = uefi.protocol.DevicePath;

pub const block_size = 4096;
const header_size = 118;
const off_ring = 4;
const off_seq = 20;
const off_boot = 28;
const off_counter = 32;
const off_prev = 40;
const off_eph = 72;
const off_nonce = 104;
const off_ctlen = 116;
const tag_size = 16;
const max_payload = block_size - header_size - tag_size;
const kdf_info = "sinty sealed log v1";

pub const comp_loader: u8 = 1;
pub const code_fail: u8 = 4;
const code_local: u8 = 32;
pub const ev_boot_start: u8 = code_local + 0;
pub const ev_slot_chosen: u8 = code_local + 1;
pub const ev_trial: u8 = code_local + 2;
pub const ev_signature_bad: u8 = code_local + 3;
pub const ev_rollback_refused: u8 = code_local + 4;
pub const ev_slot_missing: u8 = code_local + 5;
pub const ev_chainload: u8 = code_local + 6;
pub const ev_chainload_fail: u8 = code_local + 7;
pub const ev_fallback: u8 = code_local + 8;
pub const ev_halted: u8 = code_local + 9;
pub const ev_recovery: u8 = code_local + 10;
pub const ev_chooser: u8 = code_local + 11;
pub const ev_measured: u8 = code_local + 12;
pub const ev_unlock_armed: u8 = code_local + 13;

const vendor_guid align(8) = uefi.Guid{
    .time_low = 0x6a1c5e1d,
    .time_mid = 0x5b8e,
    .time_high_and_version = 0x4c2f,
    .clock_seq_high_and_reserved = 0x9d,
    .clock_seq_low = 0x4e,
    .node = [_]u8{ 0x53, 0x49, 0x58, 0x4f, 0x53, 0x01 },
};

const max_extents = 64;
const Extent = struct { offset: u64, length: u64 };

const Ring = struct {
    id: [16]u8,
    bio: *BlockIo,
    blocks: u64,
    extents: [max_extents]Extent,
    n_extents: usize,
};

var ring: ?Ring = null;
var reader_key: [32]u8 = undefined;
var boot: u32 = 0;
var counter: u64 = 0;
var next_seq: u64 = 1;
var prev_hash: [32]u8 = [_]u8{0} ** 32;
var payload: [max_payload]u8 = undefined;
var payload_len: usize = 0;
var records: usize = 0;
var last_ms: u64 = 0;
var rng_state: [32]u8 = [_]u8{0} ** 32;
var io_buf: ?[]align(4096) u8 = null;

fn readEsp(root: *File, name: []const u8, out: []u8) ?[]u8 {
    var path: [64]u16 = undefined;
    var i: usize = 0;
    for ("\\EFI\\atom\\") |c| {
        path[i] = c;
        i += 1;
    }
    for (name) |c| {
        path[i] = c;
        i += 1;
    }
    path[i] = 0;
    const f = root.open(path[0..i :0], .read, .{}) catch return null;
    defer _ = f.close() catch {};
    var total: usize = 0;
    while (total < out.len) {
        const n = f.read(out[total..]) catch return null;
        if (n == 0) break;
        total += n;
    }
    return out[0..total];
}

fn parseU64(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// partGuidBytes turns a textual partition UUID into the GPT on-disk byte
// order of the device path signature: the first three fields little endian.
fn partGuidBytes(s: []const u8) ?[16]u8 {
    var raw: [16]u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '-') continue;
        if (i + 1 >= s.len or n >= 16) return null;
        const hi = hexNibble(s[i]) orelse return null;
        const lo = hexNibble(s[i + 1]) orelse return null;
        raw[n] = hi << 4 | lo;
        n += 1;
        i += 1;
    }
    if (n != 16) return null;
    return [16]u8{ raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15] };
}

fn findPartition(sig: [16]u8) ?*BlockIo {
    const bs = uefi.system_table.boot_services orelse return null;
    const handles = (bs.locateHandleBuffer(.{ .by_protocol = &BlockIo.guid }) catch return null) orelse return null;
    for (handles) |h| {
        const bio = (bs.handleProtocol(BlockIo, h) catch continue) orelse continue;
        if (!bio.media.logical_partition) continue;
        const dp = (bs.handleProtocol(DevicePath, h) catch continue) orelse continue;
        var node: ?*const DevicePath = dp;
        var last_hd: ?*const DevicePath = null;
        while (node) |n| {
            if (n.type == .media and n.subtype == 1 and n.length >= 42) last_hd = n else if (n.type != .end) last_hd = null;
            node = n.next();
        }
        const hd = last_hd orelse continue;
        const bytes: [*]const u8 = @ptrCast(hd);
        if (bytes[41] != 2) continue;
        if (std.mem.eql(u8, bytes[24..40], &sig)) return bio;
    }
    return null;
}

fn byteOffset(r: *const Ring, index: u64) ?u64 {
    var logical: u64 = 0;
    const want = index * block_size;
    for (r.extents[0..r.n_extents]) |e| {
        if (want >= logical and want + block_size <= logical + e.length) return e.offset + (want - logical);
        logical += e.length;
    }
    return null;
}

fn ioBlock(r: *const Ring, index: u64, write: bool) bool {
    const buf = io_buf orelse return false;
    const off = byteOffset(r, index) orelse return false;
    const bsz: u64 = r.bio.media.block_size;
    if (bsz == 0 or off % bsz != 0 or block_size % bsz != 0) return false;
    const lba = off / bsz;
    if (write) {
        r.bio.writeBlocks(r.bio.media.media_id, lba, buf[0..block_size]) catch return false;
        r.bio.flushBlocks() catch {};
    } else {
        r.bio.readBlocks(r.bio.media.media_id, lba, buf[0..block_size]) catch return false;
    }
    return true;
}

fn chainHash(b: []const u8) [32]u8 {
    const n = std.mem.readInt(u16, b[off_ctlen..][0..2], .little);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(b[0 .. header_size + @as(usize, n)], &out, .{});
    return out;
}

// scan finds the newest block of the ring: the next sequence, the chain hash
// to link to and the boot number this boot takes.
fn scan(r: *const Ring) void {
    const buf = io_buf orelse return;
    var max_seq: u64 = 0;
    var max_boot: u32 = 0;
    var i: u64 = 0;
    while (i < r.blocks) : (i += 1) {
        if (!ioBlock(r, i, false)) continue;
        if (!std.mem.eql(u8, buf[0..4], "SLG1")) continue;
        if (!std.mem.eql(u8, buf[off_ring .. off_ring + 16], &r.id)) continue;
        const n = std.mem.readInt(u16, buf[off_ctlen..][0..2], .little);
        if (n < tag_size or header_size + @as(usize, n) > block_size) continue;
        const seq = std.mem.readInt(u64, buf[off_seq..][0..8], .little);
        if (seq == 0 or (seq - 1) % r.blocks != i) continue;
        const b = std.mem.readInt(u32, buf[off_boot..][0..4], .little);
        if (b > max_boot) max_boot = b;
        if (seq > max_seq) {
            max_seq = seq;
            prev_hash = chainHash(buf[0..block_size]);
        }
    }
    next_seq = max_seq + 1;
    boot = max_boot + 1;
}

fn unixMs() u64 {
    const rs = uefi.system_table.runtime_services;
    const t, _ = rs.getTime() catch return 0;
    if (t.year < 1970 or t.month < 1 or t.month > 12) return 0;
    const y: i64 = @as(i64, t.year) - @as(i64, if (t.month <= 2) 1 else 0);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const m: i64 = t.month;
    const mp = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + @as(i64, t.day) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    var secs = days * 86400 + @as(i64, t.hour) * 3600 + @as(i64, t.minute) * 60 + @as(i64, t.second);
    if (t.timezone != 2047) secs += @as(i64, t.timezone) * 60;
    if (secs < 0) return 0;
    return @as(u64, @intCast(secs)) * 1000 + t.nanosecond / 1_000_000;
}

fn appendUvarint(v_in: u64) void {
    var v = v_in;
    while (true) {
        if (payload_len >= payload.len) return;
        if (v < 0x80) {
            payload[payload_len] = @intCast(v);
            payload_len += 1;
            return;
        }
        payload[payload_len] = @as(u8, @intCast(v & 0x7f)) | 0x80;
        payload_len += 1;
        v >>= 7;
    }
}

fn seedRandom() void {
    const bs = uefi.system_table.boot_services orelse return;
    if (bs.locateProtocol(uefi.protocol.Rng, null) catch null) |rng| {
        rng.getRNG(null, &rng_state) catch {};
    }
    var mix: [80]u8 = undefined;
    @memcpy(mix[0..32], &rng_state);
    @memcpy(mix[32..64], &prev_hash);
    std.mem.writeInt(u64, mix[64..72], unixMs(), .little);
    std.mem.writeInt(u64, mix[72..80], ticks(), .little);
    std.crypto.hash.sha2.Sha256.hash(&mix, &rng_state, .{});
}

fn ticks() u64 {
    switch (@import("builtin").cpu.arch) {
        .x86_64 => {
            var lo: u32 = undefined;
            var hi: u32 = undefined;
            asm volatile ("rdtsc"
                : [lo] "={eax}" (lo),
                  [hi] "={edx}" (hi),
            );
            return @as(u64, hi) << 32 | lo;
        },
        .aarch64 => return asm volatile ("mrs %[v], cntvct_el0"
            : [v] "=r" (-> u64),
        ),
        else => return 0,
    }
}

fn randomBytes(out: []u8) void {
    var block: [40]u8 = undefined;
    var off: usize = 0;
    var ctr: u64 = 0;
    while (off < out.len) : (ctr += 1) {
        @memcpy(block[0..32], &rng_state);
        std.mem.writeInt(u64, block[32..40], ctr ^ ticks(), .little);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&block, &h, .{});
        const n = @min(32, out.len - off);
        @memcpy(out[off .. off + n], h[0..n]);
        off += n;
        std.crypto.hash.sha2.Sha256.hash(&h, &rng_state, .{});
    }
}

// owned reads block index and reports whether it belongs to this ring: an
// unwritten block of the ring, or one sealed for it at that index. Nothing
// else on the partition is ever overwritten, whatever the map says.
fn owned(r: *const Ring, index: u64) bool {
    const buf = io_buf orelse return false;
    if (!ioBlock(r, index, false)) return false;
    if (!std.mem.eql(u8, buf[off_ring .. off_ring + 16], &r.id)) return false;
    if (std.mem.eql(u8, buf[0..4], "SLG0")) return std.mem.readInt(u32, buf[20..24], .little) == index;
    if (std.mem.eql(u8, buf[0..4], "SLG1")) {
        const seq = std.mem.readInt(u64, buf[off_seq..][0..8], .little);
        return seq != 0 and (seq - 1) % r.blocks == index;
    }
    return false;
}

// open reads the ring map and the reader key from the ESP and finds the
// ring. Without them the loader keeps booting and logs nothing.
pub fn open(root: *File, tpm_counter: u64) bool {
    counter = tpm_counter;
    var keybuf: [64]u8 = undefined;
    const key = readEsp(root, "sealedlog.pub", &keybuf) orelse return false;
    if (key.len < 32) return false;
    @memcpy(&reader_key, key[0..32]);
    var mapbuf: [4096]u8 = undefined;
    const m = readEsp(root, "sealedlog.map", &mapbuf) orelse return false;
    var r: Ring = .{ .id = undefined, .bio = undefined, .blocks = 0, .extents = undefined, .n_extents = 0 };
    var sig: ?[16]u8 = null;
    var have_id = false;
    var total: u64 = 0;
    var lines = std.mem.splitScalar(u8, m, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const k = line[0..eq];
        const v = line[eq + 1 ..];
        if (std.mem.eql(u8, k, "ring")) {
            if (v.len != 32) return false;
            var j: usize = 0;
            while (j < 16) : (j += 1) {
                const hi = hexNibble(v[2 * j]) orelse return false;
                const lo = hexNibble(v[2 * j + 1]) orelse return false;
                r.id[j] = hi << 4 | lo;
            }
            have_id = true;
        } else if (std.mem.eql(u8, k, "partuuid")) {
            sig = partGuidBytes(v);
        } else if (std.mem.eql(u8, k, "blocks")) {
            r.blocks = parseU64(v) orelse return false;
        } else if (std.mem.eql(u8, k, "extent")) {
            const comma = std.mem.indexOfScalar(u8, v, ',') orelse return false;
            if (r.n_extents >= max_extents) return false;
            const e = Extent{ .offset = parseU64(v[0..comma]) orelse return false, .length = parseU64(v[comma + 1 ..]) orelse return false };
            r.extents[r.n_extents] = e;
            r.n_extents += 1;
            total += e.length;
        }
    }
    if (!have_id or r.blocks < 2 or total != r.blocks * block_size) return false;
    r.bio = findPartition(sig orelse return false) orelse return false;
    const bs = uefi.system_table.boot_services orelse return false;
    const pages = bs.allocatePages(.any, .loader_data, 1) catch return false;
    io_buf = @as([*]align(4096) u8, @ptrCast(pages.ptr))[0..block_size];
    ring = r;
    scan(&ring.?);
    seedRandom();
    payload_len = 0;
    records = 0;
    const now = unixMs();
    appendUvarint(now);
    last_ms = now;
    return true;
}

// record appends one event; it reaches the disk at the next commit.
pub fn record(code: u8, args: []const u64) void {
    if (ring == null) return;
    if (payload_len + 3 + 10 * (1 + args.len) > payload.len) return;
    const n = @min(args.len, 3);
    payload[payload_len] = comp_loader;
    payload[payload_len + 1] = code;
    payload[payload_len + 2] = @intCast(n);
    payload_len += 3;
    const now = unixMs();
    appendUvarint(if (now >= last_ms) now - last_ms else 0);
    if (now != 0) last_ms = now;
    for (args[0..n]) |a| appendUvarint(a);
    records += 1;
}

// commit seals the pending records into the next block, writes it and tells
// the running system which boot this is. Called before every chainload, since
// a successful start never returns.
pub fn commit() void {
    const r = &(ring orelse return);
    if (records == 0) return;
    const buf = io_buf orelse return;
    const index = (next_seq - 1) % r.blocks;
    if (!owned(r, index)) return;
    @memset(buf[0..block_size], 0);
    @memcpy(buf[0..4], "SLG1");
    @memcpy(buf[off_ring .. off_ring + 16], &r.id);
    std.mem.writeInt(u64, buf[off_seq..][0..8], next_seq, .little);
    std.mem.writeInt(u32, buf[off_boot..][0..4], boot, .little);
    std.mem.writeInt(u64, buf[off_counter..][0..8], counter, .little);
    @memcpy(buf[off_prev .. off_prev + 32], &prev_hash);

    const X = std.crypto.dh.X25519;
    var seed: [32]u8 = undefined;
    randomBytes(&seed);
    const kp = X.KeyPair.generateDeterministic(seed) catch return;
    const shared = X.scalarmult(kp.secret_key, reader_key) catch return;
    var salt: [64]u8 = undefined;
    @memcpy(salt[0..32], &kp.public_key);
    @memcpy(salt[32..64], &reader_key);
    const H = std.crypto.kdf.hkdf.HkdfSha256;
    const prk = H.extract(&salt, &shared);
    var key: [32]u8 = undefined;
    H.expand(&key, kdf_info, prk);
    @memcpy(buf[off_eph .. off_eph + 32], &kp.public_key);
    var nonce: [12]u8 = undefined;
    randomBytes(&nonce);
    @memcpy(buf[off_nonce .. off_nonce + 12], &nonce);
    std.mem.writeInt(u16, buf[off_ctlen..][0..2], @intCast(payload_len + tag_size), .little);
    const G = std.crypto.aead.aes_gcm.Aes256Gcm;
    var tag: [tag_size]u8 = undefined;
    G.encrypt(buf[header_size .. header_size + payload_len], &tag, payload[0..payload_len], buf[0..header_size], nonce, key);
    @memcpy(buf[header_size + payload_len .. header_size + payload_len + tag_size], &tag);
    std.crypto.secureZero(u8, &key);
    std.crypto.secureZero(u8, &seed);

    if (!ioBlock(r, index, true)) return;
    prev_hash = chainHash(buf[0..block_size]);
    const written = next_seq;
    next_seq += 1;

    var v: [12]u8 = undefined;
    std.mem.writeInt(u32, v[0..4], boot, .little);
    std.mem.writeInt(u64, v[4..12], written, .little);
    const name = std.unicode.utf8ToUtf16LeStringLiteral("SintyLogBoot");
    uefi.system_table.runtime_services.setVariable(name, &vendor_guid, .{ .bootservice_access = true, .runtime_access = true }, &v) catch {};

    payload_len = 0;
    records = 0;
    const now = unixMs();
    appendUvarint(now);
    last_ms = now;
}
