// Atom Loops EFI loader: paint the boot surface, verify the selected kernelcache
// against the root of trust, chainload it. Zero external deps.
const std = @import("std");
const uefi = std.os.uefi;
const File = uefi.protocol.File;
const cc = uefi.cc;

// Root public key, embedded from src/root.pub (32 raw bytes), same key the daemon
// uses. Swap the file + rebuild for production; no source edit.
const root_pubkey: [32]u8 = @embedFile("root.pub")[0..32].*;
comptime {
    if (@embedFile("root.pub").len < 32) @compileError("loader/src/root.pub must be a 32-byte raw Ed25519 public key");
}

fn puts(s: []const u8) void {
    const con_out = uefi.system_table.con_out orelse return;
    var buf: [256]u16 = undefined;
    var i: usize = 0;
    for (s) |c| {
        if (i + 1 >= buf.len) break;
        buf[i] = c;
        i += 1;
    }
    buf[i] = 0;
    if (con_out.outputString(buf[0..i :0])) |_| {} else |_| {}
}

// Silent boot: informational lines are suppressed by default so the user sees only
// the black surface. Errors always print via puts(). Flip to trace boot.
var verbose = false;
// Boot log ring: dbg() always records here, so Ctrl+Shift+D can dump the whole boot
// trace on screen even when verbose was off -- vital on headless hardware where
// there is no serial to read (the swtpm/OVMF nvFloor blind spot).
var dbg_log: [8192]u8 = undefined;
var dbg_log_len: usize = 0;
fn dbg(s: []const u8) void {
    for (s) |c| {
        if (dbg_log_len < dbg_log.len) {
            dbg_log[dbg_log_len] = c;
            dbg_log_len += 1;
        }
    }
    if (verbose) puts(s);
}

// showDebugLog dumps the recorded boot log to the console, in <=200-byte slices so the
// long buffer is not truncated by puts().
fn showDebugLog() void {
    puts("\r\n--- loader debug log ---\r\n");
    var i: usize = 0;
    while (i < dbg_log_len) {
        const end = @min(i + 200, dbg_log_len);
        puts(dbg_log[i..end]);
        i = end;
    }
    puts("\r\n--- end log (booting) ---\r\n");
}

// centerCursor clears to black and parks the text cursor near the screen centre --
// used only for the chooser, which is the one thing the user sees, and only when
// they hold a key at boot (centered, black, not top-left).
fn centerCursor() void {
    const con_out = uefi.system_table.con_out orelse return;
    if (con_out.clearScreen()) |_| {} else |_| {}
    const m: usize = @intCast(con_out.mode.mode);
    if (con_out.queryMode(m)) |geo| {
        const col: usize = if (geo.columns > 24) (geo.columns - 24) / 2 else 0;
        const row: usize = if (geo.rows > 2) geo.rows / 2 else 0;
        if (con_out.setCursorPosition(col, row)) |_| {} else |_| {}
    } else |_| {}
}

// renderSurface paints frame zero: the backdrop, then a centered logo/wallpaper
// composited from ESP:/EFI/atom/surface.bin ([u32 w][u32 h][w*h BGRX]). Missing or
// malformed asset leaves the backdrop alone. The framebuffer is never mode-reset
// after this, so every later layer inherits these pixels.
fn renderSurface(root: *File) void {
    const bs = uefi.system_table.boot_services orelse return;
    const GraphicsOutput = uefi.protocol.GraphicsOutput;
    const g = (bs.locateProtocol(GraphicsOutput, null) catch return) orelse return;
    const mode = g.mode;
    const info = mode.info;
    const width: usize = info.horizontal_resolution;
    const height: usize = info.vertical_resolution;
    const stride: usize = info.pixels_per_scan_line;
    const fb: [*]volatile u32 = @ptrFromInt(mode.frame_buffer_base);

    const backdrop: u32 = 0x00000000; // black, no backdrop
    var y: usize = 0;
    while (y < height) : (y += 1) {
        var x: usize = 0;
        while (x < width) : (x += 1) fb[y * stride + x] = backdrop;
    }

    const asset = readFile(root, std.unicode.utf8ToUtf16LeStringLiteral("\\EFI\\atom\\surface.bin")) orelse return;
    defer uefi.pool_allocator.free(asset);
    if (asset.len < 8) return;
    const lw: usize = std.mem.readInt(u32, asset[0..][0..4], .little);
    const lh: usize = std.mem.readInt(u32, asset[4..][0..4], .little);
    if (lw == 0 or lh == 0 or lw > width or lh > height) return;
    if (asset.len < 8 + lw * lh * 4) return;
    const ox = (width - lw) / 2;
    const oy = (height - lh) / 2;
    var yy: usize = 0;
    while (yy < lh) : (yy += 1) {
        var xx: usize = 0;
        while (xx < lw) : (xx += 1) {
            const off = 8 + (yy * lw + xx) * 4;
            fb[(oy + yy) * stride + (ox + xx)] = std.mem.readInt(u32, asset[off..][0..4], .little);
        }
    }
}

fn openRoot() ?*File {
    const bs = uefi.system_table.boot_services orelse return null;
    const li = (bs.handleProtocol(uefi.protocol.LoadedImage, uefi.handle) catch return null) orelse return null;
    const dev = li.device_handle orelse return null;
    const sfs = (bs.handleProtocol(uefi.protocol.SimpleFileSystem, dev) catch return null) orelse return null;
    return sfs.openVolume() catch return null;
}

fn readFile(root: *File, path: [*:0]const u16) ?[]u8 {
    const f = root.open(path, .read, .{}) catch return null;
    defer _ = f.close() catch {};
    f.setPosition(0xFFFF_FFFF_FFFF_FFFF) catch return null;
    const size = f.getPosition() catch return null;
    f.setPosition(0) catch return null;
    const buf = uefi.pool_allocator.alloc(u8, size) catch return null;
    var total: usize = 0;
    while (total < buf.len) {
        const n = f.read(buf[total..]) catch return null;
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

fn valueStart(buf: []const u8, key: []const u8) ?usize {
    const k = std.mem.indexOf(u8, buf, key) orelse return null;
    var i = k + key.len;
    while (i < buf.len and (buf[i] == ' ' or buf[i] == ':')) i += 1;
    return i;
}

// atomPath builds \EFI\atom\<name><suffix> as a null-terminated UTF-16 path.
fn atomPath(buf: []u16, name: []const u8, suffix: []const u8) [:0]const u16 {
    var i: usize = 0;
    for ("\\EFI\\atom\\") |c| {
        buf[i] = c;
        i += 1;
    }
    for (name) |c| {
        buf[i] = c;
        i += 1;
    }
    for (suffix) |c| {
        buf[i] = c;
        i += 1;
    }
    buf[i] = 0;
    return buf[0..i :0];
}

// verifyEd25519 checks img against a 64-byte detached signature using the given
// public key. Returns false on any problem, so the caller refuses the slot.
fn verifyEd25519(img: []const u8, sigbuf: []const u8, key: [32]u8) bool {
    if (sigbuf.len != 64) return false;
    const Ed = std.crypto.sign.Ed25519;
    const pk = Ed.PublicKey.fromBytes(key) catch return false;
    var sigbytes: [64]u8 = undefined;
    @memcpy(&sigbytes, sigbuf[0..64]);
    const sig = Ed.Signature.fromBytes(sigbytes);
    sig.verify(img, pk) catch return false;
    return true;
}

// stringValue extracts a flat JSON string value: key -> the text between the next
// pair of quotes. Same by-key scan style as the WAL fields (no JSON lib).
fn stringValue(buf: []const u8, key: []const u8) ?[]const u8 {
    const i = valueStart(buf, key) orelse return null;
    if (i >= buf.len or buf[i] != '"') return null;
    const start = i + 1;
    var e = start;
    while (e < buf.len and buf[e] != '"') e += 1;
    if (e >= buf.len) return null;
    return buf[start..e];
}

// signingKeyFromCert implements the A4.1 chain on the loader side: read the
// root-signed signing cert from the ESP, verify it against the embedded ROOT key,
// and return the operational signing public key it vouches for. Returns null when
// no cert is present (transition: the caller then falls back to the root key
// directly) or when the cert fails to verify.
fn signingKeyFromCert(root: *File) ?[32]u8 {
    var cbuf: [96]u16 = undefined;
    const cert = readFile(root, atomPath(&cbuf, "signing-cert.json", "")) orelse return null;
    defer uefi.pool_allocator.free(cert);
    var sbuf: [96]u16 = undefined;
    const csig = readFile(root, atomPath(&sbuf, "signing-cert.json", ".sig")) orelse return null;
    defer uefi.pool_allocator.free(csig);
    if (!verifyEd25519(cert, csig, root_pubkey)) return null;
    const b64 = stringValue(cert, "\"signing_pubkey\"") orelse return null;
    var out: [32]u8 = undefined;
    std.base64.standard.Decoder.decode(&out, b64) catch return null;
    return out;
}

// --- boot-state (ESP /EFI/atom/boot-state): the loader's slot + trial state. ---
const BootState = struct { target_next: bool, trial: bool, attempts: i64, recovery: bool };

// kvLine returns the value of a line-start "key=value" entry (until end of line).
fn kvLine(buf: []const u8, key: []const u8) ?[]const u8 {
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, buf, idx, key)) |k| {
        const after = k + key.len;
        if ((k == 0 or buf[k - 1] == '\n') and after < buf.len and buf[after] == '=') {
            var e = after + 1;
            while (e < buf.len and buf[e] != '\n' and buf[e] != '\r') e += 1;
            return buf[after + 1 .. e];
        }
        idx = k + 1;
    }
    return null;
}

fn parseBootState(buf: []const u8) BootState {
    var attempts: i64 = 0;
    if (kvLine(buf, "attempts")) |v| {
        for (v) |c| if (c >= '0' and c <= '9') {
            attempts = attempts * 10 + (c - '0');
        };
    }
    return .{
        .target_next = if (kvLine(buf, "target")) |v| std.mem.eql(u8, v, "next") else false,
        .trial = if (kvLine(buf, "trial")) |v| std.mem.eql(u8, v, "1") else false,
        .attempts = attempts,
        .recovery = if (kvLine(buf, "target")) |v| std.mem.eql(u8, v, "recovery") else false,
    };
}

// writeBootState rewrites boot-state after decrementing the trial budget. Attempts
// only shrinks, so overwriting from offset 0 is safe (the parser stops at newline,
// so any 1-byte tail from a shorter number is ignored).
fn writeBootState(root: *File, target_next: bool, trial: bool, attempts: i64) void {
    var pbuf: [64]u16 = undefined;
    const f = root.open(atomPath(&pbuf, "boot-state", ""), .read_write, .{}) catch return;
    defer _ = f.close() catch {};
    f.setPosition(0) catch {};
    const target = if (target_next) "next" else "active";
    const trialc: u8 = if (trial) '1' else '0';
    var buf: [64]u8 = undefined;
    const content = std.fmt.bufPrint(&buf, "target={s}\ntrial={c}\nattempts={d}\n", .{ target, trialc, attempts }) catch return;
    _ = f.write(content) catch {};
}

// Minimal EFI_TCG2_PROTOCOL binding (not in std): enough to measure an image into a
// PCR via HashLogExtendEvent. TCG2 is exposed only when the firmware has a TPM, so
// locating it is itself the TPM-present test.
const Tcg2 = extern struct {
    _get_capability: *const anyopaque,
    _get_event_log: *const anyopaque,
    _hash_log_extend_event: *const fn (*const Tcg2, u64, u64, u64, *const anyopaque) callconv(cc) uefi.Status,
    _submit_command: *const anyopaque,
    _get_active_pcr_banks: *const anyopaque,
    _set_active_pcr_banks: *const anyopaque,
    _get_result_of_set_active_pcr_banks: *const anyopaque,

    pub const guid align(8) = uefi.Guid{
        .time_low = 0x607f766c,
        .time_mid = 0x7455,
        .time_high_and_version = 0x42be,
        .clock_seq_high_and_reserved = 0x93,
        .clock_seq_low = 0x0b,
        .node = [_]u8{ 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f },
    };
};

// measureIntoPcr hashes img and extends TPM PCR 8 with it (measured boot), logging an
// EV_EFI_BOOT_SERVICES_APPLICATION event. Returns false when no TPM is present, in
// which case the loader runs at Level 1 -- not fatal.
fn measureIntoPcr(img: []const u8) bool {
    const bs = uefi.system_table.boot_services orelse return false;
    const tcg2 = (bs.locateProtocol(Tcg2, null) catch return false) orelse return false;
    const desc = "atom-loader:kernelcache";
    var ev: [64]u8 = undefined;
    const total: u32 = 4 + 14 + @as(u32, @intCast(desc.len));
    std.mem.writeInt(u32, ev[0..4], total, .little);
    std.mem.writeInt(u32, ev[4..8], 14, .little);
    std.mem.writeInt(u16, ev[8..10], 1, .little);
    std.mem.writeInt(u32, ev[10..14], 8, .little);
    std.mem.writeInt(u32, ev[14..18], 0x80000003, .little);
    @memcpy(ev[18 .. 18 + desc.len], desc);
    const st = tcg2._hash_log_extend_event(tcg2, 0, @intFromPtr(img.ptr), @as(u64, img.len), &ev);
    return st == .success;
}

// parseUint reads a leading base-10 integer from an ascii buffer (stops at the first
// non-digit / NUL / whitespace), or null if there is no digit.
fn parseUint(b: []const u8) ?u64 {
    var n: u64 = 0;
    var any = false;
    for (b) |ch| {
        if (ch >= '0' and ch <= '9') {
            n = n * 10 + (ch - '0');
            any = true;
        } else if (any) {
            break;
        } else if (ch == ' ') {
            continue;
        } else {
            return null;
        }
    }
    return if (any) n else null;
}

// readEmbeddedVersion returns the integer in the UKI's ".atomver" PE section -- the
// kernelcache version baked in at build time and covered by the Ed25519 signature, so
// an attacker cannot change it without breaking the sig. Called only on VERIFIED image
// bytes. Returns null when the section is absent or the PE is malformed (then the caller
// cannot enforce anti-rollback and boots, matching L1/no-version images).
fn readEmbeddedVersion(img: []const u8) ?u64 {
    if (img.len < 0x40 or img[0] != 'M' or img[1] != 'Z') return null;
    const pe_off = std.mem.readInt(u32, img[0x3c..][0..4], .little);
    if (@as(u64, pe_off) + 24 > img.len) return null;
    if (!std.mem.eql(u8, img[pe_off..][0..4], "PE\x00\x00")) return null;
    const coff = pe_off + 4;
    const num_sections = std.mem.readInt(u16, img[coff + 2 ..][0..2], .little);
    const opt_size = std.mem.readInt(u16, img[coff + 16 ..][0..2], .little);
    var sec: u64 = @as(u64, coff) + 20 + opt_size;
    var i: u16 = 0;
    while (i < num_sections) : (i += 1) {
        if (sec + 40 > img.len) return null;
        if (std.mem.eql(u8, img[sec..][0..8], ".atomver")) {
            const raw_size = std.mem.readInt(u32, img[sec + 16 ..][0..4], .little);
            const raw_ptr = std.mem.readInt(u32, img[sec + 20 ..][0..4], .little);
            if (raw_size == 0 or @as(u64, raw_ptr) + raw_size > img.len) return null;
            return parseUint(img[raw_ptr..][0..raw_size]);
        }
        sec += 40;
    }
    return null;
}

// The TPM NV index holding the monotonic anti-rollback counter. The daemon's counter
// backend must write/increment the SAME index (provisioning contract). The NV area is
// defined with its own empty auth so the loader can read it with a password session.
const ATOM_NV_ANTIROLLBACK: u32 = 0x0150A701;

// nvFloor reads the hardware anti-rollback counter from TPM NV via the TCG2
// SubmitCommand protocol (a raw TPM2 NV_Read). Returns the floor value, or null when no
// TPM is present or the NV index is absent -- the caller then cannot enforce and boots
// (L1: the software stage-side anti-rollback is the floor there).
fn nvFloor() ?u64 {
    const bs = uefi.system_table.boot_services orelse return null;
    const tcg2 = (bs.locateProtocol(Tcg2, null) catch return null) orelse return null;
    const submit: *const fn (*const Tcg2, u32, [*]const u8, u32, [*]u8) callconv(cc) uefi.Status =
        @ptrCast(@alignCast(tcg2._submit_command));

    var cmd: [128]u8 = undefined;
    var n: usize = 0;
    const w16 = struct {
        fn f(b: []u8, o: *usize, v: u16) void {
            std.mem.writeInt(u16, b[o.*..][0..2], v, .big);
            o.* += 2;
        }
    }.f;
    const w32 = struct {
        fn f(b: []u8, o: *usize, v: u32) void {
            std.mem.writeInt(u32, b[o.*..][0..4], v, .big);
            o.* += 4;
        }
    }.f;
    w16(&cmd, &n, 0x8002); // TPM_ST_SESSIONS
    const size_at = n;
    w32(&cmd, &n, 0); // commandSize (patched below)
    w32(&cmd, &n, 0x0000014E); // TPM_CC_NV_Read
    w32(&cmd, &n, ATOM_NV_ANTIROLLBACK); // authHandle (the NV index authorizes its own read)
    w32(&cmd, &n, ATOM_NV_ANTIROLLBACK); // nvIndex
    const auth_at = n;
    w32(&cmd, &n, 0); // authorizationSize (patched)
    const auth_start = n;
    w32(&cmd, &n, 0x40000009); // TPM_RS_PW (password session)
    w16(&cmd, &n, 0); // nonce size 0
    cmd[n] = 0; // sessionAttributes
    n += 1;
    w16(&cmd, &n, 0); // hmac/password size 0
    std.mem.writeInt(u32, cmd[auth_at..][0..4], @intCast(n - auth_start), .big);
    w16(&cmd, &n, 8); // read 8 bytes (the counter)
    w16(&cmd, &n, 0); // offset 0
    std.mem.writeInt(u32, cmd[size_at..][0..4], @intCast(n), .big); // commandSize

    var resp: [256]u8 = undefined;
    if (submit(tcg2, @intCast(n), &cmd, resp.len, &resp) != .success) return null;
    if (resp.len < 16) return null;
    if (std.mem.readInt(u32, resp[6..10], .big) != 0) return null; // responseCode != success
    // sessions response: header(10) + parameterSize(4) + TPM2B{size(2)+data}
    const data_size = std.mem.readInt(u16, resp[14..16], .big);
    if (data_size == 0 or 16 + @as(usize, data_size) > resp.len) return null;
    var v: u64 = 0;
    var i: usize = 0;
    while (i < data_size and i < 8) : (i += 1) v = (v << 8) | resp[16 + i];
    return v;
}

// chainloadSlot reads \EFI\atom\<slot>, verifies its detached .sig against the root
// key, and only then hands control to it (framebuffer preserved).
fn chainloadSlot(root: *File, slot: []const u8, key: [32]u8) bool {
    const bs = uefi.system_table.boot_services orelse return false;
    var pbuf: [96]u16 = undefined;
    const img = readFile(root, atomPath(&pbuf, slot, "")) orelse {
        puts("slot image missing\r\n");
        return false;
    };
    defer uefi.pool_allocator.free(img);

    var sbuf: [96]u16 = undefined;
    const sig = readFile(root, atomPath(&sbuf, slot, ".sig")) orelse {
        puts("slot signature missing -- refusing\r\n");
        return false;
    };
    defer uefi.pool_allocator.free(sig);

    if (!verifyEd25519(img, sig, key)) {
        puts("signature INVALID -- refusing to chain\r\n");
        return false;
    }
    dbg("signature OK\r\n");
    // Refuse a signed-but-OLDER slot when a hardware anti-rollback floor exists.
    // The version comes from the signed UKI (.atomver), the floor from the TPM NV counter;
    // no TPM or no version -> cannot enforce -> boot (L1, software stage-side floor holds).
    if (readEmbeddedVersion(img)) |ver| {
        if (nvFloor()) |floor| {
            if (ver < floor) {
                puts("anti-rollback: slot version below the floor -- refusing\r\n");
                return false;
            }
            dbg("anti-rollback: slot at or above floor\r\n");
        }
    }
    if (measureIntoPcr(img)) dbg("TPM: measured into PCR 8\r\n") else dbg("TPM: absent, Level 1\r\n");

    const handle = bs.loadImage(false, uefi.handle, .{ .buffer = img }) catch return false;
    _ = bs.startImage(handle) catch return false;
    return true;
}

// pollKey polls the console for a keypress across a short window (ms). A press opens
// the hidden chooser; otherwise the surface flows straight through to boot.
fn pollKey(window_ms: usize) bool {
    const bs = uefi.system_table.boot_services orelse return false;
    const con_in = uefi.system_table.con_in orelse return false;
    // Prefer the extended input protocol so Ctrl+Shift+D is visible (the basic protocol
    // reports no modifiers); fall back to the basic console if it is absent.
    const ex: ?*uefi.protocol.SimpleTextInputEx =
        bs.locateProtocol(uefi.protocol.SimpleTextInputEx, null) catch null;
    var elapsed: usize = 0;
    while (elapsed < window_ms) : (elapsed += 50) {
        if (ex) |exp| {
            if (exp.readKeyStroke()) |k| {
                const sh = k.state.shift;
                const ctrl = sh.left_control_pressed or sh.right_control_pressed;
                const shift = sh.left_shift_pressed or sh.right_shift_pressed;
                const is_d = k.input.unicode_char == 'd' or k.input.unicode_char == 'D' or k.input.unicode_char == 0x04;
                if (sh.shift_state_valid and ctrl and shift and is_d) {
                    verbose = true; // Ctrl+Shift+D: turn on live logging and dump the trace
                    showDebugLog();
                } else {
                    return true; // any other key opens the chooser
                }
            } else |_| {}
        } else if (con_in.readKeyStroke()) |_| {
            return true;
        } else |_| {}
        bs.stall(50 * 1000) catch {};
    }
    return false;
}

// runChooser shows the slots in-surface and returns the one the user picks. Faithful
// to policy: recovery is always offered as the safe floor; a manual pick does not pin.
fn runChooser() []const u8 {
    puts("[chooser] 1=active  2=prev  3=recovery\r\n");
    const con_in = uefi.system_table.con_in orelse return "kernelcache-active.efi";
    const bs = uefi.system_table.boot_services;
    var tries: usize = 0;
    while (tries < 240) : (tries += 1) {
        if (con_in.readKeyStroke()) |k| {
            switch (k.unicode_char) {
                '2' => return "kernelcache-prev.efi",
                '3' => return "kernelcache-recovery.efi",
                else => return "kernelcache-active.efi",
            }
        } else |_| {}
        if (bs) |b| b.stall(50 * 1000) catch {};
    }
    return "kernelcache-active.efi";
}

pub fn main() void {
    dbg("Atom Loops loader (prototype)\r\n");

    const root = openRoot() orelse {
        puts("no ESP volume\r\n");
        while (true) {}
    };
    renderSurface(root);

    // Resolve the verification key: the root-verified signing key from the ESP
    // cert (A4.1), or the root key directly during transition (no cert yet).
    const vkey = signingKeyFromCert(root) orelse blk: {
        dbg("no signing cert, verifying against root key\r\n");
        break :blk root_pubkey;
    };

    // Silent by default: a key held in a short (~2s) window opens the
    // chooser, drawn centered on the black surface. No key -> the surface flows
    // straight to boot with nothing on screen.
    if (pollKey(2000)) {
        centerCursor();
        const chosen = runChooser();
        // A manually-picked slot may not exist (e.g. 'prev' on a single-slot fresh
        // install): don't HALT on it -- fall back to the always-present active slot
        // so a stray keypress at the boot window can never strand the machine.
        if (!chainloadSlot(root, chosen, vkey)) {
            if (!std.mem.eql(u8, chosen, "kernelcache-active.efi")) {
                puts("picked slot unavailable, falling back to active\r\n");
                _ = chainloadSlot(root, "kernelcache-active.efi", vkey);
            }
            puts("boot HALTED\r\n");
        }
        while (true) {}
    }

    // Slot selection from the ESP boot-state (the daemon writes it; we own the
    // trial budget). A pending candidate with attempts left boots -next after we
    // decrement and persist; a spent budget falls back to -active.
    var slot: []const u8 = "kernelcache-active.efi";
    if (readFile(root, std.unicode.utf8ToUtf16LeStringLiteral("\\EFI\\atom\\boot-state"))) |b| {
        const st = parseBootState(b);
        if (st.recovery) {
            // The OS asked for recovery, or the daemon armed it on NeedsRecovery
            // (a spent candidate with no good slot to fall back to). Boot the
            // signed recovery slot: a separate, always-present volume that
            // survives a dead main.
            dbg("boot-state: recovery requested\r\n");
            slot = "kernelcache-recovery.efi";
        } else if (st.trial and st.target_next and st.attempts > 0) {
            writeBootState(root, true, true, st.attempts - 1);
            slot = "kernelcache-next.efi";
        }
        uefi.pool_allocator.free(b);
    } else {
        puts("no boot-state, defaulting to active\r\n");
    }

    dbg("selected slot: ");
    dbg(slot);
    dbg("\r\n");
    if (!chainloadSlot(root, slot, vkey)) puts("boot HALTED (no valid slot)\r\n");
    while (true) {}
}
