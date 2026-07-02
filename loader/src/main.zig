// Atom Loops custom EFI loader (prototype). Go-explicit Zig: every fallible call
// checked at the call site, no hidden control flow, no panics in normal paths.
//   Phase 1-2: UEFI app + GOP frame-zero paint.
//   Phase 3-4: LoadImage/StartImage chainload (framebuffer preserved).
//   Phase 6: read ESP deployment.json + PickBootTarget slot select.
//   Phase 7 (this file): Ed25519 self-verify the selected kernelcache before
//            chaining it (std.crypto, no external deps). A bad signature is fatal
//            for that slot. TPM measure + logo composite are later phases.
const std = @import("std");
const uefi = std.os.uefi;
const File = uefi.protocol.File;
const cc = uefi.cc;

// The Atom Loops root/signing public key, embedded at build time (A4.1). The
// loader refuses to chain any kernelcache whose Ed25519 signature does not verify
// against this key -- the security floor that holds even without firmware Secure
// Boot (required for aarch64 / no-SB targets).
// The root public key is embedded at build time from src/root.pub: 32 raw bytes,
// the SAME key the OTA daemon verifies manifests against, so the loader and the
// daemon share one root of trust. Production: replace src/root.pub with the real
// key (atom-sign keygen --pub loader/src/root.pub) and rebuild; no source edit.
const root_pubkey: [32]u8 = @embedFile("root.pub")[0..32].*;
comptime {
    if (@embedFile("root.pub").len < 32) @compileError("loader/src/root.pub must be a 32-byte raw Ed25519 public key (run: atom-sign keygen --pub loader/src/root.pub)");
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

    const backdrop: u32 = 0x00101828;
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
const BootState = struct { target_next: bool, trial: bool, attempts: i64 };

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
    puts("signature OK\r\n");
    if (measureIntoPcr(img)) puts("TPM: measured into PCR 8\r\n") else puts("TPM: absent, Level 1\r\n");

    const handle = bs.loadImage(false, uefi.handle, .{ .buffer = img }) catch return false;
    _ = bs.startImage(handle) catch return false;
    return true;
}

// pollKey polls the console for a keypress across a short window (ms). A press opens
// the hidden chooser; otherwise the surface flows straight through to boot.
fn pollKey(window_ms: usize) bool {
    const bs = uefi.system_table.boot_services orelse return false;
    const con_in = uefi.system_table.con_in orelse return false;
    var elapsed: usize = 0;
    while (elapsed < window_ms) : (elapsed += 50) {
        if (con_in.readKeyStroke()) |_| {
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
    puts("Atom Loops loader (prototype)\r\n");

    const root = openRoot() orelse {
        puts("no ESP volume\r\n");
        while (true) {}
    };
    renderSurface(root);

    // Resolve the verification key: the root-verified signing key from the ESP
    // cert (A4.1), or the root key directly during transition (no cert yet).
    const vkey = signingKeyFromCert(root) orelse blk: {
        puts("no signing cert, verifying against root key\r\n");
        break :blk root_pubkey;
    };

    // Hidden in-surface chooser: a keypress in a short window opens it.
    puts("chooser: press a key...\r\n");
    if (pollKey(3000)) {
        puts("chooser opened\r\n");
        const chosen = runChooser();
        puts("chooser -> ");
        puts(chosen);
        puts("\r\n");
        if (!chainloadSlot(root, chosen, vkey)) puts("boot HALTED\r\n");
        while (true) {}
    }

    // Slot selection from the ESP boot-state (the daemon writes it; we own the
    // trial budget). A pending candidate with attempts left boots -next after we
    // decrement and persist; a spent budget falls back to -active.
    var slot: []const u8 = "kernelcache-active.efi";
    if (readFile(root, std.unicode.utf8ToUtf16LeStringLiteral("\\EFI\\atom\\boot-state"))) |b| {
        const st = parseBootState(b);
        if (st.trial and st.target_next and st.attempts > 0) {
            writeBootState(root, true, true, st.attempts - 1);
            slot = "kernelcache-next.efi";
        }
        uefi.pool_allocator.free(b);
    } else {
        puts("no boot-state, defaulting to active\r\n");
    }

    puts("selected slot: ");
    puts(slot);
    puts("\r\n");
    if (!chainloadSlot(root, slot, vkey)) puts("boot HALTED (no valid slot)\r\n");
    while (true) {}
}
