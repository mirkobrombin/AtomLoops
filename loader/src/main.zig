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

// The Atom Loops root/signing public key, embedded at build time (A4.1). The
// loader refuses to chain any kernelcache whose Ed25519 signature does not verify
// against this key -- the security floor that holds even without firmware Secure
// Boot (required for aarch64 / no-SB targets).
const root_pubkey = [32]u8{ 0x93, 0x45, 0xd8, 0x5d, 0x98, 0x4e, 0x41, 0x6a, 0xc1, 0x65, 0x9e, 0x6c, 0xcb, 0x6a, 0x01, 0xb5, 0x6c, 0x4b, 0x85, 0xbd, 0x13, 0xe6, 0x48, 0xa2, 0x47, 0x5a, 0x37, 0x95, 0xa1, 0x66, 0x91, 0xfd };

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

// --- deployment.json (WAL): only the fields the loader needs, scanned by key. ---
const Wal = struct { has_pending: bool, boot_attempts: i64, has_lkg: bool };

fn valueStart(buf: []const u8, key: []const u8) ?usize {
    const k = std.mem.indexOf(u8, buf, key) orelse return null;
    var i = k + key.len;
    while (i < buf.len and (buf[i] == ' ' or buf[i] == ':')) i += 1;
    return i;
}

fn stringFieldNonEmpty(buf: []const u8, key: []const u8) bool {
    const i = valueStart(buf, key) orelse return false;
    if (i >= buf.len or buf[i] != '"') return false;
    return i + 1 < buf.len and buf[i + 1] != '"';
}

fn intField(buf: []const u8, key: []const u8) i64 {
    const start = valueStart(buf, key) orelse return 0;
    var i = start;
    var neg = false;
    if (i < buf.len and buf[i] == '-') {
        neg = true;
        i += 1;
    }
    var n: i64 = 0;
    while (i < buf.len and buf[i] >= '0' and buf[i] <= '9') : (i += 1) n = n * 10 + (buf[i] - '0');
    return if (neg) -n else n;
}

fn parseWal(buf: []const u8) Wal {
    return .{
        .has_pending = stringFieldNonEmpty(buf, "\"pending\""),
        .boot_attempts = intField(buf, "\"boot_attempts\""),
        .has_lkg = stringFieldNonEmpty(buf, "\"last_known_good\""),
    };
}

fn pickSlot(w: Wal) []const u8 {
    if (w.has_pending and w.boot_attempts <= 0 and !w.has_lkg) return "kernelcache-recovery.efi";
    if (w.has_pending and w.boot_attempts <= 0) return "kernelcache-prev.efi";
    if (w.has_pending) return "kernelcache-next.efi";
    return "kernelcache-active.efi";
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

// verifyEd25519 checks img against a 64-byte detached signature using the embedded
// root key. Returns false on any problem, so the caller refuses the slot.
fn verifyEd25519(img: []const u8, sigbuf: []const u8) bool {
    if (sigbuf.len != 64) return false;
    const Ed = std.crypto.sign.Ed25519;
    const pk = Ed.PublicKey.fromBytes(root_pubkey) catch return false;
    var sigbytes: [64]u8 = undefined;
    @memcpy(&sigbytes, sigbuf[0..64]);
    const sig = Ed.Signature.fromBytes(sigbytes);
    sig.verify(img, pk) catch return false;
    return true;
}

// chainloadSlot reads \EFI\atom\<slot>, verifies its detached .sig against the root
// key, and only then hands control to it (framebuffer preserved).
fn chainloadSlot(root: *File, slot: []const u8) bool {
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

    if (!verifyEd25519(img, sig)) {
        puts("signature INVALID -- refusing to chain\r\n");
        return false;
    }
    puts("signature OK\r\n");

    const handle = bs.loadImage(false, uefi.handle, .{ .buffer = img }) catch return false;
    _ = bs.startImage(handle) catch return false;
    return true;
}

pub fn main() void {
    puts("Atom Loops loader (prototype)\r\n");

    const root = openRoot() orelse {
        puts("no ESP volume\r\n");
        while (true) {}
    };
    renderSurface(root);

    var slot: []const u8 = "kernelcache-active.efi";
    if (readFile(root, std.unicode.utf8ToUtf16LeStringLiteral("\\EFI\\atom\\deployment.json"))) |w| {
        slot = pickSlot(parseWal(w));
        uefi.pool_allocator.free(w);
    } else {
        puts("no WAL, defaulting to active\r\n");
    }

    puts("selected slot: ");
    puts(slot);
    puts("\r\n");
    if (!chainloadSlot(root, slot)) puts("boot HALTED (no valid slot)\r\n");
    while (true) {}
}
