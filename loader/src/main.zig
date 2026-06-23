// Atom Loops custom EFI loader (prototype). Go-explicit Zig: every fallible call
// checked at the call site, no hidden control flow, no panics in normal paths.
//   Phase 1-2: UEFI app + GOP frame-zero paint.
//   Phase 3-4: LoadImage/StartImage chainload from the ESP (framebuffer preserved).
//   Phase 6 (this file): read ESP deployment.json + PickBootTarget slot -> chainload
//            that kernelcache. (Signature verify + TPM measure are later phases.)
const std = @import("std");
const uefi = std.os.uefi;
const File = uefi.protocol.File;

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

fn paintSurface() bool {
    const bs = uefi.system_table.boot_services orelse return false;
    const GraphicsOutput = uefi.protocol.GraphicsOutput;
    const g = (bs.locateProtocol(GraphicsOutput, null) catch return false) orelse return false;
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
    return true;
}

// openRoot returns the root directory of the volume the loader was loaded from.
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

// stringFieldNonEmpty is true when key's value is a non-null, non-empty JSON string.
fn stringFieldNonEmpty(buf: []const u8, key: []const u8) bool {
    const i = valueStart(buf, key) orelse return false;
    if (i >= buf.len or buf[i] != '"') return false; // null or absent
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

// pickSlot mirrors the shared PickBootTarget: candidate+budget -> next;
// candidate+spent+fallback -> prev; candidate+spent+no-fallback -> recovery;
// else active.
fn pickSlot(w: Wal) []const u8 {
    if (w.has_pending and w.boot_attempts <= 0 and !w.has_lkg) return "kernelcache-recovery.efi";
    if (w.has_pending and w.boot_attempts <= 0) return "kernelcache-prev.efi";
    if (w.has_pending) return "kernelcache-next.efi";
    return "kernelcache-active.efi";
}

fn chainloadPath(root: *File, path16: [*:0]const u16) bool {
    const bs = uefi.system_table.boot_services orelse return false;
    const img = readFile(root, path16) orelse return false;
    defer uefi.pool_allocator.free(img);
    const handle = bs.loadImage(false, uefi.handle, .{ .buffer = img }) catch return false;
    _ = bs.startImage(handle) catch return false;
    return true;
}

// chainloadSlot builds \EFI\atom\<slot> as UTF-16 and chainloads it.
fn chainloadSlot(root: *File, slot: []const u8) bool {
    var path: [96]u16 = undefined;
    var i: usize = 0;
    for ("\\EFI\\atom\\") |c| {
        path[i] = c;
        i += 1;
    }
    for (slot) |c| {
        path[i] = c;
        i += 1;
    }
    path[i] = 0;
    return chainloadPath(root, path[0..i :0]);
}

pub fn main() void {
    puts("Atom Loops loader (prototype)\r\n");
    _ = paintSurface();

    const root = openRoot() orelse {
        puts("no ESP volume\r\n");
        while (true) {}
    };

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
    if (!chainloadSlot(root, slot)) puts("chainload FAILED\r\n");
    while (true) {}
}
