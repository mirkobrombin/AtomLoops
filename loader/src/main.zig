// Atom Loops custom EFI loader (prototype).
//
// Thin UEFI application, Go-explicit style: every fallible call is checked at the
// call site, no hidden control flow, no panics in normal paths.
//   Phase 1: come up as a UEFI app, banner.
//   Phase 2: paint frame zero of the continuous surface via GOP.
//   Phase 3 (this file): chain-load a UKI (LoadImage/StartImage) from the ESP,
//            preserving the GOP framebuffer. Next: read deployment.json + slot pick.
const std = @import("std");
const uefi = std.os.uefi;

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

// readFile reads an entire file from the given volume root into a pool-allocated
// buffer. Returns null (handled by the caller) on any failure.
fn readFile(root: *const uefi.protocol.File, path: [*:0]const u16) ?[]u8 {
    const f = root.open(path, .read, .{}) catch return null;
    defer _ = f.close() catch {};
    f.setPosition(0xFFFF_FFFF_FFFF_FFFF) catch return null; // seek to EOF
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

// chainload reads an EFI image from the loader's own ESP and hands control to it,
// preserving the GOP framebuffer (no mode reset -> no black frame). It normally
// does not return (the loaded image takes over).
fn chainload(path: [*:0]const u16) bool {
    const bs = uefi.system_table.boot_services orelse return false;
    const li = (bs.handleProtocol(uefi.protocol.LoadedImage, uefi.handle) catch return false) orelse return false;
    const dev = li.device_handle orelse return false;
    const sfs = (bs.handleProtocol(uefi.protocol.SimpleFileSystem, dev) catch return false) orelse return false;
    const root = sfs.openVolume() catch return false;
    defer _ = root.close() catch {};
    const img = readFile(root, path) orelse return false;
    defer uefi.pool_allocator.free(img);
    const handle = bs.loadImage(false, uefi.handle, .{ .buffer = img }) catch return false;
    _ = bs.startImage(handle) catch return false;
    return true;
}

pub fn main() void {
    puts("Atom Loops loader (prototype)\r\n");
    _ = paintSurface();
    puts("chainloading stage2...\r\n");
    if (chainload(std.unicode.utf8ToUtf16LeStringLiteral("\\EFI\\BOOT\\STAGE2.EFI"))) {
        puts("chainload returned\r\n");
    } else {
        puts("chainload FAILED\r\n");
    }
    while (true) {}
}
