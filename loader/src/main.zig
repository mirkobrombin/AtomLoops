// Atom Loops custom EFI loader (prototype).
//
// Thin UEFI application, Go-explicit style: every fallible call is checked at the
// call site, no hidden control flow, no panics in normal paths.
//   Phase 1: come up as a UEFI app, print a banner.
//   Phase 2 (this file): paint frame zero of the continuous surface via GOP.
// Next: read deployment.json from the ESP, chain the signed UKI.
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

// paintSurface fills the whole screen with the frame-zero backdrop color. Returns
// false (handled by the caller) if GOP is unavailable, rather than trapping.
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
    const backdrop: u32 = 0x00101828; // dark navy -- the surface's frame zero

    var y: usize = 0;
    while (y < height) : (y += 1) {
        var x: usize = 0;
        while (x < width) : (x += 1) {
            fb[y * stride + x] = backdrop;
        }
    }
    return true;
}

pub fn main() void {
    puts("Atom Loops loader (prototype)\r\n");
    if (paintSurface()) {
        puts("frame zero painted\r\n");
    } else {
        puts("GOP unavailable; text-only\r\n");
    }
    while (true) {}
}
