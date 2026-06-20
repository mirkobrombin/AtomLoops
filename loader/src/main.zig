// Atom Loops custom EFI loader (prototype).
//
// Thin UEFI application, written in a deliberately Go-explicit style: every
// fallible call returns a status we check right here, no hidden control flow.
// Phase 1 (this file): prove the toolchain -- come up as a UEFI app and print a
// banner to the console. Next phases: paint frame-zero via GOP, read
// deployment.json from the ESP, chain the signed UKI.
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

pub fn main() void {
    puts("Atom Loops loader (prototype) -- frame zero\r\n");
    while (true) {}
}
