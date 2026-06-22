// Minimal second-stage UEFI app: proves the loader's LoadImage/StartImage chain.
const std = @import("std");
const uefi = std.os.uefi;
pub fn main() void {
    if (uefi.system_table.con_out) |co| {
        if (co.outputString(std.unicode.utf8ToUtf16LeStringLiteral("chainloaded stage2 OK\r\n"))) |_| {} else |_| {}
    }
    while (true) {}
}
