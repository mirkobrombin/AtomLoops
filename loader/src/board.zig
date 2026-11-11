const std = @import("std");
const builtin = @import("builtin");
const uefi = std.os.uefi;

const fdt_guid: uefi.Guid = .{
    .time_low = 0xb1b621d5,
    .time_mid = 0xf19c,
    .time_high_and_version = 0x41a5,
    .clock_seq_high_and_reserved = 0x83,
    .clock_seq_low = 0x0b,
    .node = [_]u8{ 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0 },
};

const families = [_]struct { compatible: []const u8, name: []const u8 }{
    .{ .compatible = "nvidia,tegra234", .name = "l4t" },
};

fn be32(b: []const u8, at: usize) ?u32 {
    if (at + 4 > b.len) return null;
    return std.mem.readInt(u32, b[at..][0..4], .big);
}

fn rootCompatible(blob: []const u8) ?[]const u8 {
    if (be32(blob, 0) != 0xd00dfeed) return null;
    const total = be32(blob, 4) orelse return null;
    if (total > blob.len) return null;
    const b = blob[0..total];
    const structs = be32(b, 8) orelse return null;
    const strings = be32(b, 12) orelse return null;
    var at: usize = structs;
    var depth: usize = 0;
    while (true) {
        const token = be32(b, at) orelse return null;
        at += 4;
        switch (token) {
            1 => {
                depth += 1;
                if (depth > 1) return null;
                const end = std.mem.indexOfScalarPos(u8, b, at, 0) orelse return null;
                at = std.mem.alignForward(usize, end + 1, 4);
            },
            2 => return null,
            3 => {
                const len = be32(b, at) orelse return null;
                const name_off = be32(b, at + 4) orelse return null;
                const value = at + 8;
                if (value + len > b.len or strings + name_off >= b.len) return null;
                const name_end = std.mem.indexOfScalarPos(u8, b, strings + name_off, 0) orelse return null;
                if (std.mem.eql(u8, b[strings + name_off .. name_end], "compatible")) return b[value .. value + len];
                at = std.mem.alignForward(usize, value + len, 4);
            },
            4 => {},
            else => return null,
        }
    }
}

pub fn familyOf(blob: []const u8) ?[]const u8 {
    const list = rootCompatible(blob) orelse return null;
    var it = std.mem.tokenizeScalar(u8, list, 0);
    while (it.next()) |c| {
        for (families) |f| {
            if (std.mem.eql(u8, c, f.compatible)) return f.name;
        }
    }
    return null;
}

pub fn family() ?[]const u8 {
    if (builtin.cpu.arch != .aarch64) return null;
    const st = uefi.system_table;
    for (st.configuration_table[0..st.number_of_table_entries]) |t| {
        if (!t.vendor_guid.eql(fdt_guid)) continue;
        const head: [*]const u8 = @ptrCast(t.vendor_table);
        const total = std.mem.readInt(u32, head[4..8], .big);
        if (total < 40 or total > 16 << 20) return null;
        return familyOf(head[0..total]);
    }
    return null;
}

pub fn variant(buf: []u8, slot: []const u8, name: []const u8) ?[]const u8 {
    const stem = if (std.mem.endsWith(u8, slot, ".efi")) slot[0 .. slot.len - 4] else return null;
    return std.fmt.bufPrint(buf, "{s}.{s}.efi", .{ stem, name }) catch null;
}

fn fdtWith(buf: []u8, compatible: []const u8) []const u8 {
    const strings = "compatible\x00";
    var at: usize = 40;
    const put = struct {
        fn f(b: []u8, o: *usize, v: u32) void {
            std.mem.writeInt(u32, b[o.*..][0..4], v, .big);
            o.* += 4;
        }
    }.f;
    put(buf, &at, 1);
    put(buf, &at, 0);
    put(buf, &at, 3);
    put(buf, &at, @intCast(compatible.len));
    put(buf, &at, 0);
    @memcpy(buf[at .. at + compatible.len], compatible);
    at = std.mem.alignForward(usize, at + compatible.len, 4);
    put(buf, &at, 2);
    put(buf, &at, 9);
    const str_at = at;
    @memcpy(buf[at .. at + strings.len], strings);
    at += strings.len;
    var h: usize = 0;
    put(buf, &h, 0xd00dfeed);
    put(buf, &h, @intCast(at));
    put(buf, &h, 40);
    put(buf, &h, @intCast(str_at));
    return buf[0..at];
}

test "the Orin device tree picks the L4T kernels" {
    var buf: [256]u8 = @splat(0);
    try std.testing.expectEqualStrings("l4t", familyOf(fdtWith(&buf, "nvidia,p3768-0000+p3767-0005\x00nvidia,tegra234\x00")).?);
}

test "other boards keep the mainline kernels" {
    var buf: [256]u8 = @splat(0);
    try std.testing.expect(familyOf(fdtWith(&buf, "rockchip,rk3588\x00")) == null);
    try std.testing.expect(familyOf(fdtWith(&buf, "nvidia,tegra210\x00")) == null);
    try std.testing.expect(familyOf("not a device tree at all, just bytes") == null);
}

test "a damaged device tree is ignored" {
    var buf: [256]u8 = @splat(0);
    const good = fdtWith(&buf, "nvidia,tegra234\x00");
    try std.testing.expect(familyOf(good[0 .. good.len - 20]) == null);
}

test "variant names" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("kernelcache-active.l4t.efi", variant(&buf, "kernelcache-active.efi", "l4t").?);
}
