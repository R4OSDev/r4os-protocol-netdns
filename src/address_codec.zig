//! DNS A/AAAA wire owner. Pure copied values, independent of transport family.
//! RFC1035 sections4.1 and RFC3596 section2. No resolver/cache/packet lifetime.
const std = @import("std");
pub const Family = enum(u16) { ipv4 = 4, ipv6 = 6 };
pub const max_addresses = 32;
pub const max_aliases = 16;
pub const max_message = 4096;
pub const Error = error{ InvalidName, Capacity, Short, Malformed, Mismatch, Truncated, NotFound, NoData, ServerFailure, AliasLoop };
pub const Address = struct { family: Family, bytes: [16]u8 = @splat(0), ttl_seconds: u32 };
pub const Answer = struct {
    count: usize = 0,
    ttl_seconds: u32 = 0,
    addresses: [max_addresses]Address = undefined,
};
const Name = struct {
    bytes: [255]u8 = undefined,
    len: usize = 0,
    fn equal(left: *const Name, right: *const Name) bool {
        return std.mem.eql(u8, left.bytes[0..left.len], right.bytes[0..right.len]);
    }
};
const Decoded = struct { name: Name, next: usize };
const Record = struct { owner: Name, kind: u16, class: u16, ttl: u32, data: usize, length: usize, next: usize };
const Alias = struct { owner: Name, target: Name, ttl: u32 };
pub fn recordType(family: Family) u16 {
    return if (family == .ipv4) 1 else 28;
}
fn textName(text: []const u8) Error!Name {
    if (text.len == 0 or text.len > 254) return error.InvalidName;
    if (std.mem.eql(u8, text, ".")) {
        var name: Name = .{};
        name.bytes[0] = 0;
        name.len = 1;
        return name;
    }
    const input = if (text[text.len - 1] == '.') text[0 .. text.len - 1] else text;
    if (input.len == 0 or input.len > 253) return error.InvalidName;
    var name: Name = .{};
    var start: usize = 0;
    for (0..input.len + 1) |i| {
        if (i != input.len and input[i] != '.') continue;
        const n = i - start;
        if (n == 0 or n > 63 or name.len + n + 2 > name.bytes.len) return error.InvalidName;
        name.bytes[name.len] = @intCast(n);
        name.len += 1;
        for (input[start..i]) |byte| {
            // Explicit ASCII DNS label input. No guessed IDNA/UTF8 conversion.
            if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidName;
            name.bytes[name.len] = std.ascii.toLower(byte);
            name.len += 1;
        }
        start = i + 1;
    }
    name.bytes[name.len] = 0;
    name.len += 1;
    return name;
}
pub fn buildQuery(id: u16, text: []const u8, family: Family, out: []u8) Error!usize {
    const name = try textName(text);
    const size = 12 + name.len + 4;
    if (out.len < size) return error.Capacity;
    @memset(out[0..size], 0);
    put16(out, 0, id);
    put16(out, 2, 0x0100);
    put16(out, 4, 1);
    @memcpy(out[12..][0..name.len], name.bytes[0..name.len]);
    put16(out, 12 + name.len, recordType(family));
    put16(out, 14 + name.len, 1);
    return size;
}
fn get16(data: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], .big);
}
fn get32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .big);
}
fn put16(data: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, data[offset..][0..2], value, .big);
}
fn decodeName(data: []const u8, initial: usize) Error!Decoded {
    var pos = initial;
    var next: ?usize = null;
    var name: Name = .{};
    for (0..128) |_| {
        if (pos >= data.len) return error.Short;
        const n = data[pos];
        if (n & 0xc0 == 0xc0) {
            if (data.len - pos < 2) return error.Short;
            const target = @as(usize, n & 0x3f) << 8 | data[pos + 1];
            // A compression pointer denotes a prior name occurrence.
            if (target < 12 or target >= pos) return error.Malformed;
            if (next == null) next = pos + 2;
            pos = target;
            continue;
        }
        if (n & 0xc0 != 0) return error.Malformed;
        if (n == 0) {
            if (name.len == name.bytes.len) return error.Malformed;
            name.bytes[name.len] = 0;
            name.len += 1;
            return .{ .name = name, .next = next orelse pos + 1 };
        }
        if (data.len - pos - 1 < n) return error.Short;
        if (name.len + n + 2 > name.bytes.len) return error.Malformed;
        // Preserve label boundaries: a literal dot inside one label must
        // never compare equal to two distinct labels in the requested name.
        name.bytes[name.len] = n;
        name.len += 1;
        for (data[pos + 1 ..][0..n]) |byte| {
            name.bytes[name.len] = std.ascii.toLower(byte);
            name.len += 1;
        }
        pos += 1 + @as(usize, n);
    }
    return error.Malformed;
}
fn record(data: []const u8, initial: usize) Error!Record {
    const decoded = try decodeName(data, initial);
    const pos = decoded.next;
    if (pos > data.len or data.len - pos < 10) return error.Short;
    const length = get16(data, pos + 8);
    const start = pos + 10;
    if (length > data.len - start) return error.Short;
    const kind = get16(data, pos);
    const class = get16(data, pos + 2);
    if (class == 1 and (kind == 1 and length != 4 or kind == 28 and length != 16)) return error.Malformed;
    if (class == 1 and kind == 5) {
        const target = try decodeName(data, start);
        if (target.next != start + length) return error.Malformed;
    }
    return .{ .owner = decoded.name, .kind = kind, .class = class, .ttl = get32(data, pos + 4), .data = start, .length = length, .next = start + length };
}
/// Validates a complete answer for the exact transaction, question and type.
/// Only the answer section and the question's CNAME chain supply addresses.
/// Copies all wanted records or fails Capacity; never silently loses suffixes.
/// TTL0 is preserved. Output changes only on full success, including dedup/TTL.
pub fn parseResponse(data: []const u8, id: u16, text: []const u8, family: Family, out: *Answer) Error!void {
    if (data.len < 12) return error.Short;
    if (data.len > max_message) return error.Capacity;
    const expected = try textName(text);
    const flags = get16(data, 2);
    if (get16(data, 0) != id) return error.Mismatch;
    if (flags & 0x8000 == 0 or flags & 0x7840 != 0 or get16(data, 4) != 1) return error.Malformed;
    const question = try decodeName(data, 12);
    if (data.len - question.next < 4) return error.Short;
    if (!question.name.equal(&expected) or get16(data, question.next) != recordType(family) or get16(data, question.next + 2) != 1) return error.Mismatch;
    if (flags & 0x0200 != 0) return error.Truncated;
    if (flags & 15 == 3) return error.NotFound;
    if (flags & 15 != 0) return error.ServerFailure;
    const answers = get16(data, 6);
    const answer_start = question.next + 4;
    var aliases: [max_aliases]Alias = undefined;
    var alias_count: usize = 0;
    var pos = answer_start;
    for (0..answers) |_| {
        const rr = try record(data, pos);
        pos = rr.next;
        if (rr.kind != 5 or rr.class != 1) continue;
        const target = try decodeName(data, rr.data);
        var duplicate = false;
        for (aliases[0..alias_count]) |*alias| if (alias.owner.equal(&rr.owner)) {
            if (!alias.target.equal(&target.name)) return error.Malformed;
            alias.ttl = @min(alias.ttl, rr.ttl);
            duplicate = true;
            break;
        };
        if (duplicate) continue;
        if (alias_count == aliases.len) return error.Capacity;
        aliases[alias_count] = .{ .owner = rr.owner, .target = target.name, .ttl = rr.ttl };
        alias_count += 1;
    }
    // Validate remaining sections too, but never use unrelated glue as answers.
    const remaining = @as(u32, get16(data, 8)) + get16(data, 10);
    for (0..remaining) |_| {
        const rr = try record(data, pos);
        pos = rr.next;
    }
    if (pos != data.len) return error.Malformed;
    var canonical = expected;
    var ttl: u32 = std.math.maxInt(u32);
    var hops: usize = 0;
    while (true) {
        var found = false;
        for (aliases[0..alias_count]) |*alias| if (alias.owner.equal(&canonical)) {
            if (hops == max_aliases) return error.AliasLoop;
            canonical = alias.target;
            ttl = @min(ttl, alias.ttl);
            hops += 1;
            found = true;
            break;
        };
        if (!found) break;
    }
    var result: Answer = .{};
    pos = answer_start;
    for (0..answers) |_| {
        const rr = try record(data, pos);
        pos = rr.next;
        if (rr.class != 1 or rr.kind != recordType(family) or !rr.owner.equal(&canonical)) continue;
        const n: usize = if (family == .ipv4) 4 else 16;
        var duplicate = false;
        for (result.addresses[0..result.count]) |*address| if (std.mem.eql(u8, address.bytes[0..n], data[rr.data..][0..n])) {
            address.ttl_seconds = @min(address.ttl_seconds, rr.ttl);
            duplicate = true;
            break;
        };
        ttl = @min(ttl, rr.ttl);
        if (duplicate) continue;
        if (result.count == max_addresses) return error.Capacity;
        var address: Address = .{ .family = family, .ttl_seconds = rr.ttl };
        @memcpy(address.bytes[0..n], data[rr.data..][0..n]);
        result.addresses[result.count] = address;
        result.count += 1;
    }
    if (result.count == 0) return error.NoData;
    result.ttl_seconds = ttl;
    out.* = result;
}
