const std = @import("std");
const dns = @import("address_codec.zig");
const expect = std.testing.expect;
const equal = std.testing.expectEqual;
// Independent wire fixtures: a.test, two distinct compressed A answers.
const question = "\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
    "\x01a\x04test\x00\x00\x01\x00\x01";
const rr1 = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01";
const rr2 = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc0\x00\x02\x02";

test "wire A pages preserve every distinct address, zero TTL and network order" {
    var out: dns.Answer = .{};
    try dns.parseResponse(question ++ rr1 ++ rr2, 0x1234, "A.TEST.", .ipv4, &out);
    try equal(@as(usize, 2), out.count);
    try equal(@as(u32, 0), out.ttl_seconds);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, out.addresses[0].bytes[0..4]);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, out.addresses[1].bytes[0..4]);
    try std.testing.expectEqualSlices(u8, &(@as([12]u8, @splat(0))), out.addresses[1].bytes[4..]);
}

test "transaction and complete question binding leave result unchanged on failure" {
    var out: dns.Answer = .{ .count = 17, .ttl_seconds = 91 };
    try std.testing.expectError(error.Mismatch, dns.parseResponse(question ++ rr1 ++ rr2, 0x4321, "a.test", .ipv4, &out));
    try std.testing.expectError(error.Mismatch, dns.parseResponse(question ++ rr1 ++ rr2, 0x1234, "b.test", .ipv4, &out));
    try std.testing.expectError(error.Mismatch, dns.parseResponse(question ++ rr1 ++ rr2, 0x1234, "a.test", .ipv6, &out));
    try equal(@as(usize, 17), out.count);
    try equal(@as(u32, 91), out.ttl_seconds);
    var short = (question ++ rr1 ++ rr2).*;
    short[2] |= 2;
    try std.testing.expectError(error.Truncated, dns.parseResponse(&short, 0x1234, "a.test", .ipv4, &out));
    for (0..(question ++ rr1 ++ rr2).len) |n| {
        dns.parseResponse((question ++ rr1 ++ rr2)[0..n], 0x1234, "a.test", .ipv4, &out) catch continue;
        return error.UnexpectedSuccess;
    }
    try equal(@as(usize, 17), out.count);
}

test "AAAA records are complete 128bit addresses independent of transport" {
    const response = "\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x01a\x04test\x00\x00\x1c\x00\x01" ++
        "\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x32\x00\x10" ++
        "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" ++
        "\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x14\x00\x10" ++
        "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
    var out: dns.Answer = .{};
    try dns.parseResponse(response, 0x1234, "a.test", .ipv6, &out);
    try equal(@as(usize, 2), out.count);
    try equal(@as(u32, 20), out.ttl_seconds);
    try equal(dns.Family.ipv6, out.addresses[0].family);
    try std.testing.expectEqualSlices(u8, response[response.len - 16 ..], &out.addresses[1].bytes);
}

test "reordered CNAME chain filters unrelated answers and deduplicates" {
    const response = "\x12\x34\x81\x80\x00\x01\x00\x04\x00\x00\x00\x00" ++
        "\x01a\x04test\x00\x00\x01\x00\x01" ++
        "\x01b\xc0\x0e\x00\x01\x00\x01\x00\x00\x00\x28\x00\x04\xc0\x00\x02\x09" ++
        "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x0a\x00\x02\xc0\x18" ++
        "\xc0\x18\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04\xc0\x00\x02\x09" ++
        "\x01c\xc0\x0e\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\xc0\x00\x02\x63";
    var out: dns.Answer = .{};
    try dns.parseResponse(response, 0x1234, "a.test", .ipv4, &out);
    try equal(@as(usize, 1), out.count);
    try equal(@as(u32, 10), out.ttl_seconds);
    try equal(@as(u32, 30), out.addresses[0].ttl_seconds);
    try equal(@as(u8, 9), out.addresses[0].bytes[3]);
}

test "malformed compression and CNAME loops are bounded, labels stay distinct" {
    var out: dns.Answer = .{ .count = 19 };
    var loop = (question ++ rr1 ++ rr2).*;
    loop[question.len + 1] = @intCast(question.len);
    try std.testing.expectError(error.Malformed, dns.parseResponse(&loop, 0x1234, "a.test", .ipv4, &out));
    const aliases = "\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x01a\x04test\x00\x00\x01\x00\x01" ++
        "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x0a\x00\x04\x01b\xc0\x0e" ++
        "\x01b\xc0\x0e\x00\x05\x00\x01\x00\x00\x00\x0a\x00\x02\xc0\x0c";
    try std.testing.expectError(error.AliasLoop, dns.parseResponse(aliases, 0x1234, "a.test", .ipv4, &out));
    const dot = "\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\x06a.test\x00\x00\x01\x00\x01";
    try std.testing.expectError(error.Mismatch, dns.parseResponse(dot, 0x1234, "a.test", .ipv4, &out));
    try equal(@as(usize, 19), out.count);
}

test "answer capacity never reports a shortened success, query errors preserve buffers" {
    var bytes: [1024]u8 = undefined;
    @memcpy(bytes[0..question.len], question);
    bytes[7] = 33;
    var size: usize = question.len;
    for (0..33) |i| {
        @memcpy(bytes[size..][0..rr1.len], rr1);
        bytes[size + rr1.len - 1] = @intCast(i);
        size += rr1.len;
    }
    var out: dns.Answer = .{ .count = 19 };
    try std.testing.expectError(error.Capacity, dns.parseResponse(bytes[0..size], 0x1234, "a.test", .ipv4, &out));
    try equal(@as(usize, 19), out.count);
    @memset(&bytes, 0x55);
    try std.testing.expectError(error.InvalidName, dns.buildQuery(1, "a..test", .ipv4, &bytes));
    try std.testing.expectError(error.Capacity, dns.buildQuery(1, "a.test", .ipv4, bytes[0..12]));
    try expect(std.mem.allEqual(u8, &bytes, 0x55));
    const n = try dns.buildQuery(0x1234, "A.TEST.", .ipv6, &bytes);
    try equal(@as(usize, 24), n);
    try std.testing.expectEqualSlices(u8, "\x01a\x04test\x00\x00\x1c\x00\x01", bytes[12..n]);
}
