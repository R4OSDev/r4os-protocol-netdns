const r4os = @import("r4os");

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const CLASS_IN: u16 = 1;

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("netdns_init", "netdns_shutdown", "netdns_query", "netdns_dispatch"));
}

export fn netdns_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    ctx.logInfo("NETDNS.R4P init");
    _ = ctx.registerRole("net.dns", .net, 0);
    _ = ctx.setStatus(.active, "DNS R4P active");
    return 0;
}

export fn netdns_shutdown() callconv(.c) i32 {
    return 0;
}

export fn netdns_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("DNS R4P ready"),
    };
    return 0;
}

export fn netdns_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.dns_op_build_a_query => buildAQuery(request),
        r4os.abi.dns_op_handle_response => handleResponse(request),
        else => return -4,
    }
    return request.result;
}

fn buildAQuery(request: *r4os.abi.DnsOp) void {
    request.flags = 0;
    if (request.name_len == 0 or request.name_len > request.name.len or request.payload.len < 18) {
        request.result = r4os.abi.dns_result_name;
        return;
    }
    var i: usize = 0;
    while (i < request.payload.len) : (i += 1) request.payload[i] = 0;
    writeBe16(request.payload[0..], 0, request.id);
    writeBe16(request.payload[0..], 2, 0x0100);
    writeBe16(request.payload[0..], 4, 1);
    var pos: usize = 12;
    pos = writeName(request.payload[0..], pos, request.name[0..@intCast(request.name_len)]) orelse {
        request.result = r4os.abi.dns_result_name;
        return;
    };
    if (pos + 4 > request.payload.len) {
        request.result = r4os.abi.dns_result_buffer_small;
        return;
    }
    writeBe16(request.payload[0..], pos, TYPE_A);
    writeBe16(request.payload[0..], pos + 2, CLASS_IN);
    request.payload_len = @intCast(pos + 4);
    request.result = r4os.abi.dns_result_ok;
}

fn handleResponse(request: *r4os.abi.DnsOp) void {
    request.flags = 0;
    if (request.payload_len < 12 or request.payload_len > request.payload.len) {
        request.result = r4os.abi.dns_result_short;
        return;
    }
    const payload = request.payload[0..@intCast(request.payload_len)];
    request.id = readBe16(payload, 0);
    const flags = readBe16(payload, 2);
    const qd = readBe16(payload, 4);
    const an = readBe16(payload, 6);
    const rcode = flags & 0x000F;
    if (rcode == 3) {
        request.result = r4os.abi.dns_result_nxdomain;
        return;
    }
    if ((flags & 0x8000) == 0 or qd == 0 or an == 0 or rcode != 0) {
        request.result = r4os.abi.dns_result_header;
        return;
    }
    var pos: usize = 12;
    pos = skipName(payload, pos) orelse {
        request.result = r4os.abi.dns_result_qname;
        return;
    };
    if (pos + 4 > payload.len) {
        request.result = r4os.abi.dns_result_question;
        return;
    }
    pos += 4;
    var answer_index: u16 = 0;
    while (answer_index < an) : (answer_index += 1) {
        pos = skipName(payload, pos) orelse {
            request.result = r4os.abi.dns_result_aname;
            return;
        };
        if (pos + 10 > payload.len) {
            request.result = r4os.abi.dns_result_answer;
            return;
        }
        const typ = readBe16(payload, pos);
        const class = readBe16(payload, pos + 2);
        const rdlen: usize = @intCast(readBe16(payload, pos + 8));
        pos += 10;
        if (pos + rdlen > payload.len) {
            request.result = r4os.abi.dns_result_answer;
            return;
        }
        if (typ == TYPE_A) {
            if (class != CLASS_IN or rdlen != 4) {
                request.result = r4os.abi.dns_result_atype;
                return;
            }
            request.answer = .{ payload[pos], payload[pos + 1], payload[pos + 2], payload[pos + 3] };
            request.flags = r4os.abi.dns_flag_a_record;
            request.result = r4os.abi.dns_result_ok;
            return;
        }
        if (typ == TYPE_CNAME) {
            pos += rdlen;
            continue;
        }
        pos += rdlen;
    }
    request.result = r4os.abi.dns_result_atype;
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.DnsOp {
    if (buffer.data == null) return null;
    if (buffer.len < @sizeOf(r4os.abi.DnsOp)) return null;
    return @ptrCast(@alignCast(buffer.data.?));
}

fn writeName(out: []u8, pos_in: usize, name: []const u8) ?usize {
    var pos = pos_in;
    var label_start: usize = 0;
    var i: usize = 0;
    while (i <= name.len) : (i += 1) {
        if (i == name.len or name[i] == '.') {
            const len = i - label_start;
            if (len == 0 or len > 63 or pos + 1 + len >= out.len) return null;
            out[pos] = @intCast(len);
            pos += 1;
            var j: usize = label_start;
            while (j < i) : (j += 1) {
                out[pos] = name[j];
                pos += 1;
            }
            label_start = i + 1;
        }
    }
    if (pos >= out.len) return null;
    out[pos] = 0;
    return pos + 1;
}

fn skipName(payload: []const u8, pos_in: usize) ?usize {
    var pos = pos_in;
    var guard: usize = 0;
    while (pos < payload.len and guard < 128) : (guard += 1) {
        const len = payload[pos];
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= payload.len) return null;
            return pos + 2;
        }
        if ((len & 0xC0) != 0) return null;
        if (len == 0) return pos + 1;
        if (pos + 1 + len > payload.len) return null;
        pos += 1 + len;
    }
    return null;
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    return (@as(u16, buf[offset]) << 8) | buf[offset + 1];
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @intCast(value >> 8);
    buf[offset + 1] = @intCast(value & 0xFF);
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
