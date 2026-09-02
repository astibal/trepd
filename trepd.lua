-- Wireshark dissector for the trepd TREP TCP protocol.
-- Install or load with: wireshark -X lua_script:trepd.lua

local trep = Proto("trepd", "TREP")

local f = trep.fields
f.magic = ProtoField.string("trepd.magic", "Magic")
f.version = ProtoField.uint8("trepd.version", "Version", base.DEC)
f.type = ProtoField.uint8("trepd.type", "Type", base.DEC,
    {[1] = "HELLO", [2] = "SYNC_BEGIN", [3] = "ROUTE4",
     [4] = "ROUTE6", [5] = "SYNC_END"})
f.length = ProtoField.uint16("trepd.length", "Payload length", base.DEC)
f.prefix_length = ProtoField.uint8(
    "trepd.prefix_length", "Prefix length", base.DEC)
f.reserved = ProtoField.bytes("trepd.reserved", "Reserved")
f.network4 = ProtoField.ipv4("trepd.network4", "IPv4 prefix")
f.network6 = ProtoField.ipv6("trepd.network6", "IPv6 prefix")

local header_length = 8
local type_route4 = 3
local type_route6 = 4

local type_names = {
    [1] = "HELLO",
    [2] = "SYNC_BEGIN",
    [3] = "ROUTE4",
    [4] = "ROUTE6",
    [5] = "SYNC_END",
}

-- Suggested Wireshark coloring rules:
--   trepd.type == 3 || trepd.type == 4  (route messages)
--   trepd.type == 1                     (HELLO)

local function get_len(buffer, offset)
    if buffer:len() - offset < header_length then
        return 0
    end

    return header_length + buffer(offset + 6, 2):uint()
end

local function dissect_pdu(buffer, pinfo, tree)
    if buffer:len() < header_length then
        return 0
    end

    pinfo.cols.protocol = "TREP"

    local payload_length = buffer(6, 2):uint()
    local message_length = header_length + payload_length
    local message_type = buffer(5, 1):uint()
    local message_name = type_names[message_type] or "UNKNOWN"
    local info = message_name

    local subtree = tree:add(
        trep,
        buffer(0, message_length),
        "TREP " .. (type_names[message_type] or "UNKNOWN"))

    subtree:add(f.magic, buffer(0, 4))
    subtree:add(f.version, buffer(4, 1))
    subtree:add(f.type, buffer(5, 1))
    subtree:add(f.length, buffer(6, 2))

    local payload = buffer(header_length, payload_length)

    if message_type == type_route4 and payload_length == 8 then
        local prefix_length = payload(0, 1):uint()
        local network = payload(4, 4):ipv4()

        subtree:add(f.prefix_length, payload(0, 1))
        subtree:add(f.reserved, payload(1, 3))
        subtree:add(f.network4, payload(4, 4))
        info = string.format("ROUTE4 %s/%d", tostring(network), prefix_length)
    elseif message_type == type_route6 and payload_length == 20 then
        local prefix_length = payload(0, 1):uint()
        local network = payload(4, 16):ipv6()

        subtree:add(f.prefix_length, payload(0, 1))
        subtree:add(f.reserved, payload(1, 3))
        subtree:add(f.network6, payload(4, 16))
        info = string.format("ROUTE6 %s/%d", tostring(network), prefix_length)
    elseif payload_length > 0 then
        subtree:add(payload, "Payload")
        info = string.format("%s (%d bytes)", message_name, payload_length)
    end

    pinfo.cols.info = info
    return message_length
end

function trep.dissector(buffer, pinfo, tree)
    local offset = 0

    while offset < buffer:len() do
        local remaining = buffer:len() - offset

        if remaining < header_length then
            pinfo.desegment_offset = offset
            pinfo.desegment_len = header_length - remaining
            return
        end

        local payload_length = buffer(offset + 6, 2):uint()
        local message_length = header_length + payload_length

        if remaining < message_length then
            pinfo.desegment_offset = offset
            pinfo.desegment_len = message_length - remaining
            return
        end

        dissect_pdu(buffer(offset, message_length), pinfo, tree)
        offset = offset + message_length
    end
end

local tcp_port_table = DissectorTable.get("tcp.port")
for id = 1, 255 do
    tcp_port_table:add(43000 + id, trep)
end
