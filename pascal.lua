local proto = Proto("pascal", "Pascal Strings")
proto.fields.length = ProtoField.uint8("pascal.length", "Length", base.DEC)
proto.fields.content = ProtoField.string("pascal.content", "Content")

-- The reassembly table is a table of tables,
--
--   fragments_by_stream[stream_key][packet_number] = {
--     buffer = <string or nil>,
--     prev = <number or nil>
--   }
--
-- stream_key is a unique identifier for each unidirectional stream, generated
-- by get_stream_key().
--
-- buffer is the unprocessed fragment within the given packet. If there were no
-- incomplete PDUs, then buffer is nil. Note this is distinct from an empty
-- buffer, which means that there was an incomplete PDU, but the packet did not
-- contribute any data.
--
-- prev is the packet number of the previous packet that contains a fragment of
-- the same PDU. This will be nil if this is the first fragment of a PDU.
local fragments_by_stream = {}


-- Returns a unique identifier for the stream that the packet belongs to.
local function get_stream_key(pinfo)
    return tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) ..
        "->" .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
end


-- Reads a complete PDU.
--
-- This is the only part of the dissector that needs to know how to parse the
-- protocol. Reimplement to suit other protocols.
--
-- buffer is the ByteArray containing the data to parse.
--
-- tvb is either a Tvb for the current packet, or nil if the PDU begain in an
-- earlier packet. In this case, create a new Tvb from the buffer *after* we
-- have validated that we have a complete PDU.
--
-- Returns the number of bytes consumed, or nil if there is not a complete PDU
-- in the buffer. Optionally, also return  a string to be appended to the
-- packet's Info column.
local function read_complete_pdu(buffer, tvb, tree)
    -- Parse data from the buffer, not the tvb
    if buffer:len() < 1 then return nil end
    local length = buffer:uint(0, 1)
    if buffer:len() < (1 + length) then return nil end

    -- If this is a reassembled PDU, create a new Tvb. Only do this after we've
    -- validated that we have a full PDU, because this triggers the creation
    -- of a new tab in the Packet Bytes view in the UI.
    local was_reassembled = false
    if not tvb then
        was_reassembled = true
        tvb = buffer:tvb("Reassembled PDU")
    end

    -- Make sure we only use the range of the buffer that we are consuming.
    local subtree = tree:add(
        proto,
        tvb:range(0, 1 + length),
        "Pascal String \"" .. tvb:raw(1, length) .. "\""
    )
    subtree:add(proto.fields.length, tvb:range(0, 1))
    subtree:add(proto.fields.content, tvb:range(1, length))

    -- Build a string to append to the packet's' Info column
    local info = "\"" .. tvb:raw(1, length) .. "\""
    if was_reassembled then
        info = info .. " (reassembled)"
    end

    return subtree.len, info
end


function proto.dissector(tvb, pinfo, tree)
    -- Look up the reassembly state for this stream
    local key = get_stream_key(pinfo)
    if not fragments_by_stream[key] then
        fragments_by_stream[key] = {}
    end
    local fragments = fragments_by_stream[key]

    -- Find the previous packet in this stream, i.e., the one with the greatest
    -- packet number less than the current packet number.
    local prev_pkt_num = nil
    for pkt_num, state in pairs(fragments) do
        if pkt_num < pinfo.number then
            if (not prev_pkt_num) or (pkt_num > prev_pkt_num) then
                prev_pkt_num = pkt_num
            end
        end
    end

    -- If the previous packet has a nil buffer, then it was not part of an
    -- incomplete PDU (distinct from an empty buffer).
    if prev_pkt_num and not fragments[prev_pkt_num].buffer then
        prev_pkt_num = nil
    end

    -- Otherwise, follow the linked list backwards to assemble all the fragments
    -- of the incomplete PDU.
    local whole_buffer = ByteArray.new()
    local i = prev_pkt_num
    while i do
        local prev_state = fragments[i]
        if prev_state.buffer then
            whole_buffer:prepend(ByteArray.new(prev_state.buffer, true))
        end
        i = prev_state.prev
    end

    local earlier_fragment_len = whole_buffer:len()
    local was_reassembled = earlier_fragment_len > 0

    -- Add the current packet data, too.
    whole_buffer:append(tvb:bytes())

    -- Loop to extract one or more complete PDUs.
    local offset = 0
    local pdu_count = 0
    local infos = {}
    while offset < whole_buffer:len() do
        -- If we are parsing from within the current packet, then we will pass
        -- read_complete_pdu() a TvbRange within the current packet. Otherwise,
        -- we pass nil, indicating that we are parsing from a reassembled
        -- buffer, and a new Tvb should be created if a complete PDU is found.
        local tvb2 = nil
        if offset >= earlier_fragment_len then
            tvb2 = tvb:range(offset - earlier_fragment_len)
        end

        -- Try to consume a complete PDU from the buffer at offset. If this
        -- returns nil, then it is an incomplete PDU.
        local consumed, info = read_complete_pdu(
            whole_buffer:subset(offset, whole_buffer:len() - offset),
            tvb2,
            tree
        )

        if not consumed then
            table.insert(infos, "fragment")
            break
        end

        table.insert(infos, info)
        offset = offset + consumed
        pdu_count = pdu_count + 1
    end

    -- Set the Info column to the comma-delimited list of info strings.
    pinfo.cols.info = table.concat(infos, ", ")

    -- If there is any left over data, we will save the unconsumed fragment in
    -- the fragments table.
    local leftover = nil
    if offset < whole_buffer:len() then
        local consumed_from_current = math.max(0, offset - earlier_fragment_len)
        leftover = tvb:range(consumed_from_current):bytes():raw()
    end

    -- If we failed to extract a full PDU, then use the linked list to connect
    -- our incomplete buffer with the previous packet.
    if pdu_count == 0 then
        fragments[pinfo.number] = { buffer = leftover, prev = prev_pkt_num }
    else
        fragments[pinfo.number] = { buffer = leftover, prev = nil }
    end
end

-- Register the dissector for a given UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(14641, proto.dissector)
