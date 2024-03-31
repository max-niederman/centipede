tunnel_proto = Proto("centipede", "Centipede Protocol")

discriminant = ProtoField.string("centipede.discriminant", "Discriminant", base.NONE)
sequence_number = ProtoField.uint64("centipede.sequence_number", "Sequence Number", base.DEC)

tunnel_proto.fields = { endpoint_id, sequence }

function tunnel_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CP"

    local subtree = tree:add(tunnel_proto, buffer(), "Centipede Tunnel Protocol")

    if buffer(0, 8):uint64() == UInt64.fromhex("8000000000000000") then
        pinfo.cols.info = "Control message"

        subtree:add(discriminant, buffer(0, 8), "control")

        subtree:add(buffer(8, 32), "Sender Key: " .. buffer(8, 32):bytes():tohex())
        subtree:add(buffer(40, 32), "Signature: " .. buffer(40, 64):bytes():tohex())
        subtree:add(buffer(104, 32), "Recipient Key: " .. buffer(104, 32):bytes():tohex())
        subtree:add(buffer(136, -1), "Serialized Content: " .. buffer(136, -1):raw())
        subtree:add(buffer(104, -1), "Signed Content")
    else
        pinfo.cols.info = "Packet message with sequence number " .. buffer(0, 8):uint64()

        subtree:add(discriminant, buffer(0, 8), "packet")

        subtree:add(sequence_number, buffer(0, 8), "Sequence Number: " .. buffer(0, 8):uint64())
        subtree:add(buffer(8, 8), "Sender: " .. buffer(8, 8):bytes():tohex())
        subtree:add(buffer(0, 12), "Nonce: " .. buffer(0, 12):bytes():tohex())
        subtree:add(buffer(16, 16), "Tag: " .. buffer(16, 16):bytes():tohex())
        subtree:add(buffer(32, -1), "Encrypted Packet: " .. buffer(32, -1):bytes():tohex())
    end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(5000, tunnel_proto)