tunnel_proto = Proto("cp_tunnel", "Centipede Tunnel Protocol")

endpoint_id = ProtoField.uint32("cp_tunnel.endpoint_id", "Endpoint ID", base.DEC)
sequence = ProtoField.uint64("cp_tunnel.sequence", "Sequence Number", base.DEC)

tunnel_proto.fields = { endpoint_id, sequence }

function tunnel_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CP_TUN"

    pinfo.cols.info = "Tunneled packet addressed to endpoint " .. buffer(0, 4):uint() .. " with sequence number " .. buffer(4, 8):uint64() .. "."

    local subtree = tree:add(tunnel_proto, buffer(), "Centipede Tunnel Protocol")

    subtree:add(endpoint_id, buffer(0, 4))
    subtree:add(sequence, buffer(4, 8))
    subtree:add(buffer(0, 12), "Nonce: " .. buffer(0, 12):bytes():tohex())
    subtree:add(buffer(12, 16), "Tag: " .. buffer(12, 16):bytes():tohex())
    subtree:add(buffer(28, -1), "Encrypted Packet")
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(5000, tunnel_proto)
udp_table:add(5001, tunnel_proto)