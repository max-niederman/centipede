tunnel_proto = Proto("cp_tunnel", "Centipede Tunnel Protocol")

function tunnel_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CP_TUN"

    local subtree = tree:add(tunnel_proto, buffer(), "Centipede Tunnel Protocol")
    subtree:add(buffer(0, 12), "Nonce: " .. buffer(0, 12):bytes():tohex())
    subtree:add(buffer(0, 4), "Endpoint ID: " .. buffer(0, 4):uint())
    subtree:add(buffer(4, 8), "Sequence Number: " .. buffer(4, 8):uint64())
    subtree:add(buffer(12, 16), "Tag: " .. buffer(12, 16):bytes():tohex())
    subtree:add(buffer(28, -1), "Encrypted Packet")
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(5000, tunnel_proto)
udp_table:add(5001, tunnel_proto)