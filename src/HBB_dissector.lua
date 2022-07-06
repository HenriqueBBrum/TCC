hbb_protocol = Proto("HBB",  "HBB Protocol")

next_header_type = ProtoField.uint16("hbb.next_header_type", "next_header_type", base.HEX)
flow_id         = ProtoField.int8("hbb.flow_id"     , "flow_id"    , base.DEC)
amt_bytes       = ProtoField.int32("hbb.amt_bytes"    , "amt_bytes"   , base.DEC)
time            = ProtoField.int64("hbb.time"        , "time"       , base.DEC)

hbb_protocol.fields = { next_header_type, flow_id, amt_bytes, time }

function hbb_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = hbb_protocol.name

  local subtree = tree:add(hbb_protocol, buffer(), "HBB Protocol Data")

  subtree:add(next_header_type, buffer(0,2))
  subtree:add(flow_id,     buffer(2,1))
  subtree:add(amt_bytes,    buffer(3,4))
  subtree:add(time,         buffer(7,8))

end

local eth_table = DissectorTable.GET("ethertype")
eth_table:add(0x6666, hbb_protocol)

-- local hbb_table = DissectorTable.new("hbb.port", type=ftypes.UINT16, base=base.HEX, proto=hbb_protocol)
