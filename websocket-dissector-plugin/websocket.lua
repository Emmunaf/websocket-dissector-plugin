
-- Creates a Proto object
local websocket_proto = Proto("WebSocket", "A simple WebSocket dissector")

-- Declare the value strings for the OPCodes (2nd byte of the header)
local vs_opcodes = {
  [0] = "Continuation frame",
  [1] = "Text frame",
  [2] = "Binary frame",
  [8] = "Connection Close",
  [9] = "Ping",
  [10] = "Pong",
}
local vs_boolcodes = {
  [0] = "False",
  [1] = "True"
}
local vs_pay_len = {
  [126] = "[126] Extended payload length (16 bits)",
  [127] = "[127] Extended payload length (64 bits)"
}
-- Default value for vs_pay_len
function setDefault (t, d)
  local mt = {__index = function () return d end}
  setmetatable(t, mt)
end
setDefault(vs_pay_len, "lenght")
----
handshake_complete = 0;
-- Fields for the client handshake
local f_rmethod = ProtoField.string("websocket.rmethod", "Request Method")
local f_ruri = ProtoField.string("websocket.ruri", "Requested URI")
local f_rkey = ProtoField.string("websocket.key", "Sec-WebSocket-Key")
-- Fields for the server response handshake
local f_rcode = ProtoField.string("websocket.rcode", "Response Code")
local f_shttp = ProtoField.string("websocket.shttp", "HTTP protocol") -- HTTP version used by server
-- Fields for the data-frame
---- First byte
local f_fin = ProtoField.uint8("websocket.dfin", "FIN", base.DEC, vs_boolcodes, 0x80) -- bitmask:0x80 => 128 => 10000000
local f_rsv1 = ProtoField.uint8("websocket.rsv1", "Reserved 1", base.DEC, vs_boolcodes, 0x40)
local f_rsv2 = ProtoField.uint8("websocket.rsv2", "Reserved 2", base.DEC, vs_boolcodes, 0x20)
local f_rsv3 = ProtoField.uint8("websocket.rsv3", "Reserved 3", base.DEC, vs_boolcodes, 0x10)
local f_opcode = ProtoField.uint8("websocket.dopcode", "OP Code", base.DEC, vs_opcodes, 0xF)
---- Second byte
local f_mask = ProtoField.uint8("websocket.dmask", "Mask", base.DEC, vs_boolcodes, 0x80)
local f_pay_len1 = ProtoField.uint8("websocket.dpaylen1", "Payload lenght", base.DEC, vs_pay_len, 0x7F)
---- Extra length header
local f_pay_len2 = ProtoField.uint32("websocket.dpaylen2", "Payload lenght", base.DEC)
local f_pay_len3 = ProtoField.uint64("websocket.dpaylen3", "Payload lenght", base.DEC)
---- Mask-key
local f_mkey = ProtoField.string("websocket.mkey", "Mask-Key")
---- Decoded payload
local f_mdecoded_pay = ProtoField.string("websocket.mdec_pay", "Decoded Payload")

websocket_proto.fields = {f_rmethod, f_ruri, f_rkey, f_rcode, f_shttp, f_fin, f_rsv3, f_rsv2,
                          f_rsv1, f_opcode, f_mask, f_pay_len1, f_pay_len2, f_pay_len3, f_mkey, f_mdecoded_pay}

function websocket_proto.dissector(tvb, pinfo, tree)
  pinfo.cols.protocol = websocket_proto.name
  local t_websocket = tree:add(websocket_proto, tvb(), "Websocket")

  local websocket_key = nil -- Sec-WebSocket-Key if it is a client handshake
  local soffset = 0 -- Used as starting offset to scroll the buffer
  local offset = pinfo.desegment_offset or 0 -- Needed for reassembling stream
  if tostring(tvb(0,4)) == "47455420" then -- Inizio di un pacchetto request HTTP!
    print("Inizio pacchetto semigenerico http, sarà un handshake websocket?");
    -- The method has to be GET [RFC6455], http ver > 1.1 : <GET /*pathhere* HTTP/1.1>
    hdr_str = tvb():string()
    handshake_offset = string.find(hdr_str, "Sec%-WebSocket%-Key")
    --[[
    The request MUST include a header field with the name |Sec-WebSocket-Key|.
    The value of this header field MUST be a nonce consisting of a randomly
    selected 16-byte value that has been base64-encoded[RFC6455]
    --]]
    if handshake_offset and not websocket_key then
      -- Take the WebSocket-Key so we are sure it is an handshake
      --local key_offset = string.find(string.sub(hdr_str, handshake_offset), "\r\n")+handshake_offset
      websocket_key = string.sub(hdr_str, (handshake_offset+19), (handshake_offset+43))
      --[[ The webs. key should be 16byte encoded in base 64. A generic string of n bytes is represented
      -- in base 64 using 4*(n/3) chars to represent n bytes, and this need to be rounded up to a multiple of 4
      -- 8*(n/4) = 4*(16/3) = 21-> 24
      Take ascii code ex. "Ma" = 77 97=> tobin =>01001101 01100001 => take a group of 6 because log_2(64)= 6 and add padding!
      --]]
    end

  end_offset = string.find(hdr_str, "\r\n\r\n")-- End condition fon an http message: 2 carriagereturn/newline
    if not end_offset then -- Not ended yet, go on with reassembling
      -- print("Continuo a riassemblare!");
      -- See wireshark docs case(1) https://wiki.wireshark.org/Lua/Dissectors for this block
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      pinfo.desegment_offset = 0
      return
    else
      ----- Here we have the full HTTP packet reassembled -----
      -- Ok, it is an handshake packet for WS, let's create the header tree item and set the info's coloumn
      pinfo.cols.info = "Client handshake for WebSocket"
      local t_hdr = t_websocket:add(tvb(), "Header")
      t_hdr:add(f_rmethod, tvb(soffset, 3)) -- Request method [GET]
      soffset = soffset + 4
      t_hdr:add(f_ruri, tvb(soffset, getdifference_offset(tvb(soffset):string(), "%s")))--0d0a
      t_hdr:add(f_rkey, tvb((handshake_offset+18), 23)) -- 18 not 19 because string indexing starts from 1, byte from 0
      ---------------------------------------------------------
      if not websocket_key then -- Can't find the must-have header field "Sec-WebSocket-Key"
        return 0 --                  It was just a simple http message, there is no handshake here!
      end
    end
    --------------------------Pacchetto Response Handshake----------------
  elseif tostring(tvb(9,4)) == "31303120" then -- HTTP response  message (cod. 101 -> Switching Protocol)
    print("Inizio pacchetto semigenerico http, sarà una risposta di handshake websocket?");
    hdr_str = tvb():string()
    handshake_offset = string.find(hdr_str, "Sec%-WebSocket%-Accept")
    if handshake_offset and not websocket_key then
      websocket_key = string.sub(hdr_str, (handshake_offset+22), (handshake_offset+50))
    end
    end_offset = string.find(hdr_str, "\r\n\r\n")-- End condition of http message: 2 carriagereturn/newline
    if not end_offset then -- Not ended yet, go on with reassembling
      print("Continuo a riassemblare!");
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      pinfo.desegment_offset = 0
      return
    else
      ----- Here we have the full HTTP packet reassembled -----
      -- Ok, it is an handshake packet for WS, let's create the header tree item and set the info's coloumn
      handshake_complete = 1; -- There is an handshake, can check for data-frame later
      pinfo.cols.info = "Server response handshake for WebSocket"
      local t_hdr = t_websocket:add(tvb(), "Header")
      t_hdr:add(f_shttp, tvb(soffset, 8)) -- Request method [GET]
      soffset = soffset + 9
      t_hdr:add(f_rcode, tvb(soffset, getdifference_offset(tvb(soffset):string(), "%s")))--0d0a
      t_hdr:add(f_rkey, tvb((handshake_offset+21), 28))
      ---------------------------------------------------------
      if not websocket_key then -- Can't find the must-have header field "Sec-WebSocket-Accept"
        return 0 --                  It was just a simple http message, there is no handshake here!
      end
    end
      ---------------------------- Data Frame! ------------------------------
    elseif handshake_complete then -- If there is a successful handshake in the previous packet, we can check for websocket data-frame
      local masked = 0 -- Flag used to know if the payload is masked
      local fin = tvb(0,1):bitfield(0,1);
      print("Inizio pacchetto semigenerico http, sarà un dataframe websocket?");
      local mask_key
      local payload_len
      ----- Here we have the dataframe -----
      pinfo.cols.info = "Data frame WebSocket"
      local t_hdr = t_websocket:add(tvb(0,2), "Header")
      -- Dissecting first byte
      local t_hfirst = t_hdr:add(tvb(0,1), "First byte")
      t_hfirst:add(f_fin, tvb(0,1))  -- FIN (1bit)
      t_hfirst:add(f_rsv1, tvb(0,1)) -- RSVD1 field (1bit)
      t_hfirst:add(f_rsv2, tvb(0,1)) -- RSVD2 field (1bit)
      t_hfirst:add(f_rsv3, tvb(0,1)) -- RSVD3 field (1bit)
      t_hfirst:add(f_opcode, tvb(0,1))
      -- Dissecting second byte
      local t_hsecond = t_hdr:add(tvb(1,1), "Second byte")
      t_hsecond:add(f_mask, tvb(1,1)) -- Mask (1bit)
      masked = tvb(1,1):bitfield(0,1)
      local t_hextra = t_hdr:add(tvb(2,2), "Extra header")
      -- Checking for payload lenght
      if(tvb(1,1):bitfield(1,7) == 126) then
        -- If 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length
        t_hsecond:add(f_pay_len1, tvb(1,1))
        t_hextra:add(f_pay_len2, tvb(2,2))
        payload_len = tvb(2,2):uint()
        soffset = 4
      elseif(tvb(1,1):bitfield(1,7) == 127) then
        -- If 127, the following 8 bytes interpreted as a 64-bit unsigned integer
        -- (the most significant bit MUST be 0) are the payload length.
        t_hsecond:add(f_pay_len1, tvb(1,1))
        t_hextra:add(f_pay_len3, tvb(2,8))
        payload_len = tvb(2,8):uint64() -- Da verificare LUA ha problemi a gestire interi di 64 bit
        soffset = 9
      else
        t_hsecond:add(f_pay_len1, tvb(1,1)) -- Payload length (7bit) (if 126 or 127 need to read next byte as Extended Payload length)
        payload_len = tvb(1,1):uint()
        soffset = 2
      end
      -- Get mask-key if the packet was masked (client->server )
      if(masked == 1) then -- there is a mask-key
        t_hdr:add(f_mkey, tvb(soffset, 4))
        mask_key = tostring(tvb(soffset, 4))
        local mask_key_offset = soffset
        soffset = soffset + 4
        -- Unmask data
        local decoded_payload = ''
        for i = 0, tvb(soffset):len()-1 do
          decoded_payload = decoded_payload .. string.char(bit32.bxor(tvb(soffset+i, 1):uint(), tvb(mask_key_offset+(i%4), 1):uint()))
        end
        t_hdr:add(f_mdecoded_pay, decoded_payload)
      else
        -- Payload data doesn't need unmask if not masked
        local data_payload = tvb(soffset):string()
        print("\nData payload", data_payload, "\n")
        t_hdr:add(f_mdecoded_pay, tvb(soffset))
    end
      ---------------------------------------------------------
      --  Eventuale condizione di scarto
  end
  ---------------------------- End Data Frame ---------------------------
end

-- Usefull for http in wich each line (and so header's fields) is separated by carriage return
function getdifference_offset(buffer, pattern)
  local newoffset = string.find(buffer, "%s")
  return newoffset
end

-- load the tcp port table
local tcp_table = DissectorTable.get("tcp.port")
-- register the protocol to port 80
tcp_table:add(80, websocket_proto)

--[[
tostring(tvb) return the values of the buffer in a string type in HEX format.
]]--
