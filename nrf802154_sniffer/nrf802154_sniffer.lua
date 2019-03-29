nrf802154_sniffer_proto = Proto("nrf802154_sniffer","nRF Sniffer for 802.15.4 Data")
nrf802154_sniffer_proto.fields.channel = ProtoField.uint16("nrf802154_sniffer.channel", "Channel")
nrf802154_sniffer_proto.fields.rssi = ProtoField.int16("nrf802154_sniffer.rssi", "RSSI")
nrf802154_sniffer_proto.fields.lqi = ProtoField.uint16("nrf802154_sniffer.lqi", "LQI")

-- create a function to dissect it
function nrf802154_sniffer_proto.dissector(buffer, pinfo, tree)
    HEADER_LEN = 6
    if buffer:len() > HEADER_LEN then
        local t = tree:add(nrf802154_sniffer_proto, buffer(0,HEADER_LEN), "nRF Sniffer for 802.15.4 Data")
        t:add_le(nrf802154_sniffer_proto.fields.channel, buffer(0,2))
        t:add_le(nrf802154_sniffer_proto.fields.rssi, buffer(2,2))
        t:add_le(nrf802154_sniffer_proto.fields.lqi, buffer(4,2))
        Dissector.get("wpan_nofcs"):call(buffer(HEADER_LEN):tvb(), pinfo, tree)
    end
end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER0, nrf802154_sniffer_proto)
