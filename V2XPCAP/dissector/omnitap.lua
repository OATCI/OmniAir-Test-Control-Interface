-- OmniAir OmniTap Reference Wireshark Lua Dissector (for OmniTap-Lua streams)
--
-- Purpose:
--   Decodes COER(OmniTapObject) payloads carried in pcapng Custom Blocks (block type 0x00000BAD, PEN 32473 placeholder)
--   and publishes the normative OmniTap display-filter fields on both OmniTap Custom Blocks and Enhanced Packet Blocks
--   (EPBs) that carry epb_packetid:
--     omnitap.kind
--     omnitap.session_tag
--     omnitap.record_id
--     omnitap.packet_id
--     omnitap.version.major
--     omnitap.version.minor
--     omnitap.session_id
--     omnitap.interface_name
--     omnitap.context_generation
--     omnitap.technology
--     omnitap.result_sequence
--     omnitap.producer_pen
--     omnitap.producer_name
--
-- Stream flavor note:
--   Stock Wireshark/TShark installations that have not been compiled with the asn2wrs OmniTap C dissector expose
--   standalone pcapng Custom Blocks (0x00000BAD) to Lua, but do not expose EPB Custom Binary Options (2989).
--   To inspect a standard OmniTap (Native) capture with this Lua dissector, convert it to OmniTap-Lua first:
--     python scripts/OmniLuazer.py input.pcapng output.omnitap-lua.pcapng
--     tshark -X lua_script:dissector/omnitap.lua -r output.omnitap-lua.pcapng -V

local OMNITAP_PEN = 32473 -- RFC 5612 documentation PEN placeholder (see 00-OmniTap-Registrations.md)

local p_omnitap = Proto("omnitap", "OmniAir OmniTap V2X/A2X Capture Metadata")
local p_omnitap_epb = Proto("omnitap_epb", "OmniAir OmniTap EPB Correlation")

local KIND_STRINGS = {
    [0x80] = "capture-context",
    [0x81] = "interface-context",
    [0x82] = "packet-metadata",
    [0x83] = "supplemental-result",
}

local TECH_STRINGS = {
    [0] = "lteV2x",
    [1] = "nrV2x",
    [2] = "etsiItsG5",
    [3] = "aribT109",
}

local f_kind        = ProtoField.string("omnitap.kind", "Object Kind")
local f_session_tag = ProtoField.uint32("omnitap.session_tag", "Session Tag", base.HEX)
local f_record_id   = ProtoField.uint32("omnitap.record_id", "Record ID", base.DEC)
local f_packet_id   = ProtoField.uint64("omnitap.packet_id", "Packet ID (session_tag:record_id)", base.HEX)
local f_ver_major   = ProtoField.uint8("omnitap.version.major", "Profile Major Version", base.DEC)
local f_ver_minor   = ProtoField.uint8("omnitap.version.minor", "Profile Minor Version", base.DEC)
local f_choice_tag  = ProtoField.uint8("omnitap.choice_tag", "COER Body CHOICE Tag", base.HEX)
local f_session_id  = ProtoField.bytes("omnitap.session_id", "Capture Session ID (UUID)")
local f_campaign    = ProtoField.string("omnitap.test_campaign_details", "Test Campaign Details")
local f_testcase    = ProtoField.string("omnitap.test_case_id", "Test Case ID")
local f_scenario    = ProtoField.string("omnitap.scenario_name", "Scenario Name")
local f_if_name     = ProtoField.string("omnitap.interface_name", "Interface Name (if_name)")
local f_ctx_gen     = ProtoField.uint16("omnitap.context_generation", "Context Generation", base.DEC)
local f_technology  = ProtoField.string("omnitap.technology", "V2X/A2X Technology")
local f_prod_pen    = ProtoField.uint32("omnitap.producer_pen", "Producer PEN", base.DEC)
local f_prod_name   = ProtoField.string("omnitap.producer_name", "Producer Product Name")
local f_prod_ver    = ProtoField.string("omnitap.producer_version", "Producer Software Version")
local f_res_seq     = ProtoField.uint16("omnitap.result_sequence", "Result Sequence", base.DEC)

p_omnitap.fields = {
    f_kind, f_session_tag, f_record_id, f_packet_id,
    f_ver_major, f_ver_minor, f_choice_tag,
    f_session_id, f_campaign, f_testcase, f_scenario,
    f_if_name, f_ctx_gen, f_technology,
    f_prod_pen, f_prod_name, f_prod_ver, f_res_seq,
}

-- Read an OER/COER length determinant starting at offset (0-based); returns length, next_offset
local function read_oer_length(tvb, offset)
    if offset >= tvb:len() then
        return 0, offset
    end
    local b0 = tvb(offset, 1):uint()
    if b0 < 0x80 then
        return b0, offset + 1
    end
    local count = bit.band(b0, 0x7F)
    if count == 0 or offset + 1 + count > tvb:len() then
        return 0, tvb:len()
    end
    local len_val = 0
    for i = 1, count do
        len_val = len_val * 256 + tvb(offset + i, 1):uint()
    end
    return len_val, offset + 1 + count
end

-- Check if bit_index (0 = MSB 0x80, 1 = 0x40, ...) is set in a 1-octet preamble
local function bit_is_set(byte_val, bit_index)
    local mask = bit.rshift(0x80, bit_index)
    return bit.band(byte_val, mask) ~= 0
end

-- Combine two 32-bit unsigned integers into a UInt64: (high << 32) | low
local function make_u64(high32, low32)
    return UInt64.new(low32, high32)
end

function p_omnitap.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 5 then
        return 0
    end

    pinfo.cols.protocol = "OmniTap"
    local subtree = tree:add(p_omnitap, tvb(), "OmniAir OmniTap Object (COER)")

    local major = tvb(2, 1):uint()
    local minor = tvb(3, 1):uint()
    local choice_tag = tvb(4, 1):uint()

    subtree:add(f_ver_major, tvb(2, 1))
    subtree:add(f_ver_minor, tvb(3, 1))
    subtree:add(f_choice_tag, tvb(4, 1))

    if major ~= 1 then
        pinfo.cols.info = string.format("OmniTap Unsupported Major Version %d.%d", major, minor)
        return len
    end

    local kind_str = KIND_STRINGS[choice_tag] or "unknown"
    subtree:add(f_kind, tvb(4, 1), kind_str)

    if choice_tag == 0x80 and len >= 22 then
        -- OmniTapCaptureContext:
        --   octet 5: preamble (ext_bit=0, opt0=testCampaignDetails, opt1=testCaseId, opt2=scenarioName, opt3=optionalExtensions)
        --   octet 6..21: sessionId (16 octets; last 4 octets = sessionTag)
        local preamble = tvb(5, 1):uint()
        local stag = tvb(18, 4):uint()
        subtree:add(f_session_id, tvb(6, 16))
        subtree:add(f_session_tag, tvb(18, 4), stag)
        local pos = 22
        if bit_is_set(preamble, 1) and pos < len then
            local slen, next_pos = read_oer_length(tvb, pos)
            if next_pos + slen <= len then
                subtree:add(f_campaign, tvb(next_pos, slen))
                pos = next_pos + slen
            end
        end
        if bit_is_set(preamble, 2) and pos < len then
            local slen, next_pos = read_oer_length(tvb, pos)
            if next_pos + slen <= len then
                subtree:add(f_testcase, tvb(next_pos, slen))
                pos = next_pos + slen
            end
        end
        if bit_is_set(preamble, 3) and pos < len then
            local slen, next_pos = read_oer_length(tvb, pos)
            if next_pos + slen <= len then
                subtree:add(f_scenario, tvb(next_pos, slen))
            end
        end
        pinfo.cols.info = string.format("OmniTap CaptureContext (session_tag=0x%08x)", stag)

    elseif choice_tag == 0x81 and len >= 14 then
        -- OmniTapInterfaceContext:
        --   octet 5..6: 2-octet preamble (1 extension bit + 9 optional bits = 10 bits -> 2 octets)
        --     octet 5 bit 1 (0x40) = technology present
        --   octet 7..10: sessionTag (uint32)
        --   octet 11..: interfaceName (UTF8String length + bytes), then contextGeneration (uint16), then technology (if opt0)
        local preamble = tvb(5, 1):uint()
        local stag = tvb(7, 4):uint()
        subtree:add(f_session_tag, tvb(7, 4), stag)
        local slen, next_pos = read_oer_length(tvb, 11)
        local if_name_str = ""
        if next_pos + slen + 2 <= len then
            if_name_str = tvb(next_pos, slen):string()
            subtree:add(f_if_name, tvb(next_pos, slen))
            local gen_pos = next_pos + slen
            -- contextGeneration is INTEGER (1..65535) -> 2 octets unsigned
            subtree:add(f_ctx_gen, tvb(gen_pos, 2))
            local tech_pos = gen_pos + 2
            if bit_is_set(preamble, 1) and tech_pos < len then
                local tech_code = tvb(tech_pos, 1):uint()
                local tech_name = TECH_STRINGS[tech_code] or tostring(tech_code)
                subtree:add(f_technology, tvb(tech_pos, 1), tech_name)
            end
        end
        pinfo.cols.info = string.format("OmniTap InterfaceContext (session_tag=0x%08x, if_name=%s)", stag, if_name_str)

    elseif choice_tag == 0x82 and len >= 14 then
        -- OmniTapPacketMetadata:
        --   octet 5: preamble (ext_bit=0, opt0=payload, opt1=timeQuality, opt2=observerLocation, opt3=radio, opt4=technologyMetadata, opt5=analysis, opt6=optionalExtensions)
        --   octet 6..9: recordId (uint32)
        --   octet 10..13: sessionTag (uint32)
        local rid = tvb(6, 4):uint()
        local stag = tvb(10, 4):uint()
        local pid64 = make_u64(stag, rid)
        subtree:add(f_record_id, tvb(6, 4), rid)
        subtree:add(f_session_tag, tvb(10, 4), stag)
        subtree:add(f_packet_id, tvb(6, 8), pid64)
        pinfo.cols.info = string.format("OmniTap PacketMetadata (session_tag=0x%08x, record_id=%u)", stag, rid)

    elseif choice_tag == 0x83 and len >= 29 then
        -- OmniTapSupplementalResult:
        --   octet 5: preamble (ext_bit=0, opt0=analysis, opt1=optionalExtensions)
        --   octet 6..21: sessionId (16 octets; last 4 octets = sessionTag)
        --   octet 22..25: recordId (uint32)
        --   octet 26: ResultProducer preamble (ext_bit=0, opt0=producerSoftwareVersion)
        --   octet 27..30: pen (uint32)
        --   octet 31..: productName (UTF8String), optional producerSoftwareVersion, then resultSequence (uint16)
        local stag = tvb(18, 4):uint()
        local rid = tvb(22, 4):uint()
        local pid64 = make_u64(stag, rid)
        subtree:add(f_session_id, tvb(6, 16))
        subtree:add(f_session_tag, tvb(18, 4), stag)
        subtree:add(f_record_id, tvb(22, 4), rid)
        subtree:add(f_packet_id, tvb(18, 8), pid64)
        if len >= 32 then
            local prod_preamble = tvb(26, 1):uint()
            subtree:add(f_prod_pen, tvb(27, 4))
            local plen, next_pos = read_oer_length(tvb, 31)
            if next_pos + plen <= len then
                subtree:add(f_prod_name, tvb(next_pos, plen))
                local pos = next_pos + plen
                if bit_is_set(prod_preamble, 1) and pos < len then
                    local vlen, vnext = read_oer_length(tvb, pos)
                    if vnext + vlen <= len then
                        subtree:add(f_prod_ver, tvb(vnext, vlen))
                        pos = vnext + vlen
                    end
                end
                if pos + 2 <= len then
                    subtree:add(f_res_seq, tvb(pos, 2))
                end
            end
        end
        pinfo.cols.info = string.format("OmniTap SupplementalResult (session_tag=0x%08x, record_id=%u)", stag, rid)
    end

    return len
end

-- Register for pcapng Custom Blocks (0x00000BAD / 0x40000BAD) carrying the OmniTap PEN
local cb_table = DissectorTable.get("pcapng_custom_block")
if cb_table ~= nil then
    cb_table:add(OMNITAP_PEN, p_omnitap)
end

-- Postdissector to publish omnitap.session_tag, omnitap.record_id, and omnitap.packet_id on every EPB with frame.packet_id
local fe_frame_packet_id = Field.new("frame.packet_id")

function p_omnitap_epb.dissector(tvb, pinfo, tree)
    local pid_fi = fe_frame_packet_id()
    if pid_fi ~= nil then
        local pid64 = pid_fi.value
        local stag = pid64:rshift(32):tonumber()
        local rid = pid64:band(UInt64.new(0xFFFFFFFF, 0)):tonumber()
        local subtree = tree:add(p_omnitap_epb, "OmniTap Packet Correlation (epb_packetid)")
        subtree:add(f_session_tag, stag):set_generated()
        subtree:add(f_record_id, rid):set_generated()
        subtree:add(f_packet_id, pid64):set_generated()
    end
end

register_postdissector(p_omnitap_epb)
