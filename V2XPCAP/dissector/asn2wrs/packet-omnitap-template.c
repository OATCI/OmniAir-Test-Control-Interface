/* packet-omnitap-template.c
 * OmniAir OmniTap Universal V2X/A2X Capture Metadata Dissector (ASN.1 COER / OER)
 *
 * Generated with Wireshark asn2wrs.py -e (OER mode):
 *   python tools/wireshark/asn2wrs.py -e -c dissector/asn2wrs/omnitap.cnf \
 *     -s dissector/asn2wrs/packet-omnitap-template -D . -O <out_dir> <all 12 .asn files>
 *
 * Registers for:
 *   1. pcapng Custom Blocks (0x00000BAD / 0x40000BAD) in "pcapng_custom_block" for PEN 32473 (placeholder)
 *   2. pcapng EPB Custom Binary Option 2989 (0x0BAD) in OmniTap (Native) streams
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include "packet-oer.h"

#define PNAME  "OmniAir OmniTap V2X/A2X Capture Metadata"
#define PSNAME "OmniTap"
#define PFNAME "omnitap"

#define OMNITAP_PEN_PLACEHOLDER 32473u

void proto_register_omnitap(void);
void proto_reg_handoff_omnitap(void);

static int proto_omnitap;
static dissector_handle_t omnitap_handle;

#include "packet-omnitap-hf.c"
static int ett_omnitap;
#include "packet-omnitap-ett.c"
#include "packet-omnitap-fn.c"

static int
dissect_omnitap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *omnitap_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    ti = proto_tree_add_item(tree, proto_omnitap, tvb, 0, -1, ENC_NA);
    omnitap_tree = proto_item_add_subtree(ti, ett_omnitap);

    return dissect_OmniTapObject_PDU(tvb, pinfo, omnitap_tree, NULL);
}

void
proto_register_omnitap(void)
{
    static hf_register_info hf[] = {
#include "packet-omnitap-hfarr.c"
    };

    static int *ett[] = {
        &ett_omnitap,
#include "packet-omnitap-ettarr.c"
    };

    proto_omnitap = proto_register_protocol(PNAME, PSNAME, PFNAME);
    proto_register_field_array(proto_omnitap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    omnitap_handle = register_dissector(PFNAME, dissect_omnitap, proto_omnitap);
}

void
proto_reg_handoff_omnitap(void)
{
    /* Register for OmniTap Custom Blocks (0x00000BAD) in both OmniTap Native and OmniTap-Lua */
    dissector_add_uint("pcapng_custom_block", OMNITAP_PEN_PLACEHOLDER, omnitap_handle);
}
