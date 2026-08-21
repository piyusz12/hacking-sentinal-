/**
 * Sentinel DevSecOps & Wi-Fi IDS AI Platform — High-Performance Native 802.11 Frame Decoder
 * =========================================================================================
 * Provides zero-copy IEEE 802.11 MAC header decoding, bitwise threat classification,
 * and high-throughput lockless circular ring buffering.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#pragma pack(1)

typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t  addr1[6];  // Receiver Address
    uint8_t  addr2[6];  // Transmitter Address
    uint8_t  addr3[6];  // BSSID / Destination
    uint16_t seq_ctrl;  // Sequence Control
} IEEE80211_Header;

typedef struct {
    uint8_t  frame_type;            // 0: Mgmt, 1: Ctrl, 2: Data, 3: Ext
    uint8_t  frame_subtype;         // e.g. 0x0C (Deauth), 0x08 (Beacon)
    uint8_t  to_ds;
    uint8_t  from_ds;
    uint8_t  is_protected;          // 802.11w PMF or WEP/CCMP
    uint8_t  is_threat;             // 1 if signature matched an anomaly
    uint8_t  threat_severity;       // 1 (Low) to 5 (Critical)
    uint16_t seq_num;               // Frame sequence number (0-4095)
    char     receiver_mac[18];      // "FF:FF:FF:FF:FF:FF"
    char     transmitter_mac[18];   // "DE:AD:BE:EF:00:01"
    char     bssid[18];             // "AA:BB:CC:DD:EE:FF"
    char     threat_classification[32]; // "DEAUTH_STORM", "EVIL_TWIN", etc.
} ParsedFrameResult;

#define RINGBUF_SIZE 2048
#define MAX_FRAME_PAYLOAD 2048

typedef struct {
    uint8_t  data[MAX_FRAME_PAYLOAD];
    uint32_t length;
    uint64_t timestamp_us;
} RawFrameSlot;

typedef struct {
    RawFrameSlot slots[RINGBUF_SIZE];
    volatile uint32_t head;
    volatile uint32_t tail;
    volatile uint32_t dropped_frames;
    volatile uint32_t total_processed;
} FrameRingBuffer;

#pragma pack()

static const char HEX_CHARS[] = "0123456789ABCDEF";

static inline void format_mac_fast(const uint8_t *mac, char *out) {
    out[0]  = HEX_CHARS[(mac[0] >> 4) & 0x0F];
    out[1]  = HEX_CHARS[mac[0] & 0x0F];
    out[2]  = ':';
    out[3]  = HEX_CHARS[(mac[1] >> 4) & 0x0F];
    out[4]  = HEX_CHARS[mac[1] & 0x0F];
    out[5]  = ':';
    out[6]  = HEX_CHARS[(mac[2] >> 4) & 0x0F];
    out[7]  = HEX_CHARS[mac[2] & 0x0F];
    out[8]  = ':';
    out[9]  = HEX_CHARS[(mac[3] >> 4) & 0x0F];
    out[10] = HEX_CHARS[mac[3] & 0x0F];
    out[11] = ':';
    out[12] = HEX_CHARS[(mac[4] >> 4) & 0x0F];
    out[13] = HEX_CHARS[mac[4] & 0x0F];
    out[14] = ':';
    out[15] = HEX_CHARS[(mac[5] >> 4) & 0x0F];
    out[16] = HEX_CHARS[mac[5] & 0x0F];
    out[17] = '\0';
}

EXPORT int decode_80211_frame(const uint8_t *raw_data, size_t length, ParsedFrameResult *out) {
    if (!raw_data || !out || length < sizeof(IEEE80211_Header)) {
        return -1;
    }

    const IEEE80211_Header *hdr = (const IEEE80211_Header *)raw_data;
    uint16_t fc = hdr->frame_control;

    out->frame_type    = (uint8_t)((fc >> 2) & 0x03);
    out->frame_subtype = (uint8_t)((fc >> 4) & 0x0F);
    out->to_ds         = (uint8_t)((fc >> 8) & 0x01);
    out->from_ds       = (uint8_t)((fc >> 9) & 0x01);
    out->is_protected  = (uint8_t)((fc >> 14) & 0x01);
    out->seq_num       = (hdr->seq_ctrl >> 4) & 0x0FFF;

    format_mac_fast(hdr->addr1, out->receiver_mac);
    format_mac_fast(hdr->addr2, out->transmitter_mac);
    format_mac_fast(hdr->addr3, out->bssid);

    out->is_threat = 0;
    out->threat_severity = 0;
    strcpy(out->threat_classification, "STANDARD_80211_FRAME");

    // Fast Bitwise Threat Signature Classification
    if (out->frame_type == 0) { // Management Frames
        switch (out->frame_subtype) {
            case 0x0C: // Deauthentication
                strcpy(out->threat_classification, "DEAUTH_STORM");
                out->is_threat = 1;
                out->threat_severity = 5;
                break;
            case 0x0A: // Disassociation
                strcpy(out->threat_classification, "DISASSOC_FLOOD");
                out->is_threat = 1;
                out->threat_severity = 4;
                break;
            case 0x08: // Beacon
                strcpy(out->threat_classification, "BEACON_FRAME");
                out->threat_severity = 1;
                break;
            case 0x04: // Probe Request
                strcpy(out->threat_classification, "PROBE_REQUEST");
                out->threat_severity = 2;
                break;
            case 0x05: // Probe Response
                // Karma Attack Detection: High-speed C check for anomalous SSID length or wildcard
                if (length > sizeof(IEEE80211_Header) + 12) {
                    // Check if SSID IE (Tag 0) has anomalous length > 32 (illegal) or 0 (wildcard response)
                    uint8_t ssid_tag = raw_data[sizeof(IEEE80211_Header) + 12];
                    uint8_t ssid_len = raw_data[sizeof(IEEE80211_Header) + 13];
                    if (ssid_tag == 0 && (ssid_len == 0 || ssid_len > 32)) {
                        strcpy(out->threat_classification, "KARMA_ATTACK");
                        out->is_threat = 1;
                        out->threat_severity = 5;
                    } else {
                        strcpy(out->threat_classification, "PROBE_RESPONSE");
                        out->threat_severity = 2;
                    }
                } else {
                    strcpy(out->threat_classification, "PROBE_RESPONSE");
                    out->threat_severity = 2;
                }
                break;
            case 0x0B: // Authentication
                strcpy(out->threat_classification, "AUTH_TRANSACTION");
                out->threat_severity = 2;
                break;
            default:
                break;
        }
    } else if (out->frame_type == 2) { // Data Frames
        // Check for EAPOL 4-way handshake EtherType (0x888E) in LLC / SNAP header
        if (length >= 32) {
            // Check for LLC header (0xAA 0xAA 0x03) + EtherType (0x88 0x8E)
            for (size_t i = sizeof(IEEE80211_Header); i < length - 2; i++) {
                if (raw_data[i] == 0x88 && raw_data[i + 1] == 0x8E) {
                    // PMKID Extraction & Handshake Capture Detection
                    // Scanning EAPOL body for RSN PMKID signatures natively in C for massive speedup
                    int has_pmkid = 0;
                    if (i + 50 < length) {
                        for (size_t j = i; j < length - 4; j++) {
                            // Look for RSN IE Tag (48) or WPA Key Data PMKID identifier
                            if (raw_data[j] == 0x30 && raw_data[j+1] == 0x14) { 
                                has_pmkid = 1;
                                break;
                            }
                        }
                    }
                    if (has_pmkid) {
                        strcpy(out->threat_classification, "PMKID_ROASTING");
                        out->threat_severity = 5;
                    } else {
                        strcpy(out->threat_classification, "EAPOL_HANDSHAKE");
                        out->threat_severity = 4;
                    }
                    out->is_threat = 1;
                    break;
                }
            }
        }
    }

    return 0;
}

EXPORT void ringbuf_init(FrameRingBuffer *rb) {
    if (rb) {
        memset(rb, 0, sizeof(FrameRingBuffer));
    }
}

EXPORT int ringbuf_push(FrameRingBuffer *rb, const uint8_t *data, uint32_t len, uint64_t ts) {
    if (!rb || !data || len == 0 || len > MAX_FRAME_PAYLOAD) {
        return -1;
    }

    uint32_t next_head = (rb->head + 1) % RINGBUF_SIZE;
    if (next_head == rb->tail) {
        // Buffer full — drop frame to avoid blocking
        rb->dropped_frames++;
        return -2;
    }

    memcpy(rb->slots[rb->head].data, data, len);
    rb->slots[rb->head].length = len;
    rb->slots[rb->head].timestamp_us = ts;
    rb->head = next_head;
    rb->total_processed++;

    return 0;
}

EXPORT int ringbuf_pop(FrameRingBuffer *rb, uint8_t *out_data, uint32_t *out_len, uint64_t *out_ts) {
    if (!rb || !out_data || !out_len || rb->head == rb->tail) {
        return -1; // Empty
    }

    RawFrameSlot *slot = &rb->slots[rb->tail];
    *out_len = slot->length;
    if (out_ts) *out_ts = slot->timestamp_us;
    memcpy(out_data, slot->data, slot->length);

    rb->tail = (rb->tail + 1) % RINGBUF_SIZE;
    return 0;
}

EXPORT uint32_t ringbuf_count(const FrameRingBuffer *rb) {
    if (!rb) return 0;
    if (rb->head >= rb->tail) {
        return rb->head - rb->tail;
    }
    return RINGBUF_SIZE - (rb->tail - rb->head);
}
