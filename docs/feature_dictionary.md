# Initial feature dictionary

**Schema:** `cross-layer/1` (connection observations), with packet rows tagged `packet-observations/1`.

The extractor uses only fields present in `tshark -G fields` on the installed build and records that build's version. Missing fields are omitted from the packet table. The connection aggregator emits a fixed schema with null/empty values where evidence is absent. It never uses label-registry columns as predictors.

| Feature | Layer/source | Meaning and handling |
|---|---|---|
| `tcp_packet_count` | PCAP / `tcp.stream` | Number of captured TCP packets in the joined flow. |
| `tcp_client_to_server_packets` | PCAP tuple | Packets whose source port is the peer port recorded by the server. |
| `tcp_flow_duration_seconds` | PCAP frame times | Last minus first captured frame timestamp; affected by capture boundaries. |
| `tcp_initial_window` | TCP SYN | First client SYN advertised window when the field is available. |
| `tcp_mss` | TCP SYN options | First client SYN MSS. |
| `tcp_window_scale` | TCP SYN options | First client SYN window scale, if present. |
| `tcp_syn_options_order` | TCP SYN options | Ordered TCP option kind codes from the first client SYN. |
| `tls_handshake_types` | TShark TLS dissection | Distinct handshake message type codes visible in the captured flow. |
| `tls_offered_versions` | ClientHello | Version values as dissected by TShark; not necessarily all supported versions unless extension fields are added. |
| `tls_cipher_suites_order` | ClientHello | Ordered cipher suite values from first packet row containing the field. |
| `tls_extension_types_order` | TLS handshake | Ordered extension type values from first row containing the field. Verify these are ClientHello extensions against a real PCAP before interpreting them as offers. |
| `tls_alpn_offers` | ClientHello | ALPN values exposed by the TShark build. |
| `endpoint_tls_version` | Server `connection.open` event | Negotiated TLS version; distinct from client offers. |
| `endpoint_alpn` | Server `connection.open` event | Negotiated application protocol. |
| `h2_inbound_settings_order` | Endpoint frame observer | Ordered client SETTINGS entries, excluding ACKs. Available only for negotiated H2. |
| `h2_inbound_frame_types` | Endpoint frame observer | Inbound frame type sequence. Not visible from encrypted PCAP without secrets. |
| `h2_header_names_order` | Decoded endpoint request event | Ordered request header names per request; header values are excluded. |
| `h2_request_count` | Endpoint request events | Number of decoded request-header events on the connection. |
| `*_mean` session aggregates | Dataset builder | Mean of numeric values across accepted joined connections assigned to a session. |

`session_id`, `connection_id`, `tcp_stream`, addresses, ports, timestamps, family, execution stack, controller, task outcome, and capture-quality statuses are identifiers/metadata, not predictors. The join report retains connection IDs for auditing in a separate file. Keep raw captures private and preserve their checksums.

## Known measurement limits

- TShark fields vary by version and dissector preferences. The current host has no TShark, so actual field availability and ClientHello extraction remain unverified.
- TLS 1.3 handshake bytes after ServerHello are encrypted in ordinary passive captures. Selected TLS version/cipher/ALPN are server-side negotiated fields; they are not offered-list features.
- TShark's standard field output does not preserve arbitrary TCP option presence/order in every build. `tcp.options.kind` is used only when available and must be validated against packet bytes/Wireshark before research use.
- This first extractor does not export TShark expert diagnostics, capture-drop counters, retransmission rates, JA3/JA4 hashes, or server-certificate features.
- The tuple/time join uses server-side peer tuple and event wall time. It is limited to matching capture/socket vantage and synchronized host clock; ambiguous/missing joins are excluded and listed in the report.
- The categorical Naive Bayes command is only a smoke-test baseline. It treats each observed serialized value categorically and does not provide calibrated probabilities, intervals, grouped cross-validation, feature ablations, or model selection.
