## Benchmark Results

Commit: `000da3e` | Date: 2026-04-04T09:29:50Z

| Benchmark | Median |
|-----------|--------|
| deserialize_trusted | 251.5 ns |
| hex_decode_64 | 32.4 ns |
| hex_encode_32 | 21.4 ns |
| parse_client_msg | 1.37 us |
| query_by_author/10000 | 344.24 us |
| query_by_author/100000 | 354.66 us |
| query_by_kind/10000 | 396.32 us |
| query_by_kind/100000 | 4.11 ms |
| query_by_tag_e/10000 | 360.68 us |
| query_by_tag_e/100000 | 823.71 us |
| serialize | 207.2 ns |
| serialize_fast | 92.4 ns |
| transcode_vs_deser/deser+json/10000 | 394.12 us |
| transcode_vs_deser/deser+json/100000 | 4.21 ms |
| transcode_vs_deser/transcode/10000 | 400.54 us |
| transcode_vs_deser/transcode/100000 | 4.20 ms |
| validate_event | 44.41 us |
