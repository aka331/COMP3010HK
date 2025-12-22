# COMP3010HK---CW1
COMP3010 Security Operations and Incident Management - CW1
This repo contains my CW1 PCAP investigation deliverables: identifying the infected host, reconstructing the infection vector, and summarising C2/exfil behaviour using Wireshark evidence.

## Contents
- `CW1_Documentation/` — CW1 report (PDF).
- `Capture/` — Screenshots (filters, TCP streams, Export Objects, Conversations, DNS/TLS, SMTP).

## Key Findings (IOCs)
- Victim host: `10.9.23.102` 
- Initial malicious download (UTC): `2021-09-24 164438` 
- Downloaded archive: `documents.zip` from `attirenepal.com` 
- File inside archive: `chart-1530076591.xls` [file:1]
- Additional domains (164511–164530 UTC): `finejewels.com.au`, `thietbiagt.com`, `new.americold.com`
- Suspected C2 IPs: `185.106.96.158`, `185.125.204.174` 
- C2 domains/headers observed: `survmeter.live`, `securitybusinpuff.com`, `ocsp.verisign.com`
- Post-infection domain: `maldivehost.net` (data prefix `zLIisQRWZI9`, first packet length `281`) 
- External IP check: `api.ipify.org` at `2021-09-24 170004`
- SMTP evidence: MAIL FROM `farshinmailfa.com`, recovered password `13691369`

## AI Use Declaration
Generative AI use is declared in the submission report. 
