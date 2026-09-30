# Primary cw=0.5 lexical stress comparison

| Query | Candidate cache | MRR | Hit@10 | Hit@50 | Hit@100 | Hit@1000 | B@75 | B@90 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| raw_query | raw | 0.3141 | 0.4667 | 0.6667 | 0.8000 | 0.9333 | 94 | 899 |
| raw_query | symbol | 0.1682 | 0.2444 | 0.4667 | 0.5556 | 0.8667 | 300 | 1663 |
| raw_query | strict | 0.1651 | 0.2667 | 0.5111 | 0.5778 | 0.8667 | 299 | 2039 |
| security_terms_query | raw | 0.1125 | 0.2889 | 0.4667 | 0.6000 | 0.8889 | 283 | 1238 |
| security_terms_query | symbol | 0.0715 | 0.1778 | 0.4222 | 0.4889 | 0.8000 | 702 | 2406 |
| security_terms_query | strict | 0.0922 | 0.1556 | 0.4667 | 0.5333 | 0.8444 | 603 | 1437 |

## Delta vs raw query + raw candidate

| Query | Candidate cache | dMRR | dHit@100 | dB@75 | dB@90 |
| --- | --- | ---: | ---: | ---: | ---: |
| raw_query | raw | +0.0000 | +0.0000 | +0 | +0 |
| raw_query | symbol | -0.1459 | -0.2444 | +206 | +764 |
| raw_query | strict | -0.1490 | -0.2222 | +205 | +1140 |
| security_terms_query | raw | -0.2016 | -0.2000 | +189 | +339 |
| security_terms_query | symbol | -0.2426 | -0.3111 | +608 | +1507 |
| security_terms_query | strict | -0.2219 | -0.2667 | +509 | +538 |
