# Audit bad case: jandedobbeleer__oh-my-posh::GHSA-6XJ8-QV9J-XCJQ

## Classification

This is an **audit miss after recall success**, not a recall miss. The frozen
P3C64 Top160 receipt contains four truth-overlapping anchors, at ranks 35, 57,
69, and 132. The bounded audit completed all five required m=32 groups with
valid candidate-disposition receipts, but none of its four emitted findings
localized a frozen truth span. The finalized formal score is therefore TP=0,
FP=4, FN=1.

The first attempt produced an invalid candidate-disposition receipt in group 1,
so the frozen runner resumed with `--retry-incomplete-groups`. It reused groups
2-5 and regenerated group 1 once. The resulting final receipt is complete and
formally eligible.

This record preserves the evaluation outcome only. It does not independently
claim exploitability of the four emitted findings, and it does not change the
frozen recall input, source snapshot, prompt, scorer, or paper metrics.

## Frozen experiment identity

| Field | Value |
| --- | --- |
| Run | P3C64 fixed143 stratified half71 Backend-B model run |
| Model | GPT-5.5, reasoning effort high |
| Identity | jandedobbeleer__oh-my-posh::GHSA-6XJ8-QV9J-XCJQ |
| Repository | https://github.com/JanDeDobbeleer/oh-my-posh.git |
| Checkout revision | 7ec9fb8eb0f091354795eca7b024332a59e6614f |
| Recall budget / grouping | Top160; m=32; five sequential groups |
| Fixed recall input SHA-256 | ab62b42b2c4ebfa0011fa36cd10d48d3a8bd8e410b2ea90993b150a494ac9cc3 |
| Formal eligibility | true |

## Recall and frozen-truth evidence

The projected Top160 recall record marks this case as a hit
(`best_known_anchor_rank=35`) and includes four truth-overlapping retrieved
windows:

~~~text
rank 35:  src/config/segment.go:521-600
          recalled_anchor::5b2f42930889d65741158cc1
rank 57:  src/segments/http.go:1-65
          recalled_anchor::8247b9f8090663741a163758
rank 69:  src/config/segment.go:1-80
          recalled_anchor::dacb75e324ab8866921b89c3
rank 132: src/segments/path.go:281-360
          recalled_anchor::b2c546841d74dd16edff7c36
~~~

The frozen Unified V2 trace records source-localized changed-old-line spans in
each of these files: `segment.go` lines 27-33, 301-307, and 580-586;
`http.go` lines 32-38; and `path.go` lines 282-288, 293-299, and 320-326.
The recalled windows expose corresponding visible source context, including
template rendering in `Segment`, URL/method handling in `HTTP.Enabled`, and
path rendering, width, and separator handling in `Path`. The trace is an
`m17_m9_source_verified_primary_review_entry`; this packet makes no claim
beyond those frozen spans and visible source facts.

## Audit evidence and diagnosis

All five final groups completed successfully, each with 32 candidate
dispositions. The four truth-overlapping anchors were reviewed across groups 1,
2, 4, and 5; all were dismissed:

~~~text
rank 35, group 1: dismissed
reason: "Segment cache key/storage logic persists local prompt data and does not
        authorize execution for another principal or target."

rank 57, group 2: dismissed
reason: "HTTP segment performs a configured request and JSON display; although
        request-controlled URL/method exist, there is no capability or approval
        binding failure under m9."

rank 69, group 4: dismissed
reason: "Segment struct fields and unmarshalling are local prompt configuration
        state, not an authority-boundary execution path."

rank 132, group 5: dismissed
reason: "Path max-width and separator templates affect prompt rendering only,
        not delegated action authority."
~~~

The audit emitted four findings outside the frozen target spans, including
workflow and OAuth-related observations. The fixed scorer determined that none
overlaps a frozen target span; therefore all four are FP and the case remains an
FN.

This is consequently an **audit disposition-to-finding miss**: retrieval
supplied four source-overlapping windows, but the audit dismissed each and
shifted its alarms to non-truth-localizing locations.

## Final formal result

| Metric | Count / value |
| --- | --- |
| TP | 0 |
| FP | 4 |
| FN | 1 |
| Alarms | 4 |
| Recall | 0.0 |
| Precision | 0.0 |
| F1 | 0.0 |
| Raw emitted findings | 4 |
| Extra truth hits | 0 |
| Input tokens | 4,701,931 |
| Cached input tokens | 3,943,936 |
| Output tokens | 78,005 |
| Reasoning tokens | 41,577 |
| Complete usage events | 5 |
| Retried groups | 1 (group 1 only) |
| Reused groups | 4 |

## Artifact binding

| Artifact | SHA-256 |
| --- | --- |
| Top160 half71 recall input | ab62b42b2c4ebfa0011fa36cd10d48d3a8bd8e410b2ea90993b150a494ac9cc3 |
| Frozen src/config/segment.go source file | 8e960a1713490be8d4b85dd32b606eec828735e4e7b974b6a24f02028a83f2ca |
| Frozen src/segments/http.go source file | 0cab878e4450c98f9651cc9d93ad05508ddc0c0549fdff8515216601bedcfb2a |
| Frozen src/segments/path.go source file | d5880e461300e66609eddcc6f79fb013e1bc682735223ffee73af97d9e287444 |
| Final score summary | bea224a54668cf087571e60f1f1c86ec90b8c0324c4f3e095f20dbde04eda597 |
| Final case audit receipt | 047e816a54e03fbb53b493c20a4a98db0763025fd746f168e6a5eaec10816e44 |
| Rank-35 / group-1 retry prompt | 0a2482fe0d2616c4616c27923e861309f9f58793ad9c4987483ee75f32e296c7 |
| Rank-35 / group-1 retry model JSON | efe5ea75922bb4f449d2b3c44940f7f2f65eb6f8e5f3b1eb043b9699184a03e5 |
| Rank-57 / group-2 prompt | 1a24303c41d4e76218a4f150110f3156a6bddf72690c2f86f7284670ac21d1a9 |
| Rank-57 / group-2 model JSON | 5efd68b2f8d9120a56b7155017a25e64dd2b8bed1882bc2b845c8069cf49594d |
| Rank-69 / group-4 prompt | 322f9b45d52a87e1a395c905a22f65ca58cefeffc1d956e35bc27a94bf5c2fc9 |
| Rank-69 / group-4 model JSON | 03cb9f6055c1ebcb39b380cebc81229d12de586872d4ea24ccb8b391b23e08a7 |
| Rank-132 / group-5 prompt | 777aa35634a13aad1fe2e73242c326713e215246e54e894d22f44395e4eb30eb |
| Rank-132 / group-5 model JSON | 2d8362fe5563193b445726af57edc724f5c84215f49d0cab5716cbb32dc3aeee |

Run-root path at record time:

~~~text
/Users/bytedance/tmp/hcvr-backend-b-p3c64-half-gpt55-high-top160-m32-20260823
~~~

## Follow-up hypothesis (not applied to this run)

For a separately registered protocol change, an audit that dismisses multiple
truth-overlapping runtime-code windows could be required to retain a concise
source-localized explanation of the tested boundary for each one. Such a rule
must be evaluated uniformly across cases and backends and must not alter this
frozen result.
