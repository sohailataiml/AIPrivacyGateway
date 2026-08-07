# UI Wireframes — Enterprise AI Security Gateway

## Global Shell

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Secure AI Gateway     DEMO   Gateway: Healthy             User ▾           │
├──────────────────────┬───────────────────────────────────────────────────────┤
│ Workspace            │                                                       │
│ ● Secure Chat        │                    Page Content                       │
│ Security             │                                                       │
│   Dashboard          │                                                       │
│   Sessions           │                                                       │
│   Audit              │                                                       │
│   Policies           │                                                       │
│ Platform             │                                                       │
│   Providers          │                                                       │
│   Health             │                                                       │
│ Project              │                                                       │
│   Architecture       │                                                       │
└──────────────────────┴───────────────────────────────────────────────────────┘
```

## Secure Chat

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Secure Chat     Provider: OpenAI Primary   Model: General   Policy: v4      │
├───────────────────────────────────────────────┬──────────────────────────────┤
│ Conversation                                  │ Privacy Inspector            │
│ YOU                                           │ ✓ Validated                  │
│ Contact Avery Example at avery@example.test.  │ ✓ Sensitive data detected    │
│ ASSISTANT                                     │ ✓ Policy applied             │
│ Contact Avery Example at avery@example.test.  │ ✓ Values tokenized           │
│ Privacy: 2 detected • 2 tokenized • v4        │ ✓ Mapping secured            │
│                                               │ ✓ Provider completed         │
│                                               │ ✓ Values restored            │
│                                               │ PERSON 1 • EMAIL 1          │
│                                               │ Total 681 ms                 │
├───────────────────────────────────────────────┴──────────────────────────────┤
│ Ask through the secure gateway…                                  [ Send ]    │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Blocked Request

```text
┌─────────────────────────────────────────────────────────────┐
│ Request blocked by policy                                   │
│ A US Social Security number was detected.                   │
│ Policy action: BLOCK                                        │
│ The request was not sent to the provider.                   │
└─────────────────────────────────────────────────────────────┘
```

## Dashboard

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Requests      Entities      Blocked      Gateway Overhead                   │
│ 4,281         18,921        22           84 ms                              │
├───────────────────────────────────────┬──────────────────────────────────────┤
│ Requests over time                    │ Entities by type                     │
│ line chart                            │ PERSON 34% • EMAIL 28%              │
├───────────────────────────────────────┼──────────────────────────────────────┤
│ Policy actions                        │ Provider performance                 │
│ TOKENIZE 82% • BLOCK 3%              │ Success 99.2% • 620 ms p50          │
└───────────────────────────────────────┴──────────────────────────────────────┘
```

## Audit Detail

```text
┌──────────────────────────────────────────────┐
│ Request 22d8…                                │
│ Policy                  Healthcare v4        │
│ Provider / Model        OpenAI / General     │
│ Entity counts           PERSON 1, EMAIL 2    │
│ Actions                 TOKENIZE 3           │
│ Gateway overhead        61 ms                │
│ Raw prompt stored       No                   │
│ Raw response stored     No                   │
└──────────────────────────────────────────────┘
```

## Policy Manager

```text
PERSON          TOKENIZE   0.75
EMAIL_ADDRESS   TOKENIZE   0.70
PHONE_NUMBER    TOKENIZE   0.40
US_SSN          BLOCK      0.50
CREDIT_CARD     BLOCK      0.50
```

These match the shipped defaults in `app/policy/defaults.py`. `PHONE_NUMBER` is
deliberately 0.40, not the 0.65 an earlier draft of this wireframe showed:
Presidio scores US phone numbers at 0.40 unless the literal word "phone" appears
nearby, so a higher threshold discarded ordinary phrasings like
`Call 415-555-0142` and sent them to the provider in the clear. Raising it again
reopens that leak.

### As built

```text
Secure AI Gateway     Workspace  Secure Chat   Security  Policies
─────────────────────────────────────────────────────────────────
← All policies
default                    [Test playground] [Create draft] [Publish…]

Version 5 (draft)
  Session TTL 1800s   Max entities 500   Rules 6   Providers mock

Entity rules                                   Add entity [ IP_ADDRESS ▾ ]
┌────────┬───────────────┬──────────┬──────────┬────────┬──────────────┐
│Enabled │ Entity type   │Threshold │ Action   │Priority│ Recognizer   │
├────────┼───────────────┼──────────┼──────────┼────────┼──────────────┤
│  [x]   │ EMAIL_ADDRESS │  0.70    │ tokenize │   20   │ presidio…    │
│  [x]   │ PHONE_NUMBER  │  0.40    │ tokenize │   20   │ presidio…    │
│  [x]   │ US_SSN        │  0.50    │ block    │   30   │ presidio…    │
└────────┴───────────────┴──────────┴──────────┴────────┴──────────────┘
                                            Version history
                                            ┌────────────────────────┐
                                            │ Version 5      [Draft] │
                                            │ Version 4     [Active] │
                                            │ Version 3              │
                                            └────────────────────────┘
                                            [ Compare with v4 ]
```

Thresholds and actions are rendered from the loaded version, never from a
constant in the frontend. Controls are disabled, not hidden, when no draft is
open.

## Publish Confirmation

```text
┌─ Publish policy version 5? ───────────────────────────┐
│  · 3 entity rules changed                             │
│  · 1 threshold changed                                │
│  · 1 entity added                                     │
│                                                       │
│  ⚠ Weakens protection                                 │
│    US_SSN — block → tokenize is less protective       │
│                                                       │
│              [ Cancel ]  [ Publish version 5 ]        │
└───────────────────────────────────────────────────────┘
```

The warning does not block. The backend decides what is publishable, and an
operator may have a good reason; being told before rather than after is the
useful behaviour.

## Policy Test Playground

```text
Synthetic input
┌───────────────────────────────────────────────────────┐
│ Jordan Rivera called from 415-555-0142 about the      │
│ invoice sent to jordan.rivera@example.test.           │
└───────────────────────────────────────────────────────┘
[ Run test ]

Result — v5 (draft)
⦸ Provider would NOT be called

Detected 3    PERSON 1    PHONE_NUMBER 1    EMAIL_ADDRESS 1

┌───────────────┬─────────┬────────────┬──────────┐
│ Entity type   │ Offsets │ Confidence │ Action   │
├───────────────┼─────────┼────────────┼──────────┤
│ PERSON        │  0–13   │    0.85    │ tokenize │
│ PHONE_NUMBER  │ 26–38   │    0.40    │ tokenize │
│ EMAIL_ADDRESS │ 63–89   │    0.95    │ tokenize │
└───────────────┴─────────┴────────────┴──────────┘
```

**Offsets, not matched text.** The API returns no substrings, so the table shows
positions. The browser already holds the text it submitted; the response adds
nothing that could leak from a screenshot.

## Architecture Page

```text
User → Gateway → Detect → Policy → Tokenize → Encrypted Vault
                           ↓
                    Protected Prompt → LLM
                           ↓
                Protected Response → Restore → User
```
