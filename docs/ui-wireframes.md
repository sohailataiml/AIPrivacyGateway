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

## Architecture Page

```text
User → Gateway → Detect → Policy → Tokenize → Encrypted Vault
                           ↓
                    Protected Prompt → LLM
                           ↓
                Protected Response → Restore → User
```
