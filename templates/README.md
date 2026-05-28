# templates/

Templates for customer engagements.

## Files

<!-- markdownlint-disable MD013 MD060 -->
| File | Purpose |
|------|---------|
| `customer-handover.md` | Engagement-level handover sheet. Fill out per engagement: connect string, anonymisation config, host patterns, distribution recipients, run cadence. One copy per engagement. |
| `collection-quickref.md` | Condensed step-by-step guide for the customer DBA. "Read this, run this, send me the bundle." Print-friendly, one page. |
<!-- markdownlint-enable -->

## Usage

Copy templates to your engagement folder - do not modify the originals:

```bash
cp templates/customer-handover.md engagements/ACME/handover.md
cp templates/collection-quickref.md engagements/ACME/quickref.md
```
