# Deliberately insecure Firebase rules

Scanner test fixture. **Never deploy this.** The Firebase config of an app is public by design, so these rules
are all that protects the data.

```bash
npm run scan -- scan examples/vulnerable-firebase-app --format text
```

| File | What the scanner should say |
|---|---|
| `firestore.rules`, `/{document=**}` | test-mode rule: everything open until 2099 (critical) |
| `firestore.rules`, `/users/{userId}` | `request.auth != null` is not ownership for update / delete |
| `firestore.rules`, `/orders/{orderId}` | private-looking data readable by anyone |
| `firestore.rules`, `/notes/{noteId}` | **Safe** (owner check): must not be flagged |
| `storage.rules` | `allow read, write: if true` for every file (critical) |
| `database.rules.json` | `.read` / `.write` true at the root (critical); `private/$uid` is **safe** |
