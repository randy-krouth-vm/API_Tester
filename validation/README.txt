Validation Harness Samples

1) Copy and edit: validation/validation-scenarios.sample.json
2) Set environment variable:
   API_TESTER_VALIDATION_SCENARIOS=<absolute path to your scenario json>
3) In app, click "Run Validation Harness".

Notes:
- expectedFailKeys/expectedPassKeys/expectedInconclusiveKeys are assertions.
- Start with small key sets and tighten expected verdicts as you verify behavior.
- Use authProfile values:
  - Run without credentials
  - User credentials
  - Admin credentials
