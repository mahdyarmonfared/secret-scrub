# Contributing to SecretScrub

Thank you for your interest in contributing to **SecretScrub**! 🛡️

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/mahdyarmonfared/secret-scrub.git
   cd secret-scrub
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run the test suite:
   ```bash
   npm test
   ```

4. Install the pre-commit hook on this repository:
   ```bash
   node ./bin/secret-scrub.js hook install
   ```

## Adding New Secret Rules

1. Define the rule in `src/rules.js` with:
   - `id`: Unique identifier (e.g. `openai-api-key`)
   - `name`: Human-readable title
   - `provider`: Service name (e.g. `OpenAI`)
   - `severity`: `critical` | `high` | `medium` | `low`
   - `pattern`: Exact RegExp pattern
   - `entropyCheck`: (Optional) Minimum Shannon entropy threshold
2. Add corresponding test cases in `tests/detector.test.js`.
3. Verify that false positives on common placeholders (like `your_api_key_here`) are ignored.

## Conventional Commits

We follow Conventional Commits:
- `feat:` for new features or detection rules
- `fix:` for bug fixes and false positive corrections
- `docs:` for documentation updates
- `test:` for test additions and refactoring
