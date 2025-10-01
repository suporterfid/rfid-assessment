# AI Agent Guide for RFID Sorter Assessment

## Project Overview
- **Tech stack:** PHP 8 single-file web app (`index.php`) with SQLite for persistence and a companion AI endpoint (`ai.php`).
- **Purpose:** Capture, audit, and report RFID sorter survey responses via a password-protected UI and REST API. Optional OpenAI-powered suggestions are exposed through `ai.php` when an `OPENAI_API_KEY` is configured.
- **Runtime artefacts:** `data.db` (SQLite database) and `uploads/` (file storage) are created dynamically at runtime and should not be checked into source control.

## Repository Layout
- `index.php` – Handles routing, authentication, HTML rendering, REST API, database migrations, and file uploads.
- `ai.php` – Provides AI-generated suggestions for authenticated users; requires the `OPENAI_API_KEY` environment variable.
- `README.md` – Human-facing documentation with setup, usage, and feature details.

## Getting Started
1. Ensure PHP 8.1+ is installed with the SQLite3 extension.
2. From the repository root, run the development server:
   ```bash
   php -S localhost:8000
   ```
3. Visit [http://localhost:8000](http://localhost:8000) and log in with the seeded credentials (`admin`/`admin`).
4. On first run the app creates `data.db`, seeds survey content, and provisions the `uploads/` directory.

## Development Tips
- Keep the codebase dependency-free—avoid adding frameworks or package managers unless explicitly requested.
- Maintain the single-file architecture unless the task specifically requires refactoring.
- Favor procedural PHP style consistent with the existing code.
- Sanitize and validate user-provided data before using it in SQL queries or rendering it in HTML.
- For new configuration values, prefer environment variables over hard-coded secrets.

## Testing & Verification
- Manual testing is the primary workflow: exercise critical flows (authentication, creating/editing responses, API calls) via the browser or HTTP clients.
- When modifying database logic, verify that the automatic migrations (`migrate()` in `index.php`) still succeed on a fresh database.
- If you add scripts or automated checks, document them in this file and the README.

## Contribution Workflow
- Follow clear, self-descriptive commit messages.
- Ensure generated files (`data.db`, `uploads/`) remain gitignored.
- Provide detailed descriptions of your changes in PR summaries, including any setup or testing notes for reviewers.

## Additional Notes
- Handle API errors gracefully by returning descriptive HTTP status codes and JSON payloads.
- When working on UI updates, keep the design compatible with the existing HTML/CSS structure in `index.php`.

