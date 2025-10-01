# RFID Sorter Assessment

RFID Sorter Assessment is a single-file PHP application backed by SQLite that helps teams capture, audit, and report sorter surveys for RFID implementations. It bundles an HTML interface, REST API, file upload handling, and OpenAI-powered suggestions into one repository so it can be dropped onto any PHP 8+ environment without additional dependencies.

## Features
- **Survey management** – Create and edit structured sorter survey responses that are grouped by configurable sections and questions.
- **Reporting** – Filter saved responses by client, site, or date range to generate printable tables for audits.
- **Authentication** – Password-protected access with session-based login/logout and seeded admin credentials.
- **User management** – Admins can create, edit, rotate API tokens, and remove users through the web interface.
- **File attachments** – Upload photos, diagrams, or PDFs for each response; files are stored in `uploads/` with metadata tracked in the database.
- **REST API** – `/api/responses` endpoint returns responses or an individual response with all values for system integrations.
- **AI suggestions** – Authenticated users can request contextual answer suggestions from OpenAI directly inside forms via `ai.php`.

## Requirements
- PHP 8.1 or later with SQLite3 extension enabled.
- SQLite (bundled with PHP) for local database storage.
- Optional: An [OpenAI API key](https://platform.openai.com/account/api-keys) for AI suggestions.

## Getting Started
1. **Clone the repository** and install dependencies (none beyond PHP/SQLite).
2. **Start the PHP development server:**
   ```bash
   php -S localhost:8000
   ```
   Run the command from the repository root so PHP can locate `index.php`.
3. **Visit the app** at [http://localhost:8000](http://localhost:8000) in your browser.
4. **Log in** using the seeded credentials:
   - Username: `admin`
   - Password: `admin`
5. **Manage users** via the **“Usuários”** link in the top menu to add accounts, reset API tokens, or update passwords.

### Accessing the Response Form
Once you are authenticated, the navigation bar at the top of the interface reveals the survey tooling:

1. Click **“Respostas”** in the navigation bar to open the list of saved survey entries.
2. Use the **“Nova resposta”** button to launch the multi-section response form seeded by the application.
3. Complete the questions in each section, attach any supporting files if needed, and click **Salvar** to store the response.

Returning to the **Respostas** screen lets you reopen or review previously submitted surveys at any time.

When the application runs for the first time it automatically creates `data.db` (SQLite database), seeds baseline survey sections/questions, and ensures the admin user exists.

### Database Location
- The SQLite database file is stored at `data.db` in the project root.
- Uploaded attachments are stored in `uploads/` and linked via the `attachments` table.

## REST API
The REST API shares the same base URL as the web app and requires a valid API token.

- **List responses:** `GET /api/responses?token=YOUR_TOKEN`
- **Fetch a response:** `GET /api/responses/{id}?token=YOUR_TOKEN`

Tokens are stored in the `users` table (`api_token` column) and are visible on the **Usuários** page, where you can also generate fresh tokens with a single click. The API returns JSON payloads using UTF-8 encoding and HTTP 401 when the token is invalid.

## OpenAI Suggestions
The `ai.php` endpoint enhances forms with AI-generated answer suggestions. To enable it:
1. Export your OpenAI API key before starting PHP:
   ```bash
   export OPENAI_API_KEY="sk-your-key"
   php -S localhost:8000
   ```
2. Log in to the web UI. Suggested responses become available through the “Sugerir IA” buttons next to inputs.

If the environment variable is missing the endpoint returns HTTP 500 with an explanatory JSON error.

## Project Structure
```
.
├── index.php      # Main application (routing, UI, DB migrations, REST API)
├── ai.php         # Authenticated endpoint for OpenAI-assisted suggestions
├── uploads/       # Created at runtime for file attachments
└── data.db        # SQLite database (auto-created at first run)
```

## Development Notes
- The application automatically migrates the database on each request using `migrate()` in `index.php`.
- Survey sections and questions are seeded the first time `data.db` is created. Extend them via the `sections` and `questions` tables or by editing `seedSurvey()`.
- Passwords are hashed with `password_hash()` using Bcrypt; update credentials with the `users` table or by adding UI logic.
- Error reporting is enabled by default (`display_errors=1`) for easier local debugging.

## License
This assessment project is provided as-is for evaluation purposes. Adapt or extend it to match your RFID sorter requirements.
