# Entra ID Sign-In Investigation Tool

A Python-based investigation tool for analyzing Microsoft Entra ID (formerly Azure AD) sign-in activity to detect potential security threats, session hijacking, and anomalous authentication behavior.

## Features

- **Session Hijacking Detection**: Identifies sessions with geographic anomalies that may indicate session hijacking
- **Baseline Location Enforcement**: Detects sign-in attempts from locations outside the configured baseline country
- **Threat Intelligence Enrichment**: Integrates with VirusTotal API to assess IP address reputation
- **Authentication Success Analysis**: Identifies successful authentication attempts from foreign locations
- **Automated Report Generation**: Generates comprehensive Word document reports with findings and recommendations

## Prerequisites

- Python 3.7 or higher (for local execution)
- Docker and Docker Compose (for containerized execution - recommended)
- Microsoft Entra ID sign-in logs (CSV or Excel format)
- VirusTotal API key (optional, for threat intelligence enrichment)

## File Structure:
```bash
   EntraID-Investigation-Script/
   │
   ├── app.py
   ├── README.md
   ├── requirements.txt
   ├── Dockerfile
   ├── docker-compose.yml
   │
   ├── data/
   │   ├── input/
   │   │   ├── signin_logs.csv
   │   │   └── signin_authdetails.csv
   │   │
   │   └── output/
   │       ├── main_investigation.csv
   │       └── Investigation_Report_<UserName>.docx
   │
   └── .gitignore   (optional but recommended)
```
## Installation

### Option 1: Docker (Recommended)

1. Clone this repository:
```bash
git clone https://github.com/momenyasser22/EntraID-Investigation-Script.git
cd EntraID-Investigation-Script
```

2. Build the Docker image:
```bash
docker-compose build
```

3. Place your input files in the `data/input/` directory

4. Run the investigation:
```bash
docker-compose up -d
python3 app.py
```

5. Find your results in the `data/output/` directory

### Option 2: Local Python Installation

1. Clone this repository:
```bash
git clone https://github.com/momenyasser22/EntraID-Investigation-Script.git
cd EntraID-Investigation-Script
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Before running the script, configure the following variables in `app.py`:

- `BASELINE_LOCATION`: Set to your baseline country code (default: "EG" for Egypt)
- `VT_API_KEY`: Your VirusTotal API key (required for Step 3 threat intelligence lookup)

```python
BASELINE_LOCATION = "EG"  # Change to your baseline country code
VT_API_KEY = "your-virustotal-api-key-here"
```

## Usage

### Docker Usage (Recommended)

1. Place your input files in the `data/input/` directory:
   - SignIn file (e.g., `SignIn.csv`)
   - AuthDetails file (e.g., `AuthDetails.csv`)

2. Run the investigation:
```bash
docker-compose run --rm entra-investigation
```

3. When prompted, provide the paths to your input files:
   - **SignIn file**: `/data/input/your_signin_file.csv`
   - **SignIn AuthDetails file**: `/data/input/your_authdetails_file.csv`

4. Results will be saved in `data/output/`:
   - `main_investigation.csv`: Merged and processed data
   - `Investigation_Report_{User}.docx`: Comprehensive investigation report (dynamically named based on investigated user)

### Local Python Usage

1. Run the script:
```bash
python app.py
```

2. When prompted, provide the full paths to your input files:
   - **SignIn file**: The main sign-in log file (CSV or Excel)
   - **SignIn AuthDetails file**: The authentication details file (CSV or Excel)

3. The script will perform the following investigation steps:
   - **Step 1**: Session hijacking analysis
   - **Step 2**: Baseline location violations detection
   - **Step 3**: VirusTotal threat intelligence lookup (rate-limited to 1 request/minute)
   - **Step 4**: Successful foreign authentication review

4. Output files will be generated:
   - `main_investigation.csv`: Merged and processed data
   - `Investigation_Report_{User}.docx`: Comprehensive investigation report (dynamically named based on investigated user)

## Investigation Steps

### Step 1: Session Hijacking Analysis
Identifies sessions where sign-ins occurred from both the baseline location and foreign locations, which may indicate session hijacking.

### Step 2: Baseline Location Violations
Detects all sign-in events originating from locations outside the baseline country.

### Step 3: Threat Intelligence Assessment
Enriches foreign IP addresses with threat intelligence data from VirusTotal. Note: This step respects VirusTotal's rate limits (1 request per minute).

### Step 4: Authentication Success Review
Identifies successful password-based authentication attempts from foreign locations, which may indicate credential compromise.

## Output

### CSV Output (`main_investigation.csv`)
Contains the merged sign-in and authentication data with all processing applied.

### Word Report (`Investigation_Report_{User}.docx`)
A comprehensive report dynamically named based on the investigated user(s). The report includes:
- Executive Summary
- Scope and Methodology
- Detailed Findings for each investigation step
- Risk Assessment
- Security Recommendations

**Note**: If multiple users are investigated, the report will be named `Investigation_Report_Multiple_Users.docx`. For single-user investigations, the filename will include the user's name (sanitized for filesystem compatibility).

## Input File Format

The script expects CSV or Excel files with the following columns:

**SignIn File:**
- `Request ID`
- `Date` or `Date (UTC)`
- `Session ID`
- `User`
- `IP address`
- `Location`
- `User agent`
- `Application`
- `Resource`
- `Status`

**AuthDetails File:**
- `Request ID`
- `Succeeded`
- `Authentication method`
- `Authentication method detail`

## Docker Configuration

The project includes Docker support for easy deployment and consistent execution environments:

- **Dockerfile**: Creates a Python 3.11 slim-based container with all dependencies
- **docker-compose.yml**: Configures volume mounts for input/output data
- **Volume Mounts**: 
  - `./data/input` → `/data/input` (for input files)
  - `./data/output` → `/data/output` (for generated reports)

The Docker setup ensures:
- Consistent execution environment across different systems
- Isolated dependencies
- Easy data management through mounted volumes

## Security Considerations

- **API Keys**: Never commit your VirusTotal API key to version control. Consider using environment variables or a configuration file excluded from git.
- **Sensitive Data**: The input files may contain sensitive user information. Ensure proper handling and storage of these files.
- **Rate Limiting**: The VirusTotal API lookup respects rate limits (1 request per minute) to avoid API abuse.
- **Docker Security**: When using Docker, ensure your `data/` directory has appropriate permissions to protect sensitive investigation data.

## Troubleshooting

### File Not Found Error
- **Docker**: Ensure files are in the `data/input/` directory and use paths like `/data/input/filename.csv`
- **Local**: Ensure you provide the full absolute path to your input files, or ensure relative paths are correct from the script's directory

### Unsupported File Type
The script supports CSV (`.csv`) and Excel (`.xls`, `.xlsx`) files. Ensure your files are in one of these formats.

### VirusTotal API Errors
- Verify your API key is correct
- Check your API quota/rate limits
- Ensure you have internet connectivity


## Author

[Momen Yasser /momenyasser221@gmail.com]
