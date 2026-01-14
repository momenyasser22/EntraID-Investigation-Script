# Entra ID Sign-In Investigation Tool

A Python-based investigation tool for analyzing Microsoft Entra ID (formerly Azure AD) sign-in activity to detect potential security threats, session hijacking, and anomalous authentication behavior.

## Features

- **Session Hijacking Detection**: Identifies sessions with geographic anomalies that may indicate session hijacking
- **Baseline Location Enforcement**: Detects sign-in attempts from locations outside the configured baseline country
- **Threat Intelligence Enrichment**: Integrates with VirusTotal API to assess IP address reputation
- **Authentication Success Analysis**: Identifies successful authentication attempts from foreign locations
- **Automated Report Generation**: Generates comprehensive Word document reports with findings and recommendations

## Prerequisites

- Python 3.7 or higher
- Microsoft Entra ID sign-in logs (CSV or Excel format)
- VirusTotal API key (optional, for threat intelligence enrichment)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd "EntraID Script Investigation"
```

2. Install required dependencies:
```bash
pip install pandas openpyxl python-docx requests
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

4. Output files will be generated in the script directory:
   - `main_investigation.csv`: Merged and processed data
   - `investigation_report.docx`: Comprehensive investigation report

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

### Word Report (`investigation_report.docx`)
A comprehensive report including:
- Executive Summary
- Scope and Methodology
- Detailed Findings for each investigation step
- Risk Assessment
- Security Recommendations

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

## Security Considerations

- **API Keys**: Never commit your VirusTotal API key to version control. Consider using environment variables or a configuration file excluded from git.
- **Sensitive Data**: The input files may contain sensitive user information. Ensure proper handling and storage of these files.
- **Rate Limiting**: The VirusTotal API lookup respects rate limits (1 request per minute) to avoid API abuse.

## Troubleshooting

### File Not Found Error
Ensure you provide the full absolute path to your input files, or ensure relative paths are correct from the script's directory.

### Unsupported File Type
The script supports CSV (`.csv`) and Excel (`.xls`, `.xlsx`) files. Ensure your files are in one of these formats.

### VirusTotal API Errors
- Verify your API key is correct
- Check your API quota/rate limits
- Ensure you have internet connectivity

## License

[Specify your license here]

## Contributing

[Add contribution guidelines if applicable]

## Author

[Your name/contact information]
