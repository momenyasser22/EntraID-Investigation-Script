# Input Directory

Place your Microsoft Entra ID sign-in log files in this directory.

## Required Files

1. **SignIn File**: The main sign-in log file (CSV or Excel format)
   - Example: `SignIn.csv`, `SignIn.xlsx`

2. **AuthDetails File**: The authentication details file (CSV or Excel format)
   - Example: `AuthDetails.csv`, `SignInAuthDetails.xlsx`

## File Format Requirements

See the main [README.md](../README.md) for detailed column requirements.

## Usage

When running the investigation tool, provide the full paths to these files:
- **Docker**: `/data/input/your_signin_file.csv`
- **Local**: Full path to your files

**Note**: Actual data files (CSV, Excel, DOCX) are excluded from version control for security reasons.
