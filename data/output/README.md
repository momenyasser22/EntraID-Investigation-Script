# Output Directory

Investigation results are saved to this directory.

## Generated Files

1. **main_investigation.csv**: Merged and processed sign-in and authentication data

2. **Investigation_Report_{User}.docx**: Comprehensive investigation report
   - Named dynamically based on investigated user(s)
   - Contains findings, risk assessment, and recommendations

## File Locations

- **Docker**: Files are saved to `/data/output/` inside the container
- **Local**: Files are saved to `./data/output/` relative to the script directory

## Note

Output files are excluded from version control (via `.gitignore`) to protect sensitive investigation data.
