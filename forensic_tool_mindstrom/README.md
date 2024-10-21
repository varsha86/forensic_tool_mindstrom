Forensics Tool
Overview

The Enhanced Forensics Tool is designed for digital forensics investigators to analyze and recover data from compromised systems. This tool provides features such as file metadata extraction, hash calculation, image EXIF data extraction, hidden file search, memory dump analysis, and more. It also allows for saving reports, logs, and analysis data for future reference.

Features

- File Metadata Extraction: Retrieves file size, creation time, last modification time, last access time, and checks if the file is hidden.
- Hash Calculation: Calculates MD5 and SHA-256 hashes of the specified file for data integrity verification.
- File Type Detection: Identifies the file type using the magic module.
- EXIF Data Extraction: Extracts and displays EXIF data from image files.
- Hidden File Search: Searches for hidden files in a specified directory.
- Deleted File Recovery: Attempts to recover deleted files within a specified directory.
- Memory Dump Analysis: Analyzes memory dump files for specific keywords.
- Timeline Reconstruction: Reconstructs a timeline of file creation, modification, and access events.
- Logging: Records actions and errors in a log file for auditing purposes.
- Data Storage: Saves analysis results in a text file, CSV file, and SQLite database for long-term storage.

Installation

Prerequisites

- Python 3.x
- python-magic
- Pillow

Step-by-Step Installation

1. Clone this repository or download the script.

2. Install the required packages:

   ```bash
   pip install python-magic Pillow
   ```

3. Ensure you have the necessary files for testing (e.g., images, memory dumps).

Usage

1. Save the provided script as `forensics_tool.py`.

2. Prepare the files for analysis, such as `example.jpg` and a memory dump file (optional).

3. Run the script using the following command:

   ```bash
   python forensics_tool.py
   ```

4. The output will be printed to the console and saved in the following formats:
   - `forensics_report.txt`: Detailed analysis report.
   - `analysis_results.csv`: CSV file containing metadata and hash values.
   - `forensics_data.db`: SQLite database storing analysis data.
   - `forensics_tool.log`: Log file capturing actions and errors.

Example Usage

To analyze an image file named `example.jpg`, simply replace the file path in the script:

```python
file_path = "example.jpg"  # Replace with your file path
```

You can also specify a memory dump file for analysis:

```python
memory_dump_path = "memory.dmp"  # Replace with your memory dump file
```

Contributing

If you would like to contribute to this project, feel free to open an issue or submit a pull request. Your contributions are welcome!

License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
