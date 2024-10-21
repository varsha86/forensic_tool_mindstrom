import os
import time
import hashlib
import magic  # Requires installation: pip install python-magic
from PIL import Image  # Requires installation: pip install pillow
from PIL.ExifTags import TAGS
import mmap
import re
import shutil
import csv
import logging
import sqlite3


class EnhancedForensicsTool:
    def __init__(self, file_path, report_file="forensics_report.txt", db_file="forensics_data.db"):
        self.file_path = file_path
        self.report_file = report_file
        self.db_file = db_file
        logging.basicConfig(filename='forensics_tool.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def save_to_file(self, content):
        with open(self.report_file, "a") as f:
            f.write(content + "\n")

    def save_to_csv(self, data, csv_file="analysis_results.csv"):
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(data.keys())  # Writing header
            writer.writerow(data.values())  # Writing data

    def save_to_db(self, data):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Create table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS forensic_analysis
                          (file_path TEXT, file_size TEXT, creation_time TEXT,
                           modification_time TEXT, access_time TEXT, md5_hash TEXT,
                           sha256_hash TEXT, file_type TEXT)''')

        cursor.execute('''INSERT INTO forensic_analysis
                          (file_path, file_size, creation_time, modification_time,
                           access_time, md5_hash, sha256_hash, file_type)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                          (data['File Path'], data['File Size'], data['Creation Time'],
                           data['Last Modification Time'], data['Last Access Time'], 
                           data['MD5 Hash'], data['SHA-256 Hash'], data['File Type']))

        conn.commit()
        conn.close()

    def log_activity(self, message, level="info"):
        if level == "info":
            logging.info(message)
        elif level == "error":
            logging.error(message)

    def get_file_metadata(self):
        try:
            file_stats = os.stat(self.file_path)
            metadata = {
                "File Path": self.file_path,
                "File Size": f"{file_stats.st_size} bytes",
                "Creation Time": time.ctime(file_stats.st_ctime),
                "Last Modification Time": time.ctime(file_stats.st_mtime),
                "Last Access Time": time.ctime(file_stats.st_atime),
                "Is Hidden": self.is_hidden_file()
            }
            return metadata
        except FileNotFoundError:
            self.log_activity(f"File {self.file_path} not found.", "error")
            return "File not found."

    def calculate_file_hash(self, hash_type="md5"):
        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read()
                if hash_type == "md5":
                    return hashlib.md5(file_data).hexdigest()
                elif hash_type == "sha256":
                    return hashlib.sha256(file_data).hexdigest()
        except FileNotFoundError:
            self.log_activity(f"File {self.file_path} not found for hash calculation.", "error")
            return "File not found."

    def is_hidden_file(self):
        return os.path.basename(self.file_path).startswith(".")

    def detect_file_type(self):
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(self.file_path)
            return file_type
        except Exception:
            self.log_activity("Error detecting file type or magic module not available.", "error")
            return "Unknown file type."

    def extract_image_exif(self):
        try:
            image = Image.open(self.file_path)
            exif_data = image._getexif()

            if exif_data is not None:
                exif_info = {TAGS.get(tag): value for tag, value in exif_data.items()}
                return exif_info
            else:
                return "No Exif data found."
        except Exception:
            self.log_activity(f"Error extracting Exif data from {self.file_path}.", "error")
            return "Not an image file or unable to extract Exif data."

    def search_hidden_files(self, directory):
        try:
            hidden_files = [f for f in os.listdir(directory) if f.startswith('.')]
            return hidden_files if hidden_files else "No hidden files found."
        except Exception as e:
            self.log_activity(f"Error searching hidden files in {directory}.", "error")
            return f"Error: {e}"

    def recover_deleted_files(self, search_dir):
        recovered_files = []
        try:
            for root, dirs, files in os.walk(search_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if not os.path.exists(file_path):
                        shutil.copy(file_path, f"recovered_{file}")
                        recovered_files.append(file_path)
            return recovered_files if recovered_files else "No deleted files recovered."
        except Exception as e:
            self.log_activity(f"Error recovering files in {search_dir}.", "error")
            return f"Error: {e}"

    def analyze_memory_dump(self, dump_file, search_keyword=None):
        try:
            with open(dump_file, "rb") as f:
                mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                if search_keyword:
                    match = re.search(search_keyword.encode(), mmapped_file)
                    return f"Keyword '{search_keyword}' found at position: {match.start()}" if match else "Keyword not found."
                else:
                    return "No keyword provided for memory dump analysis."
        except FileNotFoundError:
            self.log_activity(f"Memory dump file {dump_file} not found.", "error")
            return "Memory dump file not found."
        except Exception as e:
            self.log_activity(f"Error during memory dump analysis: {e}", "error")
            return f"Error: {e}"

    def reconstruct_timeline(self):
        try:
            file_stats = os.stat(self.file_path)
            timeline = {
                "Creation Time": time.ctime(file_stats.st_ctime),
                "Last Modification Time": time.ctime(file_stats.st_mtime),
                "Last Access Time": time.ctime(file_stats.st_atime)
            }
            return timeline
        except FileNotFoundError:
            self.log_activity(f"File {self.file_path} not found for timeline reconstruction.", "error")
            return "File not found."

    def display_report(self):
        metadata = self.get_file_metadata()
        file_md5 = self.calculate_file_hash(hash_type="md5")
        file_sha256 = self.calculate_file_hash(hash_type="sha256")
        file_type = self.detect_file_type()

        print("Enhanced Forensics Report")
        print("-------------------------")
        if isinstance(metadata, dict):
            for key, value in metadata.items():
                print(f"{key}: {value}")
            print(f"File Type: {file_type}")
            print(f"MD5 Hash: {file_md5}")
            print(f"SHA-256 Hash: {file_sha256}")

            # Save report to file
            report_content = f"""
            File Path: {metadata['File Path']}
            File Size: {metadata['File Size']}
            Creation Time: {metadata['Creation Time']}
            Last Modification Time: {metadata['Last Modification Time']}
            Last Access Time: {metadata['Last Access Time']}
            File Type: {file_type}
            MD5 Hash: {file_md5}
            SHA-256 Hash: {file_sha256}
            """
            self.save_to_file(report_content)

            # Save to CSV
            self.save_to_csv(metadata)

            # Save to Database
            metadata.update({"MD5 Hash": file_md5, "SHA-256 Hash": file_sha256, "File Type": file_type})
            self.save_to_db(metadata)

            # Exif Data for Images
            exif_data = self.extract_image_exif()
            if isinstance(exif_data, dict):
                print("\nExif Data (for images):")
                for key, value in exif_data.items():
                    print(f"{key}: {value}")
            else:
                print(f"\n{exif_data}")
        else:
            print(metadata)


# Example usage
file_path = "example.jpg"  # Replace with your file path
directory_path = "."  # Directory to search hidden files
memory_dump_path = "memory.dmp"  # Replace with your memory dump file

tool = EnhancedForensicsTool(file_path)
tool.display_report()

# Search for hidden files in a directory
hidden_files = tool.search_hidden_files(directory_path)
print("\nHidden Files:")
print(hidden_files)

# Recover deleted files
recovered_files = tool.recover_deleted_files(directory_path)
print("\nRecovered Files:")
print(recovered_files)

# Analyze memory dump
memory_analysis = tool.analyze_memory_dump(memory_dump_path, search_keyword="password")
print("\nMemory Dump Analysis:")
print(memory_analysis)

# Reconstruct timeline
timeline = tool.reconstruct_timeline()
print("\nTimeline Reconstruction:")
print(timeline)
