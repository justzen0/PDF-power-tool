# PDF PowerTool

A simple yet powerful desktop utility for performing essential PDF operations in bulk. Built with Python and Tkinter, this tool provides a clean graphical user interface to split, merge, and unlock multiple PDF files at once.

All processing happens 100% locally on your machine. Your files are never uploaded to any server, ensuring your data remains private and secure.

## Features

-   **Split PDF**: Split a single PDF into multiple documents based on custom page ranges (e.g., `1-5, 8, 11-14`).
-   **Merge PDFs**: Combine multiple PDF files into a single document. Easily reorder the files before merging.
-   **Unlock PDFs**: Remove passwords and usage restrictions (like copying or printing) from multiple PDF files in one batch operation. If a file is password-protected, the tool will securely prompt you to enter the password before processing.
-   **User-Friendly GUI**: A clean, tabbed interface that is easy to navigate for users of all skill levels.
-   **Cross-Platform**: Built with standard Python libraries, making it easy to run on Windows, macOS, and Linux.

## Getting Started

There are two ways to use PDF PowerTool: by running the standalone executable (easiest method, Windows only) or by running the Python script directly (requires setup, works on all platforms).

### Option 1: Using the Executable (Windows)

1.  Go to the [**Releases**](https://github.com/justzen0/PDF-power-tool/releases) page of this repository.
2.  Download the latest version of `PDF-PowerTool.exe`.
3.  Double-click the downloaded file to run the application. No installation is needed!

### Option 2: Running from the Python Script (All Platforms)

If you are on macOS/Linux or prefer to run the code from source, follow these steps.

**Prerequisites:**
-   Python 3.8 or newer installed on your system.
-   `pip` (Python's package installer) available in your terminal.

**Installation Steps:**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/your-repo-name.git
    cd your-repo-name
    ```

2.  **Install required libraries:**
    The application depends on `pypdf` and `cryptography` (for handling encrypted files). Install them using the following command:
    ```bash
    pip install pypdf cryptography
    ```

3.  **Run the application:**
    Once the dependencies are installed, you can start the application by running:
    ```bash
    python pdftool.py 
    ```
    *(Replace `pdftool.py` with the actual name of your script if it's different.)*

## How to Use the Application

1.  **To Split a PDF**:
    -   Select the "Split PDF" tab.
    -   Browse for the input PDF you want to split.
    -   Enter the page ranges (e.g., `1-3, 5, 8-10`).
    -   Select an output directory to save the new files.
    -   Click "Split PDF".

2.  **To Merge PDFs**:
    -   Select the "Merge PDFs" tab.
    -   Click "Add PDF(s)" to select all the files you want to combine.
    -   Use the "Move Up" and "Move Down" buttons to arrange the files in the correct order.
    -   Click "Save As..." to choose a name and location for the final merged document.
    -   Click "Merge PDFs".

3.  **To Unlock PDFs**:
    -   Select the "Unlock PDFs" tab.
    -   Click "Add PDF(s)" to add one or more files to the list.
    -   Select an output directory. Unlocked versions of each file will be saved there with an `_unlocked` suffix.
    -   Click "Unlock Files".
    -   If any file is password-protected, a dialog box will appear asking you to enter the password for that specific file.

## Disclaimer

The "Unlock PDFs" feature is intended for use on documents for which you have the legal right to remove such restrictions. This includes documents you own or for which you have been given the password and permission to modify. This tool is not designed for illegal activities, and the user is solely responsible for its ethical use. Please respect copyright and licensing agreements.

## Contributing

Contributions are welcome! If you have ideas for new features, bug fixes, or other improvements, please feel free to open an issue or submit a pull request.