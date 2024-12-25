# AnomaNet

### Components

- models/
  Stores trained models and related files.

- scripts/
  Core project scripts:
  - `pcap_parser.py`: Parses PCAP files, extracts packet information, and visualizes data using Dash.
  - `training.py`: Preprocesses data, trains machine learning models, and saves them.
  - `anomaly_detection.py`: Detects anomalies in packet data using K-Means, Isolation Forest, and One-Class SVM.
  - `export_results.py`: Exports filtered data to CSV, JSON, or PCAP formats.

- requirements.txt  
  Lists all necessary libraries for the project.

- README.md  
  Project documentation.

## Installation

1. Clone the Repository
    ```bash
    git clone https://github.com/WaiperOK/AnomaNet
    cd project
    ```

2. Create a Virtual Environment
    ```bash
    python -m venv venv
    source venv/bin/activate  # For Windows: venv\Scripts\activate
    ```

3. Install Dependencies
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### 1. Parsing PCAP Files and Visualization
```bash
python scripts/pcap_parser.py
