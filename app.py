import os
import pandas as pd
from flask import Flask, request, render_template, redirect, url_for, send_file
from werkzeug.utils import secure_filename

# Get the absolute path of the current directory
current_directory = os.path.abspath(os.path.dirname(__file__))

# Initialize the Flask application and set the template folder to the current directory
app = Flask(__name__, template_folder=current_directory)

app.config['UPLOAD_FOLDER'] = os.path.join(current_directory, 'uploads')
app.config['PROCESSED_FOLDER'] = os.path.join(current_directory, 'processed')
app.config['ALLOWED_EXTENSIONS'] = {'csv'}

# Ensure the upload and processed directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def delete_columns(file_path):
    columns_to_delete = [
        'TM Detection (Conventional) [Threat Hub]', 'Grid Whitelisting', 'Engines Detected (Competitors)', 'TrendX',
        'Scan Time (TM Detection)', 'VT TMDetection',
        'Rescan Status (VT TMDetection)', 'Scan Time (VT TMDetection)', 'Summarize Detection',
        'File Type (based on VT)', 'MARS', 'MCS', 'TM Detection (Smart Scan) [FRS Ninja]',
        'Pattern Version [FRS Ninja]', 'Release Date [FRS Ninja]',
        'TM Detection (Conventional) [FRS Ninja]', 'Pattern Version [FRS Ninja].1',
        'Release Date [FRS Ninja].1'
    ]

    try:
        print(f"Reading CSV file from {file_path}")
        df = pd.read_csv(file_path, skiprows=8)
        print(f"Initial DataFrame columns: {df.columns.tolist()}")

        df.drop(columns=[col for col in columns_to_delete if col in df.columns], inplace=True)
        print(f"DataFrame columns after deletion: {df.columns.tolist()}")

        processed_file_path = os.path.join(app.config['PROCESSED_FOLDER'], os.path.basename(file_path))

        with open(file_path, 'r') as file:
            lines = file.readlines()

        print(f"Writing processed file to {processed_file_path}")
        with open(processed_file_path, 'w', newline='') as file:
            file.writelines(lines[:8])
            df.to_csv(file, index=False, lineterminator='\n')

        print(f"Processed file saved at {processed_file_path}")
        return processed_file_path
    except pd.errors.ParserError as e:
        print(f"Error processing file {file_path}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    # Debugging statements
    print("Current working directory:", os.getcwd())
    print("Contents of the current directory:", os.listdir(current_directory))

    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            processed_file_path = delete_columns(file_path)
            if processed_file_path:
                return send_file(processed_file_path, as_attachment=True)
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
