from flask import Flask, render_template, request,redirect, url_for, flash, session
import boto3
from config import S3_BUCKET, S3_KEY, S3_SECRET
from botocore.client import Config
import csv

app = Flask(__name__)
app.secret_key = 'Vulnerability'  # used to encrypt session data

s3_client = boto3.client(
    's3',
    aws_access_key_id=S3_KEY,
    aws_secret_access_key=S3_SECRET,
    region_name='us-east-2',
    config=Config(signature_version='s3v4', s3={'addressing_style': 'virtual'})
)

s3_resource = boto3.resource(
    's3',
    aws_access_key_id=S3_KEY,
    aws_secret_access_key=S3_SECRET,
    region_name='us-east-2',
    config=Config(signature_version='s3v4', s3={'addressing_style': 'virtual'})
)

# ---------------- Helper Functions ----------------

def count_vulnerabilities(csv_content):
    count = 0
    reader = csv.reader(csv_content.splitlines())
    for row in reader:
        if len(row) > 7 and row[7].strip() == 'Vuln':
            count += 1
    return count

def extract_scanner_version(csv_content):
    reader = csv.reader(csv_content.splitlines())
    for row in reader:
        for cell in row:
            if "Scanner" in cell and "Scanner Appliance" not in cell:
                scanner_part = cell.split("Scanner ")[1]
                print(scanner_part)
                version = scanner_part.split(",")[0].strip()
                return version
    return "Not found"

def extract_severity_counts(csv_content):
    severity_map = {
        '1': 'Severity 1',
        '2': 'Severity 2',
        '3': 'Severity 3',
        '4': 'Severity 4',
        '5': 'Severity 5'
    }
    counts = {level: 0 for level in severity_map.values()}
    lines = csv_content.splitlines()
    try:
        header_idx = next(i for i, line in enumerate(lines) if 'IP' in line and 'DNS' in line and 'Type' in line)
        reader = csv.DictReader(lines[header_idx:])
        for row in reader:
            if row.get('Type', '').strip() == 'Vuln':
                severity = row.get('Severity', '').strip()
                if severity in severity_map:
                    counts[severity_map[severity]] += 1
    except StopIteration:
        app.logger.warning("CSV format unexpected; no header found.")
    return counts

# ---------------- Routes ----------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'array' and password == 'admin':
            session['logged_in'] = True
            return redirect(url_for('files'))
        else:
            flash('Invalid username or password. Try Again!')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('login'))

@app.route('/files')
def files():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    response = s3_client.list_objects_v2(Bucket=S3_BUCKET, Delimiter='/')
    year_prefixes = [prefix['Prefix'].rstrip('/') for prefix in response.get('CommonPrefixes', [])]
    return render_template('files.html', years=year_prefixes, selected_year=None, files=[])

@app.route('/files/<year>')
def files_by_year(year):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    response = s3_client.list_objects_v2(Bucket=S3_BUCKET, Delimiter='/')
    year_prefixes = [prefix['Prefix'].rstrip('/') for prefix in response.get('CommonPrefixes', [])]
    return render_template('files.html', years=year_prefixes, selected_year=year, quarters=['Q1', 'Q2', 'Q3', 'Q4'], files=[])

@app.route('/files/<year>/<quarter>')
def files_by_quarter(year, quarter):
    response = s3_client.list_objects_v2(Bucket=S3_BUCKET, Delimiter='/')
    year_prefixes = [prefix['Prefix'].rstrip('/') for prefix in response.get('CommonPrefixes', [])]

    my_bucket = s3_resource.Bucket(S3_BUCKET)
    summaries = my_bucket.objects.filter(Prefix=f'{year}/{quarter}/')

    files = []
    severity_totals = {'Severity 1': 0, 'Severity 2': 0, 'Severity 3': 0, 'Severity 4': 0, 'Severity 5': 0}
    product_totals = {}

    for obj in summaries:
        filename = obj.key.split('/')[-1]
        if not filename:
            continue

        head = s3_client.head_object(Bucket=S3_BUCKET, Key=obj.key)
        metadata = head.get('Metadata', {})

        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': S3_BUCKET, 'Key': obj.key},
            ExpiresIn=3600,
            HttpMethod='GET'
        )

        file_data = {
            'name': filename,
            'url': presigned_url,
            'size': obj.size,
            'last_modified': obj.last_modified,
            'product_name': metadata.get('name', 'N/A'),
            'product_build': metadata.get('build', 'N/A'),
            'status': metadata.get('status', 'N/A'),
            'vulnerability_count': 'N/A',
            'qualys_version': 'N/A',
            'severity_counts': None
        }

        if filename.lower().endswith('.csv'):
            try:
                response = s3_client.get_object(Bucket=S3_BUCKET, Key=obj.key)
                csv_content = response['Body'].read().decode('utf-8')

                vuln_count = count_vulnerabilities(csv_content)
                file_data['vulnerability_count'] = vuln_count
                file_data['qualys_version'] = extract_scanner_version(csv_content)
                file_data['severity_counts'] = extract_severity_counts(csv_content)

                # Aggregate severity counts
                for severity, count in file_data['severity_counts'].items():
                    severity_totals[severity] += count

                # Add to product totals
                product_key = f"{file_data['product_name']} {file_data['product_build']}"
                product_totals[product_key] = product_totals.get(product_key, 0) + vuln_count

            except Exception as e:
                app.logger.error(f"Error reading {obj.key}: {str(e)}")

        files.append(file_data)

    return render_template('files.html',
                           years=year_prefixes,
                           selected_year=year,
                           selected_quarter=quarter, 
                           quarters=['Q1', 'Q2', 'Q3', 'Q4'],
                           files=files,
                           severity_totals=severity_totals,
                           product_totals=product_totals)

if __name__ == '__main__':
    app.run(debug=True)
