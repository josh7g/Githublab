from flask import Flask, request, jsonify
import os
import subprocess
import logging
import hmac
import hashlib
import shutil
import json
import asyncio
from github import Github, GithubIntegration
from dotenv import load_dotenv
from datetime import datetime
from flask_cors import CORS
from models import db, AnalysisResult
from sqlalchemy import or_, text
import traceback
import requests
#from asgiref.wsgi import WsgiToAsgi
from scanner import SecurityScanner, ScanConfig, scan_repository_handler
from api import api, analysis_bp
import time

# Load environment variables in development
if os.getenv('FLASK_ENV') != 'production':
    load_dotenv()

# Initialize Flask app ONCE
app = Flask(__name__)
CORS(app)
#asgi_app = WsgiToAsgi(app)
app.register_blueprint(api)
app.register_blueprint(analysis_bp)

# Create an event loop for async operations
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.getenv('FLASK_ENV') == 'production' else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

if not DATABASE_URL:
    DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/semgrep_analysis'

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enhanced SSL and connection pool configuration for Render
if os.getenv('FLASK_ENV') == 'production':
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {
            'sslmode': 'require',
            'ssl_min_protocol_version': 'TLSv1.2',
            'keepalives': 1,
            'keepalives_idle': 30,
            'keepalives_interval': 10,
            'keepalives_count': 5
        },
        'pool_size': 5,
        'max_overflow': 10,
        'pool_timeout': 30,
        'pool_recycle': 300,
        'pool_pre_ping': True
    }

# Initialize SQLAlchemy
db.init_app(app)

def check_db_connection():
    try:
        with app.app_context():
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            return True
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        return False

def execute_with_retry(operation, max_retries=3, delay=1):
    def run_with_context():
        with app.app_context():
            return operation()
            
    for attempt in range(max_retries):
        try:
            return run_with_context()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            logger.warning(f"Database operation failed, attempt {attempt + 1} of {max_retries}")
            time.sleep(delay)
            if not check_db_connection():
                logger.info("Reconnecting to database...")
                db.session.remove()

def check_and_add_columns():
    try:
        result = db.session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='analysis_results' AND column_name='user_id'
        """))
        column_exists = bool(result.scalar())
        
        if not column_exists:
            logger.info("Adding user_id column...")
            db.session.execute(text("""
                ALTER TABLE analysis_results 
                ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)
            """))
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_analysis_results_user_id 
                ON analysis_results (user_id)
            """))
            db.session.commit()

        result = db.session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='analysis_results' AND column_name='rerank'
        """))
        rerank_exists = bool(result.scalar())
        
        if not rerank_exists:
            logger.info("Adding rerank column...")
            db.session.execute(text("""
                ALTER TABLE analysis_results 
                ADD COLUMN IF NOT EXISTS rerank JSONB
            """))
            db.session.commit()
            
    except Exception as e:
        logger.error(f"Error checking/adding columns: {str(e)}")
        db.session.rollback()
        raise

# Database initialization
with app.app_context():
    try:
        def init_db():
            # Create tables if they don't exist
            db.create_all()
            logger.info("Database tables created successfully!")

            # Test database connection
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            logger.info("Database connection successful")
            
            # Check and add columns
            check_and_add_columns()
       
        for attempt in range(3):  # 3 retries
            try:
                init_db()
                logger.info("Database initialization successful")
                break
            except Exception as e:
                if attempt == 2:  # Last attempt
                    logger.error(f"Failed to initialize database after retries: {str(e)}")
                    raise
                logger.warning(f"Database operation failed, attempt {attempt + 1} of 3")
                time.sleep(1)
                
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise
    finally:
        db.session.remove()

def format_private_key(key_data):
    """Format the private key correctly for GitHub integration"""
    try:
        if not key_data:
            raise ValueError("Private key is empty")
        
        key_data = key_data.strip()
        
        if '\\n' in key_data:
            parts = key_data.split('\\n')
            key_data = '\n'.join(part.strip() for part in parts if part.strip())
        elif '\n' not in key_data:
            key_length = len(key_data)
            if key_length < 64:
                raise ValueError("Key content too short")
            
            if not key_data.startswith('-----BEGIN'):
                key_data = (
                    '-----BEGIN RSA PRIVATE KEY-----\n' +
                    '\n'.join(key_data[i:i+64] for i in range(0, len(key_data), 64)) +
                    '\n-----END RSA PRIVATE KEY-----'
                )
        
        if not key_data.startswith('-----BEGIN RSA PRIVATE KEY-----'):
            key_data = '-----BEGIN RSA PRIVATE KEY-----\n' + key_data
        if not key_data.endswith('-----END RSA PRIVATE KEY-----'):
            key_data = key_data + '\n-----END RSA PRIVATE KEY-----'
        
        lines = key_data.split('\n')
        if len(lines) < 3:
            raise ValueError("Invalid key format - too few lines")
        
        logger.info("Private key formatted successfully")
        return key_data
        
    except Exception as e:
        logger.error(f"Error formatting private key: {str(e)}")
        raise ValueError(f"Private key formatting failed: {str(e)}")
        
#Webhook handler
def verify_webhook_signature(request_data, signature_header):
    """
    Enhanced webhook signature verification for GitHub webhooks
    """
    try:
        webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
        
        logger.info("Starting webhook signature verification")
        
        if not webhook_secret:
            logger.error("GITHUB_WEBHOOK_SECRET environment variable is not set")
            return False

        if not signature_header:
            logger.error("No X-Hub-Signature-256 header received")
            return False

        if not signature_header.startswith('sha256='):
            logger.error("Signature header doesn't start with sha256=")
            return False
            
        # Get the raw signature without 'sha256=' prefix
        received_signature = signature_header.replace('sha256=', '')
        
        # Ensure webhook_secret is bytes
        if isinstance(webhook_secret, str):
            webhook_secret = webhook_secret.strip().encode('utf-8')
            
        # Ensure request_data is bytes
        if isinstance(request_data, str):
            request_data = request_data.encode('utf-8')
            
        # Calculate expected signature
        mac = hmac.new(
            webhook_secret,
            msg=request_data,
            digestmod=hashlib.sha256
        )
        expected_signature = mac.hexdigest()
        
        # Debug logging
        logger.debug("Signature Details:")
        logger.debug(f"Request Data Length: {len(request_data)} bytes")
        logger.debug(f"Secret Key Length: {len(webhook_secret)} bytes")
        logger.debug(f"Raw Request Data: {request_data[:100]}...")  # First 100 bytes
        logger.debug(f"Received Header: {signature_header}")
        logger.debug(f"Calculated HMAC: sha256={expected_signature}")
        
        # Use constant time comparison
        is_valid = hmac.compare_digest(expected_signature, received_signature)
        
        if not is_valid:
            logger.error("Signature mismatch detected")
            logger.error(f"Header format: {signature_header}")
            logger.error(f"Received signature: {received_signature[:10]}...")
            logger.error(f"Expected signature: {expected_signature[:10]}...")
            
            # Additional debug info
            if os.getenv('FLASK_ENV') != 'production':
                logger.debug("Full signature comparison:")
                logger.debug(f"Full received: {received_signature}")
                logger.debug(f"Full expected: {expected_signature}")
        else:
            logger.info("Webhook signature verified successfully")
            
        return is_valid

    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        logger.error(traceback.format_exc())
        return False

@app.route('/debug/test-webhook', methods=['POST'])
def test_webhook():
    """Test endpoint to verify webhook signatures"""
    if os.getenv('FLASK_ENV') != 'production':
        try:
            webhook_secret = os.getenv('GITHUB_WEBHOOK_SECRET')
            raw_data = request.get_data()
            received_signature = request.headers.get('X-Hub-Signature-256')
            
            # Test with the exact data received
            result = verify_webhook_signature(raw_data, received_signature)
            
            # Calculate signature for debugging
            mac = hmac.new(
                webhook_secret.encode('utf-8') if isinstance(webhook_secret, str) else webhook_secret,
                msg=raw_data,
                digestmod=hashlib.sha256
            )
            expected_signature = f"sha256={mac.hexdigest()}"
            
            return jsonify({
                'webhook_secret_configured': bool(webhook_secret),
                'webhook_secret_length': len(webhook_secret) if webhook_secret else 0,
                'received_signature': received_signature,
                'expected_signature': expected_signature,
                'payload_size': len(raw_data),
                'signatures_match': result,
                'raw_data_preview': raw_data.decode('utf-8')[:100] if raw_data else None
            })
        except Exception as e:
            return jsonify({'error': str(e)})
    return jsonify({'message': 'Not available in production'}), 403


def clean_directory(directory):
    """Safely remove a directory"""
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory)
    except Exception as e:
        logger.error(f"Error cleaning directory {directory}: {str(e)}")

def trigger_semgrep_analysis(repo_url, installation_token, user_id):
    """Run Semgrep analysis with enhanced error handling"""
    clone_dir = None
    repo_name = repo_url.split('github.com/')[-1].replace('.git', '')
    
    try:
        repo_url_with_auth = f"https://x-access-token:{installation_token}@github.com/{repo_name}.git"
        clone_dir = f"/tmp/semgrep_{repo_name.replace('/', '_')}_{os.getpid()}"
        
        # Create initial database entry
        analysis = AnalysisResult(
            repository_name=repo_name,
            user_id=user_id,
            status='in_progress'
        )
        db.session.add(analysis)
        db.session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}")
        
        # Clean directory first
        clean_directory(clone_dir)
        logger.info(f"Cloning repository to {clone_dir}")
        
        # Enhanced clone command with detailed error capture
        try:
            # First verify the repository exists and is accessible
            test_url = f"https://api.github.com/repos/{repo_name}"
            headers = {
                'Authorization': f'Bearer {installation_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            logger.info(f"Verifying repository access: {test_url}")
            
            response = requests.get(test_url, headers=headers)
            if response.status_code != 200:
                raise ValueError(f"Repository verification failed: {response.status_code} - {response.text}")
            
            # Clone with more detailed error output
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url_with_auth, clone_dir],
                capture_output=True,
                text=True
            )
            
            if clone_result.returncode != 0:
                error_msg = (
                    f"Git clone failed with return code {clone_result.returncode}\n"
                    f"STDERR: {clone_result.stderr}\n"
                    f"STDOUT: {clone_result.stdout}"
                )
                logger.error(error_msg)
                raise Exception(error_msg)
                
            logger.info(f"Repository cloned successfully: {repo_name}")
            
            # Run semgrep analysis
            semgrep_cmd = ["semgrep", "--config=auto", "--json", "."]
            logger.info(f"Running semgrep with command: {' '.join(semgrep_cmd)}")
            
            semgrep_process = subprocess.run(
                semgrep_cmd,
                capture_output=True,
                text=True,
                check=True,
                cwd=clone_dir
            )
            
            try:
                semgrep_output = json.loads(semgrep_process.stdout)
                analysis.status = 'completed'
                analysis.results = semgrep_output
                db.session.commit()
                
                logger.info(f"Semgrep analysis completed successfully for {repo_name}")
                return semgrep_process.stdout
                
            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse Semgrep output: {str(e)}"
                logger.error(error_msg)
                analysis.status = 'failed'
                analysis.error = error_msg
                db.session.commit()
                return None

        except subprocess.CalledProcessError as e:
            error_msg = (
                f"Command '{' '.join(e.cmd)}' failed with return code {e.returncode}\n"
                f"STDERR: {e.stderr}\n"
                f"STDOUT: {e.stdout}"
            )
            logger.error(error_msg)
            if 'analysis' in locals():
                analysis.status = 'failed'
                analysis.error = error_msg
                db.session.commit()
            raise Exception(error_msg)

    except Exception as e:
        logger.error(f"Analysis error for {repo_name}: {str(e)}")
        if 'analysis' in locals():
            analysis.status = 'failed'
            analysis.error = str(e)
            db.session.commit()
        return None
        
    finally:
        if clone_dir:
            clean_directory(clone_dir)

def format_semgrep_results(raw_results):
    """Format Semgrep results for frontend"""
    try:
        # Handle string input
        if isinstance(raw_results, str):
            try:
                results = json.loads(raw_results)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON results: {str(e)}")
                return {
                    'summary': {
                        'total_files_scanned': 0,
                        'total_findings': 0,
                        'files_scanned': [],
                        'semgrep_version': 'unknown',
                        'scan_status': 'failed'
                    },
                    'findings': [],
                    'findings_by_severity': {
                        'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
                    },
                    'findings_by_category': {},
                    'errors': [f"Failed to parse results: {str(e)}"],
                    'severity_counts': {},
                    'category_counts': {}
                }
        else:
            results = raw_results

        if not isinstance(results, dict):
            raise ValueError(f"Invalid results format: expected dict, got {type(results)}")

        formatted_response = {
            'summary': {
                'total_files_scanned': len(results.get('paths', {}).get('scanned', [])),
                'total_findings': len(results.get('results', [])),
                'files_scanned': results.get('paths', {}).get('scanned', []),
                'semgrep_version': results.get('version', 'unknown'),
                'scan_status': 'success' if not results.get('errors') else 'completed_with_errors'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': results.get('errors', [])
        }

        for finding in results.get('results', []):
            try:
                severity = finding.get('extra', {}).get('severity', 'INFO')
                category = finding.get('extra', {}).get('metadata', {}).get('category', 'uncategorized')
                
                formatted_finding = {
                    'id': finding.get('check_id', 'unknown'),
                    'file': finding.get('path', 'unknown'),
                    'line_start': finding.get('start', {}).get('line', 0),
                    'line_end': finding.get('end', {}).get('line', 0),
                    'code_snippet': finding.get('extra', {}).get('lines', ''),
                    'message': finding.get('extra', {}).get('message', ''),
                    'severity': severity,
                    'category': category,
                    'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                    'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'fix_recommendations': {
                        'description': finding.get('extra', {}).get('metadata', {}).get('message', ''),
                        'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
                    }
                }

                formatted_response['findings'].append(formatted_finding)
                
                if severity not in formatted_response['findings_by_severity']:
                    formatted_response['findings_by_severity'][severity] = []
                formatted_response['findings_by_severity'][severity].append(formatted_finding)
                
                if category not in formatted_response['findings_by_category']:
                    formatted_response['findings_by_category'][category] = []
                formatted_response['findings_by_category'][category].append(formatted_finding)
                
            except Exception as e:
                logger.error(f"Error processing finding: {str(e)}")
                formatted_response['errors'].append(f"Error processing finding: {str(e)}")

        formatted_response['severity_counts'] = {
            severity: len(findings)
            for severity, findings in formatted_response['findings_by_severity'].items()
        }

        formatted_response['category_counts'] = {
            category: len(findings)
            for category, findings in formatted_response['findings_by_category'].items()
        }

        return formatted_response

    except Exception as e:
        logger.error(f"Error formatting results: {str(e)}")
        return {
            'summary': {
                'total_files_scanned': 0,
                'total_findings': 0,
                'files_scanned': [],
                'semgrep_version': 'unknown',
                'scan_status': 'failed'
            },
            'findings': [],
            'findings_by_severity': {
                'HIGH': [], 'MEDIUM': [], 'LOW': [], 'WARNING': [], 'INFO': []
            },
            'findings_by_category': {},
            'errors': [f"Failed to format results: {str(e)}"],
            'severity_counts': {},
            'category_counts': {}
        }

try:
    APP_ID = os.getenv('GITHUB_APP_ID')
    WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET')
    PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')
    
    if not all([APP_ID, WEBHOOK_SECRET, PRIVATE_KEY]):
        raise ValueError("Missing required environment variables")
    
    formatted_key = format_private_key(PRIVATE_KEY)
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("GitHub Integration initialized successfully")
except Exception as e:
    logger.error(f"Configuration error: {str(e)}")
    raise

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.getenv('PORT', 10000))
    app.run(port=port)