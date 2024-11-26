from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc
from models import db, AnalysisResult
from collections import defaultdict
import os
import ssl
import fnmatch
import logging
from pathlib import Path
from github import Github
from github import GithubIntegration
import asyncio
import logging
from scanner import scan_repository_handler
from scanner import scan_repository_handler, deduplicate_findings
from typing import Dict, Any, List
from datetime import datetime
from scanner import SecurityScanner, ScanConfig
import git



logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

api = Blueprint('api', __name__, url_prefix='/api/v1')


@api.route('/files', methods=['POST'])
def get_vulnerable_file():
    """Fetch vulnerable file content from GitHub using POST with all parameters in request body"""
    from app import git_integration
    
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters from request body
    owner = request_data.get('owner')
    repo = request_data.get('repo')
    installation_id = request_data.get('installation_id')
    filename = request_data.get('file_name')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'owner': owner,
        'repo': repo,
        'installation_id': installation_id,
        'file_name': filename,
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {'message': f'Missing required parameters: {", ".join(missing_params)}'}
        }), 400

    try:
        # Get GitHub token
        installation_token = git_integration.get_access_token(int(installation_id)).token
        gh = Github(installation_token)
        
        repository = gh.get_repo(f"{owner}/{repo}")
        default_branch = repository.default_branch
        latest_commit = repository.get_branch(default_branch).commit
        commit_sha = latest_commit.sha

        # Get file content from GitHub
        try:
            file_content = repository.get_contents(filename, ref=commit_sha)
            content = file_content.decoded_content.decode('utf-8')
            
            return jsonify({
                'success': True,
                'data': {
                    'file': content,
                    'user_id': user_id,
                    'version': commit_sha,
                    'reponame': f"{owner}/{repo}",
                    'filename': filename
                }
            })

        except Exception as e:
            logger.error(f"Error fetching file: {str(e)}")
            return jsonify({
                'success': False,
                'error': {'message': 'File not found or inaccessible'}
            }), 404

    except Exception as e:
        logger.error(f"GitHub API error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500


analysis_bp = Blueprint('analysis', __name__, url_prefix='/api/v1/analysis')

@analysis_bp.route('/<owner>/<repo>/result', methods=['GET'])
def get_analysis_findings(owner: str, repo: str):
    """Get detailed findings with filtering and pagination"""
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('limit', 30))))
        severity = request.args.get('severity', '').upper()
        category = request.args.get('category', '')
        file_path = request.args.get('file', '')
        
        repo_name = f"{owner}/{repo}"
        
        # Get latest analysis result
        result = AnalysisResult.query.filter_by(
            repository_name=repo_name
        ).order_by(
            desc(AnalysisResult.timestamp)
        ).first()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No analysis found',
                    'code': 'ANALYSIS_NOT_FOUND'
                }
            }), 404

        # Extract findings
        findings = result.results.get('findings', [])
        
        # Apply filters
        if severity:
            findings = [f for f in findings if f.get('severity', '').upper() == severity]
        if category:
            findings = [f for f in findings if f.get('category', '').lower() == category.lower()]
        if file_path:
            findings = [f for f in findings if file_path in f.get('file', '')]
        
        # Get total count before pagination
        total_findings = len(findings)
        
        # Apply pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_findings = findings[start_idx:end_idx]
        
        # Get unique values for filters
        all_severities = sorted(set(f.get('severity', '').upper() for f in findings))
        all_categories = sorted(set(f.get('category', '').lower() for f in findings))
        
        return jsonify({
            'success': True,
            'data': {
                'repository': {
                    'name': repo_name,
                    'owner': owner,
                    'repo': repo
                },
                'metadata': {
                    'analysis_id': result.id,
                    'timestamp': result.timestamp.isoformat(),
                    'status': result.status,
                    'duration_seconds': result.results.get('metadata', {}).get('scan_duration_seconds')
                },
                'summary': {
                    'files_scanned': result.results.get('stats', {}).get('scan_stats', {}).get('files_scanned', 0),
                    'total_findings': total_findings,
                    'severity_counts': result.results.get('stats', {}).get('severity_counts', {}),
                    'category_counts': result.results.get('stats', {}).get('category_counts', {})
                },
                'findings': paginated_findings,
                'pagination': {
                    'current_page': page,
                    'total_pages': (total_findings + per_page - 1) // per_page,
                    'total_items': total_findings,
                    'per_page': per_page
                },
                'filters': {
                    'available_severities': all_severities,
                    'available_categories': all_categories,
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR'
            }
        }), 500

@api.route('/users/<user_id>/top-vulnerabilities', methods=['GET'])
def get_top_vulnerabilities(user_id):
    try:
        analyses = AnalysisResult.query.filter(
            AnalysisResult.user_id == user_id,
            AnalysisResult.status == 'completed',
            AnalysisResult.results.isnot(None)
        ).order_by(AnalysisResult.timestamp.desc()).all()

        if not analyses:
            return jsonify({
                'success': False,
                'error': {'message': 'No analyses found'}
            }), 404

        # Track statistics
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        repo_counts = defaultdict(int)
        unique_vulns = {}

        for analysis in analyses:
            findings = analysis.results.get('findings', [])
            repo_name = analysis.repository_name
            
            for finding in findings:
                vuln_id = finding.get('id')
                if vuln_id not in unique_vulns:
                    unique_vulns[vuln_id] = {
                        'vulnerability_id': vuln_id,
                        'severity': finding.get('severity'),
                        'category': finding.get('category'),
                        'message': finding.get('message'),
                        'code_snippet': finding.get('code_snippet'),
                        'file': finding.get('file'),
                        'line_range': {
                            'start': finding.get('line_start'),
                            'end': finding.get('line_end')
                        },
                        'security_references': {
                            'cwe': finding.get('cwe', []),
                            'owasp': finding.get('owasp', [])
                        },
                        'fix_recommendations': {
                            'description': finding.get('fix_recommendations', ''),
                            'references': finding.get('references', [])
                        },
                        'repository': {
                            'name': repo_name.split('/')[-1],
                            'full_name': repo_name,
                            'analyzed_at': analysis.timestamp.isoformat()
                        }
                    }
                    
                    severity_counts[finding.get('severity')] += 1
                    category_counts[finding.get('category')] += 1
                    repo_counts[repo_name] += 1

        return jsonify({
            'success': True,
            'data': {
                'metadata': {
                    'user_id': user_id,
                    'total_vulnerabilities': len(unique_vulns),
                    'total_repositories': len(repo_counts),
                    'severity_breakdown': severity_counts,
                    'category_breakdown': category_counts,
                    'repository_breakdown': repo_counts,
                    'last_scan': analyses[0].timestamp.isoformat() if analyses else None,
                    'repository': None  # For compatibility with existing format
                },
                'vulnerabilities': list(unique_vulns.values())
            }
        })

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({
            'success': False,
            'error': {'message': str(e)}
        }), 500



@api.route('/scan', methods=['POST'])
def trigger_repository_scan():
    """Trigger a semgrep security scan for a repository with deduplication"""
    from app import git_integration, db
    
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters from request body
    owner = request_data.get('owner')
    repo = request_data.get('repo')
    installation_id = request_data.get('installation_id')
    user_id = request_data.get('user_id')
    
    # Validate required parameters
    required_params = {
        'owner': owner,
        'repo': repo,
        'installation_id': installation_id,
        'user_id': user_id
    }
    
    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return jsonify({
            'success': False,
            'error': {
                'message': f'Missing required parameters: {", ".join(missing_params)}',
                'code': 'INVALID_PARAMETERS'
            }
        }), 400

    repo_url = f"https://github.com/{owner}/{repo}"
    if not repo_url.startswith(('https://github.com/', 'git@github.com:')):
        return jsonify({
            'success': False,
            'error': {
                'message': 'Invalid repository URL format',
                'code': 'INVALID_REPOSITORY_URL',
                'details': 'Only GitHub repositories are supported'
            }
        }), 400

    async def run_scan():
        try:
            # Get GitHub token with error handling
            try:
                logger.info(f"Getting access token for installation ID: {installation_id}")
                token_response = git_integration.get_access_token(int(installation_id))
                
                if not token_response:
                    raise ValueError("Empty token response from GitHub")
                    
                if not hasattr(token_response, 'token'):
                    raise ValueError("Invalid token response format")
                    
                installation_token = token_response.token
                if not installation_token:
                    raise ValueError("Empty token value")
                    
                logger.info(f"Successfully obtained GitHub token for installation ID: {installation_id}")
                    
            except Exception as token_error:
                error_msg = f"Failed to get GitHub access token: {str(token_error)}"
                logger.error(error_msg)
                
                # Store token error in database
                try:
                    error_analysis = AnalysisResult(
                        repository_name=f"{owner}/{repo}",
                        user_id=user_id,
                        status='error',
                        error=error_msg,
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(error_analysis)
                    db.session.commit()
                except Exception as db_e:
                    logger.error(f"Failed to store error record: {str(db_e)}")
                    db.session.rollback()
                
                return {
                    'success': False,
                    'error': {
                        'message': 'GitHub authentication failed',
                        'code': 'AUTH_ERROR',
                        'details': str(token_error),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                }, 401

            # Initialize scanner with config and db session
            config = ScanConfig()
            
            # Use async context manager to properly initialize scanner
            async with SecurityScanner(config=config, db_session=db.session) as scanner:
                try:
                    # Pre-check repository size
                    size_info = await scanner._check_repository_size(repo_url, installation_token)
                    
                    if not size_info:
                        raise ValueError("Failed to get repository size information")
                        
                    if not size_info.get('is_compatible'):
                        return {
                            'success': False,
                            'error': {
                                'message': 'Repository too large for analysis',
                                'code': 'REPOSITORY_TOO_LARGE',
                                'details': {
                                    'size_mb': size_info.get('size_mb', 0),
                                    'limit_mb': config.max_total_size_mb,
                                    'recommendation': 'Consider analyzing specific directories or branches'
                                }
                            }
                        }, 400
                    
                    # Run the scan
                    scan_results = await scanner.scan_repository(
                        repo_url=repo_url,
                        installation_token=installation_token,
                        user_id=user_id
                    )
                    
                    if scan_results.get('success'):
                        # Add repository metadata
                        if 'data' not in scan_results:
                            scan_results['data'] = {}
                            
                        scan_results['data']['repository_info'] = {
                            'size_mb': size_info.get('size_mb', 0),
                            'primary_language': size_info.get('language', 'unknown'),
                            'default_branch': size_info.get('default_branch', 'main')
                        }
                    
                    return scan_results, 200

                except ValueError as ve:
                    error_msg = str(ve)
                    logger.error(f"Validation error: {error_msg}")
                    return {
                        'success': False,
                        'error': {
                            'message': error_msg,
                            'code': 'VALIDATION_ERROR',
                            'timestamp': datetime.utcnow().isoformat()
                        }
                    }, 400

        except Exception as e:
            error_msg = f"Unexpected error in scan handler: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': {
                    'message': 'Unexpected error in scan handler',
                    'code': 'INTERNAL_ERROR',
                    'details': str(e),
                    'type': type(e).__name__,
                    'timestamp': datetime.utcnow().isoformat()
                }
            }, 500

    # Run the async function
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results, status_code = loop.run_until_complete(run_scan())
        loop.close()
        return jsonify(results), status_code
    except Exception as e:
        logger.error(f"Error in async execution: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Error in async execution',
                'code': 'ASYNC_ERROR',
                'details': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
        }), 500