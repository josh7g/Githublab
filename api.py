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
import aiohttp
import json



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
async def trigger_repository_scan():
    """Trigger a semgrep security scan for a repository and get reranking"""
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

    async def run_scan():
        analysis = None
        try:
            # Get GitHub token
            try:
                installation_token = git_integration.get_access_token(int(installation_id)).token
            except Exception as token_error:
                return {
                    'success': False,
                    'error': {
                        'message': 'GitHub authentication failed',
                        'code': 'AUTH_ERROR',
                        'details': str(token_error)
                    }
                }, 401

            config = ScanConfig()
            
            # Create initial analysis record
            analysis = AnalysisResult(
                repository_name=f"{owner}/{repo}",
                user_id=user_id,
                status='in_progress'
            )
            db.session.add(analysis)
            db.session.commit()
            logger.info(f"Created analysis record with ID: {analysis.id}")

            # Run the security scan
            async with SecurityScanner(config=config, db_session=db.session) as scanner:
                scan_results = await scanner.scan_repository(
                    repo_url=f"https://github.com/{owner}/{repo}",
                    installation_token=installation_token,
                    user_id=user_id
                )

                if scan_results.get('success'):
                    # Store original scan results
                    analysis.results = scan_results.get('data')
                    
                    # Get findings and add IDs
                    findings = scan_results.get('data', {}).get('findings', [])
                    for idx, finding in enumerate(findings, 1):
                        finding['ID'] = idx

                    # Prepare simplified data for LLM
                    llm_data = {
                        'findings': [{
                            "ID": finding["ID"],
                            "file": finding["file"],
                            "code_snippet": finding["code_snippet"],
                            "message": finding["message"],
                            "severity": finding["severity"]
                        } for finding in findings],
                        'metadata': {
                            'repository': f"{owner}/{repo}",
                            'user_id': user_id,
                            'timestamp': datetime.utcnow().isoformat(),
                            'scan_id': analysis.id
                        }
                    }

                    # Send to AI reranking service
                    AI_RERANK_URL = os.getenv('RERANK_API_URL')
                    if not AI_RERANK_URL:
                        raise ValueError("RERANK_API_URL not configured")

                    async with aiohttp.ClientSession() as session:
                        async with session.post(AI_RERANK_URL, json=llm_data) as response:
                            if response.status == 200:
                                try:
                                    response_data = await response.json()
                                    # Get the string array from llm_response and convert it to actual array
                                    array_string = response_data.get('llm_response', '[]')
                                    # Convert string "[1,2,3]" to actual array [1,2,3]
                                    reranked_ids = json.loads(array_string)
                                    
                                    # Create mapping of ID to finding
                                    findings_map = {finding['ID']: finding for finding in findings}
                                    
                                    # Reorder findings based on LLM response
                                    reordered_findings = [findings_map[id] for id in reranked_ids]
                                    
                                    # Store reranked results
                                    rerank_results = reordered_findings
                                    
                                    # Update analysis record
                                    analysis.rerank = rerank_results
                                    analysis.status = 'completed'
                                    db.session.commit()
                                    logger.info(f"Updated analysis {analysis.id} with reranked results")
                                    
                                    # Add reranked results to response
                                    scan_results['data']['reranked_findings'] = rerank_results
                                    
                                except Exception as e:
                                    logger.error(f"Error processing LLM response: {str(e)}")
                                    logger.error(f"Raw response: {await response.text()}")
                                    analysis.status = 'reranking_failed'
                                    analysis.error = f"Error processing LLM response: {str(e)}"
                                    db.session.commit()
                            else:
                                error_text = await response.text()
                                logger.error(f"AI reranking failed: {error_text}")
                                analysis.status = 'reranking_failed'
                                analysis.error = f"Reranking failed: {error_text}"
                                db.session.commit()
                                        
                    return scan_results, 200
                else:
                    analysis.status = 'failed'
                    analysis.error = scan_results.get('error', {}).get('message', 'Scan failed')
                    db.session.commit()
                    return scan_results, 500

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            if analysis:
                analysis.status = 'failed'
                analysis.error = str(e)
                db.session.commit()
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'UNEXPECTED_ERROR'
                }
            }, 500

    # Run the async function
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results, status_code = await run_scan()
        return jsonify(results), status_code
    except Exception as e:
        logger.error(f"Error in async execution: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Error in async execution',
                'code': 'ASYNC_ERROR',
                'details': str(e)
            }
        }), 500
    

@analysis_bp.route('/<owner>/<repo>/reranked', methods=['GET'])
def get_reranked_findings(owner: str, repo: str):
    try:
        # Get latest analysis result
        result = AnalysisResult.query.filter_by(
            repository_name=f"{owner}/{repo}"
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

        if not result.rerank:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No reranked results available',
                    'code': 'NO_RERANK_RESULTS'
                }
            }), 404

        # Just return the reranked findings array
        return jsonify(result.rerank)
        
    except Exception as e:
        logger.error(f"Error getting reranked findings: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR'
            }
        }), 500