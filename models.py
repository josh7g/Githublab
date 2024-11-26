from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB

db = SQLAlchemy()

class AnalysisResult(db.Model):
    __tablename__ = 'analysis_results'
    
    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    user_id = db.Column(db.String(255))
    rerank = db.Column(JSONB)  # New column for reranked results
    
    def to_dict(self):
        return {
            'id': self.id,
            'repository_name': self.repository_name,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'results': self.results,
            'error': self.error
        }