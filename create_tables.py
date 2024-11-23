# db_cleanup.py
from app import app, db
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def backup_data():
    """Backup existing data"""
    with app.app_context():
        try:
            result = db.session.execute(text("""
                SELECT id, repository_name, timestamp, status, results, error
                FROM analysis_results
            """))
            return [dict(row) for row in result]
        except Exception as e:
            logger.error(f"Error backing up data: {str(e)}")
            return None

def rebuild_table():
    """Rebuild the table with correct schema"""
    with app.app_context():
        try:
            # Backup existing data
            logger.info("Backing up existing data...")
            backup = backup_data()
            
            if backup:
                logger.info(f"Backed up {len(backup)} records")
            
            # Drop existing table
            logger.info("Dropping existing table...")
            db.session.execute(text("DROP TABLE IF EXISTS analysis_results CASCADE"))
            db.session.commit()
            
            # Recreate table with correct schema
            logger.info("Recreating table with correct schema...")
            db.create_all()
            
            if backup:
                # Restore data with null user_id
                logger.info("Restoring data...")
                for record in backup:
                    db.session.execute(text("""
                        INSERT INTO analysis_results 
                        (id, repository_name, timestamp, status, results, error, user_id)
                        VALUES (:id, :repository_name, :timestamp, :status, :results, :error, NULL)
                    """), record)
                
                db.session.commit()
                logger.info("Data restored successfully!")
            
            logger.info("Table rebuild completed!")
            
        except Exception as e:
            logger.error(f"Error rebuilding table: {str(e)}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    rebuild_table()