import requests
import sqlite3
import logging
from datetime import datetime

# 로깅 설정
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MitreAttackDatabaseCreator:
    def __init__(self, db_path='mitre_attack.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.api_base_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.create_tables()
        logger.info("MITRE ATT&CK 데이터베이스 생성 시스템이 초기화되었습니다.")

    def create_tables(self):
        # techniques 테이블 생성
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS techniques (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            detection TEXT,
            last_updated TEXT
        )
        ''')
        self.conn.commit()
        logger.info("데이터베이스 테이블이 생성되었거나 이미 존재합니다.")

    def fetch_techniques(self):
        # MITRE ATT&CK 데이터를 가져옵니다.
        logger.info("MITRE ATT&CK에서 기술 정보를 가져오는 중...")
        response = requests.get(self.api_base_url)
        if response.status_code == 200:
            data = response.json()
            techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
            logger.info(f"성공적으로 {len(techniques)}개의 기술 정보를 가져왔습니다.")
            return techniques
        else:
            logger.error(f"기술 정보 가져오기 실패: 상태 코드 {response.status_code}")
            raise Exception(f"Failed to fetch techniques: {response.status_code}")

    def process_techniques(self, techniques):
        # 기술 정보를 데이터베이스에 저장
        logger.info(f"{len(techniques)}개의 기술 정보 처리 중...")
        for technique in techniques:
            technique_id = technique['external_references'][0]['external_id']
            name = technique['name']
            description = technique.get('description', '')
            detection = technique.get('x_mitre_detection', '')
            last_updated = datetime.now().isoformat()

            # techniques 테이블에 데이터 삽입
            self.cursor.execute('''
            INSERT OR REPLACE INTO techniques (id, name, description, detection, last_updated)
            VALUES (?, ?, ?, ?, ?)
            ''', (technique_id, name, description, detection, last_updated))
        
        self.conn.commit()
        logger.info("모든 기술 정보가 처리되어 데이터베이스에 저장되었습니다.")

    def create_database(self):
        # 데이터 수집 및 처리 과정을 관리
        logger.info("데이터 수집 및 데이터베이스 생성 프로세스 시작")
        techniques = self.fetch_techniques()
        self.process_techniques(techniques)
        logger.info(f"데이터베이스 생성 완료. {len(techniques)}개의 기술 정보가 데이터베이스에 저장되었습니다.")

    def close(self):
        # 데이터베이스 연결 종료
        self.conn.close()
        logger.info("데이터베이스 연결이 종료되었습니다.")

if __name__ == "__main__":
    # MITRE ATT&CK 데이터베이스 생성기 초기화
    db_creator = MitreAttackDatabaseCreator(db_path='mitre_attack.db')
    db_creator.create_database()
    db_creator.close()
